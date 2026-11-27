package configuration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// This composition fixture performs real DNS, TLS, LDAP BER, stable GUID and
// BASE tokenGroups reads through public production APIs. It manually seeds an
// already enabled provider and approved scoped grants; it does not qualify
// provider activation, a real AD DS installation, or native WAF qualification.
// The package has no t.Parallel tests: replacing DefaultResolver is process-local
// and restored after all fixture connections have stopped.
const directoryWireHost = "dc01.corp.test"

type directoryWireAuthority struct{ securityjournal.Authority }

func (a directoryWireAuthority) Head(ctx context.Context) (securityjournal.Head, error) {
	h, err := a.Authority.Head(ctx)
	h.RecordedAt = time.Now().UTC()
	return h, err
}

type directoryWireSecrets struct{ ca []byte }

func (s directoryWireSecrets) ResolveDirectorySecrets(context.Context, string, string) (identity.DirectorySecrets, error) {
	return identity.DirectorySecrets{BindPassword: []byte("synthetic-service-password"), CACertificatesPEM: bytes.Clone(s.ca)}, nil
}

type directoryWirePeer struct {
	listener net.Listener
	cert     tls.Certificate
	ca       []byte
	mu       sync.Mutex
	conns    []net.Conn
	wg       sync.WaitGroup
	disabled atomic.Bool
	outage   atomic.Bool
	binds    atomic.Int64
	groups   atomic.Int64
	guid     atomic.Int64
}

func directoryWireDNS(t *testing.T) {
	t.Helper()
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("open process-local synthetic DNS socket")
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buffer := make([]byte, 4096)
		for {
			n, peer, err := socket.ReadFrom(buffer)
			if err != nil {
				return
			}
			var request dnsmessage.Message
			if request.Unpack(buffer[:n]) != nil {
				continue
			}
			response := dnsmessage.Message{Header: dnsmessage.Header{ID: request.Header.ID, Response: true, Authoritative: true, RecursionAvailable: true}, Questions: request.Questions}
			for _, question := range request.Questions {
				if question.Name.String() != directoryWireHost+"." {
					response.Header.RCode = dnsmessage.RCodeNameError
					continue
				}
				if question.Type == dnsmessage.TypeA {
					response.Answers = append(response.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 0}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}})
				}
			}
			packet, err := response.Pack()
			if err == nil {
				_, _ = socket.WriteTo(packet, peer)
			}
		}
	}()
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp4", socket.LocalAddr().String())
	}}
	t.Cleanup(func() { net.DefaultResolver = previous; _ = socket.Close(); wg.Wait() })
}

func newDirectoryWirePeer(t *testing.T) *directoryWirePeer {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate synthetic CA")
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic configuration AD CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal("sign synthetic CA")
	}
	serverPub, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate synthetic DC key")
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{directoryWireHost}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, serverPub, key)
	if err != nil {
		t.Fatal("sign synthetic DC certificate")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("open synthetic DC TLS socket")
	}
	f := &directoryWirePeer{listener: listener, cert: tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: serverKey}, ca: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.conns = append(f.conns, connection)
			f.mu.Unlock()
			f.wg.Add(1)
			go func() { defer f.wg.Done(); defer connection.Close(); f.serve(connection) }()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		f.mu.Lock()
		for _, connection := range f.conns {
			_ = connection.Close()
		}
		f.mu.Unlock()
		f.wg.Wait()
	})
	return f
}

func directoryWirePacket(mid int64, tag ber.Tag, children ...*ber.Packet) *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, mid, ""))
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
	for _, child := range children {
		op.AppendChild(child)
	}
	packet.AppendChild(op)
	return packet
}

func directoryWireResult(mid int64, tag ber.Tag, code int64) *ber.Packet {
	return directoryWirePacket(mid, tag, ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""), ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""), ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "synthetic redacted diagnostic", ""))
}

func directoryWireEntry(mid int64, dn string, attributes map[string][]string) *ber.Packet {
	sequence := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	for name, values := range attributes {
		attribute := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		attribute.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, ""))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
		for _, value := range values {
			set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, ""))
		}
		attribute.AppendChild(set)
		sequence.AppendChild(attribute)
	}
	return directoryWirePacket(mid, ldap.ApplicationSearchResultEntry, ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, ""), sequence)
}

func directoryWireGUID(value string) []byte {
	raw, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	if err != nil || len(raw) != 16 {
		panic("invalid synthetic GUID constant")
	}
	raw[0], raw[1], raw[2], raw[3] = raw[3], raw[2], raw[1], raw[0]
	raw[4], raw[5] = raw[5], raw[4]
	raw[6], raw[7] = raw[7], raw[6]
	return raw
}

func (f *directoryWirePeer) serve(raw net.Conn) {
	if f.outage.Load() {
		return
	}
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	connection := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{f.cert}, MinVersion: tls.VersionTLS12})
	if connection.Handshake() != nil {
		return
	}
	for {
		packet, err := ber.ReadPacket(connection)
		if err != nil || len(packet.Children) < 2 {
			return
		}
		mid, _ := packet.Children[0].Value.(int64)
		op := packet.Children[1]
		switch op.Tag {
		case ldap.ApplicationBindRequest:
			if len(op.Children) < 3 {
				return
			}
			dn, _ := op.Children[1].Value.(string)
			code := int64(49)
			if dn == "CN=reader,OU=People,DC=corp,DC=test" && bytes.Equal(op.Children[2].Data.Bytes(), []byte("synthetic-service-password")) {
				code = 0
				f.binds.Add(1)
			}
			if _, err = connection.Write(directoryWireResult(mid, ldap.ApplicationBindResponse, code).Bytes()); err != nil {
				return
			}
		case ldap.ApplicationSearchRequest:
			if len(op.Children) < 7 {
				return
			}
			base, _ := op.Children[0].Value.(string)
			scope, _ := op.Children[1].Value.(int64)
			filter, _ := ldap.DecompileFilter(op.Children[6])
			dn, attributes := f.search(base, filter, scope)
			if attributes != nil {
				if _, err = connection.Write(directoryWireEntry(mid, dn, attributes).Bytes()); err != nil {
					return
				}
			}
			if _, err = connection.Write(directoryWireResult(mid, ldap.ApplicationSearchResultDone, 0).Bytes()); err != nil {
				return
			}
		default:
			return
		}
	}
}

func (f *directoryWirePeer) search(base, filter string, scope int64) (string, map[string][]string) {
	const domain = "DC=corp,DC=test"
	if base == "" {
		return "", map[string][]string{"defaultNamingContext": {domain}, "configurationNamingContext": {"CN=Configuration," + domain}, "supportedCapabilities": {"1.2.840.113556.1.4.800"}, "isGlobalCatalogReady": {"TRUE"}}
	}
	if base == "CN=Configuration,"+domain {
		f.guid.Add(1)
		return base, map[string][]string{"objectGUID": {string(directoryWireGUID("00112233-4455-6677-8899-aabbccddeeff"))}}
	}
	sid := []byte{1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 42, 0, 0, 0}
	if strings.Contains(filter, "objectClass=group") {
		return "CN=Portal,OU=Groups," + domain, map[string][]string{"objectGUID": {string(directoryWireGUID("10112233-4455-6677-8899-aabbccddeeff"))}, "objectSid": {string(sid)}, "groupType": {"-2147483646"}}
	}
	const userDN = "CN=Reviewer,OU=People," + domain
	attributes := map[string][]string{"objectGUID": {string(directoryWireGUID("20112233-4455-6677-8899-aabbccddeeff"))}}
	if scope == ldap.ScopeBaseObject && base == userDN {
		f.groups.Add(1)
		uac := "512"
		if f.disabled.Load() {
			uac = "514"
		}
		attributes["userPrincipalName"] = []string{"reviewer@corp.test"}
		attributes["displayName"] = []string{"Synthetic reviewer"}
		attributes["userAccountControl"] = []string{uac}
		attributes["msDS-User-Account-Control-Computed"] = []string{"0"}
		attributes["accountExpires"] = []string{"0"}
		attributes["tokenGroups"] = []string{string(sid)}
	}
	return userDN, attributes
}

type directoryWafFixture struct {
	*testFixture
	wire      *directoryWirePeer
	document  identity.DirectoryProviderDocument
	principal string
}

func directoryWafFixtureNew(t *testing.T, pg bool, principal string) *directoryWafFixture {
	t.Helper()
	f, _ := wafFixture(t, pg)
	wire := newDirectoryWirePeer(t)
	document := identity.DirectoryProviderDocument{APIVersion: "agp.identity/v1alpha1", Kind: "DirectoryProvider", Metadata: identity.DirectoryMetadata{ID: "dir_waf_wire", VersionID: "dirver_waf_wire_1", SecurityGuardID: "guard_waf_wire", SecurityGuardVersion: 1}, Spec: identity.DirectorySpec{ForestGUID: "00112233-4455-6677-8899-aabbccddeeff", DomainDNS: "corp.test", Transport: "ldaps", Endpoints: []identity.DirectoryEndpoint{{Host: directoryWireHost, Port: wire.listener.Addr().(*net.TCPAddr).Port}}, UserBaseDNs: []string{"OU=People,DC=corp,DC=test"}, GroupBaseDNs: []string{"OU=Groups,DC=corp,DC=test"}, BindDN: "CN=reader,OU=People,DC=corp,DC=test", BindSecretVersionID: "secret_waf_wire_bind", CASecretVersionID: "secret_waf_wire_ca", LoginAttribute: "userPrincipalName", Provisioning: "preprovisioned", GroupResolution: "token_groups_security", AccountCheck: "live_each_allow", OperationTimeoutSeconds: 2, MaximumGroups: 128, GroupMappings: []identity.DirectoryGroupMapping{}}}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal("encode synthetic directory document")
	}
	normalized, err := identity.ParseDirectoryProvider(bytes.NewReader(raw))
	if err != nil {
		t.Fatal("parse synthetic directory document", err)
	}
	document = *normalized
	canonical, err := configmodel.CanonicalJSON(document)
	if err != nil {
		t.Fatal("canonicalize synthetic directory document")
	}
	digest, err := configmodel.Digest(document)
	if err != nil {
		t.Fatal("digest synthetic directory document")
	}
	now := time.Now().UTC()
	// Trusted fixture seed only. Production creation/activation is not bypassed
	// by the service being tested; no synthetic live-proof context is inserted.
	err = f.store.WriteIdentity(context.Background(), func(tx storage.IdentityTx) error {
		queries := []struct {
			query string
			args  []any
		}{
			{`INSERT INTO directory_providers(id,name,forest_guid,guard_id,row_version,guard_version,enabled,active_version_id,created_at) VALUES(?,?,?,?,1,1,TRUE,?,?)`, []any{document.Metadata.ID, "Synthetic AD", document.Spec.ForestGUID, document.Metadata.SecurityGuardID, document.Metadata.VersionID, now}},
			{`INSERT INTO directory_provider_versions(id,provider_id,guard_version,content_digest,canonical_json,author_id,author_fingerprint,created_at) VALUES(?,?,1,?,?,?,?,?)`, []any{document.Metadata.VersionID, document.Metadata.ID, digest, string(canonical), "s1_admin", "synthetic-bootstrap-provenance", now}},
			{`UPDATE users SET identity_kind='directory',password_hash='' WHERE id=?`, []any{principal}},
			{`INSERT INTO directory_identities(id,principal_id,provider_id,forest_guid,object_guid,authenticator_version,created_at) VALUES('diridentity_waf_wire',?,?,?,?,1,?)`, []any{principal, document.Metadata.ID, document.Spec.ForestGUID, "20112233-4455-6677-8899-aabbccddeeff", now}},
			{`UPDATE sessions SET directory_identity_id='diridentity_waf_wire',directory_identity_version=1,directory_provider_version_id=?,directory_provider_guard_version=1 WHERE user_id=?`, []any{document.Metadata.VersionID, principal}},
		}
		for _, query := range queries {
			if _, err := tx.Exec(context.Background(), query.query, query.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal("seed synthetic directory identity", err)
	}
	coordinator := f.service.current.(*securitystate.Coordinator)
	coordinator.Authority = directoryWireAuthority{coordinator.Authority}
	connector, err := identity.NewADConnector(directoryWireSecrets{wire.ca}, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	if err != nil {
		t.Fatal("construct actual directory connector")
	}
	directory := identity.NewDirectoryService(coordinator, f.actor.Origin, connector)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal("generate synthetic identity key")
	}
	keys := &identity.Keyring{Active: "test", Keys: map[string]string{"test": base64.RawURLEncoding.EncodeToString(key)}}
	clear(key)
	authentication, err := identity.New(f.store, coordinator, keys, domain.SessionProfile{ManagementOrigin: f.actor.Origin, LoginOrigin: "https://login.test", SecureProfile: true})
	if err != nil {
		t.Fatal("construct actual identity service")
	}
	authentication.WithDirectory(directory, connector)
	f.service.WithDirectorySubjects(directory)
	return &directoryWafFixture{testFixture: f, wire: wire, document: document, principal: principal}
}

func (f *directoryWafFixture) mutate(t *testing.T, change string) {
	t.Helper()
	if change == "ad_disabled" {
		f.wire.disabled.Store(true)
		return
	}
	if change == "tls_outage" {
		f.wire.outage.Store(true)
		return
	}
	err := f.store.WriteIdentity(context.Background(), func(tx storage.IdentityTx) error {
		var err error
		switch change {
		case "revoked_link":
			_, err = tx.Exec(context.Background(), `UPDATE directory_identities SET revoked=TRUE WHERE principal_id=?`, f.principal)
		case "restored_link_below_floor":
			_, err = tx.Exec(context.Background(), `INSERT INTO authenticator_floors(principal_id,authenticator_id,minimum_version) VALUES(?,'diridentity_waf_wire',2)`, f.principal)
		case "provider_below_floor":
			_, err = tx.Exec(context.Background(), `INSERT INTO authenticator_floors(principal_id,authenticator_id,minimum_version) VALUES(?,?,2)`, f.document.Metadata.SecurityGuardID, f.document.Metadata.SecurityGuardID)
		case "provider_disabled":
			_, err = tx.Exec(context.Background(), `UPDATE directory_providers SET enabled=FALSE WHERE id=?`, f.document.Metadata.ID)
		case "provider_changed":
			document := f.document
			document.Metadata.VersionID = "dirver_waf_wire_2"
			document.Metadata.SecurityGuardVersion = 2
			canonical, err := configmodel.CanonicalJSON(document)
			if err != nil {
				return err
			}
			digest, err := configmodel.Digest(document)
			if err != nil {
				return err
			}
			if _, err = tx.Exec(context.Background(), `INSERT INTO directory_provider_versions(id,provider_id,guard_version,content_digest,canonical_json,author_id,author_fingerprint,created_at) VALUES(?,?,2,?,?,?,?,?)`, document.Metadata.VersionID, document.Metadata.ID, digest, string(canonical), "s1_admin", "synthetic-bootstrap-provenance", time.Now().UTC()); err != nil {
				return err
			}
			_, err = tx.Exec(context.Background(), `UPDATE directory_providers SET row_version=2,guard_version=2,active_version_id=? WHERE id=?`, document.Metadata.VersionID, document.Metadata.ID)
		default:
			return errors.New("unknown synthetic fixture mutation")
		}
		return err
	})
	if err != nil {
		t.Fatal("mutate synthetic directory state", err)
	}
}

func TestDirectoryWAFWireSQLite(t *testing.T)   { testDirectoryWAFWire(t, false) }
func TestDirectoryWAFWirePostgres(t *testing.T) { testDirectoryWAFWire(t, true) }

func testDirectoryWAFWire(t *testing.T, pg bool) {
	directoryWireDNS(t)
	ctx := context.Background()
	for _, change := range []string{"valid", "ad_disabled", "revoked_link", "restored_link_below_floor", "provider_below_floor", "provider_disabled", "provider_changed", "tls_outage"} {
		t.Run("historical_ad_reviewer_"+change, func(t *testing.T) {
			f := directoryWafFixtureNew(t, pg, "waf_approver")
			revision := createWaf(t, f.testFixture)
			validateWaf(t, f.testFixture, revision)
			approveWaf(t, f.testFixture, revision)
			before := f.wire.binds.Load()
			if before == 0 || f.wire.groups.Load() == 0 || f.wire.guid.Load() == 0 {
				t.Fatal("AD reviewer approval lacked actual TLS/BER identity reads")
			}
			if change != "valid" {
				f.mutate(t, change)
			}
			// The publisher is a distinct local principal with explicit edit and
			// approve grants. Its current local session cannot stand in for the
			// historical reviewer's directory identity.
			published, err := f.service.PublishWafPolicyRevision(ctx, wafActor(f.testFixture, "waf_author"), revision.ID, "directory_wire_publish_001", WafPolicyPublicationRequest{revision.ContentDigest})
			count := scalar(t, f.testFixture, `SELECT COUNT(*) FROM config_waf_policy_publications WHERE policy_revision_id=?`, revision.ID)
			if change == "valid" {
				if err != nil || published == nil || published.State != "published" || count != 1 || f.wire.binds.Load() <= before {
					t.Fatal("current actual-wire AD reviewer did not permit independent local publication", err)
				}
				return
			}
			if err == nil || count != 0 || published != nil {
				t.Fatal("invalid historical AD reviewer authorized publication")
			}
			if change == "tls_outage" && !errors.Is(err, identity.ErrDirectoryUnavailable) {
				t.Fatal("TLS infrastructure outage became stale/denied evidence instead of provider unavailable", err)
			}
			if change == "ad_disabled" && (errors.Is(err, identity.ErrDirectoryUnavailable) || f.wire.binds.Load() <= before) {
				t.Fatal("authoritative disabled account was not read/classified separately from outage", err)
			}
		})
	}
	for _, change := range []string{"valid", "ad_disabled", "revoked_link", "tls_outage"} {
		t.Run("historical_ad_author_"+change, func(t *testing.T) {
			f := directoryWafFixtureNew(t, pg, "waf_author")
			revision := createWaf(t, f.testFixture)
			validateWaf(t, f.testFixture, revision)
			if change != "valid" {
				f.mutate(t, change)
			}
			approval, err := f.service.ApproveWafPolicyRevision(ctx, wafActor(f.testFixture, "waf_approver"), revision.ID, "directory_author_approve_001", WafPolicyApprovalRequest{revision.ContentDigest, "Независимая проверка автора AD"})
			if change == "valid" {
				if err != nil || approval == nil {
					t.Fatal("local reviewer could not approve current actual-wire AD author", err)
				}
				published, err := f.service.PublishWafPolicyRevision(ctx, wafActor(f.testFixture, "waf_approver"), revision.ID, "directory_author_publish_001", WafPolicyPublicationRequest{revision.ContentDigest})
				if err != nil || published == nil || published.State != "published" || scalar(t, f.testFixture, `SELECT COUNT(*) FROM config_waf_policy_publications WHERE policy_revision_id=?`, revision.ID) != 1 {
					t.Fatal("local publication with current AD author failed", err)
				}
				return
			}
			if err == nil || approval != nil || scalar(t, f.testFixture, `SELECT COUNT(*) FROM config_waf_policy_approvals WHERE policy_revision_id=?`, revision.ID) != 0 || scalar(t, f.testFixture, `SELECT COUNT(*) FROM config_waf_policy_publications WHERE policy_revision_id=?`, revision.ID) != 0 {
				t.Fatal("invalid historical AD author authorized approval/publication")
			}
			if change == "tls_outage" && !errors.Is(err, identity.ErrDirectoryUnavailable) {
				t.Fatal("AD author TLS outage lost provider-unavailable classification", err)
			}
		})
	}
}
