package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
)

type adFixtureSecrets struct{ ca []byte }

func (s adFixtureSecrets) ResolveDirectorySecrets(context.Context, string, string) (DirectorySecrets, error) {
	return DirectorySecrets{BindPassword: []byte("synthetic-service-password"), CACertificatesPEM: append([]byte{}, s.ca...)}, nil
}

type adWireFixture struct {
	listener                                                            net.Listener
	config                                                              DirectoryProviderDocument
	connector                                                           *ADConnector
	cert                                                                tls.Certificate
	mu                                                                  sync.Mutex
	connections                                                         map[net.Conn]bool
	wg                                                                  sync.WaitGroup
	serviceBinds, userBinds                                             atomic.Int64
	wrongForest, disabled, referral, missingGroups, rejectTLS, hangBind atomic.Bool
	unmappedMembership                                                  atomic.Bool
	dnReassigned                                                        atomic.Bool
	lastUserBind                                                        string
	lastFilter                                                          string
}

func newADWireFixture(t *testing.T, transport string) *adWireFixture {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "AD fixture CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	parsedCA, e := x509.ParseCertificate(caDER)
	if e != nil {
		t.Fatal(e)
	}
	serverPub, serverKey, _ := ed25519.GenerateKey(rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"dc01.corp.example.net"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, leaf, parsedCA, serverPub, key)
	if e != nil {
		t.Fatal(e)
	}
	cert := tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: serverKey}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	connector, e := NewADConnector(adFixtureSecrets{caPEM}, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	if e != nil {
		t.Fatal(e)
	}
	connector.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	port := listener.Addr().(*net.TCPAddr).Port
	f := &adWireFixture{listener: listener, connector: connector, cert: cert, connections: map[net.Conn]bool{}}
	f.config = DirectoryProviderDocument{APIVersion: "agp.identity/v1alpha1", Kind: "DirectoryProvider", Metadata: DirectoryMetadata{ID: "dir_test", VersionID: "dirver_1", SecurityGuardID: "guard_dir_test", SecurityGuardVersion: 1}, Spec: DirectorySpec{ForestGUID: "00112233-4455-6677-8899-aabbccddeeff", DomainDNS: "corp.example.net", Transport: transport, Endpoints: []DirectoryEndpoint{{Host: "dc01.corp.example.net", Port: port}}, UserBaseDNs: []string{"OU=People,DC=corp,DC=example,DC=net"}, GroupBaseDNs: []string{"OU=Groups,DC=corp,DC=example,DC=net"}, BindDN: "CN=reader,OU=People,DC=corp,DC=example,DC=net", BindSecretVersionID: "sec_bind_1", CASecretVersionID: "sec_ca_1", LoginAttribute: "userPrincipalName", Provisioning: "preprovisioned", GroupResolution: "token_groups_security", AccountCheck: "live_each_allow", OperationTimeoutSeconds: 1, MaximumGroups: 128, GroupMappings: []DirectoryGroupMapping{{GroupObjectGUID: "10112233-4455-6677-8899-aabbccddeeff", AccessGroupID: "group_portal"}}}}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			f.mu.Lock()
			f.connections[conn] = true
			f.mu.Unlock()
			f.wg.Add(1)
			go func() { defer f.wg.Done(); defer conn.Close(); f.serve(conn, transport) }()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		f.mu.Lock()
		for c := range f.connections {
			c.Close()
		}
		f.mu.Unlock()
		f.wg.Wait()
	})
	return f
}
func adPacket(mid int64, tag ber.Tag, children ...*ber.Packet) *ber.Packet {
	envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, mid, ""))
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
	for _, child := range children {
		op.AppendChild(child)
	}
	envelope.AppendChild(op)
	return envelope
}
func adResult(mid int64, tag ber.Tag, code int64) *ber.Packet {
	return adPacket(mid, tag, ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""), ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""), ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "redacted fixture diagnostic", ""))
}
func adEntry(mid int64, dn string, attrs map[string][]string) *ber.Packet {
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	for name, values := range attrs {
		attr := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, ""))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
		for _, value := range values {
			set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, ""))
		}
		attr.AppendChild(set)
		seq.AppendChild(attr)
	}
	return adPacket(mid, ldap.ApplicationSearchResultEntry, ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, ""), seq)
}
func (f *adWireFixture) serve(raw net.Conn, transport string) {
	var conn net.Conn = raw
	if transport == "ldaps" {
		if f.rejectTLS.Load() {
			return
		}
		secure := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{f.cert}, MinVersion: tls.VersionTLS12})
		if secure.Handshake() != nil {
			return
		}
		conn = secure
	}
	for {
		packet, e := ber.ReadPacket(conn)
		if e != nil {
			return
		}
		if len(packet.Children) < 2 {
			return
		}
		mid, _ := packet.Children[0].Value.(int64)
		op := packet.Children[1]
		switch op.Tag {
		case ldap.ApplicationExtendedRequest:
			code := int64(0)
			if f.rejectTLS.Load() {
				code = 53
			}
			if _, e = conn.Write(adResult(mid, ldap.ApplicationExtendedResponse, code).Bytes()); e != nil {
				return
			}
			if code != 0 {
				return
			}
			secure := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{f.cert}, MinVersion: tls.VersionTLS12})
			if secure.Handshake() != nil {
				return
			}
			conn = secure
		case ldap.ApplicationBindRequest:
			dn, _ := op.Children[1].Value.(string)
			password := string(op.Children[2].Data.Bytes())
			code := int64(0)
			if dn == f.config.Spec.BindDN {
				f.serviceBinds.Add(1)
				if password != "synthetic-service-password" {
					code = 49
				}
			} else {
				f.userBinds.Add(1)
				f.mu.Lock()
				f.lastUserBind = dn
				f.mu.Unlock()
				if dn != "{20112233-4455-6677-8899-aabbccddeeff}" || password != "synthetic-user-password" {
					code = 49
				}
				// Model the old vulnerability: the reassigned mutable DN accepts B's
				// password while the previously selected immutable identity was A.
				if f.dnReassigned.Load() && strings.HasPrefix(dn, "CN=Alice,") && password == "synthetic-B-password" {
					code = 0
				}
			}
			if f.hangBind.Load() {
				var one [1]byte
				_, _ = conn.Read(one[:])
				return
			}
			if _, e = conn.Write(adResult(mid, ldap.ApplicationBindResponse, code).Bytes()); e != nil {
				return
			}
		case ldap.ApplicationSearchRequest:
			base, _ := op.Children[0].Value.(string)
			filter, _ := ldap.DecompileFilter(op.Children[6])
			f.mu.Lock()
			f.lastFilter = filter
			f.mu.Unlock()
			if f.referral.Load() {
				ref := adPacket(mid, ldap.ApplicationSearchResultReference, ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "ldaps://untrusted.example.net", ""))
				_, _ = conn.Write(ref.Bytes())
				_, _ = conn.Write(adResult(mid, ldap.ApplicationSearchResultDone, 0).Bytes())
				continue
			}
			dn, attrs := f.search(base, filter)
			scope, _ := op.Children[1].Value.(int64)
			if scope != ldap.ScopeBaseObject {
				delete(attrs, "tokenGroups")
			}
			if attrs != nil {
				_, _ = conn.Write(adEntry(mid, dn, attrs).Bytes())
			}
			if _, e = conn.Write(adResult(mid, ldap.ApplicationSearchResultDone, 0).Bytes()); e != nil {
				return
			}
		default:
			return
		}
	}
}

var adFixtureSID = []byte{1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 42, 0, 0, 0}

func (f *adWireFixture) search(base, filter string) (string, map[string][]string) {
	domain := "DC=corp,DC=example,DC=net"
	if base == "" {
		return "", map[string][]string{"defaultNamingContext": {domain}, "configurationNamingContext": {"CN=Configuration," + domain}, "supportedCapabilities": {"1.2.840.113556.1.4.800"}, "isGlobalCatalogReady": {"TRUE"}}
	}
	if strings.HasPrefix(base, "CN=Configuration,") {
		guid, _ := adBinaryGUID(f.config.Spec.ForestGUID)
		if f.wrongForest.Load() {
			guid[0]++
		}
		return base, map[string][]string{"objectGUID": {string(guid)}}
	}
	if strings.Contains(filter, "objectClass=group") {
		if f.missingGroups.Load() {
			return "", nil
		}
		groupGUID := "10112233-4455-6677-8899-aabbccddeeff"
		sid := append([]byte{}, adFixtureSID...)
		if f.unmappedMembership.Load() && strings.Contains(filter, "objectSid=") {
			groupGUID = "30112233-4455-6677-8899-aabbccddeeff"
			sid[len(sid)-1]++
		}
		guid, _ := adBinaryGUID(groupGUID)
		return "CN=Portal,OU=Groups," + domain, map[string][]string{"objectGUID": {string(guid)}, "objectSid": {string(sid)}, "groupType": {"-2147483646"}}
	}
	guid, _ := adBinaryGUID("20112233-4455-6677-8899-aabbccddeeff")
	sid := append([]byte{}, adFixtureSID...)
	if f.unmappedMembership.Load() {
		sid[len(sid)-1]++
	}
	uac := "512"
	if f.disabled.Load() {
		uac = "514"
	}
	return "CN=Alice,OU=People," + domain, map[string][]string{"objectGUID": {string(guid)}, "userPrincipalName": {"alice@corp.example.net"}, "displayName": {"Alice"}, "userAccountControl": {uac}, "msDS-User-Account-Control-Computed": {"0"}, "accountExpires": {"0"}, "tokenGroups": {string(sid)}}
}
func TestADConnectorTLSWire(t *testing.T) {
	for _, transport := range []string{"ldaps", "starttls"} {
		t.Run(transport, func(t *testing.T) {
			t.Run("validate_bind_and_live_guid", func(t *testing.T) {
				f := newADWireFixture(t, transport)
				proof, e := f.connector.Validate(context.Background(), f.config)
				if e != nil || !validDirectoryValidation(proof, f.config.Spec.ForestGUID) {
					t.Fatalf("validate %#v %v", proof, e)
				}
				account, e := f.connector.Authenticate(context.Background(), f.config, "alice@corp.example.net", "synthetic-user-password")
				if e != nil || account.ObjectGUID != "20112233-4455-6677-8899-aabbccddeeff" || len(account.AccessGroupIDs) != 1 {
					t.Fatalf("authenticate %#v %v", account, e)
				}
				if _, e = f.connector.LiveCheck(context.Background(), f.config, account.ObjectGUID); e != nil {
					t.Fatal(e)
				}
				f.disabled.Store(true)
				if _, e = f.connector.LiveCheck(context.Background(), f.config, account.ObjectGUID); !errors.Is(e, ErrProof) {
					t.Fatalf("disabled live check %v", e)
				}
				if f.userBinds.Load() != 1 {
					t.Fatal("password bind repeated")
				}
			})
			t.Run("DN_reassignment_cannot_authenticate_as_previous_GUID", func(t *testing.T) {
				f := newADWireFixture(t, transport)
				f.dnReassigned.Store(true)
				if account, e := f.connector.Authenticate(context.Background(), f.config, "alice@corp.example.net", "synthetic-B-password"); !errors.Is(e, ErrProof) || account != nil {
					t.Fatalf("DN reassignment misbound identity %#v %v", account, e)
				}
				f.mu.Lock()
				bind := f.lastUserBind
				f.mu.Unlock()
				if bind != "{20112233-4455-6677-8899-aabbccddeeff}" {
					t.Fatalf("mutable user bind subject %q", bind)
				}
			})
			t.Run("invalid_password_no_endpoint_retry", func(t *testing.T) {
				f := newADWireFixture(t, transport)
				f.config.Spec.Endpoints = append(f.config.Spec.Endpoints, DirectoryEndpoint{Host: "dc02.corp.example.net", Port: f.config.Spec.Endpoints[0].Port})
				if _, e := f.connector.Authenticate(context.Background(), f.config, "alice@corp.example.net", "incorrect"); !errors.Is(e, ErrProof) {
					t.Fatal(e)
				}
				if f.userBinds.Load() != 1 || f.serviceBinds.Load() != 1 {
					t.Fatal("invalid password retried")
				}
			})
			t.Run("wrong_name_egress_forest_referral_incomplete_groups", func(t *testing.T) {
				f := newADWireFixture(t, transport)
				bad := f.config
				bad.Spec.Endpoints = []DirectoryEndpoint{{Host: "wrong.corp.example.net", Port: f.config.Spec.Endpoints[0].Port}}
				if _, e := f.connector.Validate(context.Background(), bad); e == nil || f.serviceBinds.Load() != 0 {
					t.Fatal("TLS name bypass", e)
				}
				f.connector.lookup = func(context.Context, string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.0.2.1")}, nil
				}
				if _, e := f.connector.Validate(context.Background(), f.config); e == nil || f.serviceBinds.Load() != 0 {
					t.Fatal("mixed DNS egress bypass", e)
				}
				f.connector.lookup = func(context.Context, string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
				}
				f.wrongForest.Store(true)
				if _, e := f.connector.Validate(context.Background(), f.config); e == nil {
					t.Fatal("forest mismatch")
				}
				f.wrongForest.Store(false)
				f.referral.Store(true)
				if _, e := f.connector.Validate(context.Background(), f.config); e == nil {
					t.Fatal("referral accepted")
				}
				f.referral.Store(false)
				f.missingGroups.Store(true)
				if _, e := f.connector.Validate(context.Background(), f.config); e == nil {
					t.Fatal("incomplete tokenGroups accepted")
				}
			})
			t.Run("cancellation_closes_inflight_bind", func(t *testing.T) {
				f := newADWireFixture(t, transport)
				f.hangBind.Store(true)
				ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
				defer cancel()
				start := time.Now()
				if _, e := f.connector.Validate(ctx, f.config); e == nil {
					t.Fatal("cancelled bind accepted")
				}
				if time.Since(start) > 900*time.Millisecond {
					t.Fatal("operation cancellation did not close socket")
				}
			})
			if transport == "starttls" {
				t.Run("required_upgrade_no_plain_bind", func(t *testing.T) {
					f := newADWireFixture(t, transport)
					f.rejectTLS.Store(true)
					if _, e := f.connector.Validate(context.Background(), f.config); e == nil || f.serviceBinds.Load() != 0 {
						t.Fatal("StartTLS downgrade", e)
					}
				})
			}
		})
	}
}
func TestADGUIDAndAccountState(t *testing.T) {
	raw := []byte{0x33, 0x22, 0x11, 0, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	id, e := ADGUID(raw)
	if e != nil || id != "00112233-4455-6677-8899-aabbccddeeff" {
		t.Fatal(id, e)
	}
	back, e := adBinaryGUID(id)
	if e != nil || string(raw) != string(back) {
		t.Fatal("GUID field order", e)
	}
	for _, in := range []struct {
		uac, computed, expiry string
		want                  error
	}{{"512", "0", "0", nil}, {"514", "0", "0", ErrProof}, {"512", "16", "0", ErrProof}, {"512", "8388608", "0", ErrProof}, {"512", "0", strconv.FormatInt((time.Now().Add(-time.Hour).Unix()+11644473600)*10000000, 10), ErrProof}, {"512", "", "0", ErrDirectoryUnavailable}} {
		entry := ldap.NewEntry("CN=Alice", map[string][]string{"userAccountControl": {in.uac}, "msDS-User-Account-Control-Computed": {in.computed}, "accountExpires": {in.expiry}})
		if e := adAccountActive(entry, time.Now()); !errors.Is(e, in.want) {
			t.Fatalf("state %#v: %v", in, e)
		}
	}
}
