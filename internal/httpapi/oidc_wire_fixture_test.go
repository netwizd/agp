package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	jose "github.com/go-jose/go-jose/v4"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/oidcclient"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/oauth2"
)

// Outbound DNS, HTTPS IdP and LDAP in this fixture are actual local protocols.
// The small journal is an explicit in-memory double for TOTP floor/replay
// transactions; signed journal acceptance is covered by its native suite.
const oidcHTTPWireIdPHost = "idp.oidc.test"

const oidcHTTPWireLDAPHost = "dc01.corp.test"

type oidcHTTPWireLDAPSecrets struct{ ca []byte }

func (s oidcHTTPWireLDAPSecrets) ResolveDirectorySecrets(context.Context, string, string) (identity.DirectorySecrets, error) {
	return identity.DirectorySecrets{BindPassword: []byte("synthetic-service-password"), CACertificatesPEM: bytes.Clone(s.ca)}, nil
}

type oidcHTTPWireLDAPPeer struct {
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

func oidcHTTPWireDNS(t *testing.T) {
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
				if question.Name.String() != oidcHTTPWireLDAPHost+"." && question.Name.String() != oidcHTTPWireIdPHost+"." {
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

func newOIDCHTTPWireLDAPPeer(t *testing.T) *oidcHTTPWireLDAPPeer {
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
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{oidcHTTPWireLDAPHost}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, serverPub, key)
	if err != nil {
		t.Fatal("sign synthetic DC certificate")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("open synthetic DC TLS socket")
	}
	f := &oidcHTTPWireLDAPPeer{listener: listener, cert: tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: serverKey}, ca: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})}
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

type oidcHTTPWireJournal struct {
	mu     sync.Mutex
	head   securityjournal.Head
	events []securityjournal.Event
}

func newOIDCHTTPWireJournal() *oidcHTTPWireJournal {
	return &oidcHTTPWireJournal{head: securityjournal.Head{AuthorityID: "oidc_http_wire", Epoch: 1, Digest: securitystate.Digest("wire-genesis")}}
}
func (j *oidcHTTPWireJournal) Head(context.Context) (securityjournal.Head, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	head := j.head
	head.RecordedAt = time.Now().UTC()
	return head, nil
}
func (j *oidcHTTPWireJournal) Append(_ context.Context, request securityjournal.AppendRequest) (securityjournal.Event, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	digest, err := securityjournal.RequestDigest(request)
	if err != nil {
		return securityjournal.Event{}, err
	}
	for _, event := range j.events {
		if event.Request.OperationID == request.OperationID {
			if event.RequestDigest != digest {
				return securityjournal.Event{}, securityjournal.ErrConflict
			}
			return event, nil
		}
	}
	if request.ExpectedEpoch != j.head.Epoch || request.ExpectedSequence != j.head.Sequence || request.ExpectedDigest != j.head.Digest {
		return securityjournal.Event{}, securityjournal.ErrConflict
	}
	event := securityjournal.Event{AuthorityID: j.head.AuthorityID, ID: securitystate.ID("event"), Epoch: j.head.Epoch, Sequence: j.head.Sequence + 1, Request: request, RequestDigest: digest, PreviousDigest: j.head.Digest, RecordedAt: request.RecordedAt}
	event.Digest = securitystate.Digest(event)
	j.head.Sequence, j.head.Digest = event.Sequence, event.Digest
	j.events = append(j.events, event)
	return event, nil
}
func (j *oidcHTTPWireJournal) Operation(_ context.Context, id string) (securityjournal.Event, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, event := range j.events {
		if event.Request.OperationID == id {
			return event, nil
		}
	}
	return securityjournal.Event{}, securityjournal.ErrNotFound
}
func (j *oidcHTTPWireJournal) Events(_ context.Context, after securityjournal.UInt63, limit int) ([]securityjournal.Event, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	var events []securityjournal.Event
	for _, event := range j.events {
		if event.Sequence > after {
			events = append(events, event)
			if len(events) == limit {
				break
			}
		}
	}
	return events, nil
}

type oidcHTTPWireSecrets struct{ ca []byte }

func (s oidcHTTPWireSecrets) ResolveOIDCSecrets(ctx context.Context, ref, caRef string) (oidcclient.Secrets, error) {
	if ctx.Err() != nil || caRef != "oidc_wire_ca" {
		return oidcclient.Secrets{}, errors.New("synthetic secret reference")
	}
	var secret string
	switch ref {
	case "oidc_wire_login_secret":
		secret = "synthetic-login-client-secret"
	case "oidc_wire_management_secret":
		secret = "synthetic-management-client-secret"
	default:
		return oidcclient.Secrets{}, errors.New("synthetic secret reference")
	}
	return oidcclient.Secrets{ClientSecret: []byte(secret), CACertificatesPEM: bytes.Clone(s.ca)}, nil
}

type oidcHTTPWireCode struct {
	nonce, challenge, client, redirect string
	used                               bool
}
type oidcHTTPWireIdP struct {
	server   *httptest.Server
	browser  *http.Client
	issuer   string
	ca       []byte
	key      *rsa.PrivateKey
	mu       sync.Mutex
	codes    map[string]*oidcHTTPWireCode
	badNonce bool
	tokens   atomic.Int64
	metadata atomic.Int64
	jwks     atomic.Int64
	pkce     atomic.Int64
	sni      atomic.Bool
}

func newOIDCHTTPWireIdP(t *testing.T) *oidcHTTPWireIdP {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate synthetic IdP CA")
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "Synthetic OIDC HTTP CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal("sign synthetic IdP CA")
	}
	leafPub, leafKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate synthetic IdP key")
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(12), DNSNames: []string{oidcHTTPWireIdPHost}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, leafPub, key)
	if err != nil {
		t.Fatal("sign synthetic IdP leaf")
	}
	f := &oidcHTTPWireIdP{codes: map[string]*oidcHTTPWireCode{}, ca: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})}
	f.key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("generate synthetic JWT RSA key")
	}
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		f.sni.Store(hello.ServerName == oidcHTTPWireIdPHost)
		return nil, nil
	}}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	f.issuer = "https://" + net.JoinHostPort(oidcHTTPWireIdPHost, strconv.Itoa(f.server.Listener.Addr().(*net.TCPAddr).Port)) + "/tenant"
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(f.ca) {
		t.Fatal("synthetic CA roots")
	}
	f.browser = &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(f.browser.CloseIdleConnections)
	return f
}

func (f *oidcHTTPWireIdP) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/tenant/.well-known/openid-configuration":
		f.metadata.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": f.issuer, "authorization_endpoint": f.issuer + "/authorize", "token_endpoint": f.issuer + "/token", "jwks_uri": f.issuer + "/keys", "response_types_supported": []string{"code"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic"}, "code_challenge_methods_supported": []string{"S256"}})
	case "/tenant/keys":
		f.jwks.Add(1)
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "wire_rsa", Algorithm: "RS256", Use: "sig"}}})
	case "/tenant/authorize":
		q := r.URL.Query()
		if q.Get("response_type") != "code" || q.Get("scope") != "openid" || q.Get("code_challenge_method") != "S256" || q.Get("max_age") != "300" || !validFlowToken(q.Get("state")) || !validFlowToken(q.Get("nonce")) || !validFlowToken(q.Get("code_challenge")) {
			w.WriteHeader(400)
			return
		}
		origin := "https://login.test"
		if q.Get("client_id") == "wire_management" {
			origin = "https://management.test"
		} else if q.Get("client_id") != "wire_login" {
			w.WriteHeader(400)
			return
		}
		if q.Get("redirect_uri") != origin+"/auth/v2/oidc/providers/oidc_wire_provider/callback" {
			w.WriteHeader(400)
			return
		}
		code, _, err := auth.NewToken()
		if err != nil {
			w.WriteHeader(500)
			return
		}
		f.mu.Lock()
		f.codes[code] = &oidcHTTPWireCode{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), client: q.Get("client_id"), redirect: q.Get("redirect_uri")}
		f.mu.Unlock()
		w.Header().Set("Location", q.Get("redirect_uri")+"?"+url.Values{"state": {q.Get("state")}, "code": {code}, "iss": {f.issuer}, "session_state": {"bounded-untrusted-session-hint"}}.Encode())
		w.WriteHeader(302)
	case "/tenant/token":
		f.tokens.Add(1)
		user, password, ok := r.BasicAuth()
		if !ok || r.Method != http.MethodPost || r.ParseForm() != nil || r.Form.Get("grant_type") != "authorization_code" {
			w.WriteHeader(400)
			return
		}
		expected := "synthetic-login-client-secret"
		if user == "wire_management" {
			expected = "synthetic-management-client-secret"
		}
		f.mu.Lock()
		code := f.codes[r.Form.Get("code")]
		valid := code != nil && !code.used && code.client == user && password == expected && code.redirect == r.Form.Get("redirect_uri") && code.challenge == oauth2.S256ChallengeFromVerifier(r.Form.Get("code_verifier"))
		if valid {
			code.used = true
			f.pkce.Add(1)
		}
		badNonce := f.badNonce
		f.mu.Unlock()
		if !valid {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		nonce := code.nonce
		if badNonce {
			nonce = "wrong-nonce"
		}
		claims := map[string]any{"iss": f.issuer, "sub": "CaseSensitiveWireSubject", "aud": []string{user}, "iat": time.Now().Unix() - 1, "exp": time.Now().Unix() + 300, "auth_time": time.Now().Unix() - 60, "nonce": nonce, "acr": "unqualified-mfa", "amr": []string{"mfa"}}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, (&jose.SignerOptions{}).WithHeader("kid", "wire_rsa"))
		if err != nil {
			w.WriteHeader(500)
			return
		}
		payload, err := json.Marshal(claims)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		signed, err := signer.Sign(payload)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		token, err := signed.CompactSerialize()
		if err != nil {
			w.WriteHeader(500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"token_type": "Bearer", "access_token": "synthetic-unused-access-token", "id_token": token})
	default:
		w.WriteHeader(404)
	}
}

func oidcHTTPWireLDAPPacket(mid int64, tag ber.Tag, children ...*ber.Packet) *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, mid, ""))
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
	for _, child := range children {
		op.AppendChild(child)
	}
	packet.AppendChild(op)
	return packet
}

func oidcHTTPWireLDAPResult(mid int64, tag ber.Tag, code int64) *ber.Packet {
	return oidcHTTPWireLDAPPacket(mid, tag, ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""), ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""), ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "synthetic redacted diagnostic", ""))
}

func oidcHTTPWireLDAPEntry(mid int64, dn string, attributes map[string][]string) *ber.Packet {
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
	return oidcHTTPWireLDAPPacket(mid, ldap.ApplicationSearchResultEntry, ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, ""), sequence)
}

func oidcHTTPWireLDAPGUID(value string) []byte {
	raw, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	if err != nil || len(raw) != 16 {
		panic("invalid synthetic GUID constant")
	}
	raw[0], raw[1], raw[2], raw[3] = raw[3], raw[2], raw[1], raw[0]
	raw[4], raw[5] = raw[5], raw[4]
	raw[6], raw[7] = raw[7], raw[6]
	return raw
}

func (f *oidcHTTPWireLDAPPeer) serve(raw net.Conn) {
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
			if _, err = connection.Write(oidcHTTPWireLDAPResult(mid, ldap.ApplicationBindResponse, code).Bytes()); err != nil {
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
				if _, err = connection.Write(oidcHTTPWireLDAPEntry(mid, dn, attributes).Bytes()); err != nil {
					return
				}
			}
			if _, err = connection.Write(oidcHTTPWireLDAPResult(mid, ldap.ApplicationSearchResultDone, 0).Bytes()); err != nil {
				return
			}
		default:
			return
		}
	}
}

func (f *oidcHTTPWireLDAPPeer) search(base, filter string, scope int64) (string, map[string][]string) {
	const domain = "DC=corp,DC=test"
	if base == "" {
		return "", map[string][]string{"defaultNamingContext": {domain}, "configurationNamingContext": {"CN=Configuration," + domain}, "supportedCapabilities": {"1.2.840.113556.1.4.800"}, "isGlobalCatalogReady": {"TRUE"}}
	}
	if base == "CN=Configuration,"+domain {
		f.guid.Add(1)
		return base, map[string][]string{"objectGUID": {string(oidcHTTPWireLDAPGUID("00112233-4455-6677-8899-aabbccddeeff"))}}
	}
	sid := []byte{1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 42, 0, 0, 0}
	if strings.Contains(filter, "objectClass=group") {
		return "CN=Portal,OU=Groups," + domain, map[string][]string{"objectGUID": {string(oidcHTTPWireLDAPGUID("10112233-4455-6677-8899-aabbccddeeff"))}, "objectSid": {string(sid)}, "groupType": {"-2147483646"}}
	}
	const userDN = "CN=Reviewer,OU=People," + domain
	attributes := map[string][]string{"objectGUID": {string(oidcHTTPWireLDAPGUID("20112233-4455-6677-8899-aabbccddeeff"))}}
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
