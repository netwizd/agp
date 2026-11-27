package edgeauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClientRealMTLSAndClosedResponses(t *testing.T) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "EdgeAuth test CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, e = x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	issue := func(serial int64, identity string, server bool) (tls.Certificate, []byte, []byte) {
		t.Helper()
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if server {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		} else {
			u, _ := url.Parse(identity)
			template.URIs = []*url.URL{u}
		}
		d, e := x509.CreateCertificate(rand.Reader, template, ca, &k.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})
		kb, e := x509.MarshalPKCS8PrivateKey(k)
		if e != nil {
			t.Fatal(e)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})
		cert, e := tls.X509KeyPair(certPEM, keyPEM)
		if e != nil {
			t.Fatal(e)
		}
		return cert, certPEM, keyPEM
	}
	serverCert, _, _ := issue(2, "", true)
	_, clientPEM, clientKey := issue(3, "spiffe://agp/edge/node_one/gw_one", false)
	var response = `{"decision":"deny","reasonCode":"access_denied","securitySequence":"7"}`
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates[0].URIs) != 1 || r.TLS.PeerCertificates[0].URIs[0].String() != "spiffe://agp/edge/node_one/gw_one" {
			w.WriteHeader(403)
			return
		}
		if r.Method != "POST" || r.URL.Path != "/auth/v2/decisions" {
			t.Errorf("unexpected central request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(response))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if e := os.WriteFile(p, data, 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	cfg := testConfig("http://127.0.0.1:8081")
	cfg.CentralOrigin = server.URL
	cfg.ClientCertificateFile = write("client.pem", clientPEM)
	cfg.ClientKeyFile = write("client.key", clientKey)
	cfg.ServerCAFile = write("ca.pem", caPEM)
	client, e := NewClient(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	d, e := client.Decide(context.Background(), DecisionRequest{GatewayID: "gw_one", RouteID: "route_one", DeploymentGeneration: "1", Method: "GET", Path: "/"})
	if e != nil || d.Decision != "deny" {
		t.Fatalf("real mTLS failed: %+v %v", d, e)
	}
	response = `{"decision":"allow","reasonCode":"allowed","userId":"usr_one","groupIds":[],"securitySequence":"8"}`
	if d, e = client.Decide(context.Background(), DecisionRequest{}); e != nil || d.Decision != "allow" {
		t.Fatalf("allow validation failed: %v", e)
	}
	for _, bad := range []string{`{"decision":"deny","reasonCode":"unknown","securitySequence":"8"}`, `{"decision":"allow"}`, `{"decision":"deny","reasonCode":"access_denied","securitySequence":"8"} {}`, strings.Repeat("x", 65537)} {
		response = bad
		if _, e = client.Decide(context.Background(), DecisionRequest{}); e == nil {
			t.Fatal("malformed 200 accepted")
		}
	}
	wrong := cfg
	wrong.NodeID = "node_other"
	if _, e = NewClient(wrong); e == nil {
		t.Fatal("certificate accepted for another node")
	}
	_, agentPEM, agentKey := issue(4, "spiffe://agp/agent/node_one", false)
	wrong = cfg
	wrong.ClientCertificateFile = write("agent.pem", agentPEM)
	wrong.ClientKeyFile = write("agent.key", agentKey)
	if _, e = NewClient(wrong); e == nil {
		t.Fatal("management agent certificate accepted as EdgeAuth")
	}
	// An unauthenticated TLS client cannot reach a decision handler at all.
	unauth := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}, Timeout: time.Second}
	defer unauth.CloseIdleConnections()
	if _, e = unauth.Post(server.URL+"/auth/v2/decisions", "application/json", strings.NewReader(`{}`)); e == nil {
		t.Fatal("missing client certificate accepted")
	}
}
