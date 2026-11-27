package nodebootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
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

func protectedTemp(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "agp-bootstrap-test.")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}

func TestKeyGenerationAndProtectedFiles(t *testing.T) {
	dir := protectedTemp(t)
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	pin, err := Generate(dir)
	if err != nil {

		t.Fatal(err)
	}
	csr, key, err := readRequest(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	if !strings.HasPrefix(pin, "sha256:") || len(csr) == 0 {
		t.Fatal("missing CSR/key pin")
	}
	before, _ := os.ReadFile(filepath.Join(dir, "key.pem"))
	if _, err = Generate(dir); err == nil {
		t.Fatal("key overwritten")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "key.pem"))
	if !bytes.Equal(before, after) {
		t.Fatal("key changed")
	}
	alias := filepath.Join(t.TempDir(), "link")
	if err = os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	if _, err = Generate(alias); err == nil {
		t.Fatal("symlink directory accepted")
	}
	if err = os.Chmod(dir, 0770); err != nil {
		t.Fatal(err)
	}
	if _, _, err = readRequest(dir); err == nil {
		t.Fatal("shared directory accepted")
	}
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "key.pem")
	if err = os.Link(keyPath, filepath.Join(dir, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if _, _, err = readRequest(dir); err == nil {
		t.Fatal("hardlinked private key accepted")
	}
}

func TestTokenRemovalRequiresExactPrivateFile(t *testing.T) {
	dir := protectedTemp(t)
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "token")
	token := strings.Repeat("a", 43)
	if err := os.WriteFile(path, []byte(token+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveTokenFile(path, strings.Repeat("b", 43)); err == nil {
		t.Fatal("wrong token removed file")
	}
	if err := RemoveTokenFile(path, token); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("token retained")
	}
	for _, input := range []string{token + "\nextra", token + token, "", token + " "} {
		if _, err := ReadToken(strings.NewReader(input)); err == nil {
			t.Fatal("invalid token input accepted")
		}
	}
}

func TestPinnedTLSOwnerPendingAndCertificateVerification(t *testing.T) {
	dir := protectedTemp(t)
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(dir); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	caPub, caKey, _ := ed25519.GenerateKey(rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "bootstrap test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	caFile := filepath.Join(dir, "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err = os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	serverPub, serverKey, _ := ed25519.GenerateKey(rand.Reader)
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, _ := x509.CreateCertificate(rand.Reader, serverTemplate, ca, serverPub, caKey)
	serverPKCS8, _ := x509.MarshalPKCS8PrivateKey(serverKey)
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverPKCS8}))
	if err != nil {
		t.Fatal(err)
	}
	var certificate CertificateResult
	var badSAN, redirect bool
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if redirect {
			http.Redirect(w, r, "https://127.0.0.1:1/leak", http.StatusTemporaryRedirect)
			return
		}
		if r.TLS.Version != tls.VersionTLS13 {
			t.Error("TLS version")
		}
		var in map[string]string
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Error(err)
			http.Error(w, "bad", 400)
			return
		}
		if in["nodeId"] != "node_one" || in["enrollmentToken"] != strings.Repeat("a", 43) {
			t.Error("wrong binding")
			http.Error(w, "bad", 400)
			return
		}
		block, _ := pem.Decode([]byte(in["csrPem"]))
		csr, _ := x509.ParseCertificateRequest(block.Bytes)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if r.URL.Path == "/agent/v1/enrollment-requests" {
			w.WriteHeader(202)
			_ = json.NewEncoder(w).Encode(PendingRequest{ID: "enroll_one", EnrollmentID: "enroll_one", NodeID: "node_one", State: "csr_pending", PublicKeyDigest: fingerprint(csr.RawSubjectPublicKeyInfo), RequestDigest: fingerprint(csr.Raw), ExpiresAt: now.Add(10 * time.Minute)})
			return
		}
		if certificate.NodeID == "" || badSAN {
			uri, _ := url.Parse("spiffe://agp/agent/node_one")
			if badSAN {
				uri, _ = url.Parse("spiffe://agp/edge/node_one/gw_one")
			}
			leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: now, NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}
			der, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, csr.PublicKey, caKey)
			if err != nil {
				t.Error(err)
			}
			certificate = CertificateResult{NodeID: "node_one", CertificateChainPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), Serial: "3", ExpiresAt: leafTemplate.NotAfter}
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(certificate)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
	server.StartTLS()
	defer server.Close()
	cfg := ClientConfig{URL: server.URL, CAFile: caFile, CAFingerprint: fingerprint(caDER), IdentityCAFile: caFile, IdentityCAFingerprint: fingerprint(caDER), Directory: dir, NodeID: "node_one"}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err = c.Request(context.Background(), strings.Repeat("a", 43)); err != nil {
		t.Fatal(err)
	}
	out, err := c.Enroll(context.Background(), strings.Repeat("a", 43))
	if err != nil || out.Serial != "3" {
		t.Fatalf("enroll: %v", err)
	}
	if _, err = c.Enroll(context.Background(), strings.Repeat("a", 43)); err != nil {
		t.Fatalf("exact retry: %v", err)
	}
	badSAN = true
	if _, err = c.Enroll(context.Background(), strings.Repeat("a", 43)); err == nil {
		t.Fatal("EdgeAuth role accepted")
	}
	redirect = true
	if _, err = c.Request(context.Background(), strings.Repeat("a", 43)); err == nil {
		t.Fatal("redirect accepted")
	}
	cfg.CAFingerprint = "sha256:" + strings.Repeat("0", 64)
	if _, err = NewClient(cfg); err == nil {
		t.Fatal("CA pin ignored")
	}
}
