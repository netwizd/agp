package main

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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
)

func TestCLIArgumentsRootAndHelp(t *testing.T) {
	for _, args := range [][]string{nil, {"-config"}, {"-config", "relative"}, {"-config", "/"}, {"-config", "/protected/../secret"}, {"-unknown", "private-value"}, {"-config", "/private/config", "extra"}, {"-config", "/private/config", "-config", "/other"}} {
		var out bytes.Buffer
		if e := run(context.Background(), args, &out); e != errArguments || out.Len() != 0 || strings.Contains(e.Error(), "private-value") {
			t.Fatalf("bad arguments disclosed data: %v", e)
		}
	}
	var out bytes.Buffer
	if e := run(context.Background(), []string{"--help"}, &out); e != nil || !strings.Contains(out.String(), "No stdin") {
		t.Fatalf("help: %v", e)
	}
	if os.Geteuid() != 0 {
		out.Reset()
		if e := run(context.Background(), []string{"-config", "/sensitive/private-config"}, &out); e != errRoot || out.Len() != 0 {
			t.Fatalf("nonroot CLI accepted: %v", e)
		}
		if e := generate(context.Background(), "/sensitive/private-config", &out); e != errUnavailable || out.Len() != 0 {
			t.Fatalf("nonroot internal execution accepted: %v", e)
		}
	}
}
func configFixture() localConfig {
	return localConfig{
		APIVersion: localConfigVersion, OwnershipManifest: "/protected/manifest.json", OwnershipDigest: configmodel.DigestBytes([]byte("manifest")), Repository: "/protected/repository", RepositoryAnchor: "/protected/anchor.json", SandboxTool: "/usr/bin/bwrap", SandboxToolDigest: configmodel.DigestBytes([]byte("bwrap")), ExecutionUID: 1001, ExecutionGID: 1001,
		Journal: journalConfig{URL: "https://journal.example", AuthorityID: "journal", KeyID: "journal-key", PublicKey: strings.Repeat("01", 32), ClientCertificate: "/protected/client.pem", ClientKey: "/protected/client.key", ServerCA: "/protected/ca.pem"},
	}
}
func TestClosedLocalConfig(t *testing.T) {
	c := configFixture()
	raw, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	got, e := parseConfig(raw)
	if e != nil || *got != c {
		t.Fatal("valid closed installation configuration", e)
	}
	changes := map[string]func(*localConfig){
		"version": func(c *localConfig) { c.APIVersion = "unknown" },
		"rootUID": func(c *localConfig) { c.ExecutionUID = 0 }, "rootGID": func(c *localConfig) { c.ExecutionGID = 0 },
		"invalidUID": func(c *localConfig) { c.ExecutionUID = -1 }, "invalidGID": func(c *localConfig) { c.ExecutionGID = -1 },
		"manifest-pin": func(c *localConfig) { c.OwnershipDigest = "bad" }, "tool-pin": func(c *localConfig) { c.SandboxToolDigest = "bad" },
		"relative": func(c *localConfig) { c.Repository = "relative" }, "clean-path": func(c *localConfig) { c.OwnershipManifest = "/protected/../manifest" }, "key-control": func(c *localConfig) { c.Journal.ClientKey = "/private/key\n" },
		"URL-scheme": func(c *localConfig) { c.Journal.URL = "http://journal.example" }, "URL-credentials": func(c *localConfig) { c.Journal.URL = "https://user:secret@journal.example" }, "URL-query": func(c *localConfig) { c.Journal.URL = "https://journal.example?key=secret" }, "URL-path": func(c *localConfig) { c.Journal.URL = "https://journal.example/private" },
		"authority": func(c *localConfig) { c.Journal.AuthorityID = "bad/value" }, "key-id": func(c *localConfig) { c.Journal.KeyID = "" }, "public-key": func(c *localConfig) { c.Journal.PublicKey = "secret" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			c := configFixture()
			change(&c)
			b, _ := json.Marshal(c)
			if got, e := parseConfig(b); got != nil || e != errUnavailable || strings.Contains(e.Error(), "secret") {
				t.Fatalf("unsafe configuration accepted/disclosed: %v", e)
			}
		})
	}
	for _, b := range [][]byte{bytes.Replace(raw, []byte(`"apiVersion":`), []byte(`"unknown":"secret","apiVersion":`), 1), bytes.Replace(raw, []byte(`"executionUid":1001`), []byte(`"executionUid":1.5`), 1), bytes.Replace(raw, []byte(`"executionUid":1001`), []byte(`"executionUid":null`), 1), bytes.Replace(raw, []byte(`"executionUid":1001`), []byte(`"executionUid":1001,"executionUid":1002`), 1), []byte(strings.Repeat(" ", 16<<10+1))} {
		if got, e := parseConfig(b); got != nil || e != errUnavailable {
			t.Fatalf("invalid JSON config accepted: %v", e)
		}
	}
}
func tlsFixture(t *testing.T) journalConfig {
	t.Helper()
	dir, e := os.MkdirTemp("/tmp", "agp-bootstrap-cli-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-test-only"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	priv, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	c := journalConfig{ClientCertificate: filepath.Join(dir, "client.pem"), ClientKey: filepath.Join(dir, "client.key"), ServerCA: filepath.Join(dir, "ca.pem")}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for name, b := range map[string][]byte{c.ClientCertificate: cert, c.ServerCA: cert, c.ClientKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv})} {
		if e = os.WriteFile(name, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	return c
}
func TestProtectedTLSReads(t *testing.T) {
	c := tlsFixture(t)
	cfg, e := protectedTLS(c)
	if e != nil || cfg == nil || cfg.MinVersion != tls.VersionTLS13 || cfg.InsecureSkipVerify || len(cfg.Certificates) != 1 || cfg.RootCAs == nil {
		t.Fatal("protected TLS fixture rejected", e)
	}
	for _, change := range []string{"key-mode", "symlink", "invalid-key", "missing"} {
		t.Run(change, func(t *testing.T) {
			c := tlsFixture(t)
			switch change {
			case "key-mode":
				os.Chmod(c.ClientKey, 0644)
			case "symlink":
				name := c.ClientKey + ".link"
				os.Symlink(c.ClientKey, name)
				c.ClientKey = name
			case "invalid-key":
				os.WriteFile(c.ClientKey, []byte("secret-private-key"), 0600)
			case "missing":
				c.ServerCA += ".missing"
			}
			if cfg, e := protectedTLS(c); cfg != nil || e != errUnavailable || strings.Contains(e.Error(), c.ClientKey) {
				t.Fatalf("unsafe TLS path accepted/disclosed: %v", e)
			}
		})
	}
}
