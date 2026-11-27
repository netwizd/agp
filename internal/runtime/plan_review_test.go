package runtime

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/netwizd/agp/internal/configuration"
)

func TestPlanReviewSigningKeyProtectedLoader(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "agp-plan-review-key-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "review-key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ConfigurePlanReviewSigner(new(configuration.Service), "review-key", path); err != nil {
		t.Fatal(err)
	}
	if err := ConfigurePlanReviewSigner(nil, "", ""); err != nil {
		t.Fatal("absent signer must remain optional", err)
	}
	for _, mode := range []os.FileMode{0640, 0666} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := ConfigurePlanReviewSigner(new(configuration.Service), "review-key", path); err == nil {
			t.Fatal("nonprivate key accepted")
		}
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := ConfigurePlanReviewSigner(new(configuration.Service), "review-key", link); err == nil {
		t.Fatal("symlink key accepted")
	}
	if err := ConfigurePlanReviewSigner(new(configuration.Service), "bad/key", path); err == nil {
		t.Fatal("invalid key ID accepted")
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ = x509.MarshalPKCS8PrivateKey(ecdsaKey)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ConfigurePlanReviewSigner(new(configuration.Service), "review-key", path); err == nil {
		t.Fatal("non-Ed25519 key accepted")
	}
}
