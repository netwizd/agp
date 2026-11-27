package identity

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDirectoryProtectedFileSecrets(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "agp-directory-secrets-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	passwordFile := filepath.Join(root, "bind-secret")
	caFile := filepath.Join(root, "ca.pem")
	manifest := filepath.Join(root, "directory-secrets.json")
	password := []byte("synthetic-file-bind-password")
	ca := []byte("synthetic-certificate-content")
	write := func(name string, data []byte, mode os.FileMode) {
		t.Helper()
		if e := os.WriteFile(name, data, mode); e != nil {
			t.Fatal(e)
		}
	}
	write(passwordFile, password, 0600)
	write(caFile, ca, 0644)
	references := DirectoryFileSecretManifest{APIVersion: "agp.directory-secrets/v1alpha1", Secrets: []DirectoryFileSecretReference{{VersionID: "sec_bind_1", Purpose: "directory_bind", File: passwordFile, ContentDigest: directoryBytesDigest(password)}, {VersionID: "sec_ca_1", Purpose: "directory_ca", File: caFile, ContentDigest: directoryBytesDigest(ca)}}}
	raw, _ := json.Marshal(references)
	write(manifest, raw, 0600)
	resolver, e := NewDirectoryFileSecrets(manifest)
	if e != nil {
		t.Fatal(e)
	}
	got, e := resolver.ResolveDirectorySecrets(context.Background(), "sec_bind_1", "sec_ca_1")
	if e != nil || string(got.BindPassword) != string(password) {
		t.Fatal("protected refs", e)
	}
	if _, e = resolver.ResolveDirectorySecrets(context.Background(), "sec_ca_1", "sec_bind_1"); e == nil {
		t.Fatal("purpose substitution")
	}
	if e = os.Chmod(passwordFile, 0640); e != nil {
		t.Fatal(e)
	}
	if _, e = resolver.ResolveDirectorySecrets(context.Background(), "sec_bind_1", "sec_ca_1"); e == nil {
		t.Fatal("nonprivate password")
	}
	_ = os.Chmod(passwordFile, 0600)
	write(passwordFile, []byte("silently-replaced"), 0600)
	if _, e = resolver.ResolveDirectorySecrets(context.Background(), "sec_bind_1", "sec_ca_1"); e == nil {
		t.Fatal("immutable version content changed")
	}
	write(passwordFile, password, 0600)
	_ = os.Remove(passwordFile)
	if e = os.Symlink(caFile, passwordFile); e != nil {
		t.Fatal(e)
	}
	if _, e = resolver.ResolveDirectorySecrets(context.Background(), "sec_bind_1", "sec_ca_1"); e == nil {
		t.Fatal("secret symlink")
	}
	_ = os.Remove(passwordFile)
	write(passwordFile, password, 0600)
	write(manifest, append(raw, ' '), 0600)
	if _, e = resolver.ResolveDirectorySecrets(context.Background(), "sec_bind_1", "sec_ca_1"); e == nil {
		t.Fatal("manifest substitution")
	}
}
