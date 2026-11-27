package runtime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netwizd/agp/internal/identity"
)

func TestDirectoryConnectorInstallationBoundary(t *testing.T) {
	if service, connector, err := OpenDirectoryService(nil, "https://management.test", ""); err != nil || service == nil || connector != nil {
		t.Fatal("unconfigured connector became enabled")
	}
	base, err := os.MkdirTemp("/tmp", "agp-directory-runtime-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	manifest := filepath.Join(base, "secrets.json")
	d := identity.DirectoryFileSecretManifest{APIVersion: "agp.directory-secrets/v1alpha1", Secrets: []identity.DirectoryFileSecretReference{{VersionID: "bind_1", Purpose: "directory_bind", File: filepath.Join(base, "bind"), ContentDigest: "sha256:" + strings.Repeat("a", 64)}, {VersionID: "ca_1", Purpose: "directory_ca", File: filepath.Join(base, "ca"), ContentDigest: "sha256:" + strings.Repeat("b", 64)}}}
	raw, _ := json.Marshal(d)
	if err := os.WriteFile(manifest, raw, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := DirectoryConnectorConfig{APIVersion: "agp.directory-connector/v1alpha1", SecretsManifest: manifest, AllowedCIDRs: []string{"192.0.2.0/24", "2001:db8::/32"}}
	file := filepath.Join(base, "connector.json")
	write := func(v any) {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(cfg)
	if service, connector, err := OpenDirectoryService(nil, "https://management.test", file); err != nil || service == nil || connector == nil {
		t.Fatal("protected connector policy rejected", err)
	}
	for _, prefixes := range [][]string{nil, {"192.0.2.1/24"}, {"::ffff:192.0.2.0/120"}, {"192.0.2.0/24", "192.0.2.0/24"}, {"not-a-network"}} {
		bad := cfg
		bad.AllowedCIDRs = prefixes
		write(bad)
		if service, connector, err := OpenDirectoryService(nil, "https://management.test", file); err == nil || service != nil || connector != nil {
			t.Fatal("invalid trusted egress policy accepted", prefixes)
		}
	}
	write(map[string]any{"apiVersion": cfg.APIVersion, "secretsManifest": manifest, "allowedCidrs": cfg.AllowedCIDRs, "skipVerify": true})
	if _, _, err := OpenDirectoryService(nil, "https://management.test", file); err == nil {
		t.Fatal("unknown TLS bypass field accepted")
	}
	write(cfg)
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenDirectoryService(nil, "https://management.test", file); err == nil {
		t.Fatal("public connector file accepted")
	}
	if err := os.Chmod(file, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link.json")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenDirectoryService(nil, "https://management.test", link); err == nil {
		t.Fatal("symlink connector policy accepted")
	}
}
