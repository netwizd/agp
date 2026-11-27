package secretfiles

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func secretFixture(t *testing.T) (string, string, Manifest) {
	t.Helper()
	base, e := os.MkdirTemp("/tmp", "agp-external-secrets-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	password := filepath.Join(base, "password")
	if e = os.WriteFile(password, []byte("synthetic-password"), 0600); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(base, "manifest.json")
	m := Manifest{APIVersion: "agp.external-secrets/v1alpha1", Secrets: []Reference{{VersionID: "smtp_password_1", Purpose: SMTPPassword, File: password, ContentDigest: digest([]byte("synthetic-password"))}}}
	writeManifest(t, file, m)
	return file, password, m
}
func writeManifest(t *testing.T, file string, value any) {
	t.Helper()
	b, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(file, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func TestPurposeBoundProtectedImmutableSecrets(t *testing.T) {
	file, password, m := secretFixture(t)
	r, e := Open(file)
	if e != nil {
		t.Fatal(e)
	}
	first, e := r.Read(context.Background(), "smtp_password_1", SMTPPassword)
	if e != nil {
		t.Fatal(e)
	}
	first[0] = 'x'
	clear(first)
	second, e := r.Read(context.Background(), "smtp_password_1", SMTPPassword)
	if e != nil || string(second) != "synthetic-password" {
		t.Fatal("buffer reused", e)
	}
	clear(second)
	for _, purpose := range []string{SMTPCA, OIDCClient, OIDCCA, "", "directory_bind"} {
		if b, e := r.Read(context.Background(), "smtp_password_1", purpose); e == nil || len(b) != 0 {
			t.Fatal("purpose confused", purpose)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := r.Read(ctx, "smtp_password_1", SMTPPassword); !errors.Is(e, context.Canceled) {
		t.Fatal("cancel ignored", e)
	}
	if e = os.WriteFile(password, []byte("replacement-password"), 0600); e != nil {
		t.Fatal(e)
	}
	if b, e := r.Read(context.Background(), "smtp_password_1", SMTPPassword); e == nil || len(b) != 0 {
		t.Fatal("immutable bytes replaced")
	}
	if e = os.WriteFile(password, []byte("synthetic-password"), 0600); e != nil {
		t.Fatal(e)
	}
	m.Secrets[0].ContentDigest = digest([]byte("other"))
	writeManifest(t, file, m)
	if _, e := r.Read(context.Background(), "smtp_password_1", SMTPPassword); e == nil {
		t.Fatal("manifest changed under existing resolver")
	}
}
func TestSecretManifestAndFileBoundary(t *testing.T) {
	for _, change := range []string{"public_manifest", "symlink_manifest", "public_password", "symlink_password", "duplicate_version", "wrong_purpose", "relative_path", "unclean_path", "unknown_field", "empty_versions"} {
		t.Run(change, func(t *testing.T) {
			file, password, m := secretFixture(t)
			switch change {
			case "public_manifest":
				if e := os.Chmod(file, 0644); e != nil {
					t.Fatal(e)
				}
			case "symlink_manifest":
				link := file + ".link"
				if e := os.Symlink(file, link); e != nil {
					t.Fatal(e)
				}
				file = link
			case "public_password":
				if e := os.Chmod(password, 0644); e != nil {
					t.Fatal(e)
				}
			case "symlink_password":
				link := password + ".link"
				if e := os.Symlink(password, link); e != nil {
					t.Fatal(e)
				}
				m.Secrets[0].File = link
				writeManifest(t, file, m)
			case "duplicate_version":
				m.Secrets = append(m.Secrets, m.Secrets[0])
				writeManifest(t, file, m)
			case "wrong_purpose":
				m.Secrets[0].Purpose = "anything"
				writeManifest(t, file, m)
			case "relative_path":
				m.Secrets[0].File = "relative"
				writeManifest(t, file, m)
			case "unclean_path":
				m.Secrets[0].File = filepath.Dir(password) + "/../" + filepath.Base(filepath.Dir(password)) + "/password"
				writeManifest(t, file, m)
			case "unknown_field":
				writeManifest(t, file, map[string]any{"apiVersion": m.APIVersion, "secrets": m.Secrets, "skipOwnership": true})
			case "empty_versions":
				m.Secrets = nil
				writeManifest(t, file, m)
			}
			r, e := Open(file)
			if e == nil {
				if _, e = r.Read(context.Background(), "smtp_password_1", SMTPPassword); e == nil {
					t.Fatal("untrusted secret configuration accepted")
				}
			}
		})
	}
}
