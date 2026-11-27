package runtime

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/secretfiles"
	"github.com/netwizd/agp/internal/securitystate"
)

func TestEmailProtectedInstallationConfiguration(t *testing.T) {
	if email, e := OpenEmailService(nil, ""); e != nil || email != nil {
		t.Fatal("unconfigured mail enabled")
	}
	base, e := os.MkdirTemp("/tmp", "agp-email-runtime-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	write := func(file string, value any) {
		t.Helper()
		raw, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(file, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	password, ca := filepath.Join(base, "password"), filepath.Join(base, "ca.pem")
	for file, raw := range map[string][]byte{password: []byte("synthetic-password"), ca: []byte("synthetic-ca-bytes")} {
		if e = os.WriteFile(file, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	digest := func(raw string) string {
		sum := sha256.Sum256([]byte(raw))
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	manifest := filepath.Join(base, "secrets.json")
	write(manifest, secretfiles.Manifest{APIVersion: "agp.external-secrets/v1alpha1", Secrets: []secretfiles.Reference{{VersionID: "smtp_pass_1", Purpose: secretfiles.SMTPPassword, File: password, ContentDigest: digest("synthetic-password")}, {VersionID: "smtp_ca_1", Purpose: secretfiles.SMTPCA, File: ca, ContentDigest: digest("synthetic-ca-bytes")}}})
	keys := filepath.Join(base, "email-keys.json")
	write(keys, map[string]any{"apiVersion": "agp.email-keyring/v1alpha1", "activeEncryption": "email_enc_1", "activePepper": "email_mac_1", "encryption": map[string]string{"email_enc_1": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{51}, 32))}, "peppers": map[string]string{"email_mac_1": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{52}, 32))}})
	service := &identity.Service{Coordinator: securitystate.New(nil, nil)}
	cfg := EmailConfig{APIVersion: "agp.email/v1alpha1", KeyringFile: keys, SecretsManifest: manifest, AllowedCIDRs: []string{"192.0.2.0/24"}, SMTP: SMTPConfig{Host: "smtp.corp.test", Port: 465, Transport: "implicit_tls", HelloName: "agp.corp.test", From: "agp@corp.test", Authentication: "plain", Username: "synthetic-user", PasswordVersionID: "smtp_pass_1", CAVersionID: "smtp_ca_1", OperationTimeoutSeconds: 5}}
	file := filepath.Join(base, "email.json")
	write(file, cfg)
	email, e := OpenEmailService(service, file)
	if e != nil || email == nil {
		t.Fatal("valid protected config", e)
	}
	email.Close()
	for _, change := range []string{"unknown_field", "overbroad_noncanonical_cidr", "duplicate_cidr", "missing_keys", "missing_secret", "zero_timeout", "plaintext", "public_config", "symlink_config"} {
		t.Run(change, func(t *testing.T) {
			bad := cfg
			current := file
			switch change {
			case "overbroad_noncanonical_cidr":
				bad.AllowedCIDRs = []string{"192.0.2.1/24"}
			case "duplicate_cidr":
				bad.AllowedCIDRs = []string{"192.0.2.0/24", "192.0.2.0/24"}
			case "missing_keys":
				bad.KeyringFile = filepath.Join(base, "absent")
			case "missing_secret":
				bad.SMTP.PasswordVersionID = "missing_version"
			case "zero_timeout":
				bad.SMTP.OperationTimeoutSeconds = 0
			case "plaintext":
				bad.SMTP.Transport = "plaintext"
			}
			write(file, bad)
			switch change {
			case "unknown_field":
				raw, _ := json.Marshal(bad)
				var doc map[string]any
				_ = json.Unmarshal(raw, &doc)
				doc["skipVerify"] = true
				write(file, doc)
			case "public_config":
				if e := os.Chmod(file, 0644); e != nil {
					t.Fatal(e)
				}
				defer os.Chmod(file, 0600)
			case "symlink_config":
				current = file + ".link"
				if e := os.Symlink(file, current); e != nil {
					t.Fatal(e)
				}
			}
			if email, e := OpenEmailService(service, current); e == nil || email != nil {
				t.Fatal("invalid installation config enabled", change)
			}
		})
	}
}
