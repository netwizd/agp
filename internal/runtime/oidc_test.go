package runtime

import (
	"bytes"
	"context"
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

func TestOIDCProtectedInstallationConfiguration(t *testing.T) {
	if c, e := OpenOIDCConnector(""); e != nil || c != nil {
		t.Fatal("unconfigured OIDC connector enabled")
	}
	base, e := os.MkdirTemp("/tmp", "agp-oidc-runtime-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	write := func(file string, v any) {
		t.Helper()
		raw, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(file, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	secret, ca := filepath.Join(base, "client-secret"), filepath.Join(base, "ca.pem")
	for file, raw := range map[string][]byte{secret: []byte("synthetic-oidc-secret"), ca: []byte("synthetic-ca-bytes")} {
		if e = os.WriteFile(file, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	digest := func(s string) string { sum := sha256.Sum256([]byte(s)); return "sha256:" + hex.EncodeToString(sum[:]) }
	manifest := filepath.Join(base, "secrets.json")
	write(manifest, secretfiles.Manifest{APIVersion: "agp.external-secrets/v1alpha1", Secrets: []secretfiles.Reference{{VersionID: "oidc_client_1", Purpose: secretfiles.OIDCClient, File: secret, ContentDigest: digest("synthetic-oidc-secret")}, {VersionID: "oidc_ca_1", Purpose: secretfiles.OIDCCA, File: ca, ContentDigest: digest("synthetic-ca-bytes")}}})
	stateKeys := filepath.Join(base, "state-keys.json")
	write(stateKeys, map[string]any{"apiVersion": "agp.oidc-state-keyring/v1alpha1", "activeKeyId": "oidc_state_1", "keys": map[string]string{"oidc_state_1": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{82}, 32))}})
	cfg := OIDCConnectorConfig{APIVersion: "agp.oidc-connector/v1alpha1", StateKeyringFile: stateKeys, SecretsManifest: manifest, HTTPSOrigins: []string{"https://idp.test"}, AllowedCIDRs: []string{"192.0.2.0/24"}, OperationTimeoutSeconds: 5, MaximumConcurrent: 4}
	file := filepath.Join(base, "oidc.json")
	write(file, cfg)
	c := securitystate.New(nil, nil)
	service := &identity.Service{Coordinator: c, Keys: &identity.Keyring{Active: "mfa_1", Keys: map[string]string{"mfa_1": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{81}, 32))}}}
	service.WithDirectory(identity.NewDirectoryService(c, "https://management.test", nil), nil)
	if oidc, e := OpenOIDCService(service, file); e != nil || oidc == nil {
		t.Fatal("protected OIDC config", e)
	}
	for _, change := range []string{"unknown_field", "http_origin", "duplicate_origin", "endpoint_instead_of_origin", "duplicate_cidr", "noncanonical_cidr", "zero_timeout", "zero_concurrency", "missing_state_keys", "public_config", "symlink_config"} {
		t.Run(change, func(t *testing.T) {
			bad := cfg
			current := file
			switch change {
			case "http_origin":
				bad.HTTPSOrigins = []string{"http://idp.test"}
			case "duplicate_origin":
				bad.HTTPSOrigins = []string{"https://idp.test", "https://idp.test"}
			case "endpoint_instead_of_origin":
				bad.HTTPSOrigins = []string{"https://idp.test/token"}
			case "duplicate_cidr":
				bad.AllowedCIDRs = []string{"192.0.2.0/24", "192.0.2.0/24"}
			case "noncanonical_cidr":
				bad.AllowedCIDRs = []string{"192.0.2.1/24"}
			case "zero_timeout":
				bad.OperationTimeoutSeconds = 0
			case "zero_concurrency":
				bad.MaximumConcurrent = 0
			case "missing_state_keys":
				bad.StateKeyringFile = filepath.Join(base, "absent")
			}
			write(file, bad)
			switch change {
			case "unknown_field":
				raw, _ := json.Marshal(bad)
				var m map[string]any
				_ = json.Unmarshal(raw, &m)
				m["skipVerify"] = true
				write(file, m)
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
			if oidc, e := OpenOIDCService(service, current); e == nil || oidc != nil {
				t.Fatal("invalid OIDC installation config enabled", change)
			}
		})
	}
	resolver, e := secretfiles.Open(manifest)
	if e != nil {
		t.Fatal(e)
	}
	secrets, e := (oidcFileSecrets{resolver}).ResolveOIDCSecrets(context.Background(), "oidc_client_1", "oidc_ca_1")
	if e != nil || string(secrets.ClientSecret) != "synthetic-oidc-secret" {
		t.Fatal("bound resolver", e)
	}
	clear(secrets.ClientSecret)
	clear(secrets.CACertificatesPEM)
	if value, e := (mailFileSecrets{resolver}).ResolveMailSecrets(context.Background(), "oidc_client_1", "oidc_ca_1"); e == nil || len(value.Password) != 0 {
		t.Fatal("OIDC credential substituted for SMTP credential")
	}
}
