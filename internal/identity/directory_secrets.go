package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/inventory"
)

// DirectoryFileSecretManifest is installation configuration, not an API input.
// Every version resolves to protected bytes with an exact immutable digest.
// Changes require a new trusted startup configuration, never hot substitution.
type DirectoryFileSecretManifest struct {
	APIVersion string                         `json:"apiVersion"`
	Secrets    []DirectoryFileSecretReference `json:"secrets"`
}
type DirectoryFileSecretReference struct {
	VersionID     string `json:"versionId"`
	Purpose       string `json:"purpose"`
	File          string `json:"file"`
	ContentDigest string `json:"contentDigest"`
}
type directoryFileSecrets struct {
	file, digest string
	references   map[string]DirectoryFileSecretReference
}

func directoryBytesDigest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}
func NewDirectoryFileSecrets(file string) (DirectorySecretResolver, error) {
	if !filepath.IsAbs(file) {
		return nil, ErrDirectoryInvalid
	}
	raw, e := inventory.ReadProtectedFile(file, true)
	if e != nil {
		return nil, ErrDirectoryUnavailable
	}
	var m DirectoryFileSecretManifest
	if configmodel.StrictJSON(bytes.NewReader(raw), &m, 64<<10) != nil || m.APIVersion != "agp.directory-secrets/v1alpha1" || len(m.Secrets) < 2 || len(m.Secrets) > 256 {
		return nil, ErrDirectoryInvalid
	}
	resolver := &directoryFileSecrets{file: file, digest: directoryBytesDigest(raw), references: map[string]DirectoryFileSecretReference{}}
	for _, ref := range m.Secrets {
		if !configmodel.ValidID(ref.VersionID) || (ref.Purpose != "directory_bind" && ref.Purpose != "directory_ca") || !filepath.IsAbs(ref.File) || filepath.Clean(ref.File) != ref.File || !configmodel.ValidDigest(ref.ContentDigest) {
			return nil, ErrDirectoryInvalid
		}
		if _, exists := resolver.references[ref.VersionID]; exists {
			return nil, ErrDirectoryInvalid
		}
		resolver.references[ref.VersionID] = ref
	}
	return resolver, nil
}
func (r *directoryFileSecrets) ResolveDirectorySecrets(ctx context.Context, bindID, caID string) (DirectorySecrets, error) {
	if e := ctx.Err(); e != nil {
		return DirectorySecrets{}, e
	}
	manifest, e := inventory.ReadProtectedFile(r.file, true)
	if e != nil || directoryBytesDigest(manifest) != r.digest {
		return DirectorySecrets{}, ErrDirectoryUnavailable
	}
	bind, ok := r.references[bindID]
	ca, okCA := r.references[caID]
	if !ok || !okCA || bind.Purpose != "directory_bind" || ca.Purpose != "directory_ca" || bindID == caID {
		return DirectorySecrets{}, ErrDirectoryUnavailable
	}
	password, e := inventory.ReadProtectedFile(bind.File, true)
	if e != nil || len(password) == 0 || len(password) > 65536 || directoryBytesDigest(password) != bind.ContentDigest {
		for i := range password {
			password[i] = 0
		}
		return DirectorySecrets{}, ErrDirectoryUnavailable
	}
	certificates, e := inventory.ReadProtectedFile(ca.File, false)
	if e != nil || directoryBytesDigest(certificates) != ca.ContentDigest {
		for i := range password {
			password[i] = 0
		}
		return DirectorySecrets{}, ErrDirectoryUnavailable
	}
	if e = ctx.Err(); e != nil {
		for i := range password {
			password[i] = 0
		}
		return DirectorySecrets{}, e
	}
	return DirectorySecrets{BindPassword: password, CACertificatesPEM: certificates}, nil
}
