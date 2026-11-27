// Package secretfiles resolves purpose-bound immutable installation secrets.
// It accepts protected startup files only; it is not a browser secret store.
package secretfiles

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/inventory"
)

var ErrUnavailable = errors.New("installation secret unavailable")

const (
	SMTPPassword = "smtp_password"
	SMTPCA       = "smtp_ca"
	OIDCClient   = "oidc_client"
	OIDCCA       = "oidc_ca"
)

type Reference struct {
	VersionID     string `json:"versionId"`
	Purpose       string `json:"purpose"`
	File          string `json:"file"`
	ContentDigest string `json:"contentDigest"`
}
type Manifest struct {
	APIVersion string      `json:"apiVersion"`
	Secrets    []Reference `json:"secrets"`
}
type Resolver struct {
	file, digest string
	references   map[string]Reference
}

func digest(raw []byte) string {
	s := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(s[:])
}
func absolute(file string) bool { return filepath.IsAbs(file) && filepath.Clean(file) == file }
func purposeValid(p string) bool {
	return p == SMTPPassword || p == SMTPCA || p == OIDCClient || p == OIDCCA
}

// Open snapshots the exact protected manifest. Replacing any listed version or
// the manifest invalidates this resolver; rotation requires a new startup.
func Open(file string) (*Resolver, error) {
	if !absolute(file) {
		return nil, ErrUnavailable
	}
	raw, e := inventory.ReadProtectedFile(file, true)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer clear(raw)
	var m Manifest
	if configmodel.StrictJSON(bytes.NewReader(raw), &m, 64<<10) != nil || m.APIVersion != "agp.external-secrets/v1alpha1" || len(m.Secrets) == 0 || len(m.Secrets) > 256 {
		return nil, ErrUnavailable
	}
	r := &Resolver{file: file, digest: digest(raw), references: map[string]Reference{}}
	for _, ref := range m.Secrets {
		if !configmodel.ValidID(ref.VersionID) || !purposeValid(ref.Purpose) || !absolute(ref.File) || !configmodel.ValidDigest(ref.ContentDigest) {
			return nil, ErrUnavailable
		}
		if _, exists := r.references[ref.VersionID]; exists {
			return nil, ErrUnavailable
		}
		r.references[ref.VersionID] = ref
	}
	return r, nil
}

// Read transfers a new buffer to the caller, who must clear it after use.
// Public CA files still require trusted ownership and a matching content hash.
func (r *Resolver) Read(ctx context.Context, version, purpose string) ([]byte, error) {
	if r == nil || !purposeValid(purpose) {
		return nil, ErrUnavailable
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	manifest, e := inventory.ReadProtectedFile(r.file, true)
	if e != nil {
		return nil, ErrUnavailable
	}
	valid := digest(manifest) == r.digest
	clear(manifest)
	ref, exists := r.references[version]
	if !valid || !exists || ref.Purpose != purpose {
		return nil, ErrUnavailable
	}
	raw, e := inventory.ReadProtectedFile(ref.File, purpose == SMTPPassword || purpose == OIDCClient)
	if e != nil || len(raw) == 0 || len(raw) > 65536 || digest(raw) != ref.ContentDigest {
		clear(raw)
		return nil, ErrUnavailable
	}
	if e = ctx.Err(); e != nil {
		clear(raw)
		return nil, e
	}
	return raw, nil
}
