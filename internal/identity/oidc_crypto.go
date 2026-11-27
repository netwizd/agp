package identity

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"path/filepath"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/inventory"
)

// OIDCStateKeyring is separate protected installation material, never the MFA
// seed keyring or email keys. Its constructor owns a detached private copy.
type OIDCStateKeyring struct {
	ring   *Keyring
	hashes map[[32]byte]bool
}

func NewOIDCStateKeyring(active string, keys map[string][]byte) (*OIDCStateKeyring, error) {
	if !configmodel.ValidID(active) || len(keys) < 1 || len(keys) > 16 {
		return nil, ErrDirectoryUnavailable
	}
	k := &OIDCStateKeyring{ring: &Keyring{Active: active, Keys: map[string]string{}}, hashes: map[[32]byte]bool{}}
	for id, key := range keys {
		if !configmodel.ValidID(id) || len(key) != 32 {
			return nil, ErrDirectoryUnavailable
		}
		h := sha256.Sum256(key)
		if k.hashes[h] {
			return nil, ErrDirectoryUnavailable
		}
		k.hashes[h] = true
		k.ring.Keys[id] = base64.RawURLEncoding.EncodeToString(key)
	}
	if _, ok := k.ring.Keys[active]; !ok {
		return nil, ErrDirectoryUnavailable
	}
	return k, nil
}
func LoadOIDCStateKeyring(file string) (*OIDCStateKeyring, error) {
	if !filepath.IsAbs(file) || filepath.Clean(file) != file {
		return nil, ErrDirectoryUnavailable
	}
	raw, e := inventory.ReadProtectedFile(file, true)
	if e != nil {
		return nil, ErrDirectoryUnavailable
	}
	defer clear(raw)
	var doc struct {
		APIVersion  string            `json:"apiVersion"`
		ActiveKeyID string            `json:"activeKeyId"`
		Keys        map[string]string `json:"keys"`
	}
	if configmodel.StrictJSON(bytes.NewReader(raw), &doc, 32<<10) != nil || doc.APIVersion != "agp.oidc-state-keyring/v1alpha1" {
		return nil, ErrDirectoryUnavailable
	}
	keys := map[string][]byte{}
	for id, s := range doc.Keys {
		v, e := base64.RawURLEncoding.DecodeString(s)
		if e != nil {
			return nil, ErrDirectoryUnavailable
		}
		defer clear(v)
		keys[id] = v
	}
	return NewOIDCStateKeyring(doc.ActiveKeyID, keys)
}
func (s *OIDCService) WithStateKeys(keys *OIDCStateKeyring) (*OIDCService, error) {
	if s == nil || keys == nil || keys.ring == nil {
		return nil, ErrDirectoryUnavailable
	}
	if s.identity.Keys != nil {
		for _, raw := range s.identity.Keys.Keys {
			key, e := base64.RawURLEncoding.DecodeString(raw)
			if e != nil {
				return nil, ErrDirectoryUnavailable
			}
			duplicate := keys.hashes[sha256.Sum256(key)]
			clear(key)
			if duplicate {
				return nil, ErrDirectoryUnavailable
			}
		}
	}
	if s.identity.email != nil && s.identity.email.keys != nil {
		for _, m := range []map[string][]byte{s.identity.email.keys.encryption, s.identity.email.keys.peppers} {
			for _, key := range m {
				if keys.hashes[sha256.Sum256(key)] {
					return nil, ErrDirectoryUnavailable
				}
			}
		}
	}
	s.stateKeys = keys
	return s, nil
}
