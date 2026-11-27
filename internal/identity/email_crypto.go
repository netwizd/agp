package identity

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/inventory"
)

var ErrEmailUnavailable = errors.New("email identity unavailable")
var ErrContactStale = errors.New("contact revision conflict")
var ErrEmailReauthRequired = errors.New("email operation requires recent reauthentication")

// EmailKeyring is a private copy of installation-owned keys. Encryption and
// pepper namespaces are separate, never derived from a password or MFA key.
// Existing key IDs must retain immutable bytes when an installation rotates.
type EmailKeyring struct {
	activeEncryption, activePepper string
	encryption, peppers            map[string][]byte
}

func NewEmailKeyring(activeEncryption, activePepper string, encryption, peppers map[string][]byte) (*EmailKeyring, error) {
	k := &EmailKeyring{activeEncryption: activeEncryption, activePepper: activePepper, encryption: map[string][]byte{}, peppers: map[string][]byte{}}
	if len(encryption) < 1 || len(encryption) > 16 || len(peppers) < 1 || len(peppers) > 16 {
		return nil, ErrEmailUnavailable
	}
	seen := map[string]bool{}
	values := map[[32]byte]bool{}
	for i, m := range []map[string][]byte{encryption, peppers} {
		for id, key := range m {
			if !configmodel.ValidID(id) || seen[id] || len(key) != 32 {
				return nil, ErrEmailUnavailable
			}
			digest := sha256.Sum256(key)
			if values[digest] {
				return nil, ErrEmailUnavailable
			}
			values[digest] = true
			seen[id] = true
			if i == 0 {
				k.encryption[id] = bytes.Clone(key)
			} else {
				k.peppers[id] = bytes.Clone(key)
			}
		}
	}
	if k.encryption[activeEncryption] == nil || k.peppers[activePepper] == nil {
		return nil, ErrEmailUnavailable
	}
	return k, nil
}

// LoadEmailKeyring reads a bounded, protected installation file, not a database
// record or request. The file must not be reused for the MFA keyring.
func LoadEmailKeyring(file string) (*EmailKeyring, error) {
	if !filepath.IsAbs(file) || filepath.Clean(file) != file {
		return nil, ErrEmailUnavailable
	}
	raw, e := inventory.ReadProtectedFile(file, true)
	if e != nil {
		return nil, ErrEmailUnavailable
	}
	defer clear(raw)
	var doc struct {
		APIVersion       string            `json:"apiVersion"`
		ActiveEncryption string            `json:"activeEncryption"`
		ActivePepper     string            `json:"activePepper"`
		Encryption       map[string]string `json:"encryption"`
		Peppers          map[string]string `json:"peppers"`
	}
	if configmodel.StrictJSON(bytes.NewReader(raw), &doc, 32<<10) != nil || doc.APIVersion != "agp.email-keyring/v1alpha1" {
		return nil, ErrEmailUnavailable
	}
	maps := []map[string][]byte{{}, {}}
	for i, src := range []map[string]string{doc.Encryption, doc.Peppers} {
		for id, s := range src {
			b, e := base64.RawURLEncoding.DecodeString(s)
			if e != nil {
				return nil, ErrEmailUnavailable
			}
			maps[i][id] = b
			defer clear(b)
		}
	}
	return NewEmailKeyring(doc.ActiveEncryption, doc.ActivePepper, maps[0], maps[1])
}
func emailAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrEmailUnavailable
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, ErrEmailUnavailable
	}
	return cipher.NewGCM(b)
}
func emailSeal(key, plaintext, aad []byte) (nonce, ciphertext string, err error) {
	a, e := emailAEAD(key)
	if e != nil {
		return "", "", e
	}
	n := make([]byte, a.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return "", "", ErrEmailUnavailable
	}
	return base64.RawURLEncoding.EncodeToString(n), base64.RawURLEncoding.EncodeToString(a.Seal(nil, n, plaintext, aad)), nil
}
func emailOpen(key []byte, nonce, ciphertext string, aad []byte) ([]byte, error) {
	a, e := emailAEAD(key)
	if e != nil {
		return nil, e
	}
	n, e := base64.RawURLEncoding.DecodeString(nonce)
	if e != nil || len(n) != a.NonceSize() {
		return nil, ErrEmailUnavailable
	}
	b, e := base64.RawURLEncoding.DecodeString(ciphertext)
	if e != nil || len(b) > 4096 {
		return nil, ErrEmailUnavailable
	}
	plain, e := a.Open(nil, n, b, aad)
	if e != nil {
		return nil, ErrEmailUnavailable
	}
	return plain, nil
}
func emailEncoding(fields ...string) []byte {
	var out bytes.Buffer
	for _, f := range fields {
		_ = binary.Write(&out, binary.BigEndian, uint32(len(f)))
		out.WriteString(f)
	}
	return out.Bytes()
}
func emailContactAAD(principal, id string, version uint64) []byte {
	return emailEncoding("AGP-EMAIL-CONTACT-v1", principal, id, fmt.Sprint(version))
}
func emailCode() (string, error) {
	n, e := rand.Int(rand.Reader, big.NewInt(100000000))
	if e != nil {
		return "", ErrEmailUnavailable
	}
	return fmt.Sprintf("%08d", n.Int64()), nil
}
func emailMAC(key []byte, fields ...string) string {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(emailEncoding(fields...))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
func emailEqual(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
