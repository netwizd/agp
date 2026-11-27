package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

type Keyring struct {
	Active string            `json:"active"`
	Keys   map[string]string `json:"keys"`
}
type Sealed struct {
	KeyID      string `json:"keyId"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func LoadKeyring(path string) (*Keyring, error) {
	stat, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() || stat.Mode().Perm()&0077 != 0 {
		return nil, errors.New("MFA keyring must be a regular private 0600 file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(stat, opened) {
		return nil, errors.New("MFA keyring changed while opening")
	}
	var keys Keyring
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&keys); err != nil {
		return nil, err
	}
	if keys.Active == "" || len(keys.Keys) == 0 {
		return nil, errors.New("empty keyring")
	}
	for id, raw := range keys.Keys {
		key, err := base64.RawURLEncoding.DecodeString(raw)
		if id == "" || err != nil || len(key) != 32 {
			return nil, errors.New("invalid AES256 MFA key")
		}
	}
	if _, ok := keys.Keys[keys.Active]; !ok {
		return nil, errors.New("active key is unavailable")
	}
	return &keys, nil
}
func (k *Keyring) aead(id string) (cipher.AEAD, error) {
	raw, ok := k.Keys[id]
	if !ok {
		return nil, errors.New("MFA encryption key unavailable")
	}
	key, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil, errors.New("invalid MFA key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func (k *Keyring) Seal(seed []byte, aad string) (Sealed, error) {
	a, err := k.aead(k.Active)
	if err != nil {
		return Sealed{}, err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Sealed{}, err
	}
	return Sealed{KeyID: k.Active, Nonce: base64.RawURLEncoding.EncodeToString(nonce), Ciphertext: base64.RawURLEncoding.EncodeToString(a.Seal(nil, nonce, seed, []byte(aad)))}, nil
}
func (k *Keyring) Open(sealed Sealed, aad string) ([]byte, error) {
	a, err := k.aead(sealed.KeyID)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.RawURLEncoding.DecodeString(sealed.Nonce)
	if err != nil || len(nonce) != a.NonceSize() {
		return nil, errors.New("invalid nonce")
	}
	data, err := base64.RawURLEncoding.DecodeString(sealed.Ciphertext)
	if err != nil {
		return nil, err
	}
	return a.Open(nil, nonce, data, []byte(aad))
}
func GenerateSeed() ([]byte, error) {
	seed := make([]byte, 20)
	_, err := rand.Read(seed)
	return seed, err
}
func ReplayID(principal string) string   { return "totp_replay_" + principal }
func FactorID(principal string) string   { return "totp_" + principal }
func PasswordID(principal string) string { return "password_" + principal }
func RecoveryID(principal string) string { return "recovery_" + principal }
func factorAAD(principal string, version uint64) string {
	return fmt.Sprintf("AGP-TOTP-v1\n%s\n%s\n%d", principal, FactorID(principal), version)
}
func TOTP(seed []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	m := hmac.New(sha1.New, seed)
	_, _ = m.Write(counter[:])
	sum := m.Sum(nil)
	offset := sum[len(sum)-1] & 15
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000)
}
func VerifyTOTP(seed []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	if len(code) != 6 || strings.Trim(code, "0123456789") != "" {
		return 0, false
	}
	step := now.Unix() / 30
	accepted := int64(-1)
	for candidate := step - 1; candidate <= step+1; candidate++ {
		match := subtle.ConstantTimeCompare([]byte(TOTP(seed, candidate)), []byte(code))
		if match == 1 && candidate > lastStep && candidate > accepted {
			accepted = candidate
		}
	}
	return accepted, accepted >= 0
}
func ProvisioningURI(username string, seed []byte) string {
	query := url.Values{"secret": {base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)}, "issuer": {"NLGate AGP"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + url.PathEscape("NLGate AGP:"+username) + "?" + query.Encode()
}
