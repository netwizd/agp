package deploymentplan

import (
	"crypto/ed25519"
	"encoding/base64"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
)

const signatureDomain = "AGP-DEPLOYMENT-PLAN-v1"

func envelopeShape(s SignedPlan) error {
	if len(s.Signature) != base64.RawURLEncoding.EncodedLen(ed25519.SignatureSize) {
		return ErrInvalid
	}
	b, err := base64.RawURLEncoding.DecodeString(s.Signature)
	if s.APIVersion != SignedVersion || s.Purpose != ExecutionPurpose || !configmodel.ValidID(s.KeyID) || err != nil || len(b) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(b) != s.Signature {
		return ErrInvalid
	}
	return nil
}

func signingBytes(s SignedPlan) ([]byte, error) {
	s.Signature = ""
	d, err := configmodel.Digest(s)
	if err != nil {
		return nil, ErrInvalid
	}
	return []byte(signatureDomain + "\n" + d), nil
}

// Sign seals normalized immutable bytes. Its caller remains responsible for
// release qualification, approvals and current authority checks before signing.
func Sign(p Plan, keyID string, key ed25519.PrivateKey) (*SignedPlan, error) {
	if !configmodel.ValidID(keyID) || len(key) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	n, err := Normalize(p)
	if err != nil {
		return nil, ErrInvalid
	}
	s := SignedPlan{APIVersion: SignedVersion, Purpose: ExecutionPurpose, KeyID: keyID, Plan: *n}
	b, err := signingBytes(s)
	if err != nil {
		return nil, ErrInvalid
	}
	s.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, b))
	return &s, nil
}

// Verify checks integrity, purpose, separately pinned signer and current plan
// lifetime. It does not check node identity, approval or the live journal head.
// Set order is canonicalized identically to Sign; duplicate members fail closed.
func Verify(s SignedPlan, keyID string, key ed25519.PublicKey, now time.Time) error {
	if envelopeShape(s) != nil || VerifyDigest(s.Plan) != nil {
		return ErrInvalid
	}
	if !configmodel.ValidID(keyID) || s.KeyID != keyID || len(key) != ed25519.PublicKeySize {
		return ErrUnauthorized
	}
	n, err := Normalize(s.Plan)
	if err != nil {
		return ErrInvalid
	}
	s.Plan = *n
	b, err := signingBytes(s)
	if err != nil {
		return ErrInvalid
	}
	signature, _ := base64.RawURLEncoding.DecodeString(s.Signature)
	if !ed25519.Verify(key, b, signature) {
		return ErrUnauthorized
	}
	created, _ := utc(s.Plan.CreatedAt)
	expires, _ := utc(s.Plan.ExpiresAt)
	if now.IsZero() || now.Before(created) || !now.Before(expires) {
		return ErrNotCurrent
	}
	return nil
}
