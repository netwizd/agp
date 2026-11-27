package helper

import (
	"crypto/ed25519"
	"encoding/base64"

	"github.com/netwizd/agp/internal/configmodel"
)

func executionReceiptKey(a ExecutionAnchor) (ed25519.PublicKey, error) {
	key, err := base64.RawURLEncoding.DecodeString(a.ReceiptPublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(key) != a.ReceiptPublicKey || !configmodel.ValidID(a.ReceiptKeyID) {
		return nil, ErrInvalid
	}
	return ed25519.PublicKey(key), nil
}

// VerifyExecutionReceipt authenticates a historical helper observation using a
// separately installer-pinned root-held receipt identity. Agent mTLS alone is
// insufficient. The control plane must ALSO bind every field to its exact task.
func VerifyExecutionReceipt(r ExecutionReceipt, keyID string, key ed25519.PublicKey) error {
	if r.APIVersion != ExecutionReceiptVersion || r.Purpose != "local_execution_outcome" || r.KeyID != keyID || !configmodel.ValidID(keyID) || !configmodel.ValidID(r.ReceiptID) || !configmodel.ValidID(r.NodeID) || !configmodel.ValidID(r.TaskID) || !configmodel.ValidDigest(r.RequestDigest) || r.ReceiptSequence == 0 || r.NodeDeploymentSequence == 0 || !validCounters(r.ReceiptSequence, r.NodeDeploymentSequence) || validateGeneration(r.Active) != nil || r.Active.Baseline.NodeDeploymentSequence > r.NodeDeploymentSequence {
		return ErrUnauthorized
	}
	if _, err := utc(r.RecordedAt); err != nil {
		return ErrUnauthorized
	}
	switch r.State {
	case "succeeded":
		if r.RecoveryRequired || r.Active.Baseline.NodeDeploymentSequence != r.NodeDeploymentSequence {
			return ErrUnauthorized
		}
	case "failed", "recovered":
		if r.RecoveryRequired {
			return ErrUnauthorized
		}
	case "recovery_required":
		if !r.RecoveryRequired {
			return ErrUnauthorized
		}
	default:
		return ErrUnauthorized
	}
	signature := r.Signature
	r.Signature = ""
	if !verifySignature(r, signature, "AGP-HELPER-EXECUTION-RECEIPT-v1", key) {
		return ErrUnauthorized
	}
	return nil
}

func signExecutionReceipt(r ExecutionReceipt, keyID string, key ed25519.PrivateKey) (ExecutionReceipt, error) {
	if len(key) != ed25519.PrivateKeySize {
		return ExecutionReceipt{}, ErrInvalid
	}
	r.KeyID = keyID
	r.Signature = ""
	digest, err := configmodel.Digest(r)
	if err != nil {
		return ExecutionReceipt{}, ErrInvalid
	}
	r.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte("AGP-HELPER-EXECUTION-RECEIPT-v1\n"+digest)))
	if VerifyExecutionReceipt(r, keyID, key.Public().(ed25519.PublicKey)) != nil {
		return ExecutionReceipt{}, ErrInvalid
	}
	return r, nil
}
