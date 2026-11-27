package runtime

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/configuration"
	"github.com/netwizd/agp/internal/inventory"
)

// ConfigurePlanReviewSigner loads an optional dedicated planning-review key.
// No key is generated or persisted by the server. This is not an execution or
// helper-control signer and does not enable any start endpoint.
func ConfigurePlanReviewSigner(service *configuration.Service, keyID, keyFile string) error {
	if keyID == "" && keyFile == "" {
		return nil
	}
	if service == nil || !configmodel.ValidID(keyID) || keyFile == "" {
		return errors.New("invalid plan review signer configuration")
	}
	raw, err := inventory.ReadProtectedFile(keyFile, true)
	if err != nil || len(raw) > 8192 {
		return errors.New("plan review signing key unavailable")
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(rest) != 0 {
		return errors.New("invalid plan review signing key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return errors.New("invalid plan review signing key")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid plan review signing key")
	}
	return service.WithPlanReviewSigningKey(keyID, key)
}
