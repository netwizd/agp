package runtime

import (
	"crypto/tls"

	"github.com/netwizd/agp/internal/config"
	"github.com/netwizd/agp/internal/inventory"
)

func EnrollmentTLS(cfg config.Config) (*tls.Config, error) {
	if cfg.ValidateAgent() != nil || cfg.NodeIdentityConfig == "" {
		return nil, inventory.ErrUnavailable
	}
	cert, err := inventory.ReadProtectedFile(cfg.EnrollmentTLSCertFile, false)
	if err != nil {
		return nil, err
	}
	key, err := inventory.ReadProtectedFile(cfg.EnrollmentTLSKeyFile, true)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, inventory.ErrUnavailable
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.NoClientCert, Certificates: []tls.Certificate{pair}}, nil
}
