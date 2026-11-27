package runtime

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/oidcclient"
	"github.com/netwizd/agp/internal/secretfiles"
)

var errOIDCStartup = errors.New("oidc_connector_configuration_rejected")

// OIDCConnectorConfig pins egress and secret storage independently of the
// provider documents accepted by the management API.
type OIDCConnectorConfig struct {
	APIVersion              string   `json:"apiVersion"`
	StateKeyringFile        string   `json:"stateKeyringFile"`
	SecretsManifest         string   `json:"secretsManifest"`
	HTTPSOrigins            []string `json:"httpsOrigins"`
	AllowedCIDRs            []string `json:"allowedCidrs"`
	OperationTimeoutSeconds int      `json:"operationTimeoutSeconds"`
	MaximumConcurrent       int      `json:"maximumConcurrent"`
}
type oidcFileSecrets struct{ resolver *secretfiles.Resolver }

func (r oidcFileSecrets) ResolveOIDCSecrets(ctx context.Context, clientID, caID string) (oidcclient.Secrets, error) {
	var out oidcclient.Secrets
	var e error
	out.ClientSecret, e = r.resolver.Read(ctx, clientID, secretfiles.OIDCClient)
	if e != nil {
		return out, e
	}
	out.CACertificatesPEM, e = r.resolver.Read(ctx, caID, secretfiles.OIDCCA)
	if e != nil {
		clear(out.ClientSecret)
		return oidcclient.Secrets{}, e
	}
	return out, nil
}

func OpenOIDCConnector(file string) (*oidcclient.Connector, error) {
	connector, _, err := openOIDCConnector(file)
	return connector, err
}

func OpenOIDCService(service *identity.Service, file string) (*identity.OIDCService, error) {
	connector, keyFile, err := openOIDCConnector(file)
	if err != nil {
		return nil, err
	}
	oidc, err := identity.NewOIDCService(service, connector)
	if err != nil {
		return nil, err
	}
	if connector != nil {
		keys, err := identity.LoadOIDCStateKeyring(keyFile)
		if err != nil {
			return nil, errOIDCStartup
		}
		if _, err = oidc.WithStateKeys(keys); err != nil {
			return nil, errOIDCStartup
		}
	}
	return oidc, nil
}

func openOIDCConnector(file string) (*oidcclient.Connector, string, error) {
	if file == "" {
		return nil, "", nil
	}
	if !filepath.IsAbs(file) || filepath.Clean(file) != file {
		return nil, "", errOIDCStartup
	}
	raw, e := inventory.ReadProtectedFile(file, true)
	if e != nil {
		return nil, "", errOIDCStartup
	}
	defer clear(raw)
	var cfg OIDCConnectorConfig
	if configmodel.StrictJSON(bytes.NewReader(raw), &cfg, 64<<10) != nil || cfg.APIVersion != "agp.oidc-connector/v1alpha1" || !filepath.IsAbs(cfg.StateKeyringFile) || filepath.Clean(cfg.StateKeyringFile) != cfg.StateKeyringFile || len(cfg.AllowedCIDRs) == 0 || len(cfg.AllowedCIDRs) > 64 || cfg.OperationTimeoutSeconds < 1 || cfg.OperationTimeoutSeconds > 10 || cfg.MaximumConcurrent < 1 || cfg.MaximumConcurrent > 16 {
		return nil, "", errOIDCStartup
	}
	var prefixes []netip.Prefix
	seen := map[netip.Prefix]bool{}
	for _, cidr := range cfg.AllowedCIDRs {
		p, e := netip.ParsePrefix(cidr)
		if e != nil || p != p.Masked() || p.Addr().Is4In6() || seen[p] {
			return nil, "", errOIDCStartup
		}
		prefixes = append(prefixes, p)
		seen[p] = true
	}
	secrets, e := secretfiles.Open(cfg.SecretsManifest)
	if e != nil {
		return nil, "", errOIDCStartup
	}
	connector, e := oidcclient.New(oidcclient.NetworkPolicy{HTTPSOrigins: cfg.HTTPSOrigins, AllowedCIDRs: prefixes, Timeout: time.Duration(cfg.OperationTimeoutSeconds) * time.Second, MaximumConcurrent: cfg.MaximumConcurrent}, oidcFileSecrets{secrets})
	if e != nil {
		return nil, "", errOIDCStartup
	}
	return connector, cfg.StateKeyringFile, nil
}
