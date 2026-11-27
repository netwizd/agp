package runtime

import (
	"bytes"
	"errors"
	"net/netip"
	"path/filepath"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/securitystate"
)

var errDirectoryStartup = errors.New("directory_connector_configuration_rejected")

// DirectoryConnectorConfig is protected installation policy. Browser provider
// documents cannot expand its network allowlist or replace secret references.
type DirectoryConnectorConfig struct {
	APIVersion      string   `json:"apiVersion"`
	SecretsManifest string   `json:"secretsManifest"`
	AllowedCIDRs    []string `json:"allowedCidrs"`
}

func OpenDirectoryService(c *securitystate.Coordinator, origin, file string) (*identity.DirectoryService, *identity.ADConnector, error) {
	if file == "" {
		return identity.NewDirectoryService(c, origin, nil), nil, nil
	}
	if !filepath.IsAbs(file) || filepath.Clean(file) != file {
		return nil, nil, errDirectoryStartup
	}
	raw, err := inventory.ReadProtectedFile(file, true)
	if err != nil {
		return nil, nil, errDirectoryStartup
	}
	var cfg DirectoryConnectorConfig
	if configmodel.StrictJSON(bytes.NewReader(raw), &cfg, 64<<10) != nil || cfg.APIVersion != "agp.directory-connector/v1alpha1" || !filepath.IsAbs(cfg.SecretsManifest) || filepath.Clean(cfg.SecretsManifest) != cfg.SecretsManifest || len(cfg.AllowedCIDRs) == 0 || len(cfg.AllowedCIDRs) > 64 {
		return nil, nil, errDirectoryStartup
	}
	prefixes := make([]netip.Prefix, 0, len(cfg.AllowedCIDRs))
	seen := map[netip.Prefix]bool{}
	for _, raw := range cfg.AllowedCIDRs {
		p, err := netip.ParsePrefix(raw)
		if err != nil || p != p.Masked() || p.Addr().Is4In6() || seen[p] {
			return nil, nil, errDirectoryStartup
		}
		prefixes = append(prefixes, p)
		seen[p] = true
	}
	secrets, err := identity.NewDirectoryFileSecrets(cfg.SecretsManifest)
	if err != nil {
		return nil, nil, errDirectoryStartup
	}
	connector, err := identity.NewADConnector(secrets, prefixes)
	if err != nil {
		return nil, nil, errDirectoryStartup
	}
	return identity.NewDirectoryService(c, origin, connector), connector, nil
}
