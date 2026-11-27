package configuration

import (
	"context"
	"fmt"
	"time"

	"github.com/netwizd/agp/internal/rolescope"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type Ownership struct {
	GatewayID string `json:"gatewayId"`
	SiteID    string `json:"siteId"`
}
type BootstrapManifest struct {
	Grants     []ScopeGrant        `json:"grants"`
	Ownership  []Ownership         `json:"ownership"`
	ScopeGraph *rolescope.Manifest `json:"scopeGraph,omitempty"`
}

// BootstrapAccess is only initial installation provisioning. The caller holds
// the offline identity lease and supplies a verified independent authority epoch.
func BootstrapAccess(ctx context.Context, store storage.Store, epoch int64, m BootstrapManifest) error {
	if epoch < 1 || len(m.Grants) > 10000 || len(m.Ownership) > 10000 || len(m.Grants) == 0 {
		return ErrInvalidRequest
	}
	return store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		ids, e := securitystate.Strings(ctx, tx, `SELECT authority_id FROM security_state`)
		if e != nil {
			return e
		}
		if len(ids) > 0 {
			return fmt.Errorf("configuration bootstrap is forbidden after secure authority activation")
		}
		for _, o := range m.Ownership {
			if !validID.MatchString(o.GatewayID) || !validID.MatchString(o.SiteID) {
				return ErrInvalidRequest
			}
			if _, e = tx.Exec(ctx, `INSERT INTO config_gateway_ownership(gateway_id,site_id) VALUES(?,?)`, o.GatewayID, o.SiteID); e != nil {
				return e
			}
		}
		for _, g := range m.Grants {
			if !validID.MatchString(g.PrincipalID) || (g.Permission != "config.read" && g.Permission != "config.edit" && g.Permission != "config.approve") || (g.ScopeType != "global" && g.ScopeType != "site") || (g.ScopeType == "global" && g.ScopeID != "") || (g.ScopeType == "site" && !validID.MatchString(g.ScopeID)) || g.ID != "" {
				return ErrInvalidRequest
			}
			var found string
			if e = securitystate.One(ctx, tx, `SELECT id FROM users WHERE id=? AND blocked_at IS NULL`, []any{g.PrincipalID}, func(r storage.IdentityRows) error { return r.Scan(&found) }); e != nil {
				return e
			}
			if _, e = tx.Exec(ctx, `INSERT INTO config_scope_grants(id,principal_id,permission,scope_type,scope_id,authority_epoch,created_at) VALUES(?,?,?,?,?,?,?)`, securitystate.ID("cgrant"), g.PrincipalID, g.Permission, g.ScopeType, g.ScopeID, epoch, time.Now().UTC()); e != nil {
				return e
			}
		}
		if m.ScopeGraph != nil {
			if e = rolescope.BootstrapTx(ctx, tx, securityjournal.UInt63(epoch), *m.ScopeGraph); e != nil {
				return e
			}
		}
		return securitystate.Audit(ctx, tx, "config.access.bootstrapped", "cli", map[string]any{"grantCount": len(m.Grants), "ownershipCount": len(m.Ownership), "epoch": epoch})
	})
}
