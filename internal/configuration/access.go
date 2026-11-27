package configuration

import (
	"context"
	"sort"
	"strconv"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/rolescope"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type ScopeGrant struct {
	ID          string `json:"id"`
	PrincipalID string `json:"principalId"`
	Permission  string `json:"permission"`
	ScopeType   string `json:"scopeType"`
	ScopeID     string `json:"scopeId"`
}
type Principal struct {
	ID               string
	Admin            bool
	Epoch            int64
	MFAAt            time.Time
	SecurityVersion  int64
	grants           []ScopeGrant
	grantEvidence    []securitystate.EffectiveGrant
	head             securityjournal.Head
	gatewayResolver  *rolescope.GatewayRecipientResolver
	gatewayEvidence  map[string]gatewayScopeWitness
	gatewayOwners    map[string]string
	gatewaySnapshots map[string]rolescope.GatewayRecipients
	resourceResolver *rolescope.ResourceAuthorityResolver
	resourceEvidence map[string]string
}

func (p *Principal) Require(permission, site string) error {
	if p.Admin && (permission == "config.read" || permission == "config.edit") {
		return nil
	}
	for _, g := range p.grants {
		if g.Permission != permission && !(permission == "config.read" && g.Permission == "config.edit") {
			continue
		}
		if g.ScopeType == "global" || (site != "" && g.ScopeType == "site" && g.ScopeID == site) {
			return nil
		}
	}
	return storage.ErrPermissionDenied
}
func (p *Principal) ReadSites(permission string) (bool, []string) {
	if p.Require(permission, "") == nil {
		return true, []string{}
	}
	set := map[string]bool{}
	for _, g := range p.grants {
		if g.ScopeType == "site" && p.Require(permission, g.ScopeID) == nil {
			set[g.ScopeID] = true
		}
	}
	out := []string{}
	for site := range set {
		out = append(out, site)
	}
	sort.Strings(out)
	return false, out
}
func (p *Principal) RequireGateway(ctx context.Context, tx storage.IdentityTx, permission string, g configmodel.Gateway) error {
	if p.Require(permission, "") == nil {
		return nil
	}
	if p.Require(permission, g.Metadata.SiteID) != nil {
		return p.requireGatewayRecipients(ctx, tx, permission, g)
	}
	var site string
	e := securitystate.One(ctx, tx, `SELECT site_id FROM config_gateway_ownership WHERE gateway_id=?`, []any{g.Metadata.ID}, func(r storage.IdentityRows) error { return r.Scan(&site) })
	if e == storage.ErrNotFound || (e == nil && site != g.Metadata.SiteID) {
		return storage.ErrPermissionDenied
	}
	if e != nil {
		return subjectFailure(tx, e)
	}
	if p.gatewayOwners == nil {
		p.gatewayOwners = map[string]string{}
	}
	p.gatewayOwners[g.Metadata.ID] = site
	return nil
}

func (p *Principal) RequireSiteSnapshot(ctx context.Context, tx storage.IdentityTx, permission, base, site string) error {
	if e := p.Require(permission, site); e != nil {
		return storage.ErrNotFound
	}
	r, e := readRevision(ctx, tx, base)
	if e != nil {
		return e
	}
	doc, e := parseContent(r.Content)
	if e != nil {
		return e
	}
	for _, g := range doc.Configuration.Gateways {
		if g.Metadata.SiteID == site {
			if e = p.RequireGateway(ctx, tx, permission, g); e != nil {
				return concealedGatewayError(e)
			}
		}
	}
	return nil
}
func (s *Service) transactScoped(ctx context.Context, a Actor, write bool, fn func(storage.IdentityTx, *Principal) error) error {
	if s == nil || s.current == nil || a.Origin != s.origin || a.TokenHash == "" || s.origin == "" {
		return storage.ErrPermissionDenied
	}
	return securitystate.WithManagementSession(ctx, a.TokenHash, s.current, func(ctx context.Context) error {
		return s.current.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
			p, err := readConfigurationActor(ctx, tx, h, a, write, s.current, s.origin)
			if err != nil {
				return err
			}
			evidence := &subjectEvidenceTx{IdentityTx: tx, proofContext: ctx, subjects: map[string]configurationSubjectWitness{}}
			return s.finishConfigurationEvidence(ctx, a, write, p, evidence, fn(evidence, p))
		})
	})
}

type SiteAccess struct {
	SiteID  string `json:"siteId"`
	Read    bool   `json:"read"`
	Edit    bool   `json:"edit"`
	Approve bool   `json:"approve,omitempty"`
}
type Access struct {
	PrincipalID    string       `json:"principalId"`
	GlobalRead     bool         `json:"globalRead"`
	GlobalEdit     bool         `json:"globalEdit"`
	GlobalApprove  bool         `json:"globalApprove,omitempty"`
	AuthorityEpoch string       `json:"authorityEpoch"`
	Sites          []SiteAccess `json:"sites"`
	GatewayRead    bool         `json:"gatewayRead"`
	GatewayEdit    bool         `json:"gatewayEdit"`
	ResourceRead   bool         `json:"resourceRead"`
	ResourceEdit   bool         `json:"resourceEdit"`
}

func (s *Service) Access(ctx context.Context, a Actor) (out Access, err error) {
	err = s.transactScoped(ctx, a, false, func(tx storage.IdentityTx, p *Principal) error {
		out = Access{PrincipalID: p.ID, GlobalRead: p.Require("config.read", "") == nil, GlobalEdit: p.Require("config.edit", "") == nil, GlobalApprove: p.Require("config.approve", "") == nil, AuthorityEpoch: strconv.FormatInt(p.Epoch, 10), Sites: []SiteAccess{}}
		out.GatewayRead = p.hasGatewayPermission("config.read")
		out.GatewayEdit = p.hasGatewayPermission("config.edit")
		out.ResourceRead = p.hasResourcePermission("config.read")
		out.ResourceEdit = p.hasResourcePermission("config.edit")
		siteSet := map[string]bool{}
		for _, grant := range p.grants {
			if grant.ScopeType == "site" && p.Require("config.read", grant.ScopeID) == nil {
				siteSet[grant.ScopeID] = true
			}
		}
		sites := []string{}
		for site := range siteSet {
			sites = append(sites, site)
		}
		sort.Strings(sites)
		for _, site := range sites {
			out.Sites = append(out.Sites, SiteAccess{SiteID: site, Read: true, Edit: p.Require("config.edit", site) == nil, Approve: p.Require("config.approve", site) == nil})
		}
		return nil
	})
	return
}

// Authorize checks current scoped access even for stateless normalization APIs.
func (s *Service) Authorize(ctx context.Context, a Actor, write bool) error {
	permission := "config.read"
	if write {
		permission = "config.edit"
	}
	return s.AuthorizePermission(ctx, a, permission, write)
}

func (s *Service) AuthorizePermission(ctx context.Context, a Actor, permission string, write bool) error {
	if permission != "config.read" && permission != "config.edit" && permission != "config.approve" {
		return storage.ErrPermissionDenied
	}
	return s.transactScoped(ctx, a, write, func(_ storage.IdentityTx, p *Principal) error {
		global, sites := p.ReadSites(permission)
		if !global && len(sites) == 0 {
			return storage.ErrPermissionDenied
		}
		return nil
	})
}
