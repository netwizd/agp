package configuration

import (
	"context"
	"sort"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/rolescope"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

func (p *Principal) hasResourcePermission(permission string) bool {
	if p.hasGatewayPermission(permission) {
		return true
	}
	for _, grant := range p.grants {
		if grant.ScopeType == "resource" && gatewayPermissionMatches(grant.Permission, permission) {
			return true
		}
	}
	return false
}

func (p *Principal) hasExactResourceGrant(permission, id string) bool {
	for _, grant := range p.grants {
		if grant.ScopeType == "resource" && grant.ScopeID == id && gatewayPermissionMatches(grant.Permission, permission) {
			return true
		}
	}
	return false
}

// Admission advertises only an available object workflow. Every selected route,
// indirect routing effect and final source is checked inside the actual TX.
func (s *Service) AuthorizeResource(ctx context.Context, a Actor, write bool) error {
	permission := "config.read"
	if write {
		permission = "config.edit"
	}
	return s.transactScoped(ctx, a, write, func(_ storage.IdentityTx, p *Principal) error {
		if !p.hasResourcePermission(permission) {
			return storage.ErrPermissionDenied
		}
		return nil
	})
}

func (p *Principal) resources(ctx context.Context, tx storage.IdentityTx) (*rolescope.ResourceAuthorityResolver, error) {
	if p.resourceResolver == nil {
		var err error
		p.resourceResolver, err = rolescope.NewResourceAuthorityResolver(ctx, tx, p.head)
		if err != nil {
			return nil, subjectFailure(tx, err)
		}
	}
	return p.resourceResolver, nil
}

func (p *Principal) requireResourceRoute(ctx context.Context, tx storage.IdentityTx, permission, resourceID string, gateway configmodel.Gateway, routeID string) (rolescope.ResourceAuthority, error) {
	if !p.hasExactResourceGrant(permission, resourceID) && !p.hasGatewayPermission(permission) {
		return rolescope.ResourceAuthority{}, storage.ErrPermissionDenied
	}
	resolver, err := p.resources(ctx, tx)
	if err != nil {
		return rolescope.ResourceAuthority{}, err
	}
	mapped, err := resolver.LookupRoute(gateway.Metadata.ID, routeID)
	if err != nil {
		return rolescope.ResourceAuthority{}, subjectFailure(tx, err)
	}
	if mapped != resourceID {
		return rolescope.ResourceAuthority{}, storage.ErrNotFound
	}
	if !p.hasExactResourceGrant(permission, resourceID) {
		if err := p.RequireGateway(ctx, tx, permission, gateway); err != nil {
			return rolescope.ResourceAuthority{}, err
		}
	}
	authority, err := resolver.Resolve(resourceID)
	if err != nil {
		return rolescope.ResourceAuthority{}, subjectFailure(tx, err)
	}
	recipients, err := p.currentGatewayRecipients(ctx, tx, gateway)
	if err != nil {
		return rolescope.ResourceAuthority{}, err
	}
	if len(recipients.Nodes) == 0 {
		return rolescope.ResourceAuthority{}, storage.ErrPermissionDenied
	}
	p.rememberGatewayRecipients(gateway, recipients)
	if p.resourceEvidence == nil {
		p.resourceEvidence = map[string]string{}
	}
	p.resourceEvidence[resourceID] = authority.Digest
	return authority, nil
}

func (p *Principal) revalidateResourceEvidence(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head) error {
	if len(p.resourceEvidence) == 0 {
		return nil
	}
	resolver, err := rolescope.NewResourceAuthorityResolver(ctx, tx, h)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(p.resourceEvidence))
	for id := range p.resourceEvidence {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		current, err := resolver.Resolve(id)
		if err != nil {
			return err
		}
		if current.Digest != p.resourceEvidence[id] {
			return storage.ErrPermissionDenied
		}
	}
	return nil
}
