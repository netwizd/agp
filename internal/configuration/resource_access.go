package configuration

import (
	"bytes"
	"context"
	"errors"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/rolescope"
	"github.com/netwizd/agp/internal/storage"
)

func resourceLocation(doc *configmodel.Document, gatewayID, routeID string) (int, int, error) {
	for gi, gateway := range doc.Configuration.Gateways {
		if gateway.Metadata.ID != gatewayID {
			continue
		}
		for ri, route := range gateway.Spec.Routes {
			if route.ID == routeID {
				return gi, ri, nil
			}
		}
	}
	return 0, 0, storage.ErrNotFound
}

func resourceRevisionView(revision *Revision, authority rolescope.ResourceAuthority, gatewayID string, route configmodel.Route, access GatewayAccess) *Revision {
	out := *revision
	out.Content, out.GatewayView, out.GatewayAccess = nil, nil, nil
	out.ViewScope = "resource"
	out.ResourceView = &ResourceRouteView{ResourceID: authority.ResourceID, ResourceName: authority.Name, GatewayID: gatewayID, Route: route}
	out.ResourceAccess = &access
	return &out
}

func (p *Principal) resourceViewAccess(ctx context.Context, tx storage.IdentityTx, resourceID string, gateway configmodel.Gateway, routeID string) (GatewayAccess, error) {
	out := GatewayAccess{Read: true}
	_, err := p.requireResourceRoute(ctx, tx, "config.edit", resourceID, gateway, routeID)
	if err == nil {
		out.Edit = true
		return out, nil
	}
	if errors.Is(err, storage.ErrPermissionDenied) || errors.Is(err, storage.ErrNotFound) {
		return out, nil
	}
	return out, err
}

func (s *Service) ResourceRevision(ctx context.Context, a Actor, revisionID, resourceID, gatewayID, routeID string) (out *Revision, err error) {
	for _, id := range []string{revisionID, resourceID, gatewayID, routeID} {
		if !validID.MatchString(id) {
			return nil, ErrInvalidRequest
		}
	}
	err = s.transactScoped(ctx, a, false, func(tx storage.IdentityTx, p *Principal) error {
		r, e := readRevision(ctx, tx, revisionID)
		if e != nil {
			return e
		}
		doc, e := parseContent(r.Content)
		if e != nil {
			return e
		}
		gi, ri, e := resourceLocation(doc, gatewayID, routeID)
		if e != nil {
			return e
		}
		gateway := doc.Configuration.Gateways[gi]
		authority, e := p.requireResourceRoute(ctx, tx, "config.read", resourceID, gateway, routeID)
		if e != nil {
			return concealedGatewayError(e)
		}
		access, e := p.resourceViewAccess(ctx, tx, resourceID, gateway, routeID)
		if e != nil {
			return e
		}
		out = resourceRevisionView(r, authority, gatewayID, gateway.Spec.Routes[ri], access)
		return nil
	})
	if err != nil {
		out = nil
	}
	return
}

func (s *Service) ChangeResource(ctx context.Context, a Actor, key string, in CreateRevision) (out *Revision, err error) {
	change := in.ResourceChange
	if change == nil || in.GatewayChange != nil || in.WafZoneChange != nil || len(in.Content) > 0 || !validID.MatchString(in.BaseRevisionID) || !validID.MatchString(change.ResourceID) || !validID.MatchString(change.GatewayID) || !validID.MatchString(change.RouteID) {
		return nil, ErrInvalidRequest
	}
	next, err := configmodel.ParseRoute(bytes.NewReader(change.Content), configmodel.JSON)
	if err != nil {
		return nil, err
	}
	if next.ID != change.RouteID {
		return nil, ErrInvalidRequest
	}
	canonicalRoute, err := configmodel.CanonicalJSON(next)
	if err != nil {
		return nil, err
	}
	fp := digest([]string{"resource_change/v1", in.BaseRevisionID, change.ResourceID, change.GatewayID, change.RouteID, string(canonicalRoute)})
	err = s.transactScoped(ctx, a, true, func(tx storage.IdentityTx, p *Principal) error {
		base, e := readRevision(ctx, tx, in.BaseRevisionID)
		if e != nil {
			return e
		}
		doc, e := parseContent(base.Content)
		if e != nil {
			return e
		}
		gi, ri, e := resourceLocation(doc, change.GatewayID, change.RouteID)
		if e != nil {
			return e
		}
		old := doc.Configuration.Gateways[gi]
		authority, e := p.requireResourceRoute(ctx, tx, "config.edit", change.ResourceID, old, change.RouteID)
		if e != nil {
			return concealedGatewayError(e)
		}
		candidate := old
		candidate.Spec.Routes = append([]configmodel.Route(nil), old.Spec.Routes...)
		candidate.Spec.Routes[ri] = *next
		if _, e = p.requireResourceRoute(ctx, tx, "config.edit", change.ResourceID, candidate, change.RouteID); e != nil {
			return concealedGatewayError(e)
		}
		if e = p.requireResourceRoutingEffects(ctx, tx, old, candidate, change.RouteID); e != nil {
			return concealedGatewayError(e)
		}
		if e = p.checkResourceHostReceivers(ctx, tx, doc, old, candidate, change.RouteID); e != nil {
			return e
		}
		handle, e := request(ctx, tx, p.ID, "revision.create", key, fp)
		if e != nil {
			return e
		}
		if handle != nil {
			revision, e := readRevision(ctx, tx, handle.id)
			if e != nil {
				return e
			}
			published, e := parseContent(revision.Content)
			if e != nil {
				return e
			}
			pi, pr, e := resourceLocation(published, change.GatewayID, change.RouteID)
			if e != nil {
				return e
			}
			if _, e = p.requireResourceRoute(ctx, tx, "config.read", change.ResourceID, published.Configuration.Gateways[pi], change.RouteID); e != nil {
				return concealedGatewayError(e)
			}
			out = resourceRevisionView(revision, authority, change.GatewayID, published.Configuration.Gateways[pi].Spec.Routes[pr], GatewayAccess{Read: true, Edit: true})
			return nil
		}
		doc.Configuration.Gateways[gi] = candidate
		canonical, e := configmodel.Canonicalize(doc.Configuration)
		if e != nil {
			return storage.ErrConflict
		}
		revision, e := insertRevision(ctx, tx, p.ID, in.BaseRevisionID, canonical)
		if e != nil {
			var invalid *configmodel.ValidationError
			if errors.As(e, &invalid) {
				for _, issue := range invalid.Issues {
					if issue.Code == "zone_resolution_required" {
						return zoneIssue("/resourceChange", "zone_resolution_required", "Changing assigned resource security inputs requires a new trusted zone resolution")
					}
				}
				return storage.ErrConflict
			}
			return e
		}
		if e = remember(ctx, tx, p.ID, "revision.create", key, fp, responseHandle{"revision", revision.ID, 0}); e != nil {
			return e
		}
		out = resourceRevisionView(revision, authority, change.GatewayID, *next, GatewayAccess{Read: true, Edit: true})
		return nil
	})
	if err != nil {
		out = nil
	}
	return
}

func (p *Principal) requireResourceRoutingEffects(ctx context.Context, tx storage.IdentityTx, old, candidate configmodel.Gateway, editedID string) error {
	impacted, err := configmodel.RoutingChangeImpacts(old, candidate, editedID)
	if err != nil {
		return storage.ErrConflict
	}
	resolver, err := p.resources(ctx, tx)
	if err != nil {
		return err
	}
	for _, id := range impacted {
		if id == editedID {
			continue
		}
		resourceID, err := resolver.LookupRoute(old.Metadata.ID, id)
		if err != nil {
			return subjectFailure(tx, err)
		}
		if resourceID == "" {
			if err := p.RequireGateway(ctx, tx, "config.edit", old); err != nil {
				return err
			}
			continue
		}
		if _, err := p.requireResourceRoute(ctx, tx, "config.edit", resourceID, old, id); err != nil {
			return err
		}
	}
	return nil
}

func (p *Principal) checkResourceHostReceivers(ctx context.Context, tx storage.IdentityTx, doc *configmodel.Document, old, candidate configmodel.Gateway, editedID string) error {
	hosts := map[string]bool{}
	for _, gateway := range []configmodel.Gateway{old, candidate} {
		for _, route := range gateway.Spec.Routes {
			if route.ID == editedID {
				hosts[route.Hostname] = true
			}
		}
	}
	receiving, err := p.currentGatewayRecipients(ctx, tx, candidate)
	if err != nil {
		return err
	}
	if len(receiving.Nodes) == 0 {
		return rolescope.ErrUnavailable
	}
	p.rememberGatewayRecipients(candidate, receiving)
	selected := map[string]bool{}
	for _, node := range receiving.Nodes {
		selected[node.NodeID] = true
	}
	for _, other := range doc.Configuration.Gateways {
		if other.Metadata.ID == old.Metadata.ID {
			continue
		}
		sharesHost := false
		for _, route := range other.Spec.Routes {
			sharesHost = sharesHost || hosts[route.Hostname]
		}
		if !sharesHost {
			continue
		}
		neighbors, err := p.currentGatewayRecipients(ctx, tx, other)
		if err != nil {
			return err
		}
		if len(neighbors.Nodes) == 0 {
			return rolescope.ErrUnavailable
		}
		p.rememberGatewayRecipients(other, neighbors)
		for _, node := range neighbors.Nodes {
			if selected[node.NodeID] {
				return storage.ErrConflict
			}
		}
	}
	return nil
}
