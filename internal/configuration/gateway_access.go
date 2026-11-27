package configuration

import (
	"bytes"
	"context"
	"errors"
	"sort"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/storage"
)

func gatewayFrom(r *Revision, id string) (configmodel.Gateway, error) {
	d, e := parseContent(r.Content)
	if e != nil {
		return configmodel.Gateway{}, e
	}
	for _, g := range d.Configuration.Gateways {
		if g.Metadata.ID == id {
			return g, nil
		}
	}
	return configmodel.Gateway{}, storage.ErrNotFound
}
func gatewayView(r *Revision, g configmodel.Gateway, access GatewayAccess) *Revision {
	v := *r
	v.Content = nil
	v.ViewScope = "gateway"
	v.GatewayView = &g
	v.GatewayAccess = &access
	return &v
}

func (p *Principal) gatewayViewAccess(ctx context.Context, tx storage.IdentityTx, g configmodel.Gateway) (GatewayAccess, error) {
	out := GatewayAccess{Read: true}
	err := p.RequireGateway(ctx, tx, "config.edit", g)
	if err == nil {
		out.Edit = true
		return out, nil
	}
	if errors.Is(err, storage.ErrPermissionDenied) || errors.Is(err, storage.ErrNotFound) {
		return out, nil
	}
	return out, err
}
func (s *Service) GatewayRevision(ctx context.Context, a Actor, id, gatewayID string) (out *Revision, err error) {
	if !validID.MatchString(gatewayID) {
		return nil, ErrInvalidRequest
	}
	err = s.transactScoped(ctx, a, false, func(tx storage.IdentityTx, p *Principal) error {
		r, e := readRevision(ctx, tx, id)
		if e != nil {
			return e
		}
		g, e := gatewayFrom(r, gatewayID)
		if e != nil {
			return e
		}
		if e = p.RequireGateway(ctx, tx, "config.read", g); e != nil {
			return concealedGatewayError(e)
		}
		access, e := p.gatewayViewAccess(ctx, tx, g)
		if e != nil {
			return e
		}
		out = gatewayView(r, g, access)
		return nil
	})
	return
}

// ChangeGateway merges only one authorized logical Gateway into the server-owned
// full base. It never returns the neighbors or permits a scoped infrastructure move.
func (s *Service) ChangeGateway(ctx context.Context, a Actor, key string, in CreateRevision) (out *Revision, err error) {
	if in.GatewayChange == nil || in.ResourceChange != nil || in.WafZoneChange != nil || len(in.Content) > 0 || !validID.MatchString(in.BaseRevisionID) {
		return nil, ErrInvalidRequest
	}
	next, e := configmodel.ParseGateway(bytes.NewReader(in.GatewayChange.Content), configmodel.JSON)
	if e != nil {
		return nil, e
	}
	if next.Metadata.ID != in.GatewayChange.GatewayID {
		return nil, ErrInvalidRequest
	}
	raw, e := configmodel.CanonicalJSON(next)
	if e != nil {
		return nil, e
	}
	fp := digest([]string{in.BaseRevisionID, next.Metadata.ID, string(raw)})
	err = s.transactScoped(ctx, a, true, func(tx storage.IdentityTx, p *Principal) error {
		base, e := readRevision(ctx, tx, in.BaseRevisionID)
		if e != nil {
			return e
		}
		old, e := gatewayFrom(base, next.Metadata.ID)
		exists := e == nil
		if e != nil && !(errors.Is(e, storage.ErrNotFound) && p.Require("config.edit", "") == nil) {
			return concealedGatewayError(e)
		}
		gateways := []configmodel.Gateway{*next}
		if exists {
			gateways = append(gateways, old)
		}
		for _, g := range gateways {
			if e = p.RequireGateway(ctx, tx, "config.edit", g); e != nil {
				return concealedGatewayError(e)
			}
		}
		if exists && old.Metadata.SiteID != next.Metadata.SiteID {
			return storage.ErrPermissionDenied
		}
		if p.Require("config.edit", "") != nil {
			before, _ := configmodel.CanonicalJSON(old.Spec.NodeSelector)
			after, _ := configmodel.CanonicalJSON(next.Spec.NodeSelector)
			if !bytes.Equal(before, after) || old.Spec.Ownership != next.Spec.Ownership || old.Spec.ComponentProfileRef != next.Spec.ComponentProfileRef || old.Spec.TLS != next.Spec.TLS {
				return storage.ErrPermissionDenied
			}
		}
		h, e := request(ctx, tx, p.ID, "revision.create", key, fp)
		if e != nil {
			return e
		}
		if h != nil {
			r, e := readRevision(ctx, tx, h.id)
			if e != nil {
				return e
			}
			g, e := gatewayFrom(r, next.Metadata.ID)
			if e != nil {
				return e
			}
			if e = p.RequireGateway(ctx, tx, "config.read", g); e != nil {
				return concealedGatewayError(e)
			}
			access, e := p.gatewayViewAccess(ctx, tx, g)
			if e != nil {
				return e
			}
			out = gatewayView(r, g, access)
			return nil
		}
		doc, e := parseContent(base.Content)
		if e != nil {
			return e
		}
		for i, g := range doc.Configuration.Gateways {
			if g.Metadata.ID == next.Metadata.ID {
				doc.Configuration.Gateways[i] = *next
			}
		}
		if !exists {
			doc.Configuration.Gateways = append(doc.Configuration.Gateways, *next)
		}
		canonical, e := configmodel.Canonicalize(doc.Configuration)
		if e != nil {
			if p.Require("config.edit", "") != nil {
				return storage.ErrConflict
			}
			return e
		}
		r, e := insertRevision(ctx, tx, p.ID, in.BaseRevisionID, canonical)
		if e != nil {
			return e
		}
		if e = remember(ctx, tx, p.ID, "revision.create", key, fp, responseHandle{"revision", r.ID, 0}); e != nil {
			return e
		}
		out = gatewayView(r, *next, GatewayAccess{Read: true, Edit: true})
		return nil
	})
	return
}

// ListGateways filters the captured immutable snapshot before pagination. No
// count, cursor or summary is derived from an object outside current access.
func (s *Service) ListGateways(ctx context.Context, a Actor, revisionID string, limit int, cursor string) (out GatewayPage, err error) {
	if limit < 1 || limit > 200 || revisionID != "" && !validID.MatchString(revisionID) || cursor != "" && (!validID.MatchString(cursor) || revisionID == "") {
		return out, ErrInvalidRequest
	}
	out.Items = []GatewaySummary{}
	err = s.transactScoped(ctx, a, false, func(tx storage.IdentityTx, p *Principal) error {
		if !p.hasGatewayPermission("config.read") {
			return storage.ErrPermissionDenied
		}
		id := revisionID
		if id == "" {
			var e error
			id, _, e = readHead(ctx, tx)
			if e != nil {
				return e
			}
			if id == "" {
				return nil
			}
		}
		r, e := readRevision(ctx, tx, id)
		if e != nil {
			return e
		}
		doc, e := parseContent(r.Content)
		if e != nil {
			return e
		}
		sort.Slice(doc.Configuration.Gateways, func(i, j int) bool {
			return doc.Configuration.Gateways[i].Metadata.ID < doc.Configuration.Gateways[j].Metadata.ID
		})
		cursorFound := cursor == ""
		for _, gateway := range doc.Configuration.Gateways {
			if e := p.RequireGateway(ctx, tx, "config.read", gateway); e != nil {
				if errors.Is(e, storage.ErrPermissionDenied) || errors.Is(e, storage.ErrNotFound) {
					continue
				}
				return e
			}
			if gateway.Metadata.ID == cursor {
				cursorFound = true
			}
			if gateway.Metadata.ID <= cursor {
				continue
			}
			if len(out.Items) == limit {
				out.NextCursor = out.Items[len(out.Items)-1].ID
				break
			}
			access, e := p.gatewayViewAccess(ctx, tx, gateway)
			if e != nil {
				return e
			}
			out.Items = append(out.Items, GatewaySummary{ID: gateway.Metadata.ID, SiteID: gateway.Metadata.SiteID, Name: gateway.Metadata.Name, DeploymentState: "unknown", Access: access})
		}
		if !cursorFound {
			return storage.ErrNotFound
		}
		out.RevisionID = r.ID
		return nil
	})
	if err != nil {
		return GatewayPage{}, err
	}
	return out, nil
}
func verifyOwnership(ctx context.Context, tx storage.IdentityTx, doc *configmodel.Document) error {
	rows, e := tx.Query(ctx, `SELECT gateway_id,site_id FROM config_gateway_ownership`)
	if e != nil {
		return e
	}
	owners := map[string]string{}
	for rows.Next() {
		var id, site string
		if e = rows.Scan(&id, &site); e != nil {
			rows.Close()
			return e
		}
		owners[id] = site
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, g := range doc.Configuration.Gateways {
		if site, ok := owners[g.Metadata.ID]; ok && site != g.Metadata.SiteID {
			return storage.ErrPermissionDenied
		}
	}
	return nil
}
