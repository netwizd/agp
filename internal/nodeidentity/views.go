package nodeidentity

import (
	"context"

	"github.com/netwizd/agp/internal/inventory"

	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type NodeView struct {
	ID            string                 `json:"id"`
	SiteID        string                 `json:"siteId"`
	Name          string                 `json:"name"`
	Labels        map[string]string      `json:"labels"`
	Connectivity  string                 `json:"connectivity"`
	Maintenance   bool                   `json:"maintenance"`
	IdentityState string                 `json:"identityState"`
	Revision      securityjournal.UInt63 `json:"revision"`
}

func (s *Service) ListNodeViews(ctx context.Context, a Actor) (out []NodeView, err error) {
	out = []NodeView{}
	err = s.withAccess(ctx, a, "nodes.read", false, func(tx storage.IdentityTx, h securityjournal.Head, access *inventory.NodeAccess) error {
		if e := access.Resolve(ctx, tx); e != nil {
			return e
		}
		registry, e := s.issuer.Registry(ctx, h)
		if e != nil {
			return e
		}
		active := map[string]bool{}
		revoked := map[string]bool{}
		for _, r := range registry.Nodes {
			if r.Revoked {
				revoked[r.NodeID] = true
			}
			if r.AcceptUntil == nil && !r.Revoked && r.IssuanceEpoch == h.Epoch {
				certs, e := parseCertificates([]byte(r.CertificatePEM))
				if e != nil {
					return ErrUnavailable
				}
				if !h.RecordedAt.Before(certs[0].NotBefore) && h.RecordedAt.Before(certs[0].NotAfter) {
					active[r.NodeID] = true
				}
			}
		}
		rows, e := tx.Query(ctx, `SELECT node_json FROM managed_nodes ORDER BY id LIMIT 10001`)
		if e != nil {
			return e
		}
		var nodes []Node
		for rows.Next() {
			var raw string
			var n Node
			if rows.Scan(&raw) != nil || decodeJSON(raw, &n) != nil {
				rows.Close()
				return ErrUnavailable
			}
			nodes = append(nodes, n)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		if len(nodes) > 10000 {
			return ErrUnavailable
		}
		for _, n := range nodes {
			allowed, e := access.AllowsNode(ctx, tx, n.ID)
			if e != nil {
				return e
			}
			if !allowed {
				continue
			}
			v := NodeView{ID: n.ID, SiteID: n.SiteID, Name: n.Name, Labels: n.Labels, Connectivity: "unknown", IdentityState: "pending", Revision: 1}
			if e = notRevoked(ctx, tx, n.ID); e == ErrDenied || revoked[n.ID] {
				v.IdentityState = "revoked"
			} else if e != nil {
				return e
			} else if active[n.ID] {
				v.IdentityState = "active"
			} else {
				var count int
				e = securitystate.One(ctx, tx, `SELECT COUNT(*) FROM node_enrollments WHERE node_id=? AND state='issued_certificate'`, []any{n.ID}, func(r storage.IdentityRows) error { return r.Scan(&count) })
				if e != nil {
					return e
				}
				if count > 0 {
					v.IdentityState = "expired"
				}
			}
			out = append(out, v)
		}
		return nil
	})
	if err != nil {
		out = nil
	}
	return
}
func (s *Service) GetNodeView(ctx context.Context, a Actor, id string) (NodeView, error) {
	all, e := s.ListNodeViews(ctx, a)
	if e != nil {
		return NodeView{}, e
	}
	for _, v := range all {
		if v.ID == id {
			return v, nil
		}
	}
	return NodeView{}, storage.ErrNotFound
}
