package nodeidentity

import (
	"context"
	"sort"

	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

// DeclaredNodes uses the caller's already fenced CP transaction. It includes
// pending nodes; an issuer's active-certificate list is not a complete Site.
func (c *Client) DeclaredNodes(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, site string) ([]inventory.DeclaredNode, error) {
	return declaredNodes(ctx, tx, h, site)
}
func (c *LocalIssuer) DeclaredNodes(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, site string) ([]inventory.DeclaredNode, error) {
	return declaredNodes(ctx, tx, h, site)
}
func declaredNodes(ctx context.Context, tx storage.IdentityTx, _ securityjournal.Head, site string) ([]inventory.DeclaredNode, error) {
	rows, e := tx.Query(ctx, `SELECT node_json FROM managed_nodes WHERE site_id=? ORDER BY id LIMIT 10001`, site)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []inventory.DeclaredNode{}
	for rows.Next() {
		if len(out) >= 10000 {
			return nil, ErrUnavailable
		}
		var raw string
		var n Node
		if rows.Scan(&raw) != nil || decodeJSON(raw, &n) != nil {
			return nil, ErrUnavailable
		}
		sort.Strings(n.GroupIDs)
		out = append(out, inventory.DeclaredNode{NodeID: n.ID, SiteID: n.SiteID, Name: n.Name, Labels: n.Labels, GroupIDs: n.GroupIDs})
	}
	return out, rows.Err()
}
