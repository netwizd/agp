package configuration

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/storage"
)

// The complete immutable JSON and indexed relational projections commit together.
func insertProjections(ctx context.Context, tx storage.IdentityTx, id string, doc *configmodel.Document) error {
	for _, g := range doc.Configuration.Gateways {
		raw, e := json.Marshal(g)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO config_gateways(revision_id,id,site_id,canonical_json) VALUES(?,?,?,?)`, id, g.Metadata.ID, g.Metadata.SiteID, string(raw)); e != nil {
			return e
		}
		for _, n := range g.Spec.NodeSelector.NodeIDs {
			if _, e = tx.Exec(ctx, `INSERT INTO config_gateway_nodes(revision_id,gateway_id,node_id) VALUES(?,?,?)`, id, g.Metadata.ID, n); e != nil {
				return e
			}
		}
		for _, r := range g.Spec.Routes {
			if _, e = tx.Exec(ctx, `INSERT INTO config_routes(revision_id,id,gateway_id,hostname,path_prefix,upstream_url) VALUES(?,?,?,?,?,?)`, id, r.ID, g.Metadata.ID, r.Hostname, r.Path, r.Upstream.URL); e != nil {
				return e
			}
		}
	}
	for _, a := range doc.Configuration.ProfileAssignments {
		raw, e := json.Marshal(a)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO config_profile_assignments(revision_id,id,canonical_json) VALUES(?,?,?)`, id, a.ID, string(raw)); e != nil {
			return e
		}
	}
	// Reconstruct independently from stored projections before publishing the head.
	reconstructed := doc.Configuration
	reconstructed.Gateways = []configmodel.Gateway{}
	reconstructed.ProfileAssignments = []configmodel.ProfileAssignment{}
	rows, e := tx.Query(ctx, `SELECT canonical_json FROM config_gateways WHERE revision_id=? ORDER BY id`, id)
	if e != nil {
		return e
	}
	for rows.Next() {
		var raw string
		var g configmodel.Gateway
		if e = rows.Scan(&raw); e != nil {
			rows.Close()
			return e
		}
		if e = json.Unmarshal([]byte(raw), &g); e != nil {
			rows.Close()
			return e
		}
		reconstructed.Gateways = append(reconstructed.Gateways, g)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	rows, e = tx.Query(ctx, `SELECT canonical_json FROM config_profile_assignments WHERE revision_id=? ORDER BY id`, id)
	if e != nil {
		return e
	}
	for rows.Next() {
		var raw string
		var a configmodel.ProfileAssignment
		if e = rows.Scan(&raw); e != nil {
			rows.Close()
			return e
		}
		if e = json.Unmarshal([]byte(raw), &a); e != nil {
			rows.Close()
			return e
		}
		reconstructed.ProfileAssignments = append(reconstructed.ProfileAssignments, a)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	parity, e := configmodel.Canonicalize(reconstructed)
	if e != nil {
		return e
	}
	if parity.Digest != doc.Digest {
		return fmt.Errorf("configuration projection mismatch")
	}
	expectedRoutes := map[string]configmodel.Route{}
	gatewayForRoute := map[string]string{}
	expectedNodes := map[string]bool{}
	for _, g := range doc.Configuration.Gateways {
		for _, r := range g.Spec.Routes {
			expectedRoutes[r.ID] = r
			gatewayForRoute[r.ID] = g.Metadata.ID
		}
		for _, n := range g.Spec.NodeSelector.NodeIDs {
			expectedNodes[g.Metadata.ID+"/"+n] = true
		}
	}
	rows, e = tx.Query(ctx, `SELECT id,gateway_id,hostname,path_prefix,upstream_url FROM config_routes WHERE revision_id=?`, id)
	if e != nil {
		return e
	}
	for rows.Next() {
		var rid, gid, host, path, upstream string
		if e = rows.Scan(&rid, &gid, &host, &path, &upstream); e != nil {
			rows.Close()
			return e
		}
		r, ok := expectedRoutes[rid]
		if !ok || gatewayForRoute[rid] != gid || r.Hostname != host || r.Path != path || r.Upstream.URL != upstream {
			rows.Close()
			return fmt.Errorf("route projection mismatch")
		}
		delete(expectedRoutes, rid)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if len(expectedRoutes) != 0 {
		return fmt.Errorf("missing route projection")
	}
	rows, e = tx.Query(ctx, `SELECT gateway_id,node_id FROM config_gateway_nodes WHERE revision_id=?`, id)
	if e != nil {
		return e
	}
	for rows.Next() {
		var gid, nid string
		if e = rows.Scan(&gid, &nid); e != nil {
			rows.Close()
			return e
		}
		key := gid + "/" + nid
		if !expectedNodes[key] {
			rows.Close()
			return fmt.Errorf("node projection mismatch")
		}
		delete(expectedNodes, key)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if len(expectedNodes) != 0 {
		return fmt.Errorf("missing node projection")
	}
	return nil
}
