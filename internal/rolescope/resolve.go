package rolescope

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type nodeFact struct {
	ID        string            `json:"id"`
	SiteID    string            `json:"siteId"`
	Name      string            `json:"name"`
	Labels    map[string]string `json:"labels"`
	GroupIDs  []string          `json:"groupIds"`
	CreatedAt time.Time         `json:"createdAt"`
}
type resourceFact struct {
	ID        string
	Enabled   bool
	UpdatedAt time.Time
}
type resolver struct {
	ctx               context.Context
	tx                storage.IdentityTx
	head              securityjournal.Head
	graph             Manifest
	nodes             map[string]Node
	live              map[string]nodeFact
	revoked           map[string]bool
	owners            map[string]string
	resources         map[string]resourceFact
	sources           map[string]Source
	configuration     *configmodel.Document
	configurationRead bool
	placements        map[string][]ResourceRoute
	gateways          map[string]*configmodel.Gateway
	routes            map[string]map[string]bool
	gatewayNodes      map[string]map[string]bool
	nodeManagement    bool
}

func validScope(kind, id string) bool {
	if kind == "global" {
		return id == ""
	}
	switch kind {
	case "site", "node_group", "node", "resource":
		return configmodel.ValidID(id)
	}
	return false
}

// Resolve includes pending managed nodes. Neither a certificate-only registry
// nor an authoring catalog is a complete authority for ownership or membership.
func Resolve(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, kind, id string) (Snapshot, error) {
	return resolve(ctx, tx, h, kind, id, false)
}

// ResolveNodeManagement proves ownership for node metadata reads and restrictive
// revocation only. Revoked nodes retain their ownership; this projection omits
// resources and cannot authorize enrollment, apply or positive role delegation.
func ResolveNodeManagement(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, kind, id string) (Snapshot, error) {
	if kind == "resource" {
		return Snapshot{}, ErrInvalid
	}
	return resolve(ctx, tx, h, kind, id, true)
}

func resolve(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, kind, id string, nodeManagement bool) (Snapshot, error) {
	out := Snapshot{ScopeType: kind, ScopeID: id, Closure: []Ref{}, Sources: []Source{}}
	if !validScope(kind, id) || h.Epoch == 0 || h.RecordedAt.IsZero() {
		return out, ErrInvalid
	}
	if kind == "global" {
		out.Closure = append(out.Closure, Ref{ScopeType: kind})
		return finish(out)
	}
	m, digest, e := readGraph(ctx, tx, h)
	if e != nil {
		return out, e
	}
	r := &resolver{ctx: ctx, tx: tx, head: h, graph: m, nodes: map[string]Node{}, live: map[string]nodeFact{}, revoked: map[string]bool{}, owners: map[string]string{}, resources: map[string]resourceFact{}, sources: map[string]Source{}, placements: map[string][]ResourceRoute{}, gateways: map[string]*configmodel.Gateway{}, routes: map[string]map[string]bool{}, gatewayNodes: map[string]map[string]bool{}}
	r.nodeManagement = nodeManagement
	r.sources["scope_graph\x00"+m.ID] = Source{Kind: "scope_graph", ID: m.ID, Revision: 1, Digest: digest}
	if nodeManagement {
		r.sources["node_management_ownership\x00"+m.ID] = Source{Kind: "node_management_ownership", ID: m.ID, Revision: 1, Digest: digest}
	}
	for _, n := range m.Nodes {
		r.nodes[n.ID] = n
	}
	for _, placement := range m.ResourceRoutes {
		r.placements[placement.ResourceID] = append(r.placements[placement.ResourceID], placement)
	}
	if e = r.loadFacts(); e != nil {
		return out, e
	}
	selected := map[string]bool{}
	known := false
	switch kind {
	case "site":
		for _, s := range m.Sites {
			if s.ID == id {
				known = true
			}
		}
		for _, n := range m.Nodes {
			if n.SiteID == id {
				selected[n.ID] = true
			}
		}
	case "node_group":
		for _, g := range m.NodeGroups {
			if g.ID == id {
				known = true
			}
		}
		for _, n := range m.Nodes {
			for _, group := range n.GroupIDs {
				if group == id {
					selected[n.ID] = true
				}
			}
		}
	case "node":
		_, known = r.nodes[id]
		selected[id] = true
	case "resource":
		for _, resource := range m.Resources {
			if resource.ID == id {
				known = true
			}
		}
	}
	if !known {
		return out, storage.ErrNotFound
	}
	out.Closure = append(out.Closure, Ref{kind, id})
	selectedSites := map[string]bool{}
	for node := range selected {
		if e = r.checkNode(node); e != nil {
			return out, e
		}
		if kind != "node" {
			out.Closure = append(out.Closure, Ref{"node", node})
		}
		selectedSites[r.nodes[node].SiteID] = true
	}
	if kind == "site" {
		for _, g := range m.NodeGroups {
			if g.SiteID == id {
				out.Closure = append(out.Closure, Ref{"node_group", g.ID})
			}
		}
	}
	if nodeManagement {
		for _, source := range r.sources {
			out.Sources = append(out.Sources, source)
		}
		return finish(out)
	}
	if kind == "resource" {
		placements, e := r.resourceNodes(id)
		if e != nil {
			return out, e
		}
		for node := range placements {
			out.Closure = append(out.Closure, Ref{"node", node})
		}
	} else {
		for _, resource := range m.Resources {
			candidate := false
			allSites := true
			for _, p := range r.placements[resource.ID] {
				site, ok := r.owners[p.GatewayID]
				if !ok {
					return out, ErrUnavailable
				}
				if kind == "site" {
					candidate = true
					if site != id {
						allSites = false
					}
				} else {
					candidate = candidate || selectedSites[site]
				}
			}
			if !candidate || !allSites {
				continue
			}
			placements, e := r.resourceNodes(resource.ID)
			if e != nil {
				return out, e
			}
			covered := len(placements) > 0
			if kind != "site" {
				for node := range placements {
					if !selected[node] {
						covered = false
					}
				}
			}
			if covered {
				out.Closure = append(out.Closure, Ref{"resource", resource.ID})
			}
		}
	}
	for _, source := range r.sources {
		out.Sources = append(out.Sources, source)
	}
	return finish(out)
}

func finish(out Snapshot) (Snapshot, error) {
	sort.Slice(out.Closure, func(i, j int) bool {
		a, b := out.Closure[i], out.Closure[j]
		return a.ScopeType+"\x00"+a.ScopeID < b.ScopeType+"\x00"+b.ScopeID
	})
	sort.Slice(out.Sources, func(i, j int) bool {
		a, b := out.Sources[i], out.Sources[j]
		return a.Kind+"\x00"+a.ID < b.Kind+"\x00"+b.ID
	})
	if len(out.Closure) > 131072 || len(out.Sources) > 131072 {
		return out, ErrUnavailable
	}
	digest, e := configmodel.Digest(struct {
		ScopeType string   `json:"scopeType"`
		ScopeID   string   `json:"scopeId,omitempty"`
		Closure   []Ref    `json:"closure"`
		Sources   []Source `json:"sources"`
	}{out.ScopeType, out.ScopeID, out.Closure, out.Sources})
	out.Digest = digest
	return out, e
}

func (r *resolver) loadFacts() error {
	// Selection needs every declared node, including revoked identities. Filtering
	// them here would silently shrink a label selector before checking its scope.
	rows, e := r.tx.Query(r.ctx, `SELECT n.id,n.site_id,n.node_json,EXISTS(SELECT 1 FROM security_node_revocations d WHERE d.node_id=n.id) FROM managed_nodes n WHERE n.authority_epoch=? ORDER BY n.id LIMIT 10001`, int64(r.head.Epoch))
	if e != nil {
		return e
	}
	for rows.Next() {
		var id, site, raw string
		var n nodeFact
		var revoked bool
		if e = rows.Scan(&id, &site, &raw, &revoked); e != nil {
			break
		}
		if len(r.live) >= 10000 || configmodel.StrictJSON(strings.NewReader(raw), &n, 65536) != nil || id != n.ID || site != n.SiteID || n.GroupIDs == nil || len(n.GroupIDs) > 100 || n.Labels == nil {
			e = ErrUnavailable
			break
		}
		sort.Strings(n.GroupIDs)
		r.live[id] = n
		r.revoked[id] = revoked
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return e
	}
	if r.nodeManagement {
		return nil
	}
	rows, e = r.tx.Query(r.ctx, `SELECT gateway_id,site_id FROM config_gateway_ownership ORDER BY gateway_id LIMIT 10001`)
	if e != nil {
		return e
	}
	for rows.Next() {
		var id, site string
		if e = rows.Scan(&id, &site); e != nil {
			break
		}
		if len(r.owners) >= 10000 {
			e = ErrUnavailable
			break
		}
		r.owners[id] = site
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return e
	}
	rows, e = r.tx.Query(r.ctx, `SELECT id,enabled,updated_at FROM resources ORDER BY id LIMIT 100001`)
	if e != nil {
		return e
	}
	for rows.Next() {
		var f resourceFact
		if e = rows.Scan(&f.ID, &f.Enabled, &f.UpdatedAt); e != nil {
			break
		}
		if len(r.resources) >= 100000 {
			e = ErrUnavailable
			break
		}
		r.resources[f.ID] = f
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	return e
}

func (r *resolver) checkNode(id string) error {
	if r.revoked[id] && !r.nodeManagement {
		return ErrUnavailable
	}
	if _, ok := r.sources["managed_node\x00"+id]; ok {
		return nil
	}
	n, ok := r.nodes[id]
	if !ok {
		return ErrUnavailable
	}
	f, ok := r.live[id]
	if !ok || f.SiteID != n.SiteID || len(f.GroupIDs) != len(n.GroupIDs) {
		return ErrUnavailable
	}
	for i, group := range n.GroupIDs {
		if f.GroupIDs[i] != group {
			return ErrUnavailable
		}
	}
	digest, e := configmodel.Digest(f)
	if e != nil {
		return e
	}
	r.sources["managed_node\x00"+id] = Source{Kind: "managed_node", ID: id, Revision: 1, Digest: digest}
	return nil
}

func (r *resolver) readConfiguration() error {
	if r.configurationRead {
		if r.configuration == nil {
			return ErrUnavailable
		}
		return nil
	}
	r.configurationRead = true
	var id sql.NullString
	var version uint64
	e := securitystate.One(r.ctx, r.tx, `SELECT revision_id,row_version FROM config_head WHERE id=1`, nil, func(rows storage.IdentityRows) error { return rows.Scan(&id, &version) })
	if errors.Is(e, storage.ErrNotFound) || (e == nil && !id.Valid) {
		return ErrUnavailable
	}
	if e != nil {
		return e
	}
	var raw, digest, profile string
	e = securitystate.One(r.ctx, r.tx, `SELECT canonical_json,content_digest,capacity_profile FROM config_revisions WHERE id=?`, []any{id.String}, func(rows storage.IdentityRows) error { return rows.Scan(&raw, &digest, &profile) })
	if e != nil {
		return e
	}
	doc, e := configmodel.ParseConfigurationForProfile(strings.NewReader(raw), configmodel.JSON, profile)
	if e != nil || doc.Digest != digest || string(doc.Canonical) != raw {
		return ErrUnavailable
	}
	r.configuration = doc
	for i := range doc.Configuration.Gateways {
		g := &doc.Configuration.Gateways[i]
		r.gateways[g.Metadata.ID] = g
		r.routes[g.Metadata.ID] = map[string]bool{}
		for _, route := range g.Spec.Routes {
			r.routes[g.Metadata.ID][route.ID] = true
		}
	}
	r.sources["configuration\x00"+id.String] = Source{Kind: "configuration", ID: id.String, Revision: securityjournal.UInt63(version), Digest: digest}
	return nil
}

func (r *resolver) resourceNodes(id string) (map[string]bool, error) {
	f, ok := r.resources[id]
	if !ok {
		return nil, ErrUnavailable
	}
	digest, e := configmodel.Digest(f)
	if e != nil {
		return nil, e
	}
	r.sources["resource\x00"+id] = Source{Kind: "resource", ID: id, Revision: 1, Digest: digest}
	out := map[string]bool{}
	for _, placement := range r.placements[id] {
		if e = r.readConfiguration(); e != nil {
			return nil, e
		}
		gateway := r.gateways[placement.GatewayID]
		if gateway == nil || r.owners[placement.GatewayID] != gateway.Metadata.SiteID {
			return nil, ErrUnavailable
		}
		if !r.routes[placement.GatewayID][placement.RouteID] {
			return nil, ErrUnavailable
		}
		owner := struct{ GatewayID, SiteID string }{gateway.Metadata.ID, gateway.Metadata.SiteID}
		digest, e = configmodel.Digest(owner)
		if e != nil {
			return nil, e
		}
		r.sources["gateway_ownership\x00"+placement.GatewayID] = Source{Kind: "gateway_ownership", ID: placement.GatewayID, Revision: 1, Digest: digest}
		selected, ready := r.gatewayNodes[placement.GatewayID]
		if !ready {
			selected = map[string]bool{}
			if len(gateway.Spec.NodeSelector.NodeIDs) > 0 {
				for _, node := range gateway.Spec.NodeSelector.NodeIDs {
					selected[node] = true
				}
			} else if labels := gateway.Spec.NodeSelector.MatchLabels; labels != nil {
				for node, fact := range r.live {
					if fact.SiteID != gateway.Metadata.SiteID {
						continue
					}
					matches := true
					for key, value := range *labels {
						actual, exists := fact.Labels[key]
						if !exists || actual != value {
							matches = false
							break
						}
					}
					if matches {
						selected[node] = true
					}
				}
			}
			if len(selected) == 0 {
				return nil, ErrUnavailable
			}
			for node := range selected {
				if e = r.checkNode(node); e != nil {
					return nil, e
				}
				if r.nodes[node].SiteID != gateway.Metadata.SiteID {
					return nil, ErrUnavailable
				}
			}
			r.gatewayNodes[placement.GatewayID] = selected
		}
		for node := range selected {
			out[node] = true
		}
	}
	return out, nil
}

// CanContain checks the typed hierarchy before examining impact closure. A
// resource's placement on a node never grants authority over the whole node.
func CanContain(parent, child string) bool {
	if parent == "global" || parent == child {
		return true
	}
	switch parent {
	case "site":
		return child == "node_group" || child == "node" || child == "resource"
	case "node_group":
		return child == "node" || child == "resource"
	case "node":
		return child == "resource"
	}
	return false
}
