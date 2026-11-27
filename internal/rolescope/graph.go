// Package rolescope resolves administrative scopes from installation-owned
// facts. Authoring catalogs and observed labels never supply ownership.
package rolescope

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

const MaxGraphBytes = 16 << 20

var ErrInvalid = errors.New("invalid_role_scope_graph")
var ErrUnavailable = errors.New("role_scope_authority_unavailable")

type Site struct {
	ID string `json:"id"`
}
type NodeGroup struct {
	ID     string `json:"id"`
	SiteID string `json:"siteId,omitempty"`
}
type Node struct {
	ID       string   `json:"id"`
	SiteID   string   `json:"siteId"`
	GroupIDs []string `json:"groupIds"`
}
type Resource struct {
	ID string `json:"id"`
}
type ResourceRoute struct {
	ResourceID string `json:"resourceId"`
	GatewayID  string `json:"gatewayId"`
	RouteID    string `json:"routeId"`
}
type Manifest struct {
	APIVersion     string          `json:"apiVersion"`
	ID             string          `json:"id"`
	Sites          []Site          `json:"sites"`
	NodeGroups     []NodeGroup     `json:"nodeGroups"`
	Nodes          []Node          `json:"nodes"`
	Resources      []Resource      `json:"resources"`
	ResourceRoutes []ResourceRoute `json:"resourceRoutes"`
}
type Ref struct {
	ScopeType string `json:"scopeType"`
	ScopeID   string `json:"scopeId,omitempty"`
}
type Source struct {
	Kind     string                 `json:"kind"`
	ID       string                 `json:"id"`
	Revision securityjournal.UInt63 `json:"revision"`
	Digest   string                 `json:"digest,omitempty"`
}
type Snapshot struct {
	ScopeType string   `json:"scopeType"`
	ScopeID   string   `json:"scopeId,omitempty"`
	Closure   []Ref    `json:"closure"`
	Sources   []Source `json:"sources"`
	Digest    string   `json:"digest"`
}

// CanonicalManifest copies caller-owned arrays before sorting. IDs are typed
// and unambiguous; resource IDs are never inferred from route IDs.
func CanonicalManifest(input Manifest) (Manifest, []byte, error) {
	var m Manifest
	if input.APIVersion != "agp.role-scopes/v1alpha1" || !configmodel.ValidID(input.ID) || len(input.Sites) > 10000 || len(input.NodeGroups) > 10000 || len(input.Nodes) > 10000 || len(input.Resources) > 100000 || len(input.ResourceRoutes) > 100000 || input.Sites == nil || input.NodeGroups == nil || input.Nodes == nil || input.Resources == nil || input.ResourceRoutes == nil {
		return m, nil, ErrInvalid
	}
	raw, e := json.Marshal(input)
	if e != nil || len(raw) > MaxGraphBytes {
		return m, nil, ErrInvalid
	}
	if e = json.Unmarshal(raw, &m); e != nil {
		return m, nil, ErrInvalid
	}
	seen := map[string]bool{}
	sites := map[string]bool{}
	groups := map[string]string{}
	resources := map[string]bool{}
	claim := func(id string) bool {
		if !configmodel.ValidID(id) || seen[id] {
			return false
		}
		seen[id] = true
		return true
	}
	for _, s := range m.Sites {
		if !claim(s.ID) {
			return m, nil, ErrInvalid
		}
		sites[s.ID] = true
	}
	for _, g := range m.NodeGroups {
		if !claim(g.ID) || (g.SiteID != "" && !sites[g.SiteID]) {
			return m, nil, ErrInvalid
		}
		groups[g.ID] = g.SiteID
	}
	for i := range m.Nodes {
		n := &m.Nodes[i]
		if !claim(n.ID) || !sites[n.SiteID] || n.GroupIDs == nil || len(n.GroupIDs) > 100 {
			return m, nil, ErrInvalid
		}
		sort.Strings(n.GroupIDs)
		for j, id := range n.GroupIDs {
			site, ok := groups[id]
			if !ok || (site != "" && site != n.SiteID) || (j > 0 && id == n.GroupIDs[j-1]) {
				return m, nil, ErrInvalid
			}
		}
	}
	for _, r := range m.Resources {
		if !claim(r.ID) {
			return m, nil, ErrInvalid
		}
		resources[r.ID] = true
	}
	placements := map[string]bool{}
	for _, r := range m.ResourceRoutes {
		key := r.GatewayID + "\x00" + r.RouteID
		if !resources[r.ResourceID] || !configmodel.ValidID(r.GatewayID) || !configmodel.ValidID(r.RouteID) || placements[key] {
			return m, nil, ErrInvalid
		}
		placements[key] = true
	}
	sort.Slice(m.Sites, func(i, j int) bool { return m.Sites[i].ID < m.Sites[j].ID })
	sort.Slice(m.NodeGroups, func(i, j int) bool { return m.NodeGroups[i].ID < m.NodeGroups[j].ID })
	sort.Slice(m.Nodes, func(i, j int) bool { return m.Nodes[i].ID < m.Nodes[j].ID })
	sort.Slice(m.Resources, func(i, j int) bool { return m.Resources[i].ID < m.Resources[j].ID })
	sort.Slice(m.ResourceRoutes, func(i, j int) bool {
		a, b := m.ResourceRoutes[i], m.ResourceRoutes[j]
		return a.ResourceID+"\x00"+a.GatewayID+"\x00"+a.RouteID < b.ResourceID+"\x00"+b.GatewayID+"\x00"+b.RouteID
	})
	raw, e = configmodel.CanonicalJSON(m)
	if e != nil || len(raw) > MaxGraphBytes {
		return m, nil, ErrInvalid
	}
	return m, raw, nil
}

// BootstrapTx is called only by the existing offline, leased configuration
// bootstrap transaction. SQL separately forbids insertion after activation.
func BootstrapTx(ctx context.Context, tx storage.IdentityTx, epoch securityjournal.UInt63, m Manifest) error {
	if epoch == 0 || epoch > securityjournal.MaxUInt63 {
		return ErrInvalid
	}
	m, raw, e := CanonicalManifest(m)
	if e != nil {
		return e
	}
	var n int
	if e = securitystate.One(ctx, tx, `SELECT COUNT(*) FROM security_state`, nil, func(r storage.IdentityRows) error { return r.Scan(&n) }); e != nil {
		return e
	}
	if n != 0 {
		return storage.ErrPermissionDenied
	}
	// Gateway ownership is already authoritative in the same bootstrap TX.
	sites := map[string]bool{}
	for _, site := range m.Sites {
		sites[site.ID] = true
	}
	for _, r := range m.ResourceRoutes {
		var site string
		if e = securitystate.One(ctx, tx, `SELECT site_id FROM config_gateway_ownership WHERE gateway_id=?`, []any{r.GatewayID}, func(row storage.IdentityRows) error { return row.Scan(&site) }); e != nil {
			return e
		}
		if !sites[site] {
			return ErrInvalid
		}
	}
	_, e = tx.Exec(ctx, `INSERT INTO role_scope_graph(id,graph_id,revision,authority_epoch,graph_digest,manifest_json,created_at) VALUES(1,?,1,?,?,?,?)`, m.ID, int64(epoch), configmodel.DigestBytes(raw), string(raw), time.Now().UTC())
	return e
}

func readGraph(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head) (Manifest, string, error) {
	var raw, digest, id string
	var epoch, revision uint64
	e := securitystate.One(ctx, tx, `SELECT graph_id,revision,authority_epoch,graph_digest,manifest_json FROM role_scope_graph WHERE id=1`, nil, func(r storage.IdentityRows) error { return r.Scan(&id, &revision, &epoch, &digest, &raw) })
	if errors.Is(e, storage.ErrNotFound) {
		return Manifest{}, "", ErrUnavailable
	}
	if e != nil {
		return Manifest{}, "", e
	}
	if h.Epoch == 0 || h.RecordedAt.IsZero() || epoch != uint64(h.Epoch) || revision != 1 || len(raw) > MaxGraphBytes || configmodel.DigestBytes([]byte(raw)) != digest {
		return Manifest{}, "", ErrUnavailable
	}
	var m Manifest
	if configmodel.DecodeEnvelopeJSONWithArrayLimits([]byte(raw), &m, map[string]int{"/resources": 100000, "/resourceRoutes": 100000}) != nil {
		return m, "", ErrUnavailable
	}
	m, canonical, e := CanonicalManifest(m)
	if e != nil || string(canonical) != raw || m.ID != id {
		return m, "", ErrUnavailable
	}
	return m, digest, nil
}
