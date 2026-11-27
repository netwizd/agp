package rolescope

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

// GatewayRecipient is an installation-owned recipient, not a grant. In
// particular, resource placement never authorizes management of its gateway.
type GatewayRecipient struct {
	NodeID   string   `json:"nodeId"`
	SiteID   string   `json:"siteId"`
	GroupIDs []string `json:"groupIds"`
}

type GatewayRecipients struct {
	GatewayID string             `json:"gatewayId"`
	SiteID    string             `json:"siteId"`
	Nodes     []GatewayRecipient `json:"nodes"`
	Sources   []Source           `json:"sources"`
	Digest    string             `json:"digest"`
}

type gatewayNodeEvidence struct {
	Node    nodeFact               `json:"node"`
	Epoch   securityjournal.UInt63 `json:"epoch"`
	Revoked bool                   `json:"revoked"`
}

// GatewayRecipientResolver holds one transaction's lazily read, immutable
// authority snapshot. It is not safe for concurrent use and must not escape the
// transaction callback. A final authorization check must construct a new
// resolver to reread external facts before the final independent security head.
// Snapshot failures remain failures for every later call on this resolver.
type GatewayRecipientResolver struct {
	ctx        context.Context
	tx         storage.IdentityTx
	head       securityjournal.Head
	loaded     bool
	loadErr    error
	graphPin   Source
	nodes      map[string]Node
	declared   map[string][]string
	live       map[string]gatewayNodeEvidence
	nodePins   map[string]Source
	owners     map[string]string
	siteNodes  map[string][]string
	labelNodes map[string]map[string][]string
	universe   Source
	checked    map[string]error
}

func NewGatewayRecipientResolver(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head) (*GatewayRecipientResolver, error) {
	if ctx == nil || tx == nil || h.Epoch == 0 || h.Epoch > securityjournal.MaxUInt63 || h.RecordedAt.IsZero() {
		return nil, ErrInvalid
	}
	return &GatewayRecipientResolver{ctx: ctx, tx: tx, head: h}, nil
}

func ResolveGatewayRecipients(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, gateway configmodel.Gateway) (GatewayRecipients, error) {
	r, err := NewGatewayRecipientResolver(ctx, tx, h)
	if err != nil {
		return GatewayRecipients{}, err
	}
	return r.Resolve(gateway)
}

// Resolve accepts an old or candidate gateway as an input value. It never reads
// config_head, operator catalogs, resource placements or a metadata-management
// projection. A configuration CAS consequently cannot invalidate these source
// pins merely by publishing its own successor.
func (r *GatewayRecipientResolver) Resolve(gateway configmodel.Gateway) (GatewayRecipients, error) {
	if r == nil {
		return GatewayRecipients{}, ErrInvalid
	}
	if err := r.ctx.Err(); err != nil {
		return GatewayRecipients{}, err
	}
	// The parser both validates the closed gateway contract and detaches every
	// caller-owned slice/map before normalization and evidence hashing.
	raw, err := json.Marshal(gateway)
	if err != nil {
		return GatewayRecipients{}, ErrInvalid
	}
	g, err := configmodel.ParseGatewayForProfile(bytes.NewReader(raw), configmodel.JSON, configmodel.Fleet.Profile)
	if err != nil {
		return GatewayRecipients{}, ErrInvalid
	}
	if err = r.load(); err != nil {
		return GatewayRecipients{}, err
	}
	if r.owners[g.Metadata.ID] != g.Metadata.SiteID {
		return GatewayRecipients{}, ErrUnavailable
	}
	ownerDigest, err := configmodel.Digest(struct {
		GatewayID string `json:"gatewayId"`
		SiteID    string `json:"siteId"`
	}{g.Metadata.ID, g.Metadata.SiteID})
	if err != nil {
		return GatewayRecipients{}, err
	}
	out := GatewayRecipients{
		GatewayID: g.Metadata.ID, SiteID: g.Metadata.SiteID,
		Nodes:   []GatewayRecipient{},
		Sources: []Source{r.graphPin, {Kind: "gateway_ownership", ID: g.Metadata.ID, Revision: 1, Digest: ownerDigest}},
	}
	selected := g.Spec.NodeSelector.NodeIDs
	if selected == nil {
		if err = r.checkDeclaredUniverse(g.Metadata.SiteID); err != nil {
			return GatewayRecipients{}, err
		}
		out.Sources = append(out.Sources, r.universe)
		selected = r.matchingNodes(g.Metadata.SiteID, *g.Spec.NodeSelector.MatchLabels)
	}
	for _, id := range selected {
		n, err := r.recipient(id)
		if err != nil || n.SiteID != g.Metadata.SiteID {
			return GatewayRecipients{}, ErrUnavailable
		}
		out.Nodes = append(out.Nodes, n)
		out.Sources = append(out.Sources, r.nodePins[id])
	}
	sort.Slice(out.Nodes, func(i, j int) bool { return out.Nodes[i].NodeID < out.Nodes[j].NodeID })
	sort.Slice(out.Sources, func(i, j int) bool {
		a, b := out.Sources[i], out.Sources[j]
		return a.Kind+"\x00"+a.ID < b.Kind+"\x00"+b.ID
	})
	out.Digest, err = configmodel.Digest(struct {
		Purpose      string                   `json:"purpose"`
		GatewayID    string                   `json:"gatewayId"`
		SiteID       string                   `json:"siteId"`
		NodeSelector configmodel.NodeSelector `json:"nodeSelector"`
		Nodes        []GatewayRecipient       `json:"nodes"`
		Sources      []Source                 `json:"sources"`
	}{"gateway_recipients/v1", g.Metadata.ID, g.Metadata.SiteID, g.Spec.NodeSelector, out.Nodes, out.Sources})
	if err != nil {
		return GatewayRecipients{}, err
	}
	return out, nil
}

func (r *GatewayRecipientResolver) load() error {
	if r.loaded {
		return r.loadErr
	}
	r.loaded = true
	r.loadErr = r.loadSnapshot()
	return r.loadErr
}

func (r *GatewayRecipientResolver) loadSnapshot() error {
	m, digest, err := readGraph(r.ctx, r.tx, r.head)
	if err != nil {
		return err
	}
	r.graphPin = Source{Kind: "scope_graph", ID: m.ID, Revision: 1, Digest: digest}
	r.nodes = make(map[string]Node, len(m.Nodes))
	r.declared = map[string][]string{}
	r.checked = map[string]error{}
	for _, n := range m.Nodes {
		r.nodes[n.ID] = n
		r.declared[n.SiteID] = append(r.declared[n.SiteID], n.ID)
	}
	r.live = map[string]gatewayNodeEvidence{}
	r.nodePins = map[string]Source{}
	r.siteNodes = map[string][]string{}
	r.labelNodes = map[string]map[string][]string{}
	rows, err := r.tx.Query(r.ctx, `SELECT n.id,n.site_id,n.node_json,EXISTS(SELECT 1 FROM security_node_revocations d WHERE d.node_id=n.id) FROM managed_nodes n WHERE n.authority_epoch=? ORDER BY n.id LIMIT 10001`, int64(r.head.Epoch))
	if err != nil {
		return err
	}
	evidence := []gatewayNodeEvidence{}
	for rows.Next() {
		var id, site, raw string
		fact := gatewayNodeEvidence{Epoch: r.head.Epoch}
		if err = rows.Scan(&id, &site, &raw, &fact.Revoked); err != nil {
			break
		}
		n := &fact.Node
		if len(r.live) >= 10000 || configmodel.StrictJSON(strings.NewReader(raw), n, 65536) != nil || id != n.ID || site != n.SiteID || !configmodel.ValidID(id) || !configmodel.ValidID(site) || n.GroupIDs == nil || len(n.GroupIDs) > 100 || n.Labels == nil {
			err = ErrUnavailable
			break
		}
		sort.Strings(n.GroupIDs)
		for i, group := range n.GroupIDs {
			if !configmodel.ValidID(group) || (i > 0 && group == n.GroupIDs[i-1]) {
				err = ErrUnavailable
				break
			}
		}
		if err != nil {
			break
		}
		nodeDigest, e := configmodel.Digest(fact)
		if e != nil {
			err = e
			break
		}
		r.live[id] = fact
		r.nodePins[id] = Source{Kind: "managed_node", ID: id, Revision: 1, Digest: nodeDigest}
		evidence = append(evidence, fact)
		r.siteNodes[site] = append(r.siteNodes[site], id)
		if r.labelNodes[site] == nil {
			r.labelNodes[site] = map[string][]string{}
		}
		for k, v := range n.Labels {
			key := k + "\x00" + v
			r.labelNodes[site][key] = append(r.labelNodes[site][key], id)
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	// PostgreSQL collation and SQLite's byte ordering need not agree. The
	// aggregate pin has one ordering regardless of the storage backend.
	sort.Slice(evidence, func(i, j int) bool { return evidence[i].Node.ID < evidence[j].Node.ID })
	digest, err = configmodel.Digest(evidence)
	if err != nil {
		return err
	}
	r.universe = Source{Kind: "managed_node_universe", ID: m.ID, Revision: 1, Digest: digest}
	r.owners = map[string]string{}
	rows, err = r.tx.Query(r.ctx, `SELECT gateway_id,site_id FROM config_gateway_ownership ORDER BY gateway_id LIMIT 10001`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id, site string
		if err = rows.Scan(&id, &site); err != nil {
			break
		}
		if len(r.owners) >= 10000 || !configmodel.ValidID(id) || !configmodel.ValidID(site) {
			err = ErrUnavailable
			break
		}
		r.owners[id] = site
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	return err
}

func (r *GatewayRecipientResolver) ownedNode(id string) (Node, error) {
	n, ok := r.nodes[id]
	if !ok {
		return Node{}, ErrUnavailable
	}
	f, ok := r.live[id]
	if !ok || f.Node.SiteID != n.SiteID || len(f.Node.GroupIDs) != len(n.GroupIDs) {
		return Node{}, ErrUnavailable
	}
	for i, group := range n.GroupIDs {
		if f.Node.GroupIDs[i] != group {
			return Node{}, ErrUnavailable
		}
	}
	return n, nil
}

func (r *GatewayRecipientResolver) recipient(id string) (GatewayRecipient, error) {
	n, err := r.ownedNode(id)
	if err != nil || r.live[id].Revoked {
		return GatewayRecipient{}, ErrUnavailable
	}
	groups := append([]string{}, n.GroupIDs...)
	return GatewayRecipient{NodeID: id, SiteID: n.SiteID, GroupIDs: groups}, nil
}

func (r *GatewayRecipientResolver) checkDeclaredUniverse(site string) error {
	if err, checked := r.checked[site]; checked {
		return err
	}
	var checkErr error
	for _, id := range r.declared[site] {
		if _, err := r.ownedNode(id); err != nil {
			checkErr = err
			break
		}
	}
	r.checked[site] = checkErr
	return checkErr
}

func (r *GatewayRecipientResolver) matchingNodes(site string, labels configmodel.Labels) []string {
	candidates := r.siteNodes[site]
	for k, v := range labels {
		matches := r.labelNodes[site][k+"\x00"+v]
		if len(matches) < len(candidates) {
			candidates = matches
		}
	}
	out := []string{}
	for _, id := range candidates {
		matched := true
		for k, v := range labels {
			actual, exists := r.live[id].Node.Labels[k]
			if !exists || actual != v {
				matched = false
				break
			}
		}
		if matched {
			out = append(out, id)
		}
	}
	return out
}
