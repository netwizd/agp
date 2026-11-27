package rolescope

import (
	"context"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

// ResourceAuthority is an administrative route-ownership projection. Neither
// its placements nor a resource grant authorize a whole Gateway or receiving
// node. An empty placement set is a valid snapshot, not a routable object.
type ResourceAuthority struct {
	ResourceID string          `json:"resourceId"`
	Name       string          `json:"name"`
	Placements []ResourceRoute `json:"placements"`
	Sources    []Source        `json:"sources"`
	Digest     string          `json:"digest"`
}

type resourceAuthorityFact struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Enabled   bool      `json:"enabled"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// ResourceAuthorityResolver retains one transaction-local authority snapshot.
// It is not safe for concurrent use and must not escape its transaction
// callback. Callers must create a new resolver for a final source reread before
// their last independent security Head check; this instance never refreshes.
type ResourceAuthorityResolver struct {
	ctx        context.Context
	tx         storage.IdentityTx
	head       securityjournal.Head
	loaded     bool
	loadErr    error
	graphPin   Source
	ids        []string
	declared   map[string]bool
	placements map[string][]ResourceRoute
	routes     map[string]string
	live       map[string]resourceAuthorityFact
}

func NewResourceAuthorityResolver(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head) (*ResourceAuthorityResolver, error) {
	if ctx == nil || tx == nil || h.Epoch == 0 || h.Epoch > securityjournal.MaxUInt63 || h.RecordedAt.IsZero() {
		return nil, ErrInvalid
	}
	return &ResourceAuthorityResolver{ctx: ctx, tx: tx, head: h}, nil
}

// Resolve uses only the installation-sealed resource identity and exact
// Gateway/route placements plus the live resource metadata. It deliberately
// omits config_head, authoring catalogs, receiving nodes and runtime access.
// Disabled resources remain visible for administrative draft editing.
func (r *ResourceAuthorityResolver) Resolve(resourceID string) (ResourceAuthority, error) {
	if !configmodel.ValidID(resourceID) {
		return ResourceAuthority{}, ErrInvalid
	}
	if err := r.load(); err != nil {
		return ResourceAuthority{}, err
	}
	if !r.declared[resourceID] {
		return ResourceAuthority{}, storage.ErrNotFound
	}
	fact, ok := r.live[resourceID]
	if !ok || !utf8.ValidString(fact.Name) {
		return ResourceAuthority{}, ErrUnavailable
	}
	factDigest, err := configmodel.Digest(fact)
	if err != nil {
		return ResourceAuthority{}, err
	}
	out := ResourceAuthority{
		ResourceID: resourceID, Name: fact.Name,
		Placements: append([]ResourceRoute{}, r.placements[resourceID]...),
		Sources: []Source{
			{Kind: "resource_metadata", ID: resourceID, Revision: 1, Digest: factDigest},
			r.graphPin,
		},
	}
	out.Digest, err = configmodel.Digest(struct {
		Purpose    string          `json:"purpose"`
		ResourceID string          `json:"resourceId"`
		Name       string          `json:"name"`
		Placements []ResourceRoute `json:"placements"`
		Sources    []Source        `json:"sources"`
	}{"resource_authority/v1", out.ResourceID, out.Name, out.Placements, out.Sources})
	if err != nil {
		return ResourceAuthority{}, err
	}
	return out, nil
}

// LookupRoute returns the exact sealed identity or an empty string for an
// unmapped route. It never guesses a resource identity from the route's ID.
// A mapped resource's missing live metadata is detected by Resolve, rather
// than silently turning that mapping into an unowned routing neighbor.
func (r *ResourceAuthorityResolver) LookupRoute(gatewayID, routeID string) (string, error) {
	if !configmodel.ValidID(gatewayID) || !configmodel.ValidID(routeID) {
		return "", ErrInvalid
	}
	if err := r.load(); err != nil {
		return "", err
	}
	return r.routes[gatewayID+"\x00"+routeID], nil
}

// ResourceIDs includes every sealed identity, including identities whose live
// row is currently missing. Callers filter by current permission before
// resolving the resources actually used by their response or mutation.
func (r *ResourceAuthorityResolver) ResourceIDs() ([]string, error) {
	if err := r.load(); err != nil {
		return nil, err
	}
	return append([]string{}, r.ids...), nil
}

func (r *ResourceAuthorityResolver) load() error {
	if r == nil {
		return ErrInvalid
	}
	if err := r.ctx.Err(); err != nil {
		return err
	}
	if r.loaded {
		return r.loadErr
	}
	r.loaded = true
	r.loadErr = r.loadSnapshot()
	return r.loadErr
}

func (r *ResourceAuthorityResolver) loadSnapshot() error {
	manifest, digest, err := readGraph(r.ctx, r.tx, r.head)
	if err != nil {
		return err
	}
	r.graphPin = Source{Kind: "scope_graph", ID: manifest.ID, Revision: 1, Digest: digest}
	r.ids = make([]string, 0, len(manifest.Resources))
	r.declared = make(map[string]bool, len(manifest.Resources))
	r.placements = map[string][]ResourceRoute{}
	r.routes = make(map[string]string, len(manifest.ResourceRoutes))
	for _, resource := range manifest.Resources {
		r.ids = append(r.ids, resource.ID)
		r.declared[resource.ID] = true
	}
	sort.Strings(r.ids)
	// readGraph verifies the canonical order by resource, Gateway and route.
	for _, placement := range manifest.ResourceRoutes {
		r.placements[placement.ResourceID] = append(r.placements[placement.ResourceID], placement)
		r.routes[placement.GatewayID+"\x00"+placement.RouteID] = placement.ResourceID
	}
	r.live = map[string]resourceAuthorityFact{}
	rows, err := r.tx.Query(r.ctx, `SELECT id,name,enabled,updated_at FROM resources ORDER BY id LIMIT 100001`)
	if err != nil {
		return err
	}
	count := 0
	for rows.Next() {
		var fact resourceAuthorityFact
		if err = rows.Scan(&fact.ID, &fact.Name, &fact.Enabled, &fact.UpdatedAt); err != nil {
			break
		}
		count++
		if count > 100000 {
			err = ErrUnavailable
			break
		}
		fact.UpdatedAt = fact.UpdatedAt.UTC()
		r.live[fact.ID] = fact
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	return err
}
