package configuration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/storage"
)

type resourceListKey [3]string

func (key resourceListKey) ordered() string { return strings.Join(key[:], "\x00") }
func (key resourceListKey) cursor() string {
	raw, _ := json.Marshal(key)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func parseResourceCursor(cursor string) (resourceListKey, error) {
	var key resourceListKey
	if len(cursor) > 1024 {
		return key, ErrInvalidRequest
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(cursor)
	if err != nil || json.Unmarshal(raw, &key) != nil || key.cursor() != cursor {
		return key, ErrInvalidRequest
	}
	for _, id := range key {
		if !validID.MatchString(id) {
			return resourceListKey{}, ErrInvalidRequest
		}
	}
	return key, nil
}

func (s *Service) ListResources(ctx context.Context, actor Actor, revisionID string, limit int, cursor string) (out ResourceRoutePage, err error) {
	if limit < 1 || limit > 200 || revisionID != "" && !validID.MatchString(revisionID) || cursor != "" && revisionID == "" {
		return out, ErrInvalidRequest
	}
	var after resourceListKey
	if cursor != "" {
		after, err = parseResourceCursor(cursor)
		if err != nil {
			return out, err
		}
	}
	out.Items = []ResourceRouteSummary{}
	err = s.transactScoped(ctx, actor, false, func(tx storage.IdentityTx, p *Principal) error {
		if !p.hasResourcePermission("config.read") {
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
		revision, e := readRevision(ctx, tx, id)
		if e != nil {
			return e
		}
		doc, e := parseContent(revision.Content)
		if e != nil {
			return e
		}
		resolver, e := p.resources(ctx, tx)
		if e != nil {
			return e
		}
		type selectedRoute struct {
			key     resourceListKey
			gateway *configmodel.Gateway
			route   *configmodel.Route
		}
		selected := []selectedRoute{}
		for gi := range doc.Configuration.Gateways {
			gateway := &doc.Configuration.Gateways[gi]
			for ri := range gateway.Spec.Routes {
				route := &gateway.Spec.Routes[ri]
				resourceID, e := resolver.LookupRoute(gateway.Metadata.ID, route.ID)
				if e != nil {
					return subjectFailure(tx, e)
				}
				if resourceID != "" {
					selected = append(selected, selectedRoute{resourceListKey{resourceID, gateway.Metadata.ID, route.ID}, gateway, route})
				}
			}
		}
		sort.Slice(selected, func(i, j int) bool { return selected[i].key.ordered() < selected[j].key.ordered() })
		cursorFound := cursor == ""
		for _, item := range selected {
			if item.key.ordered() < after.ordered() {
				continue
			}
			authority, e := p.requireResourceRoute(ctx, tx, "config.read", item.key[0], *item.gateway, item.route.ID)
			if e != nil {
				if errors.Is(e, storage.ErrPermissionDenied) || errors.Is(e, storage.ErrNotFound) {
					continue
				}
				return e
			}
			if item.key == after && cursor != "" {
				cursorFound = true
				continue
			}
			if len(out.Items) == limit {
				last := out.Items[len(out.Items)-1]
				out.NextCursor = (resourceListKey{last.ResourceID, last.GatewayID, last.RouteID}).cursor()
				break
			}
			access, e := p.resourceViewAccess(ctx, tx, item.key[0], *item.gateway, item.route.ID)
			if e != nil {
				return e
			}
			out.Items = append(out.Items, ResourceRouteSummary{ResourceID: authority.ResourceID, ResourceName: authority.Name, GatewayID: item.gateway.Metadata.ID, RouteID: item.route.ID, RouteName: item.route.Name, Hostname: item.route.Hostname, Path: item.route.Path, Access: access})
		}
		if !cursorFound {
			return storage.ErrNotFound
		}
		out.RevisionID = revision.ID
		return nil
	})
	if err != nil {
		out = ResourceRoutePage{}
	}
	return
}
