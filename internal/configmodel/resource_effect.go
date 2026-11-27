package configmodel

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// RoutingChangeImpacts returns the route IDs whose request ownership changes
// when one existing route is replaced. It follows EdgeAuth's longest segment
// prefix policy: /, an exact path, or a prefix followed by /. Content changes
// within the same winning route do not add other routes to the result.
//
// Both inputs are detached and normalized. Gateway metadata, infrastructure,
// route membership and all other routes must remain unchanged. The caller must
// separately authorize the edited route, the returned routes and the receiving
// nodes; this function makes no authorization or inventory decisions.
func RoutingChangeImpacts(oldGateway, candidateGateway Gateway, editedRouteID string) ([]string, error) {
	old, err := routingGateway(oldGateway)
	if err != nil {
		return nil, err
	}
	candidate, err := routingGateway(candidateGateway)
	if err != nil {
		return nil, err
	}
	oldRoutes, candidateRoutes := old.Spec.Routes, candidate.Spec.Routes
	old.Spec.Routes, candidate.Spec.Routes = nil, nil
	if !reflect.DeepEqual(old, candidate) {
		return nil, problem("", "resource_change_boundary", "only the selected route may change")
	}
	oldByID, candidateByID := routeIDs(oldRoutes), routeIDs(candidateRoutes)
	oldEdited, oldExists := oldByID[editedRouteID]
	newEdited, newExists := candidateByID[editedRouteID]
	if !oldExists || !newExists || len(oldByID) != len(candidateByID) {
		return nil, problem("/spec/routes", "resource_change_boundary", "the same existing route must be replaced")
	}
	for id, previous := range oldByID {
		next, exists := candidateByID[id]
		if !exists || id != editedRouteID && !reflect.DeepEqual(previous, next) {
			return nil, problem("/spec/routes", "resource_change_boundary", "route membership and other routes must remain unchanged")
		}
	}

	hosts := map[string]bool{oldEdited.Hostname: true, newEdited.Hostname: true}
	affected := map[string]bool{}
	for host := range hosts {
		witnesses := map[string]bool{"/": true}
		for _, routes := range [][]Route{oldRoutes, candidateRoutes} {
			for _, route := range routes {
				if route.Hostname == host {
					witnesses[route.Path] = true
				}
			}
		}
		// For any request, its longest matching prefix in the union of both
		// route sets has exactly the same matching prefixes as the request.
		// Therefore these finite witnesses cover every possible winner change.
		for path := range witnesses {
			previous := routingWinner(oldRoutes, host, path)
			next := routingWinner(candidateRoutes, host, path)
			if previous == next {
				continue
			}
			if previous != "" {
				affected[previous] = true
			}
			if next != "" {
				affected[next] = true
			}
		}
	}
	result := make([]string, 0, len(affected))
	for id := range affected {
		result = append(result, id)
	}
	sort.Strings(result)
	return result, nil
}

func routingGateway(g Gateway) (Gateway, error) {
	if len(g.Spec.Routes) < 1 || len(g.Spec.Routes) > 1000 {
		return Gateway{}, problem("/spec/routes", "count_limit", "expected 1..1000 routes")
	}
	if err := validGoUnicode(reflect.ValueOf(g), 0); err != nil {
		return Gateway{}, err
	}
	raw, err := json.Marshal(g)
	if err != nil {
		return Gateway{}, err
	}
	// A gateway in a fleet configuration may exceed the standalone pilot
	// parser's byte budget. Keep the full fleet envelope while enforcing the
	// same closed Gateway schema and the 1000-route per-gateway bound.
	detached, err := ParseGatewayForProfile(bytes.NewReader(raw), JSON, Fleet.Profile)
	if err != nil {
		return Gateway{}, err
	}
	ids, keys := map[string]bool{}, map[string]bool{}
	for i, route := range detached.Spec.Routes {
		path := "/spec/routes/" + strconv.Itoa(i)
		// Historical gateway documents retain their accepted syntax. A narrow
		// resource edit can prove routing ownership only when every route in
		// both snapshots follows the actual EdgeAuth segment-prefix policy.
		if err := validateResourceRoutingPrefix(route.Path, path); err != nil {
			return Gateway{}, err
		}
		if ids[route.ID] || route.ID == detached.Metadata.ID {
			return Gateway{}, problem(path+"/id", "duplicate_id", "route IDs must be unique")
		}
		ids[route.ID] = true
		key := route.Hostname + "\n" + route.Path
		if keys[key] {
			return Gateway{}, problem(path, "route_collision", "duplicate canonical host/path")
		}
		keys[key] = true
	}
	return *detached, nil
}

func routeIDs(routes []Route) map[string]Route {
	result := make(map[string]Route, len(routes))
	for _, route := range routes {
		result[route.ID] = route
	}
	return result
}

func routingWinner(routes []Route, host, path string) string {
	id, longest := "", -1
	for _, route := range routes {
		if route.Hostname == host && len(route.Path) > longest &&
			(route.Path == "/" || route.Path == path || strings.HasPrefix(path, route.Path+"/")) {
			id, longest = route.ID, len(route.Path)
		}
	}
	return id
}
