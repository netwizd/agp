package configmodel

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"
)

type ZoneRevision struct {
	ID        string  `json:"id"`
	Digest    string  `json:"digest"`
	Content   WafZone `json:"content"`
	Published bool    `json:"published"`
}
type ReplacementAssignment struct {
	GatewayID      string `json:"gatewayId"`
	ZoneRevisionID string `json:"zoneRevisionId"`
}
type ResolveRequest struct {
	ID                   string
	SiteID               string
	ZoneRevisionID       string
	BaseConfigRevisionID string
	Action               string
	CapacityProfile      string
	CreatedAt            time.Time
	// CurrentAssignments are pinned config provenance, never a live label search.
	CurrentAssignments     map[string]string
	ReplacementAssignments []ReplacementAssignment
	ZoneRevisions          []ZoneRevision
	AllowLegacyMigration   bool
}

// ResolveZones freezes the complete affected Site closure. Derived exceptions
// without qualified lineage become explicit conflicts, never inherited silently.
func ResolveZones(ctx context.Context, c Configuration, catalog Catalog, request ResolveRequest) (*WafZoneResolution, error) {
	inventory, err := CanonicalizeCatalog(catalog)
	if err != nil {
		return nil, err
	}
	return resolveZoneInputs(ctx, c, inventory.Catalog.Nodes, inventory.Catalog.Inputs, inventory.Digest, "", request)
}

// TrustedZoneInputs can only carry server-verified observations and immutable
// published policy pins. It deliberately has no operator catalog source kind.
// SourceDigest binds identity, epoch and current component qualification; callers
// must independently recheck observation freshness on every consumption.
type TrustedZoneInputs struct {
	SourceDigest   string         `json:"sourceDigest"`
	MinimumWAFMode string         `json:"minimumWafMode"`
	Nodes          []CatalogNode  `json:"nodes"`
	Policies       []CatalogInput `json:"policies"`
}

func ResolveTrustedZones(ctx context.Context, c Configuration, inputs TrustedZoneInputs, request ResolveRequest) (*WafZoneResolution, error) {
	if (inputs.MinimumWAFMode != "detection" && inputs.MinimumWAFMode != "blocking") || !ValidDigest(inputs.SourceDigest) || len(inputs.Nodes) > 500 || len(inputs.Policies) > 50000 {
		return nil, problem("/inventory", "invalid_trusted_inputs", "invalid trusted source digest or capacity")
	}
	// Validate and normalize typed facts without constructing an operator catalog.
	raw, err := CanonicalJSON(inputs)
	if err != nil {
		return nil, err
	}
	v, err := jsonValue(raw)
	if err != nil {
		return nil, err
	}
	var normalized TrustedZoneInputs
	if err = decodeTyped(v, &normalized); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for i := range normalized.Nodes {
		n := &normalized.Nodes[i]
		if seen[n.ID] || n.SiteID != request.SiteID || !ValidDigest(n.CapabilityDigest) {
			return nil, problem("/inventory/nodes", "invalid_trusted_inputs", "duplicate, foreign Site or unqualified node")
		}
		seen[n.ID] = true
		normalizeLabels(n.Labels)
		set(n.NodeGroupIDs)
	}
	seen = map[string]bool{}
	for _, p := range normalized.Policies {
		if seen[p.ID] || p.Kind != "waf_policy" || p.State != "published" || p.SiteID != request.SiteID || p.Profile != nil {
			return nil, problem("/inventory/policies", "invalid_trusted_inputs", "invalid published policy pin")
		}
		seen[p.ID] = true
	}
	sort.Slice(normalized.Nodes, func(i, j int) bool { return normalized.Nodes[i].ID < normalized.Nodes[j].ID })
	sort.Slice(normalized.Policies, func(i, j int) bool { return normalized.Policies[i].ID < normalized.Policies[j].ID })
	closureDigest, err := Digest(normalized)
	if err != nil {
		return nil, err
	}
	return resolveZoneInputs(ctx, c, normalized.Nodes, normalized.Policies, closureDigest, normalized.MinimumWAFMode, request)
}

func resolveZoneInputs(ctx context.Context, c Configuration, nodes []CatalogNode, inputs []CatalogInput, sourceDigest, minimumWAFMode string, request ResolveRequest) (*WafZoneResolution, error) {
	doc, err := Canonicalize(c)
	if err != nil {
		return nil, err
	}
	c = doc.Configuration
	if !ValidID(request.ID) || !ValidID(request.SiteID) || !ValidID(request.ZoneRevisionID) || !ValidID(request.BaseConfigRevisionID) || request.CreatedAt.IsZero() || (request.Action != "reconcile" && request.Action != "retire") || request.CapacityProfile != doc.Capacity.Profile {
		return nil, problem("", "invalid_resolution_request", "invalid base, IDs, action or explicit capacity profile")
	}
	gatewayMap := map[string]Gateway{}
	for _, g := range c.Gateways {
		gatewayMap[g.Metadata.ID] = g
	}
	revisions := map[string]ZoneRevision{}
	stable := map[string]string{}
	for _, revision := range request.ZoneRevisions {
		if !ValidID(revision.ID) || !revision.Published {
			return nil, problem("/zoneRevisions", "zone_not_published", "zone revisions must be immutable and published")
		}
		if _, ok := revisions[revision.ID]; ok {
			return nil, problem("/zoneRevisions", "duplicate_id", "duplicate zone revision")
		}
		content := revision.Content
		raw, err := CanonicalJSON(content)
		if err != nil {
			return nil, err
		}
		var parsed WafZone
		v, err := jsonValue(raw)
		if err != nil {
			return nil, err
		}
		if err = decodeTyped(v, &parsed); err != nil {
			return nil, err
		}
		if err = ValidateWafZone(&parsed); err != nil {
			return nil, err
		}
		digest, err := Digest(parsed)
		if err != nil || digest != revision.Digest {
			return nil, problem("/zoneRevisions", "digest_mismatch", "zone content digest differs")
		}
		revision.Content = parsed
		revisions[revision.ID] = revision
	}
	target, ok := revisions[request.ZoneRevisionID]
	if !ok || target.Content.Metadata.SiteID != request.SiteID {
		return nil, problem("/zoneRevisionId", "waf_zone_site_mismatch", "requested exact zone revision is unavailable in Site")
	}
	selected := map[string]ZoneRevision{}
	for gatewayID, id := range request.CurrentAssignments {
		gateway, exists := gatewayMap[gatewayID]
		if !exists {
			return nil, problem("/currentAssignments", "unresolved_reference", "assignment Gateway is missing")
		}
		if gateway.Metadata.SiteID != request.SiteID {
			continue
		}
		revision, ok := revisions[id]
		if !ok {
			return nil, problem("/currentAssignments", "unresolved_reference", "pinned zone revision is missing")
		}
		key := revision.Content.Metadata.ID
		if existing, ok := selected[key]; ok && existing.ID != id {
			return nil, problem("/currentAssignments", "waf_zone_lineage_conflict", "one stable zone is pinned to multiple revisions")
		}
		selected[key] = revision
	}
	affectedStable := map[string]bool{target.Content.Metadata.ID: true}
	selected[target.Content.Metadata.ID] = target
	replacements := map[string]string{}
	for _, replacement := range request.ReplacementAssignments {
		if _, ok := replacements[replacement.GatewayID]; ok {
			return nil, problem("/replacementAssignments", "duplicate_id", "duplicate replacement Gateway")
		}
		revision, ok := revisions[replacement.ZoneRevisionID]
		if !ok || revision.Content.Metadata.SiteID != request.SiteID {
			return nil, problem("/replacementAssignments", "waf_zone_site_mismatch", "replacement zone must be exact published revision in Site")
		}
		key := revision.Content.Metadata.ID
		if old, ok := stable[key]; ok && old != revision.ID {
			return nil, problem("/replacementAssignments", "waf_zone_lineage_conflict", "replacement revisions disagree for one stable zone")
		}
		stable[key] = revision.ID
		selected[key] = revision
		affectedStable[key] = true
		replacements[replacement.GatewayID] = revision.ID
	}
	if request.Action == "retire" {
		delete(selected, target.Content.Metadata.ID)
	}
	zones := []ZoneRevision{}
	for _, z := range selected {
		if z.Content.Metadata.SiteID != request.SiteID {
			return nil, problem("/zoneRevisions", "waf_zone_site_mismatch", "selected zone belongs to another Site")
		}
		zones = append(zones, z)
	}
	sort.Slice(zones, func(i, j int) bool { return zones[i].ID < zones[j].ID })

	// Index explicit membership once. A fleet Gateway must never scan a
	// 10,000-entry list for every candidate zone.
	zoneGatewaySets := make(map[string]map[string]bool, len(zones))
	for _, z := range zones {
		if z.Content.Spec.Membership.GatewayIDs != nil {
			ids := make(map[string]bool, len(z.Content.Spec.Membership.GatewayIDs))
			for _, id := range z.Content.Spec.Membership.GatewayIDs {
				ids[id] = true
			}
			zoneGatewaySets[z.ID] = ids
		}
		for _, id := range z.Content.Spec.Membership.GatewayIDs {
			g, ok := gatewayMap[id]
			if !ok || g.Metadata.SiteID != request.SiteID {
				return nil, problem("/zoneRevisions", "waf_zone_site_mismatch", "explicit member must exist in the same Site")
			}
		}
	}
	for id := range replacements {
		if g, ok := gatewayMap[id]; !ok || g.Metadata.SiteID != request.SiteID {
			return nil, problem("/replacementAssignments", "waf_zone_site_mismatch", "replacement Gateway must exist in Site")
		}
	}
	request.ZoneRevisions = make([]ZoneRevision, 0, len(revisions))
	for _, revision := range revisions {
		request.ZoneRevisions = append(request.ZoneRevisions, revision)
	}
	sort.Slice(request.ZoneRevisions, func(i, j int) bool { return request.ZoneRevisions[i].ID < request.ZoneRevisions[j].ID })
	request.ReplacementAssignments = append([]ReplacementAssignment{}, request.ReplacementAssignments...)
	sort.Slice(request.ReplacementAssignments, func(i, j int) bool {
		return request.ReplacementAssignments[i].GatewayID < request.ReplacementAssignments[j].GatewayID
	})
	closure := struct {
		CatalogDigest, ConfigDigest string
		Request                     ResolveRequest
	}{sourceDigest, doc.Digest, request}
	inventoryDigest, err := Digest(closure)
	if err != nil {
		return nil, err
	}
	out := &WafZoneResolution{APIVersion: "agp.waf-zone-resolution/v1alpha1", Kind: "WafZoneResolution", ID: request.ID, SiteID: request.SiteID, ZoneRevisionID: request.ZoneRevisionID, BaseConfigRevisionID: request.BaseConfigRevisionID, Action: request.Action, InventoryDigest: inventoryDigest, CapacityProfile: request.CapacityProfile, CreatedAt: request.CreatedAt.UTC().Format(time.RFC3339Nano), ExpiresAt: request.CreatedAt.Add(30 * time.Minute).UTC().Format(time.RFC3339Nano), Members: []ZoneMember{}, Conflicts: []ZoneConflict{}}
	// Bound output while building members, before marshaling the complete
	// fleet snapshot. Account for the actual envelope, final SHA-256 digest
	// and array separators without reducing the selected fleet capacity.
	const maxResolutionBytes = 64 << 20
	envelope, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	resolutionBytes := len(envelope) + len("sha256:") + 64
	policy := map[string]CatalogInput{}
	for _, in := range inputs {
		if in.Kind == "waf_policy" {
			policy[in.ID] = in
		}
	}
	for _, g := range c.Gateways {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if g.Metadata.SiteID != request.SiteID {
			continue
		}
		sourceID := request.CurrentAssignments[g.Metadata.ID]
		source, sourceExists := revisions[sourceID]
		affected := sourceExists && affectedStable[source.Content.Metadata.ID]
		matches, defaults := []ZoneRevision{}, []ZoneRevision{}
		for _, z := range zones {
			m := z.Content.Spec.Membership
			if m.SiteDefault != nil {
				defaults = append(defaults, z)
				continue
			}
			match := false
			if m.GatewayIDs != nil {
				match = zoneGatewaySets[z.ID][g.Metadata.ID]
			} else {
				match = zoneLabels(*m.MatchLabels, g.Metadata.Labels)
			}
			if match {
				matches = append(matches, z)
				if affectedStable[z.Content.Metadata.ID] {
					affected = true
				}
			}
		}
		if _, ok := replacements[g.Metadata.ID]; ok {
			affected = true
		}
		if len(matches) == 0 {
			for _, z := range defaults {
				if affectedStable[z.Content.Metadata.ID] {
					affected = true
				}
			}
		}
		if !affected {
			continue
		}
		bindingDigest, _ := Digest(g.Spec.WAF)
		member := ZoneMember{GatewayID: g.Metadata.ID, SourceZoneRevisionID: sourceID, SourcePolicyRevisionID: g.Spec.WAF.PolicyRevisionID, BaseBindingDigest: bindingDigest, Disposition: "conflict", RouteIDs: []string{}, NodeIDs: []string{}}
		for _, r := range g.Spec.Routes {
			member.RouteIDs = append(member.RouteIDs, r.ID)
		}
		member.NodeIDs = zoneNodes(g, nodes)
		code, message := "", ""
		candidates := []string{}
		if len(matches) > 1 {
			code = "waf_zone_ambiguous"
			message = "Several ordinary zones match; explicit lists have no priority"
			for _, z := range matches {
				candidates = append(candidates, z.ID)
			}
		} else if len(matches) == 0 {
			if len(defaults) == 1 {
				matches = defaults
			} else if len(defaults) > 1 {
				code = "waf_zone_ambiguous"
				message = "Several Site defaults are pinned"
				for _, z := range defaults {
					candidates = append(candidates, z.ID)
				}
			} else {
				code = "waf_zone_unassigned"
				message = "No ordinary zone or unique Site default matches"
			}
		}
		var destination ZoneRevision
		if len(matches) == 1 {
			destination = matches[0]
		}
		leaving := sourceExists && source.Content.Metadata.ID == target.Content.Metadata.ID && (request.Action == "retire" || destination.Content.Metadata.ID != target.Content.Metadata.ID)
		if code == "" && leaving && replacements[g.Metadata.ID] == "" {
			code = "waf_zone_replacement_required"
			message = "Leaving Gateway requires an explicit safe replacement"
		}
		if code == "" && replacements[g.Metadata.ID] != "" && replacements[g.Metadata.ID] != destination.ID {
			code = "waf_zone_ambiguous"
			message = "Replacement must satisfy ordinary membership and uniqueness"
		}
		if code == "" && !sourceExists && !request.AllowLegacyMigration {
			code = "waf_zone_lineage_conflict"
			message = "Unzoned Gateway requires an explicit controlled migration"
		}
		if code == "" {
			p, ok := policy[destination.Content.Spec.PolicyRevisionID]
			if !ok || p.State != "published" || p.SiteID != request.SiteID {
				code = "waf_zone_policy_not_published"
				message = "Exact published same-Site base policy is unavailable"
			} else if p.BaseExceptionCount != 0 {
				code = "waf_zone_base_exceptions"
				message = "Shared base policy must have no route exceptions"
			}
		}
		if code == "" {
			for _, r := range g.Spec.Routes {
				if len(r.WAFExceptionIDs) > 0 {
					code = "waf_zone_lineage_conflict"
					message = "Local exceptions require qualified derivation and three-way rebase evidence"
					break
				}
			}
		}
		if code == "" && (len(member.NodeIDs) == 0 || !completeZoneNodes(g, nodes)) {
			code = "waf_zone_node_unresolved"
			message = "Gateway resolves to no complete node target set"
		}
		if code == "" && minimumWAFMode == "blocking" && destination.Content.Spec.Mode != "blocking" {
			code, message = "waf_zone_security_minimum", "Zone mode falls below the server's required WAF minimum"
		}
		if code == "" {
			binding := WAFBinding{Engine: "modsecurity", PolicyRevisionID: destination.Content.Spec.PolicyRevisionID, Mode: destination.Content.Spec.Mode}
			member.Disposition = "inherited"
			member.TargetZoneRevisionID = destination.ID
			member.TargetPolicyRevisionID = binding.PolicyRevisionID
			member.TargetBindingDigest, _ = Digest(binding)
		} else {
			conflict := ZoneConflict{GatewayID: g.Metadata.ID, Code: code, Path: "/gateways/" + strconv.Itoa(len(out.Members)), Message: message}
			if len(candidates) > 0 && len(candidates) <= 100 {
				sort.Strings(candidates)
				conflict.CandidateZoneRevisionIDs = candidates
			}
			rawConflict, err := json.Marshal(conflict)
			if err != nil {
				return nil, err
			}
			conflictBytes := len(rawConflict)
			if len(out.Conflicts) > 0 {
				conflictBytes++
			}
			if conflictBytes > maxResolutionBytes-resolutionBytes {
				return nil, problem("/members", "resolution_byte_limit", "Complete resolution exceeds the 64 MiB document budget")
			}
			resolutionBytes += conflictBytes
			out.Conflicts = append(out.Conflicts, conflict)
		}
		rawMember, err := json.Marshal(member)
		if err != nil {
			return nil, err
		}
		memberBytes := len(rawMember)
		if len(out.Members) > 0 {
			memberBytes++
		}
		if memberBytes > maxResolutionBytes-resolutionBytes {
			return nil, problem("/members", "resolution_byte_limit", "Complete resolution exceeds the 64 MiB document budget")
		}
		resolutionBytes += memberBytes
		out.Members = append(out.Members, member)
	}
	if err = ValidateResolution(out); err != nil {
		return nil, err
	}
	digest, err := ResolutionDigest(*out)
	if err != nil {
		return nil, err
	}
	out.ResolutionDigest = digest
	return out, nil
}
func zoneLabels(selector, labels Labels) bool {
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}
func zoneNodes(g Gateway, nodes []CatalogNode) []string {
	out := []string{}
	explicit := map[string]bool{}
	for _, id := range g.Spec.NodeSelector.NodeIDs {
		explicit[id] = true
	}
	for _, n := range nodes {
		if n.SiteID != g.Metadata.SiteID {
			continue
		}
		if g.Spec.NodeSelector.NodeIDs != nil {
			if !explicit[n.ID] {
				continue
			}
		} else if !zoneLabels(*g.Spec.NodeSelector.MatchLabels, n.Labels) {
			continue
		}
		out = append(out, n.ID)
	}
	sort.Strings(out)
	return out
}
func ResolutionDigest(r WafZoneResolution) (string, error) {
	raw, err := CanonicalJSON(r)
	if err != nil {
		return "", err
	}
	var value map[string]any
	if err := decodeJSONMap(raw, &value); err != nil {
		return "", err
	}
	delete(value, "resolutionDigest")
	return Digest(value)
}
func decodeJSONMap(raw []byte, out *map[string]any) error { return json.Unmarshal(raw, out) }

// MaterializeResolution is the low-level binding primitive. Storage services
// must first revalidate all current security inputs with MaterializeWithInventory
// inside the same CAS transaction. It provides no inventory authorization.
func MaterializeResolution(c Configuration, zones []ZoneRevision, r WafZoneResolution, now time.Time) (*Document, error) {
	digest, err := ResolutionDigest(r)
	if err != nil || digest != r.ResolutionDigest {
		return nil, problem("/resolutionDigest", "digest_mismatch", "resolution digest differs")
	}
	if err = ValidateResolution(&r); err != nil {
		return nil, err
	}
	expires, _ := time.Parse(time.RFC3339Nano, r.ExpiresAt)
	created, _ := time.Parse(time.RFC3339Nano, r.CreatedAt)
	if now.Before(created) || !now.Before(expires) {
		return nil, problem("/expiresAt", "resolution_expired", "resolution expired")
	}
	if len(r.Conflicts) > 0 {
		return nil, problem("/conflicts", "conflict", "resolution has conflicts")
	}
	doc, err := Canonicalize(c)
	if err != nil {
		return nil, err
	}
	c = doc.Configuration
	byID := map[string]ZoneRevision{}
	for _, z := range zones {
		byID[z.ID] = z
	}
	members := map[string]ZoneMember{}
	for _, m := range r.Members {
		members[m.GatewayID] = m
	}
	for i := range c.Gateways {
		g := &c.Gateways[i]
		m, ok := members[g.Metadata.ID]
		if !ok {
			continue
		}
		base, _ := Digest(g.Spec.WAF)
		if base != m.BaseBindingDigest {
			return nil, problem("/members", "revision_mismatch", "Gateway binding changed since resolution")
		}
		z, ok := byID[m.TargetZoneRevisionID]
		if !ok || !z.Published || z.Content.Metadata.SiteID != r.SiteID || g.Metadata.SiteID != r.SiteID {
			return nil, problem("/members", "unresolved_reference", "target exact zone is missing")
		}
		binding := WAFBinding{Engine: "modsecurity", PolicyRevisionID: m.TargetPolicyRevisionID, Mode: z.Content.Spec.Mode}
		target, _ := Digest(binding)
		if target != m.TargetBindingDigest || binding.PolicyRevisionID != z.Content.Spec.PolicyRevisionID {
			return nil, problem("/members", "digest_mismatch", "target binding differs from frozen resolution")
		}
		if len(m.RouteIDs) != len(g.Spec.Routes) {
			return nil, fmt.Errorf("route closure changed")
		}
		for j, route := range g.Spec.Routes {
			if route.ID != m.RouteIDs[j] {
				return nil, problem("/members", "revision_mismatch", "route closure changed")
			}
		}
		g.Spec.WAF = binding
		delete(members, g.Metadata.ID)
	}
	if len(members) > 0 {
		return nil, problem("/members", "unresolved_reference", "resolution member is missing")
	}
	return Canonicalize(c)
}

func completeZoneNodes(g Gateway, nodes []CatalogNode) bool {
	if g.Spec.NodeSelector.NodeIDs == nil {
		return true
	}
	found := map[string]bool{}
	for _, n := range nodes {
		if n.SiteID == g.Metadata.SiteID {
			found[n.ID] = true
		}
	}
	for _, id := range g.Spec.NodeSelector.NodeIDs {
		if !found[id] {
			return false
		}
	}
	return true
}

// MaterializeWithInventory repeats the exact frozen computation under the
// service's CAS transaction. Callers must provide the current immutable config,
// catalog and pinned assignments, never an inventory supplied by the browser.
func MaterializeWithInventory(c Configuration, catalog Catalog, request ResolveRequest, r WafZoneResolution, now time.Time) (*Document, error) {
	expected, err := ResolveZones(context.Background(), c, catalog, request)
	if err != nil {
		return nil, err
	}
	if expected.ResolutionDigest != r.ResolutionDigest || expected.InventoryDigest != r.InventoryDigest {
		return nil, problem("/inventoryDigest", "revision_mismatch", "security inputs or frozen membership changed")
	}
	return MaterializeResolution(c, request.ZoneRevisions, r, now)
}

// MaterializeWithTrustedInputs rechecks the exact frozen request against fresh
// server observations. A newly received unchanged heartbeat does not alter the
// stable source digest; an expired observation must be rejected by the caller.
func MaterializeWithTrustedInputs(ctx context.Context, c Configuration, inputs TrustedZoneInputs, request ResolveRequest, r WafZoneResolution, now time.Time) (*Document, error) {
	expected, err := ResolveTrustedZones(ctx, c, inputs, request)
	if err != nil {
		return nil, err
	}
	if expected.ResolutionDigest != r.ResolutionDigest || expected.InventoryDigest != r.InventoryDigest {
		return nil, problem("/inventoryDigest", "revision_mismatch", "security inputs or frozen membership changed")
	}
	return MaterializeResolution(c, request.ZoneRevisions, r, now)
}
