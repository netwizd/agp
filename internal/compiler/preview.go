// Package compiler deterministically resolves an immutable authoring catalog
// into complete per-node preview artifacts. It never applies or reloads them.
package compiler

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/netwizd/agp/internal/configmodel"
	nginx "github.com/netwizd/agp/internal/reverseproxy/nginx"
)

type Options struct {
	Version        string
	BuildDigest    string
	MinimumWAFMode string
	ReservedHosts  []string
}
type Input struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	Digest string `json:"digest"`
}
type Artifact struct {
	Name    string `json:"name"`
	Content string `json:"content"`
	Digest  string `json:"digest"`
}
type Provenance struct {
	Field             string `json:"field"`
	AssignmentID      string `json:"assignmentId"`
	ProfileRevisionID string `json:"profileRevisionId"`
	Locked            bool   `json:"locked"`
}
type EffectiveRoute struct {
	GatewayID  string                 `json:"gatewayId"`
	RouteID    string                 `json:"routeId"`
	Route      configmodel.Route      `json:"route"`
	WAF        configmodel.WAFBinding `json:"waf"`
	RequireMFA bool                   `json:"requireMfa"`
	Provenance []Provenance           `json:"provenance"`
}
type NodeBundle struct {
	NodeID           string           `json:"nodeId"`
	CapabilityDigest string           `json:"capabilityDigest,omitempty"`
	BaseBundleDigest string           `json:"baseBundleDigest,omitempty"`
	GatewayIDs       []string         `json:"gatewayIds"`
	Routes           []EffectiveRoute `json:"routes"`
	ResolvedInputs   []Input          `json:"resolvedInputs"`
	SecretVersionIDs []string         `json:"secretVersionIds"`
	Artifacts        []Artifact       `json:"artifacts"`
	BundleDigest     string           `json:"bundleDigest"`
	Deployable       bool             `json:"deployable"`
}
type Result struct {
	ConfigDigest    string              `json:"configDigest"`
	CatalogDigest   string              `json:"catalogDigest"`
	CompilerDigest  string              `json:"compilerDigest"`
	CompilerVersion string              `json:"compilerVersion"`
	CapacityProfile string              `json:"capacityProfile"`
	PreviewDigest   string              `json:"previewDigest"`
	Deployable      bool                `json:"deployable"`
	Bundles         []NodeBundle        `json:"bundles"`
	ResolvedInputs  []Input             `json:"resolvedInputs"`
	Issues          []configmodel.Issue `json:"issues"`
}

func Preview(ctx context.Context, c configmodel.Configuration, catalog configmodel.Catalog, options Options) (*Result, error) {
	doc, err := configmodel.Canonicalize(c)
	if err != nil {
		return nil, err
	}
	inventory, err := configmodel.CanonicalizeCatalog(catalog)
	if err != nil {
		return nil, err
	}
	c = doc.Configuration
	catalog = inventory.Catalog
	if options.Version == "" || len(options.Version) > 64 || !configmodel.ValidDigest(options.BuildDigest) {
		return nil, fmt.Errorf("compiler version and immutable build digest are required")
	}
	if options.MinimumWAFMode == "" {
		options.MinimumWAFMode = "detection"
	}
	if options.MinimumWAFMode != "detection" && options.MinimumWAFMode != "blocking" {
		return nil, fmt.Errorf("unsupported mandatory WAF minimum")
	}
	reservedHosts := map[string]bool{}
	canonicalReserved := make([]string, 0, len(options.ReservedHosts))
	for _, host := range options.ReservedHosts {
		host, err := configmodel.CanonicalHostname(host)
		if err != nil {
			return nil, fmt.Errorf("invalid reserved hostname: %w", err)
		}
		if !reservedHosts[host] {
			reservedHosts[host] = true
			canonicalReserved = append(canonicalReserved, host)
		}
	}
	sort.Strings(canonicalReserved)
	options.ReservedHosts = canonicalReserved
	compilerDigest, _ := configmodel.Digest(options)
	result := &Result{ConfigDigest: doc.Digest, CatalogDigest: inventory.Digest, CompilerDigest: compilerDigest, CompilerVersion: options.Version, CapacityProfile: doc.Capacity.Profile, Bundles: []NodeBundle{}, ResolvedInputs: []Input{}, Issues: []configmodel.Issue{}}
	issue := func(path, code, message string) {
		if len(result.Issues) < 100 {
			result.Issues = append(result.Issues, configmodel.Issue{Path: path, Code: code, Message: message, Severity: "error"})
		} else {
			result.Issues[99] = configmodel.Issue{Path: "", Code: "issues_truncated", Message: "Additional blocking issues were omitted; this preview is not authoring-valid", Severity: "error"}
		}
	}
	issue("", "native_qualification_required", "Operator-declared inventory provides no native runtime qualification; artifacts are proposals and cannot be deployed")
	sites, groups := map[string]bool{}, map[string]bool{}
	nodes := map[string]configmodel.CatalogNode{}
	inputs := map[string]configmodel.CatalogInput{}
	for _, s := range catalog.Sites {
		sites[s.ID] = true
	}
	for _, id := range catalog.Groups {
		groups[id] = true
	}
	for _, n := range catalog.Nodes {
		nodes[n.ID] = n
	}
	for _, in := range catalog.Inputs {
		inputs[in.Kind+"/"+in.ID] = in
	}
	used := map[string]Input{}
	resolve := func(kind, id, site, digest, path string) bool {
		in, ok := inputs[kind+"/"+id]
		if !ok || in.State != "published" || (in.SiteID != "" && in.SiteID != site) || (digest != "" && in.Digest != digest) {
			issue(path, "unresolved_reference", "Exact published scoped input is unavailable or its digest differs: "+kind+"/"+id)
			return false
		}
		used[kind+"/"+id] = Input{Kind: kind, ID: id, Digest: in.Digest}
		return true
	}
	selectionBytes := 0
	selectionRoutes := 0
	nodeSecrets := map[string]map[string]bool{}
	selected := map[string][]configmodel.Gateway{}
	gatewayNodes := map[string][]string{}
	for _, g := range c.Gateways {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		path := "/gateways/" + g.Metadata.ID
		if !sites[g.Metadata.SiteID] {
			issue(path+"/metadata/siteId", "unresolved_reference", "Unknown Site")
		}
		resolve("component_profile", g.Spec.ComponentProfileRef.ID, g.Metadata.SiteID, g.Spec.ComponentProfileRef.Digest, path+"/spec/componentProfileRef")
		resolve("certificate", g.Spec.TLS.CertificateVersionID, g.Metadata.SiteID, "", path+"/spec/tls")
		resolve("waf_policy", g.Spec.WAF.PolicyRevisionID, g.Metadata.SiteID, "", path+"/spec/waf")
		if wafRank(g.Spec.WAF.Mode) < wafRank(options.MinimumWAFMode) {
			issue(path+"/spec/waf/mode", "security_minimum", "Authored WAF mode is below the mandatory platform minimum")
		}
		ids := []string{}
		if g.Spec.NodeSelector.NodeIDs != nil {
			ids = append(ids, g.Spec.NodeSelector.NodeIDs...)
		} else {
			for id, n := range nodes {
				if n.SiteID == g.Metadata.SiteID && labelsMatch(*g.Spec.NodeSelector.MatchLabels, n.Labels) {
					ids = append(ids, id)
				}
			}
		}
		sort.Strings(ids)
		gatewayBytes, _ := json.Marshal(g)
		for _, id := range ids {
			n, ok := nodes[id]
			if !ok || n.SiteID != g.Metadata.SiteID {
				issue(path+"/spec/nodeSelector", "node_scope_mismatch", "Selected node is missing or belongs to another Site")
				continue
			}
			if nodeSecrets[id] == nil {
				nodeSecrets[id] = map[string]bool{}
			}
			nodeSecrets[id][g.Spec.TLS.CertificateVersionID] = true
			for _, r := range g.Spec.Routes {
				if r.Upstream.TLS.CASecretVersionID != "" {
					nodeSecrets[id][r.Upstream.TLS.CASecretVersionID] = true
				}
			}
			if len(nodeSecrets[id]) > 100 {
				return nil, previewCapacity("Per-node secret version limit is 100")
			}
			selectionBytes += len(gatewayBytes) * 2
			selectionRoutes += len(g.Spec.Routes)
			if selectionBytes > 64<<20 || int64(selectionRoutes)*int64(len(c.ProfileAssignments)+1) > 10000000 {
				return nil, previewCapacity("Replicated per-node configuration or profile work exceeds bounded preview budget")
			}
			selected[id] = append(selected[id], g)
			gatewayNodes[g.Metadata.ID] = append(gatewayNodes[g.Metadata.ID], id)
		}
		if len(gatewayNodes[g.Metadata.ID]) == 0 {
			issue(path+"/spec/nodeSelector", "node_unresolved", "Gateway resolves to no nodes")
		}
		for _, r := range g.Spec.Routes {
			for _, id := range r.Access.GroupIDs {
				if !groups[id] {
					issue(path+"/spec/routes/"+r.ID+"/access", "unresolved_reference", "Unknown access group: "+id)
				}
			}
			if r.Upstream.TLS.CASecretVersionID != "" {
				resolve("certificate", r.Upstream.TLS.CASecretVersionID, g.Metadata.SiteID, "", path+"/spec/routes/"+r.ID+"/upstream/tls")
			}
			if len(r.WAFExceptionIDs) > 0 {
				issue(path+"/spec/routes/"+r.ID+"/wafExceptionIds", "waf_exception_qualification_required", "Route exceptions require qualified policy lineage and expiry evidence")
			}
		}
	}
	routeSites := map[string]string{}
	for _, g := range c.Gateways {
		for _, r := range g.Spec.Routes {
			routeSites[r.ID] = g.Metadata.SiteID
		}
	}
	nodeGroupSites := map[string]string{}
	for _, n := range catalog.Nodes {
		for _, group := range n.NodeGroupIDs {
			if old, ok := nodeGroupSites[group]; ok && old != n.SiteID {
				issue("/nodes", "node_group_scope_mismatch", "NodeGroup membership crosses Sites")
			} else {
				nodeGroupSites[group] = n.SiteID
			}
		}
	}
	for _, a := range c.ProfileAssignments {
		site := ""
		exists := true
		switch a.ScopeType {
		case "site":
			site = a.ScopeID
			exists = sites[site]
		case "node":
			n, ok := nodes[a.ScopeID]
			exists = ok
			site = n.SiteID
		case "route":
			site, exists = routeSites[a.ScopeID]
		case "node_group":
			site, exists = nodeGroupSites[a.ScopeID]
		}
		if !exists {
			issue("/profileAssignments/"+a.ID, "unresolved_reference", "Unknown assignment scope target")
			continue
		}
		resolve("policy_profile", a.ProfileRevisionID, site, "", "/profileAssignments/"+a.ID)
	}
	inputLimit := 1000
	if doc.Capacity.Profile == "fleet-10k" {
		inputLimit = 50000
	}
	if len(used) > inputLimit {
		return nil, previewCapacity("Pinned input cardinality exceeds capacity profile")
	}
	if err := admitPreview(selected, c.ProfileAssignments); err != nil {
		return nil, err
	}
	nodeIDs := []string{}
	for id := range selected {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Strings(nodeIDs)
	for _, id := range nodeIDs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n := nodes[id]
		bundle := NodeBundle{NodeID: id, CapabilityDigest: n.CapabilityDigest, BaseBundleDigest: n.BaselineBundleDigest, GatewayIDs: []string{}, Routes: []EffectiveRoute{}, ResolvedInputs: []Input{}, SecretVersionIDs: []string{}, Artifacts: []Artifact{}}
		if n.CapabilityDigest == "" {
			issue("/nodes/"+id, "capability_unqualified", "Node capability evidence is unavailable")
		}
		if n.BaselineBundleDigest == "" {
			issue("/nodes/"+id, "baseline_unavailable", "Node baseline bundle evidence is unavailable")
		}
		hostOwners := map[string]string{}
		sharedHosts := map[string]bool{}
		nativeBlocked := false
		for _, g := range selected[id] {
			for _, route := range g.Spec.Routes {
				if reservedHosts[route.Hostname] {
					nativeBlocked = true
					if _, seen := hostOwners[route.Hostname]; !seen {
						issue("/nodes/"+id+"/hosts/"+route.Hostname, "reserved_origin", "Gateway hostname belongs to a reserved management or login origin")
					}
				}
				if owner, exists := hostOwners[route.Hostname]; exists && owner != g.Metadata.ID {
					nativeBlocked = true
					if !sharedHosts[route.Hostname] {
						issue("/nodes/"+id+"/hosts/"+route.Hostname, "shared_host_conflict", "Hostname belongs to multiple Gateways on this node: "+owner+", "+g.Metadata.ID)
						sharedHosts[route.Hostname] = true
					}
				} else {
					hostOwners[route.Hostname] = g.Metadata.ID
				}
			}
		}
		secretSet := map[string]bool{}
		var proposal strings.Builder
		for _, g := range selected[id] {
			bundle.GatewayIDs = append(bundle.GatewayIDs, g.Metadata.ID)
			secretSet[g.Spec.TLS.CertificateVersionID] = true
			hosts := map[string]bool{}
			for _, route := range g.Spec.Routes {
				effective := EffectiveRoute{GatewayID: g.Metadata.ID, RouteID: route.ID, Route: route, WAF: g.Spec.WAF, RequireMFA: true, Provenance: []Provenance{}}
				applyProfiles(&effective, c.ProfileAssignments, n, g, inputs, issue)
				if wafRank(effective.WAF.Mode) < wafRank(options.MinimumWAFMode) || !effective.RequireMFA {
					issue("/nodes/"+id+"/routes/"+route.ID, "security_minimum", "Resolved profile violates mandatory WAF/MFA minimum")
				}
				for _, gid := range effective.Route.Access.GroupIDs {
					if !groups[gid] {
						issue("/nodes/"+id+"/routes/"+route.ID, "unresolved_reference", "Profile grants unknown group")
					}
				}
				bundle.Routes = append(bundle.Routes, effective)
				hosts[route.Hostname] = true
				if route.Upstream.TLS.CASecretVersionID != "" {
					secretSet[route.Upstream.TLS.CASecretVersionID] = true
				}
			}
			if nativeBlocked {
				continue
			}
			orderedHosts := []string{}
			for host := range hosts {
				orderedHosts = append(orderedHosts, host)
			}
			sort.Strings(orderedHosts)
			for _, host := range orderedHosts {
				socketDigest := configmodel.DigestBytes([]byte(id + "\n" + g.Metadata.ID + "\n" + host))
				socket := "/run/agp/edge-" + strings.TrimPrefix(socketDigest, "sha256:")[:24] + ".sock"
				server, err := nginx.GenerateEdgeGatewayServerWithTLS("https://"+host, socket, "/etc/agp/secrets/"+g.Spec.TLS.CertificateVersionID+"/certificate.pem", "/etc/agp/secrets/"+g.Spec.TLS.CertificateVersionID+"/private.key")
				if err != nil {
					issue("/nodes/"+id, "proposal_generation_failed", err.Error())
					continue
				}
				proposal.WriteString(server)
				proposal.WriteByte('\n')
			}
		}
		for secret := range secretSet {
			bundle.SecretVersionIDs = append(bundle.SecretVersionIDs, secret)
		}
		sort.Strings(bundle.SecretVersionIDs)
		if len(bundle.SecretVersionIDs) > 100 {
			issue("/nodes/"+id, "secret_capacity_exceeded", "A node proposal cannot reference more than 100 secret versions")
		}
		nodeKeys := map[string]bool{}
		for _, g := range selected[id] {
			nodeKeys["component_profile/"+g.Spec.ComponentProfileRef.ID] = true
			nodeKeys["certificate/"+g.Spec.TLS.CertificateVersionID] = true
			nodeKeys["waf_policy/"+g.Spec.WAF.PolicyRevisionID] = true
			for _, r := range g.Spec.Routes {
				if r.Upstream.TLS.CASecretVersionID != "" {
					nodeKeys["certificate/"+r.Upstream.TLS.CASecretVersionID] = true
				}
			}
		}
		for _, route := range bundle.Routes {
			for _, p := range route.Provenance {
				nodeKeys["policy_profile/"+p.ProfileRevisionID] = true
			}
		}
		for key := range nodeKeys {
			if in, ok := used[key]; ok {
				bundle.ResolvedInputs = append(bundle.ResolvedInputs, in)
			}
		}

		sortInputs(bundle.ResolvedInputs)
		normalized, _ := configmodel.CanonicalJSON(bundle.Routes)
		bundle.Artifacts = append(bundle.Artifacts, artifact("effective-routes.json", string(normalized)))
		if !nativeBlocked {
			bundle.Artifacts = append(bundle.Artifacts, artifact("nginx/proposal.conf", proposal.String()))
		}
		digest, err := configmodel.Digest(struct {
			Config, Catalog, Compiler string
			Bundle                    NodeBundle
		}{doc.Digest, inventory.Digest, compilerDigest, bundle})
		if err != nil {
			return nil, err
		}
		bundle.BundleDigest = digest
		result.Bundles = append(result.Bundles, bundle)
	}
	for _, in := range used {
		result.ResolvedInputs = append(result.ResolvedInputs, in)
	}
	sortInputs(result.ResolvedInputs)
	max := 1000
	if doc.Capacity.Profile == "fleet-10k" {
		max = 50000
	}
	if len(result.ResolvedInputs) > max {
		issue("/resolvedInputs", "input_capacity_exceeded", "Pinned input count exceeds capacity profile")
	}
	projection, _ := configmodel.CanonicalJSON(result.ResolvedInputs)
	byteLimit := 256 << 10
	if doc.Capacity.Profile == "fleet-10k" {
		byteLimit = 16 << 20
	}
	if len(projection) > byteLimit {
		issue("/resolvedInputs", "input_byte_limit", "Pinned input projection exceeds capacity profile")
	}
	sort.Slice(result.Issues, func(i, j int) bool {
		a, b := result.Issues[i], result.Issues[j]
		return a.Path+"/"+a.Code+"/"+a.Message < b.Path+"/"+b.Code+"/"+b.Message
	})
	digest, err := configmodel.Digest(result)
	if err != nil {
		return nil, err
	}
	result.PreviewDigest = digest
	finalJSON, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	if len(finalJSON) > 64<<20 {
		return nil, previewCapacity("Aggregate preview output exceeds 64 MiB")
	}
	return result, nil
}
func artifact(name, content string) Artifact {
	return Artifact{Name: name, Content: content, Digest: configmodel.DigestBytes([]byte(content))}
}
func labelsMatch(selector, labels configmodel.Labels) bool {
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}
func sortInputs(in []Input) {
	sort.Slice(in, func(i, j int) bool { return in[i].Kind+"/"+in[i].ID < in[j].Kind+"/"+in[j].ID })
}
func wafRank(mode string) int {
	switch mode {
	case "blocking":
		return 2
	case "detection":
		return 1
	}
	return 0
}
func applyProfiles(e *EffectiveRoute, assignments []configmodel.ProfileAssignment, node configmodel.CatalogNode, g configmodel.Gateway, inputs map[string]configmodel.CatalogInput, issue func(string, string, string)) {
	locks := map[string]json.RawMessage{}
	levels := []string{"global", "site", "node_group", "node", "route"}
	for _, level := range levels {
		peers := map[string]json.RawMessage{}
		for _, a := range assignments {
			if a.ScopeType != level {
				continue
			}
			match := false
			switch level {
			case "global":
				match = true
			case "site":
				match = a.ScopeID == g.Metadata.SiteID
			case "node":
				match = a.ScopeID == node.ID
			case "route":
				match = a.ScopeID == e.RouteID
			case "node_group":
				for _, id := range node.NodeGroupIDs {
					if id == a.ScopeID {
						match = true
					}
				}
			}
			if !match {
				continue
			}
			in, ok := inputs["policy_profile/"+a.ProfileRevisionID]
			if !ok || in.Profile == nil {
				continue
			}
			p := in.Profile
			if p.Spec.Level != level || (p.Metadata.SiteID != "" && p.Metadata.SiteID != g.Metadata.SiteID) {
				issue("/profileAssignments/"+a.ID, "profile_scope_mismatch", "Profile level/Site differs from assignment")
				continue
			}
			raw, _ := json.Marshal(p.Spec.Overrides)
			fields := map[string]json.RawMessage{}
			json.Unmarshal(raw, &fields)
			keys := []string{}
			for f := range fields {
				keys = append(keys, f)
			}
			sort.Strings(keys)
			for _, field := range keys {
				value := fields[field]
				if old, ok := locks[field]; ok && string(old) != string(value) {
					issue("/profileAssignments/"+a.ID, "profile_locked", "Descendant changes locked field: "+field)
					continue
				}
				if old, ok := peers[field]; ok && string(old) != string(value) {
					issue("/profileAssignments/"+a.ID, "profile_peer_conflict", "Equal-level assignments disagree: "+field)
					continue
				}
				peers[field] = value
				switch field {
				case "wafMode":
					json.Unmarshal(value, &e.WAF.Mode)
				case "allowedGroupIds":
					json.Unmarshal(value, &e.Route.Access.GroupIDs)
				case "allowCidrs":
					json.Unmarshal(value, &e.Route.Access.AllowCIDRs)
				case "requireMfa":
					json.Unmarshal(value, &e.RequireMFA)
				case "connectTimeoutSeconds":
					json.Unmarshal(value, &e.Route.Upstream.ConnectTimeoutSeconds)
				case "readTimeoutSeconds":
					json.Unmarshal(value, &e.Route.Upstream.ReadTimeoutSeconds)
				}
				locked := false
				for _, f := range p.Spec.LockedFields {
					if f == field {
						locks[field] = value
						locked = true
					}
				}
				e.Provenance = append(e.Provenance, Provenance{Field: field, AssignmentID: a.ID, ProfileRevisionID: a.ProfileRevisionID, Locked: locked})
			}
			for _, field := range p.Spec.LockedFields {
				if _, authored := fields[field]; authored {
					continue
				}
				value := effectiveField(*e, field)
				raw, _ := json.Marshal(value)
				if old, ok := locks[field]; ok && string(old) != string(raw) {
					issue("/profileAssignments/"+a.ID, "profile_locked", "Profile lock conflicts with inherited locked value")
					continue
				}
				locks[field] = raw
				e.Provenance = append(e.Provenance, Provenance{Field: field, AssignmentID: a.ID, ProfileRevisionID: a.ProfileRevisionID, Locked: true})
			}
		}
	}
}
func effectiveField(e EffectiveRoute, field string) any {
	switch field {
	case "wafMode":
		return e.WAF.Mode
	case "allowedGroupIds":
		return e.Route.Access.GroupIDs
	case "allowCidrs":
		return e.Route.Access.AllowCIDRs
	case "requireMfa":
		return e.RequireMFA
	case "connectTimeoutSeconds":
		return e.Route.Upstream.ConnectTimeoutSeconds
	case "readTimeoutSeconds":
		return e.Route.Upstream.ReadTimeoutSeconds
	}
	return nil
}

func previewCapacity(message string) error {
	return &configmodel.ValidationError{Issues: []configmodel.Issue{{Path: "", Code: "preview_capacity_exceeded", Message: message, Severity: "error"}}}
}
func admitPreview(selected map[string][]configmodel.Gateway, assignments []configmodel.ProfileAssignment) error {
	costByGateway := map[string]int{}
	total := 0
	for _, gateways := range selected {
		total += 4096
		for _, g := range gateways {
			cost, ok := costByGateway[g.Metadata.ID]
			if !ok {
				hosts := map[string]bool{}
				cost = 256
				for _, route := range g.Spec.Routes {
					e := EffectiveRoute{GatewayID: g.Metadata.ID, RouteID: route.ID, Route: route, WAF: g.Spec.WAF, RequireMFA: true, Provenance: []Provenance{}}
					raw, _ := json.Marshal(e)
					escaped, _ := json.Marshal(string(raw))
					cost += len(raw) + len(escaped) + 2 + len(assignments)*7200
					hosts[route.Hostname] = true
				}
				for host := range hosts {
					server, err := nginx.GenerateEdgeGatewayServerWithTLS("https://"+host, "/run/agp/edge-000000000000000000000000.sock", "/etc/agp/secrets/"+g.Spec.TLS.CertificateVersionID+"/certificate.pem", "/etc/agp/secrets/"+g.Spec.TLS.CertificateVersionID+"/private.key")
					if err != nil {
						return err
					}
					escaped, _ := json.Marshal(server)
					cost += len(escaped) + 1
				}
				costByGateway[g.Metadata.ID] = cost
			}
			if cost > 64<<20-total {
				return previewCapacity("Per-node artifacts and full effective routes exceed aggregate 64 MiB preview budget")
			}
			total += cost
		}
	}
	return nil
}
