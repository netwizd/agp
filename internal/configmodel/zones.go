package configmodel

import (
	"encoding/json"
	"golang.org/x/text/unicode/norm"
	"sort"
	"strconv"
	"strings"
	"time"
)

func ValidateWafZone(z *WafZone) error {
	z.Metadata.Name = norm.NFC.String(z.Metadata.Name)
	z.Spec.Reason = norm.NFC.String(z.Spec.Reason)
	n := 0
	if z.Spec.Membership.GatewayIDs != nil {
		n++
		set(z.Spec.Membership.GatewayIDs)
	}
	if z.Spec.Membership.MatchLabels != nil {
		normalizeLabels(*z.Spec.Membership.MatchLabels)
		n++
		if len(*z.Spec.Membership.MatchLabels) == 0 {
			return problem("/spec/membership/matchLabels", "empty_selector", "zone selector cannot be empty")
		}
	}
	if z.Spec.Membership.SiteDefault != nil {
		n++
	}
	if n != 1 {
		return problem("/spec/membership", "selector_union", "exactly one membership variant is required")
	}
	return nil
}
func ValidateProfile(p *PolicyProfile) error {
	p.Metadata.Name = norm.NFC.String(p.Metadata.Name)
	if (p.Spec.Level == "global") != (p.Metadata.SiteID == "") {
		return problem("/metadata/siteId", "invalid_scope", "global profile forbids Site; other levels require it")
	}
	b, _ := json.Marshal(p.Spec.Overrides)
	if string(b) == "{}" {
		return problem("/spec/overrides", "empty_override", "at least one override is required")
	}
	valid := map[string]bool{"wafMode": true, "allowedGroupIds": true, "allowCidrs": true, "requireMfa": true, "connectTimeoutSeconds": true, "readTimeoutSeconds": true}
	seen := map[string]bool{}
	for _, f := range p.Spec.LockedFields {
		if !valid[f] || seen[f] {
			return problem("/spec/lockedFields", "invalid_lock", "invalid or duplicate locked field")
		}
		seen[f] = true
	}
	set(p.Spec.LockedFields)
	if p.Spec.Overrides.AllowedGroupIDs != nil {
		set(*p.Spec.Overrides.AllowedGroupIDs)
	}
	if p.Spec.Overrides.AllowCIDRs != nil {
		v, err := canonicalCIDRs(*p.Spec.Overrides.AllowCIDRs)
		if err != nil {
			return problem("/spec/overrides/allowCidrs", "invalid_cidr", err.Error())
		}
		p.Spec.Overrides.AllowCIDRs = &v
	}
	return nil
}
func ValidateResolution(r *WafZoneResolution) error {
	created, _ := time.Parse(time.RFC3339Nano, r.CreatedAt)
	expires, _ := time.Parse(time.RFC3339Nano, r.ExpiresAt)
	if expires.Sub(created) != 30*time.Minute {
		return problem("/expiresAt", "resolution_ttl", "resolution expires exactly 30 minutes after creation")
	}
	if r.CapacityProfile == "pilot-500" && len(r.Members) > 500 {
		return problem("/members", "count_limit", "pilot maximum is 500 members")
	}
	members := map[string]string{}
	conflicts := map[string]bool{}
	for _, c := range r.Conflicts {
		conflicts[c.GatewayID] = true
	}
	for i := range r.Members {
		m := &r.Members[i]
		if _, ok := members[m.GatewayID]; ok {
			return problem("/members", "duplicate_id", "duplicate member Gateway")
		}
		members[m.GatewayID] = m.Disposition
		if m.Disposition == "conflict" {
			if m.TargetZoneRevisionID != "" || m.TargetPolicyRevisionID != "" || m.TargetBindingDigest != "" || !conflicts[m.GatewayID] {
				return problem("/members", "invalid_conflict", "conflict has no target and requires diagnostic")
			}
		} else if m.TargetZoneRevisionID == "" || m.TargetPolicyRevisionID == "" || m.TargetBindingDigest == "" || len(m.NodeIDs) == 0 {
			return problem("/members", "missing_target", "resolved member requires complete target and nodes")
		}
		set(m.RouteIDs)
		set(m.NodeIDs)
	}
	for id := range conflicts {
		if members[id] != "conflict" {
			return problem("/conflicts", "invalid_conflict", "diagnostics must point to conflict members")
		}
	}
	sort.Slice(r.Members, func(i, j int) bool { return r.Members[i].GatewayID < r.Members[j].GatewayID })
	sort.Slice(r.Conflicts, func(i, j int) bool {
		a, b := r.Conflicts[i], r.Conflicts[j]
		return a.GatewayID+"/"+a.Code < b.GatewayID+"/"+b.Code
	})
	return nil
}

type Change struct {
	Path      string          `json:"path"`
	Kind      string          `json:"kind"`
	Before    json.RawMessage `json:"before,omitempty"`
	After     json.RawMessage `json:"after,omitempty"`
	Dangerous bool            `json:"dangerous"`
}

func SemanticDiff(base, next Configuration) ([]Change, error) {
	a, err := Canonicalize(base)
	if err != nil {
		return nil, err
	}
	b, err := Canonicalize(next)
	if err != nil {
		return nil, err
	}
	var av, bv any
	json.Unmarshal(a.Canonical, &av)
	json.Unmarshal(b.Canonical, &bv)
	out := []Change{}
	var walk func(string, any, any)
	walk = func(path string, a, b any) {
		am, aok := a.(map[string]any)
		bm, bok := b.(map[string]any)
		if aok && bok {
			keys := map[string]bool{}
			for k := range am {
				keys[k] = true
			}
			for k := range bm {
				keys[k] = true
			}
			ordered := []string{}
			for k := range keys {
				ordered = append(ordered, k)
			}
			sort.Strings(ordered)
			for _, k := range ordered {
				walk(pointer(path, k), am[k], bm[k])
			}
			return
		}
		aa, aArray := a.([]any)
		ba, bArray := b.([]any)
		if aArray && bArray {
			key := func(value any) string {
				m, ok := value.(map[string]any)
				if !ok {
					return ""
				}
				if id, ok := m["id"].(string); ok {
					return id
				}
				if meta, ok := m["metadata"].(map[string]any); ok {
					id, _ := meta["id"].(string)
					return id
				}
				return ""
			}
			ai, bi := map[string]int{}, map[string]int{}
			keyed := len(aa)+len(ba) > 0
			for i, item := range aa {
				id := key(item)
				if id == "" {
					keyed = false
					break
				}
				ai[id] = i
			}
			for i, item := range ba {
				id := key(item)
				if id == "" {
					keyed = false
					break
				}
				bi[id] = i
			}
			if keyed {
				ids := []string{}
				for id := range ai {
					ids = append(ids, id)
				}
				for id := range bi {
					if _, ok := ai[id]; !ok {
						ids = append(ids, id)
					}
				}
				sort.Strings(ids)
				for _, id := range ids {
					var av, bv any
					index := 0
					if i, ok := ai[id]; ok {
						av = aa[i]
						index = i
					}
					if i, ok := bi[id]; ok {
						bv = ba[i]
						index = i
					}
					walk(pointer(path, strconv.Itoa(index)), av, bv)
				}
				return
			}
		}
		ab, _ := json.Marshal(a)
		bb, _ := json.Marshal(b)
		if string(ab) == string(bb) {
			return
		}
		kind := "replace"
		if a == nil {
			kind = "add"
		}
		if b == nil {
			kind = "remove"
		}
		dangerous := path == "/gateways" || (strings.HasPrefix(path, "/gateways/") && strings.Count(path, "/") == 2) || strings.Contains(path, "/access") || strings.Contains(path, "/waf") || strings.Contains(path, "/authorization") || strings.Contains(path, "/tls") || strings.Contains(path, "/profileAssignments") || strings.Contains(path, "/routes") || strings.Contains(path, "/labels")
		out = append(out, Change{Path: path, Kind: kind, Before: ab, After: bb, Dangerous: dangerous})
	}
	walk("", av, bv)
	return out, nil
}
