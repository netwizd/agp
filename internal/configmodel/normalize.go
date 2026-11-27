package configmodel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"
)

func validUTC(s string) error {
	if len(s) > 35 || !strings.HasSuffix(s, "Z") {
		return fmt.Errorf("UTC timestamp ending in Z is required")
	}
	_, err := time.Parse(time.RFC3339Nano, s)
	return err
}

// CanonicalHostname normalizes a DNS hostname with IDNA lookup rules. Ports,
// IP addresses and a trailing dot are rejected, as they are for route hosts.
func CanonicalHostname(s string) (string, error) { return canonicalHost(s) }

func canonicalHost(s string) (string, error) {
	h, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return "", err
	}
	h = strings.ToLower(h)
	if len(h) < 1 || len(h) > 253 || strings.HasSuffix(h, ".") || net.ParseIP(h) != nil {
		return "", fmt.Errorf("a DNS hostname without port or trailing dot is required")
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid DNS label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("invalid DNS character")
			}
		}
	}
	return h, nil
}
func canonicalCIDRs(items []string) ([]string, error) {
	out := make([]string, 0, len(items))
	seen := map[string]bool{}
	for _, s := range items {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Addr().Is4In6() {
			return nil, fmt.Errorf("invalid CIDR")
		}
		s = p.Masked().String()
		if seen[s] {
			return nil, fmt.Errorf("duplicate canonical CIDR")
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}
func set(s []string) { sort.Strings(s) }
func validatePath(s string) error {
	if s == "" || s[0] != '/' || strings.Contains(s, "//") || strings.ContainsAny(s, "\\%?#") {
		return fmt.Errorf("route must be an unambiguous absolute prefix")
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) || strings.ContainsRune(";{}\"'$`", r) {
			return fmt.Errorf("unsafe route character")
		}
	}
	for _, segment := range strings.Split(s, "/") {
		if segment == "." || segment == ".." {
			return fmt.Errorf("route traversal is forbidden")
		}
	}
	return nil
}
func normalizeUpstream(u *Upstream) error {
	v, err := url.Parse(u.URL)
	if err != nil || v.Opaque != "" || v.Host == "" || v.User != nil || v.RawQuery != "" || v.ForceQuery || v.Fragment != "" || (v.Scheme != "http" && v.Scheme != "https") || v.RawPath != "" {
		return fmt.Errorf("upstream requires an unambiguous HTTP(S) URL without userinfo/query/fragment")
	}
	if strings.ContainsAny(u.URL, ";{}\"'$`\\") {
		return fmt.Errorf("unsafe upstream token")
	}
	for _, r := range u.URL {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("unsafe upstream character")
		}
	}
	if v.Path != "" {
		if err := validatePath(v.Path); err != nil {
			return err
		}
	}
	host := v.Hostname()
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.String()
		if ip.Is6() {
			host = "[" + host + "]"
		}
	} else {
		host, err = canonicalHost(host)
		if err != nil {
			return err
		}
	}
	port := v.Port()
	if strings.HasSuffix(v.Host, ":") {
		return fmt.Errorf("empty upstream port")
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return fmt.Errorf("invalid upstream port")
		}
		if !(v.Scheme == "https" && port == "443" || v.Scheme == "http" && port == "80") {
			host = net.JoinHostPort(strings.Trim(host, "[]"), port)
		}
	}
	v.Host = host
	u.URL = v.String()
	if utf8.RuneCountInString(u.URL) > 2048 {
		return fmt.Errorf("normalized upstream exceeds 2048 characters")
	}
	if u.TLS.ServerName != "" {
		h, err := canonicalHost(u.TLS.ServerName)
		if err != nil {
			return err
		}
		u.TLS.ServerName = h
	}
	return nil
}
func normalizeLabels(labels Labels) {
	for k, v := range labels {
		labels[k] = norm.NFC.String(v)
	}
}

// NormalizeRoute normalizes a standalone resource edit and requires a prefix
// supported by the managed EdgeAuth routing proof. Gateway and Configuration
// normalization retain their historical accepted syntax.
// As with NormalizeGateway, callers that accept untrusted values must first
// enforce the closed DTO schema, for example by using ParseRoute.
func NormalizeRoute(r *Route) error {
	if err := normalizeRoute(r, ""); err != nil {
		return err
	}
	return validateResourceRoutingPrefix(r.Path, "")
}

func validateResourceRoutingPrefix(prefix, path string) error {
	if prefix != "/" && strings.HasSuffix(prefix, "/") {
		return problem(path+"/path", "invalid_path", "route segment prefixes must not end in a slash")
	}
	if strings.HasPrefix(prefix, "/_agp") {
		return problem(path+"/path", "invalid_path", "route prefix overlaps the reserved EdgeAuth namespace")
	}
	return nil
}

func normalizeRoute(r *Route, path string) error {
	r.Name = norm.NFC.String(r.Name)
	h, err := canonicalHost(r.Hostname)
	if err != nil {
		return problem(path+"/hostname", "invalid_hostname", err.Error())
	}
	r.Hostname = h
	if err = validatePath(r.Path); err != nil {
		return problem(path+"/path", "invalid_path", err.Error())
	}
	if err = normalizeUpstream(&r.Upstream); err != nil {
		return problem(path+"/upstream", "invalid_upstream", err.Error())
	}
	r.Access.AllowCIDRs, err = canonicalCIDRs(r.Access.AllowCIDRs)
	if err != nil {
		return problem(path+"/access/allowCidrs", "invalid_cidr", err.Error())
	}
	set(r.Access.GroupIDs)
	set(r.WAFExceptionIDs)
	return nil
}

func NormalizeGateway(g *Gateway) error {
	if g.Spec.NodeSelector.MatchLabels != nil {
		normalizeLabels(*g.Spec.NodeSelector.MatchLabels)
	}
	g.Metadata.Name = norm.NFC.String(g.Metadata.Name)
	for k, v := range g.Metadata.Labels {
		g.Metadata.Labels[k] = norm.NFC.String(v)
	}
	if (g.Spec.NodeSelector.NodeIDs != nil) == (g.Spec.NodeSelector.MatchLabels != nil) {
		return problem("/spec/nodeSelector", "selector_union", "exactly one selector variant is required")
	}
	set(g.Spec.NodeSelector.NodeIDs)
	for i := range g.Spec.Routes {
		if err := normalizeRoute(&g.Spec.Routes[i], "/spec/routes/"+strconv.Itoa(i)); err != nil {
			return err
		}
	}
	// Routes are a set resolved by the single longest-prefix compiler policy.
	sort.Slice(g.Spec.Routes, func(i, j int) bool { return g.Spec.Routes[i].ID < g.Spec.Routes[j].ID })
	return nil
}
func Canonicalize(c Configuration) (*Document, error) {
	if err := validGoUnicode(reflect.ValueOf(c), 0); err != nil {
		return nil, err
	}
	// Round-trip detaches caller-owned slices/maps and enforces required fields
	// for direct form/Go callers using exactly the same closed schema as imports.
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	v, err := jsonValue(raw)
	if err != nil {
		return nil, err
	}
	if err = decodeTyped(v, &c); err != nil {
		return nil, err
	}
	cap := Pilot
	if c.APIVersion == "agp.config/v1alpha2" {
		if c.CapacityProfile != "fleet-10k" {
			return nil, problem("/capacityProfile", "capacity_profile_required", "v1alpha2 requires fleet-10k")
		}
		cap = Fleet
	} else if c.CapacityProfile != "" {
		return nil, problem("/capacityProfile", "unknown_field", "v1alpha1 has no capacityProfile")
	}
	if len(c.Gateways) > cap.MaxGateways || len(c.ProfileAssignments) > cap.MaxAssignments {
		return nil, problem("", "count_limit", "configuration exceeds selected capacity")
	}
	c.Metadata.Name = norm.NFC.String(c.Metadata.Name)
	ids := map[string]bool{c.Metadata.ID: true}
	routes, routeKeys := 0, map[string]string{}
	for i := range c.Gateways {
		g := &c.Gateways[i]
		p := "/gateways/" + strconv.Itoa(i)
		if ids[g.Metadata.ID] {
			return nil, problem(p+"/metadata/id", "duplicate_id", "IDs are globally unique")
		}
		ids[g.Metadata.ID] = true
		if err := NormalizeGateway(g); err != nil {
			if ve, ok := err.(*ValidationError); ok {
				for i := range ve.Issues {
					ve.Issues[i].Path = p + ve.Issues[i].Path
				}
			}
			return nil, err
		}
		routes += len(g.Spec.Routes)
		if routes > cap.MaxRoutes {
			return nil, problem(p+"/spec/routes", "route_limit", "total routes exceed selected capacity")
		}
		for j, r := range g.Spec.Routes {
			rp := p + "/spec/routes/" + strconv.Itoa(j)
			if ids[r.ID] {
				return nil, problem(rp+"/id", "duplicate_id", "IDs are globally unique")
			}
			ids[r.ID] = true
			key := r.Hostname + "\n" + r.Path
			if previous, ok := routeKeys[key]; ok {
				return nil, problem(rp, "route_collision", "duplicate host/path with "+previous)
			}
			routeKeys[key] = r.ID
		}
	}
	for i, a := range c.ProfileAssignments {
		p := "/profileAssignments/" + strconv.Itoa(i)
		if ids[a.ID] {
			return nil, problem(p+"/id", "duplicate_id", "IDs are globally unique")
		}
		ids[a.ID] = true
		if (a.ScopeType == "global") != (a.ScopeID == "") {
			return nil, problem(p+"/scopeId", "invalid_scope", "global scope forbids scopeId; other scopes require it")
		}
	}
	sort.Slice(c.Gateways, func(i, j int) bool { return c.Gateways[i].Metadata.ID < c.Gateways[j].Metadata.ID })
	sort.Slice(c.ProfileAssignments, func(i, j int) bool { return c.ProfileAssignments[i].ID < c.ProfileAssignments[j].ID })
	canonical, err := CanonicalJSON(c)
	if err != nil {
		return nil, err
	}
	if len(canonical) > cap.MaxBytes {
		return nil, problem("", "byte_limit", "canonical configuration exceeds capacity")
	}
	return &Document{Configuration: c, Canonical: canonical, Digest: DigestBytes(canonical), Capacity: cap}, nil
}

// CanonicalJSON implements RFC8785 for this closed DTO domain: its only JSON
// numbers are schema-bounded exact integers, so no floating-point conversion or
// ECMAScript rounding is admitted. Object keys sort by UTF-16 code units.
func CanonicalJSON(v any) ([]byte, error) {
	if err := validGoUnicode(reflect.ValueOf(v), 0); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value any
	if err = d.Decode(&value); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	var write func(any) error
	write = func(v any) error {
		switch x := v.(type) {
		case nil:
			out.WriteString("null")
		case bool:
			out.WriteString(strconv.FormatBool(x))
		case string:
			if !utf8.ValidString(x) {
				return fmt.Errorf("invalid UTF-8")
			}
			var b bytes.Buffer
			e := json.NewEncoder(&b)
			e.SetEscapeHTML(false)
			_ = e.Encode(x)
			s := strings.TrimSuffix(b.String(), "\n")
			s = strings.ReplaceAll(strings.ReplaceAll(s, `\u2028`, "\u2028"), `\u2029`, "\u2029")
			out.WriteString(s)
		case json.Number:
			n, err := strconv.ParseInt(string(x), 10, 64)
			if err != nil || n > 9007199254740991 || n < -9007199254740991 {
				return fmt.Errorf("JCS numbers must be exact I-JSON integers")
			}
			out.WriteString(strconv.FormatInt(n, 10))
		case []any:
			out.WriteByte('[')
			for i, item := range x {
				if i > 0 {
					out.WriteByte(',')
				}
				if err := write(item); err != nil {
					return err
				}
			}
			out.WriteByte(']')
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool {
				a, b := utf16.Encode([]rune(keys[i])), utf16.Encode([]rune(keys[j]))
				for k := 0; k < len(a) && k < len(b); k++ {
					if a[k] != b[k] {
						return a[k] < b[k]
					}
				}
				return len(a) < len(b)
			})
			out.WriteByte('{')
			for i, k := range keys {
				if i > 0 {
					out.WriteByte(',')
				}
				if err := write(k); err != nil {
					return err
				}
				out.WriteByte(':')
				if err := write(x[k]); err != nil {
					return err
				}
			}
			out.WriteByte('}')
		default:
			return fmt.Errorf("unsupported canonical value")
		}
		return nil
	}
	if err = write(value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
func DigestBytes(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func Digest(v any) (string, error) {
	b, err := CanonicalJSON(v)
	if err != nil {
		return "", err
	}
	return DigestBytes(b), nil
}

func validGoUnicode(v reflect.Value, depth int) error {
	if !v.IsValid() {
		return nil
	}
	if depth > 64 {
		return fmt.Errorf("canonical value exceeds depth budget")
	}
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer:
		if !v.IsNil() {
			return validGoUnicode(v.Elem(), depth+1)
		}
	case reflect.String:
		if !utf8.ValidString(v.String()) {
			return fmt.Errorf("canonical strings must be valid UTF-8")
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if err := validGoUnicode(v.Index(i), depth+1); err != nil {
				return err
			}
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			if err := validGoUnicode(iter.Key(), depth+1); err != nil {
				return err
			}
			if err := validGoUnicode(iter.Value(), depth+1); err != nil {
				return err
			}
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).PkgPath != "" {
				continue
			}
			if err := validGoUnicode(v.Field(i), depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
