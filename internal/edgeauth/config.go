// Package edgeauth implements the node-bound browser handoff and application
// proxy. It does not authenticate passwords or make offline access decisions.
package edgeauth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/netwizd/agp/internal/origin"
)

const (
	GatewayCookie = "__Host-agp_gateway"
	PendingCookie = "__Host-agp_edge_pending"
	StartPath     = "/_agp/start"
	CallbackPath  = "/_agp/callback"
	LogoutPath    = "/_agp/logout"
	AuthorizePath = "/_agp/authorize"
)

var opaqueID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var cookieName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

type Route struct {
	ID                 string   `json:"id"`
	PathPrefix         string   `json:"pathPrefix"`
	Upstream           string   `json:"upstream"`
	ApplicationCookies []string `json:"applicationCookies"`
}

// Config is an immutable, operator-provisioned deployment. There is no runtime
// request field that can select a node, generation or upstream.
type Config struct {
	NodeID                string  `json:"nodeId"`
	GatewayID             string  `json:"gatewayId"`
	Origin                string  `json:"origin"`
	LoginOrigin           string  `json:"loginOrigin"`
	CentralOrigin         string  `json:"centralOrigin"`
	DeploymentGeneration  string  `json:"deploymentGeneration"`
	Routes                []Route `json:"routes"`
	SocketPath            string  `json:"socketPath"`
	StatePath             string  `json:"statePath"`
	ClientCertificateFile string  `json:"clientCertificateFile"`
	ClientKeyFile         string  `json:"clientKeyFile"`
	ServerCAFile          string  `json:"serverCaFile"`
}

func canonicalOrigin(raw string) (*url.URL, error) {
	if _, err := origin.HTTPS(raw); err != nil {
		return nil, err
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.RawPath != "" || strings.ToLower(u.Host) != u.Host || strings.ContainsAny(u.Host, "\\\r\n\t ") {
		return nil, fmt.Errorf("expected a canonical HTTPS origin")
	}
	if u.Port() == "443" {
		return nil, fmt.Errorf("default HTTPS port must be omitted")
	}
	if _, err := url.ParseRequestURI(raw); err != nil {
		return nil, fmt.Errorf("invalid origin: %w", err)
	}
	return u, nil
}

func (c Config) Validate() error {
	if !opaqueID.MatchString(c.NodeID) || !opaqueID.MatchString(c.GatewayID) || !opaqueID.MatchString(c.DeploymentGeneration) {
		return fmt.Errorf("invalid node, gateway or deployment generation")
	}
	app, err := canonicalOrigin(c.Origin)
	if err != nil {
		return fmt.Errorf("gateway origin: %w", err)
	}
	login, err := canonicalOrigin(c.LoginOrigin)
	if err != nil {
		return fmt.Errorf("login origin: %w", err)
	}
	if app.Hostname() == login.Hostname() {
		return fmt.Errorf("gateway and login hostnames must differ")
	}
	if _, err := canonicalOrigin(c.CentralOrigin); err != nil {
		return fmt.Errorf("central mTLS origin: %w", err)
	}
	if len(c.Routes) == 0 || len(c.Routes) > 1000 {
		return fmt.Errorf("expected 1..1000 routes")
	}
	ids, prefixes := map[string]bool{}, map[string]bool{}
	for _, r := range c.Routes {
		if !opaqueID.MatchString(r.ID) || ids[r.ID] || prefixes[r.PathPrefix] {
			return fmt.Errorf("invalid or duplicate route")
		}
		ids[r.ID], prefixes[r.PathPrefix] = true, true
		if !safePath(r.PathPrefix) || strings.Contains(r.PathPrefix, "?") || (r.PathPrefix != "/" && strings.HasSuffix(r.PathPrefix, "/")) || strings.HasPrefix(r.PathPrefix, "/_agp") {
			return fmt.Errorf("invalid route prefix")
		}
		u, err := url.Parse(r.Upstream)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" || strings.ContainsAny(r.Upstream, "\\\r\n\t ") {
			return fmt.Errorf("invalid fixed upstream for route %s", r.ID)
		}
		seen := map[string]bool{}
		for _, name := range r.ApplicationCookies {
			if !cookieName.MatchString(name) || reservedCookie(name) || seen[name] {
				return fmt.Errorf("invalid application cookie policy")
			}
			seen[name] = true
		}
	}
	return nil
}

func (c Config) callbackURI() string { return c.Origin + CallbackPath }
func (c Config) fingerprint() string {
	b, _ := json.Marshal(struct {
		Node, Gateway, Origin, Login, Generation string
		Routes                                   []Route
	}{c.NodeID, c.GatewayID, c.Origin, c.LoginOrigin, c.DeploymentGeneration, c.Routes})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func safePath(raw string) bool {
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "\\\r\n\t\x00") {
		return false
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.IsAbs() || u.Host != "" || u.Fragment != "" || strings.ContainsAny(u.Path, "\\\r\n\t\x00") || strings.HasPrefix(u.Path, "//") || path.Clean(u.Path) != strings.TrimSuffix(u.Path, "/") && u.Path != "/" {
		return false
	}
	// Reject encoded path separators and nested encodings rather than relying on
	// different normalization rules in Nginx and an application.
	lower := strings.ToLower(u.EscapedPath())
	return !strings.Contains(lower, "%2f") && !strings.Contains(lower, "%5c") && !strings.Contains(lower, "%25")
}

func sortedRoutes(routes []Route) []Route {
	out := append([]Route(nil), routes...)
	for i := range out {
		out[i].ApplicationCookies = append([]string(nil), out[i].ApplicationCookies...)
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i].PathPrefix) > len(out[j].PathPrefix) })
	return out
}

func matchRoute(routes []Route, raw string) *Route {
	if !safePath(raw) {
		return nil
	}
	u, _ := url.ParseRequestURI(raw)
	if strings.HasPrefix(u.Path, "/_agp") {
		return nil
	}
	for i := range routes {
		p := routes[i].PathPrefix
		if p == "/" || u.Path == p || strings.HasPrefix(u.Path, p+"/") {
			return &routes[i]
		}
	}
	return nil
}
