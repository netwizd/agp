package edgeauth

import (
	"net/http"
	"strings"
)

func reservedCookie(name string) bool {
	n := strings.ToLower(name)
	return strings.HasPrefix(n, "agp") || strings.HasPrefix(n, "__host-agp") || strings.HasPrefix(n, "__secure-agp")
}
func stripIdentity(h http.Header) {
	for name := range h {
		if strings.HasPrefix(strings.ToLower(name), "x-agp-") {
			h.Del(name)
		}
	}
}
func allowedCookie(name string, names []string) bool {
	if reservedCookie(name) {
		return false
	}
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}
func filterRequestCookies(r *http.Request, names []string) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, c := range cookies {
		if allowedCookie(c.Name, names) {
			r.AddCookie(c)
		}
	}
}
func filterResponseCookies(resp *http.Response, names []string) {
	cookies := resp.Cookies()
	resp.Header.Del("Set-Cookie")
	for _, c := range cookies {
		if allowedCookie(c.Name, names) && c.Domain == "" && (c.Path == "" || safePath(c.Path) && !strings.Contains(c.Path, "?")) && c.Valid() == nil {
			resp.Header.Add("Set-Cookie", c.String())
		}
	}
}
