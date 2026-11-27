package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/rolloutexecution"
)

func TestExecutionHTTPBoundarySQLite(t *testing.T)   { testExecutionHTTPBoundary(t, false) }
func TestExecutionHTTPBoundaryPostgres(t *testing.T) { testExecutionHTTPBoundary(t, true) }

// This test exercises real audience/session/CSRF middleware, not a qualified
// native runtime. The callback deliberately does not invoke the service.
func testExecutionHTTPBoundary(t *testing.T, pg bool) {
	f := newResourceScopeHTTPFixture(t, pg)
	a := f.actor("execution_http_scoped", gatewayHTTPGrant{"config.read", "node", "node_msk01"})
	called := 0
	f.server.SetExecution(new(rolloutexecution.Service))
	h := f.server.withExecution(true, func(w http.ResponseWriter, r *http.Request, actor rolloutexecution.Actor) {
		if actor.TokenHash != auth.TokenHash(a.cookies[0].Value) || actor.Origin != "https://management.test" {
			t.Fatal("execution actor was not bound to actual session and management origin")
		}
		called++
		w.WriteHeader(204)
	})
	request := func(host string, cookies bool, origin string, csrf []string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://"+host+"/api/v2/config/execution-plans", strings.NewReader(`{}`))
		if cookies {
			for _, c := range a.cookies {
				r.AddCookie(c)
			}
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		for _, value := range csrf {
			r.Header.Add("X-CSRF-Token", value)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	csrf := a.headers["X-CSRF-Token"]
	for _, tc := range []struct {
		name, host, origin string
		cookies            bool
		csrf               []string
	}{
		{"missing session", "management.test", "https://management.test", false, []string{csrf}},
		{"wrong listener", "portal.test", "https://management.test", true, []string{csrf}},
		{"cross origin", "management.test", "https://other.test", true, []string{csrf}},
		{"missing origin", "management.test", "", true, []string{csrf}},
		{"missing CSRF", "management.test", "https://management.test", true, nil},
		{"wrong CSRF", "management.test", "https://management.test", true, []string{"wrong"}},
		{"duplicate CSRF", "management.test", "https://management.test", true, []string{csrf, csrf}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := called
			w := request(tc.host, tc.cookies, tc.origin, tc.csrf)
			if w.Code < 400 || called != before {
				t.Fatalf("unsafe transport admitted: status=%d calls=%d body=%s", w.Code, called, w.Body.String())
			}
		})
	}
	if w := request("management.test", true, "https://management.test", []string{csrf}); w.Code != 204 || called != 1 {
		t.Fatalf("scoped session must reach service authorization without global scope promotion: %d %s calls=%d", w.Code, w.Body.String(), called)
	}
	f.server.SetExecution(nil)
	if w := request("management.test", true, "https://management.test", []string{csrf}); w.Code != 404 || called != 1 {
		t.Fatal("execution must be explicitly installed", w.Code, w.Body.String())
	}
	// Agent execution paths must never be reachable from the browser listener.
	for _, path := range []string{"tasks", "start-proofs", "receipts"} {
		w := identityHTTPRequest(t, f.server.Handler(), "POST", "management.test", "/agent/v1/execution/"+path, struct{}{}, a.cookies, a.headers)
		if w.Code < 400 {
			t.Fatal("browser listener exposed agent execution", path, w.Code)
		}
	}
}
