package httpapi

import (
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/netwizd/agp/internal/identity"
)

// oidcCallbackQuery accepts only the bounded protocol response profile. Opaque
// diagnostics/session hints are discarded, never logged, fetched or trusted.
func oidcCallbackQuery(r *http.Request) (url.Values, bool) {
	if len(r.URL.RawQuery) > 32<<10 {
		return nil, false
	}
	q, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		return nil, false
	}
	limits := map[string]int{"state": 43, "code": 4096, "error": 128, "iss": 2048, "error_description": 1024, "error_uri": 2048, "session_state": 1024}
	for key, values := range q {
		limit, known := limits[key]
		if !known || len(values) != 1 || len(values[0]) < 1 || len(values[0]) > limit || !utf8.ValidString(values[0]) {
			return nil, false
		}
	}
	if !validFlowToken(q.Get("state")) || ((q.Get("code") == "") == (q.Get("error") == "")) {
		return nil, false
	}
	if q.Get("error") == "" && (q.Get("error_description") != "" || q.Get("error_uri") != "") {
		return nil, false
	}
	if v := q.Get("session_state"); v != "" {
		for _, c := range v {
			if c < 33 || c > 126 {
				return nil, false
			}
		}
	}
	return q, true
}

func (s *Server) oidcIdentityDispatch(w http.ResponseWriter, r *http.Request, requestOrigin string) bool {
	const methods = "/auth/v2/oidc/providers"
	if r.URL.Path == methods {
		if r.Method != http.MethodGet {
			identityProblem(w, 405, "method_not_allowed")
			return true
		}
		if r.URL.RawQuery != "" {
			identityProblem(w, 400, "invalid_query")
			return true
		}
		if s.oidc == nil {
			identityProblem(w, 503, "identity_provider_unavailable")
			return true
		}
		out, e := s.oidc.LoginMethods(r.Context(), requestOrigin)
		if e != nil {
			identityError(w, e)
		} else {
			writeJSON(w, 200, out)
		}
		return true
	}
	if !strings.HasPrefix(r.URL.Path, methods+"/") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, methods+"/"), "/")
	if len(parts) != 2 || parts[1] != "callback" || !validIdentityID(parts[0]) {
		identityProblem(w, 404, "not_found")
		return true
	}
	if r.Method != http.MethodGet {
		identityProblem(w, 405, "method_not_allowed")
		return true
	}
	q, ok := oidcCallbackQuery(r)
	if !ok {
		identityProblem(w, 400, "invalid_oidc_callback")
		return true
	}
	binding, ok := uniqueIdentityCookie(r, flowBindingCookie)
	if !ok || !validFlowToken(binding) {
		identityProblem(w, 401, "binding_required")
		return true
	}
	if s.oidc == nil {
		identityProblem(w, 503, "identity_provider_unavailable")
		return true
	}
	out, e := s.oidc.Callback(r.Context(), identity.FlowAuth{Binding: binding, Origin: requestOrigin}, parts[0], q.Get("state"), q.Get("code"), q.Get("error"), q.Get("iss"))
	if e != nil {
		identityError(w, e)
		return true
	}
	if !validIdentityID(out.Transition.View.ID) {
		identityProblem(w, 409, "oidc_authorization_finished")
		return true
	}
	if !out.Terminal {
		if !validFlowToken(out.Transition.Binding) || out.Transition.View.Purpose != "login" && out.Transition.View.Purpose != "step_up" || out.Transition.View.State != "pending_mfa" || out.Transition.View.MFASatisfied {
			identityProblem(w, 503, "security_state_unavailable")
			return true
		}
		http.SetCookie(w, sessionCookie(flowBindingCookie, out.Transition.Binding, out.Transition.View.ExpiresAt, true))
	}
	w.Header().Set("Location", "/auth-ui/?flow="+url.QueryEscape(out.Transition.View.ID))
	w.WriteHeader(http.StatusSeeOther)
	return true
}
