package httpapi

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/origin"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

const flowBindingCookie = "__Host-agp_flow"
const flowCSRFCookie = "__Host-agp_flow_csrf"

// SetIdentity is startup-only. The service must have reconciled the independent
// authority before either browser or mTLS listeners begin accepting requests.
func (s *Server) SetIdentity(service *identity.Service) { s.identity = service }

func (s *Server) secureOrigin(r *http.Request) (string, string, bool) {
	authority, err := origin.Authority(r.Host)
	if err != nil {
		return "", "", false
	}
	actual := "https://" + authority
	switch actual {
	case s.cfg.ManagementOrigin:
		return actual, domain.SessionAudienceManagement, actual != "https://"
	case s.cfg.LoginOrigin:
		return actual, domain.SessionAudienceLogin, actual != "https://"
	}
	return "", "", false
}

func identityProblem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "about:blank", "title": http.StatusText(status), "status": status, "code": code, "traceId": securitystate.ID("request"), "retryable": status == http.StatusServiceUnavailable})
}

func identityError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, identity.ErrEmailReauthRequired), errors.Is(err, identity.ErrOIDCReauthRequired), errors.Is(err, identity.ErrLifecycleReauthRequired):
		identityProblem(w, http.StatusForbidden, "step_up_required")
	case errors.Is(err, identity.ErrLifecycleInvalid):
		identityProblem(w, 400, "invalid_identity_request")
	case errors.Is(err, identity.ErrLifecycleStale):
		identityProblem(w, 409, "identity_preconditions_changed")
	case errors.Is(err, identity.ErrLifecycleUnavailable):
		identityProblem(w, 503, "identity_lifecycle_unavailable")
	case errors.Is(err, identity.ErrEmailUnavailable):
		identityProblem(w, http.StatusServiceUnavailable, "email_unavailable")
	case errors.Is(err, identity.ErrDirectoryUnavailable):
		identityProblem(w, http.StatusServiceUnavailable, "identity_provider_unavailable")
	case errors.Is(err, identity.ErrLimited):
		w.Header().Set("Retry-After", "60")
		identityProblem(w, http.StatusTooManyRequests, "rate_limited")
	case errors.Is(err, identity.ErrExpired):
		identityProblem(w, http.StatusGone, "flow_expired")
	case errors.Is(err, identity.ErrProof), errors.Is(err, storage.ErrNotFound), errors.Is(err, storage.ErrPermissionDenied):
		identityProblem(w, http.StatusUnauthorized, "invalid_proof")
	default:
		identityProblem(w, http.StatusServiceUnavailable, "security_state_unavailable")
	}
}

func strictIdentityJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		identityProblem(w, http.StatusUnsupportedMediaType, "json_required")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	raw, err := io.ReadAll(r.Body)
	if err != nil || !utf8.Valid(raw) || !unambiguousIdentityObject(raw) {
		identityProblem(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil || d.Decode(new(any)) != io.EOF {
		identityProblem(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	return true
}

func unambiguousIdentityObject(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool)
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return false
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return false
		}
	}
	token, err = d.Token()
	return err == nil && token == json.Delim('}') && d.Decode(new(any)) == io.EOF
}

func validFlowToken(value string) bool {
	if len(value) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == value
}

// Reject ambiguous duplicate cookies rather than choosing an attacker-controlled
// first or last value. __Host- additionally prevents sibling domain cookie tossing.
func uniqueIdentityCookie(r *http.Request, name string) (string, bool) {
	value, count := "", 0
	for _, c := range r.Cookies() {
		if c.Name == name {
			value, count = c.Value, count+1
		}
	}
	return value, count == 1 && validFlowToken(value)
}

func identityOriginAndCSRF(w http.ResponseWriter, r *http.Request, expected string) (string, bool) {
	values := r.Header.Values("Origin")
	if len(values) != 1 || values[0] != expected {
		identityProblem(w, http.StatusForbidden, "origin_required")
		return "", false
	}
	cookie, ok := uniqueIdentityCookie(r, flowCSRFCookie)
	headers := r.Header.Values("X-CSRF-Token")
	if !ok || len(headers) != 1 || !validFlowToken(headers[0]) || subtle.ConstantTimeCompare([]byte(cookie), []byte(headers[0])) != 1 {
		identityProblem(w, http.StatusForbidden, "csrf_required")
		return "", false
	}
	return cookie, true
}

func validIdentityID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for i, c := range value {
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || i > 0 && (c == '_' || c == '-') {
			continue
		}
		return false
	}
	return true
}

// identityDispatch owns the public v2 namespace. Private EdgeAuth endpoints are
// served exclusively by EdgeHandler on the independently configured mTLS socket.
func (s *Server) identityDispatch(w http.ResponseWriter, r *http.Request) bool {
	if !pathWithin(r.URL.Path, "/auth/v2") {
		return false
	}
	if !s.cfg.SecureProfile || s.identity == nil {
		identityProblem(w, http.StatusServiceUnavailable, "security_state_unavailable")
		return true
	}
	requestOrigin, audience, ok := s.secureOrigin(r)
	if !ok {
		identityProblem(w, http.StatusForbidden, "origin_required")
		return true
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if s.oidcIdentityDispatch(w, r, requestOrigin) {
		return true
	}
	if r.URL.Path == "/auth/v2/bootstrap" && r.Method == http.MethodGet {
		if values := r.Header.Values("Origin"); len(values) > 0 && (len(values) != 1 || values[0] != requestOrigin) {
			identityProblem(w, http.StatusForbidden, "origin_required")
			return true
		}
		if err := s.identity.Coordinator.Ready(r.Context()); err != nil {
			identityError(w, err)
			return true
		}
		csrf, exists := uniqueIdentityCookie(r, flowCSRFCookie)
		if !exists {
			var err error
			csrf, _, err = auth.NewToken()
			if err != nil {
				identityError(w, err)
				return true
			}
		}
		http.SetCookie(w, csrfCookie(flowCSRFCookie, csrf, time.Now().Add(10*time.Minute), true))
		writeJSON(w, http.StatusOK, map[string]string{"csrfToken": csrf, "csrfCookieName": flowCSRFCookie, "audience": audience, "loginUrl": s.cfg.LoginOrigin, "managementUrl": s.cfg.ManagementOrigin})
		return true
	}
	if r.URL.Path == "/auth/v2/authorize" && r.Method == http.MethodGet {
		s.identityAuthorize(w, r, audience)
		return true
	}
	if r.URL.Path == "/auth/v2/handoffs/redeem" || r.URL.Path == "/auth/v2/decisions" {
		identityProblem(w, http.StatusForbidden, "mtls_required")
		return true
	}
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		identityProblem(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return true
	}
	csrf := ""
	if r.Method == http.MethodPost {
		var verified bool
		csrf, verified = identityOriginAndCSRF(w, r, requestOrigin)
		if !verified {
			return true
		}
	}
	if r.URL.Path == "/auth/v2/password-reset-requests" && r.Method == http.MethodPost {
		var in identity.PasswordResetRequest
		if !strictIdentityJSON(w, r, &in) {
			return true
		}
		manager := s.identity.RecoveryService()
		if manager == nil {
			identityError(w, identity.ErrLifecycleUnavailable)
			return true
		}
		if e := manager.RequestPasswordReset(r.Context(), requestOrigin, s.clientIP(r), in); e != nil {
			identityError(w, e)
			return true
		}
		w.WriteHeader(http.StatusAccepted)
		return true
	}
	if r.URL.Path == "/auth/v2/flows" && r.Method == http.MethodPost {
		var input struct {
			Purpose  string `json:"purpose"`
			Audience string `json:"audience"`
		}
		if !strictIdentityJSON(w, r, &input) {
			return true
		}
		if input.Audience != audience && !((input.Purpose == "recover" || input.Purpose == "activate") && input.Audience == "setup") {
			identityProblem(w, http.StatusForbidden, "origin_required")
			return true
		}
		sourceHash := ""
		if input.Purpose == "step_up" || input.Purpose == "verify_email" {
			cookieName := domain.LoginSessionCookieName
			if audience == domain.SessionAudienceManagement {
				cookieName = domain.ManagementSessionCookieName
			}
			token, present := uniqueIdentityCookie(r, cookieName)
			if !present {
				identityProblem(w, http.StatusUnauthorized, "invalid_proof")
				return true
			}
			sourceHash = auth.TokenHash(token)
		}
		transition, err := s.identity.StartWithSource(r.Context(), input.Purpose, input.Audience, requestOrigin, csrf, sourceHash, s.clientIP(r))
		if err != nil {
			identityError(w, err)
			return true
		}
		http.SetCookie(w, sessionCookie(flowBindingCookie, transition.Binding, transition.View.ExpiresAt, true))
		writeJSON(w, http.StatusCreated, transition.View)
		return true
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/auth/v2/flows/"), "/")
	if !strings.HasPrefix(r.URL.Path, "/auth/v2/flows/") || len(parts) == 0 || !validIdentityID(parts[0]) {
		identityProblem(w, http.StatusNotFound, "not_found")
		return true
	}
	binding, present := uniqueIdentityCookie(r, flowBindingCookie)
	if !present {
		identityProblem(w, http.StatusUnauthorized, "binding_required")
		return true
	}
	a := identity.FlowAuth{ID: parts[0], Binding: binding, CSRF: csrf, Origin: requestOrigin}
	if len(parts) == 1 && r.Method == http.MethodGet {
		view, err := s.identity.Get(r.Context(), a)
		if err != nil {
			identityError(w, err)
		} else {
			writeJSON(w, http.StatusOK, view)
		}
		return true
	}
	if len(parts) == 3 && parts[1] == "email-challenges" && validIdentityID(parts[2]) && r.Method == http.MethodGet {
		if s.email == nil {
			identityProblem(w, 503, "email_unavailable")
			return true
		}
		out, err := s.email.Get(r.Context(), a, parts[2])
		if err != nil {
			emailError(w, err)
		} else {
			writeJSON(w, 200, out)
		}
		return true
	}
	if len(parts) == 4 && parts[1] == "email-challenges" && validIdentityID(parts[2]) && parts[3] == "proofs" && r.Method == http.MethodPost {
		if s.email == nil {
			identityProblem(w, 503, "email_unavailable")
			return true
		}
		var input struct {
			Code string `json:"code"`
		}
		if !strictIdentityJSON(w, r, &input) {
			return true
		}
		if len(input.Code) != 8 || strings.Trim(input.Code, "0123456789") != "" {
			identityProblem(w, 400, "invalid_email_proof")
			return true
		}
		out, err := s.email.Verify(r.Context(), a, parts[2], input.Code)
		if err != nil {
			emailError(w, err)
		} else {
			writeJSON(w, 200, out)
		}
		return true
	}
	if r.Method != http.MethodPost {
		identityProblem(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return true
	}
	if len(parts) == 2 {
		s.identityTransition(w, r, a, parts[1])
		return true
	}
	if len(parts) == 4 && parts[1] == "totp-enrollments" && validIdentityID(parts[2]) && parts[3] == "confirmations" {
		var input struct {
			Code string `json:"code"`
		}
		if !strictIdentityJSON(w, r, &input) {
			return true
		}
		out, err := s.identity.ConfirmEnrollment(r.Context(), a, parts[2], input.Code)
		if err != nil {
			identityError(w, err)
		} else {
			writeJSON(w, http.StatusCreated, out)
		}
		return true
	}
	identityProblem(w, http.StatusNotFound, "not_found")
	return true
}

func (s *Server) identityTransition(w http.ResponseWriter, r *http.Request, a identity.FlowAuth, action string) {
	switch action {
	case "oidc-authorizations":
		if s.oidc == nil {
			identityProblem(w, 503, "identity_provider_unavailable")
			return
		}
		var in struct {
			ProviderID string `json:"providerId"`
		}
		if !strictIdentityJSON(w, r, &in) {
			return
		}
		out, err := s.oidc.BeginAuthorization(r.Context(), a, in.ProviderID, s.clientIP(r))
		if err != nil {
			identityError(w, err)
			return
		}
		writeJSON(w, 201, out)
	case "email-challenges":
		if s.email == nil {
			identityProblem(w, 503, "email_unavailable")
			return
		}
		var input identity.EmailIssue
		if !strictIdentityJSON(w, r, &input) {
			return
		}
		out, err := s.email.Issue(r.Context(), a, input, s.clientIP(r))
		if err != nil {
			emailError(w, err)
			return
		}
		writeJSON(w, 202, out)
	case "password-setups":
		var in struct {
			NewPassword string `json:"newPassword"`
		}
		if !strictIdentityJSON(w, r, &in) {
			return
		}
		out, e := s.identity.SetPassword(r.Context(), a, in.NewPassword)
		if e != nil {
			identityError(w, e)
			return
		}
		writeJSON(w, 200, out)
	case "primary-proofs":
		s.lifecyclePrimaryProof(w, r, a)
	case "recovery-proofs":
		s.lifecycleRecoveryProof(w, r, a)
	case "totp-proofs":
		var in struct {
			Code string `json:"code"`
		}
		if !strictIdentityJSON(w, r, &in) {
			return
		}
		out, e := s.identity.TOTPProof(r.Context(), a, in.Code)
		if e != nil {
			identityError(w, e)
			return
		}
		writeJSON(w, 200, out)
	case "totp-enrollments":
		if !emptyIdentityJSON(w, r) {
			return
		}
		out, err := s.identity.StartEnrollment(r.Context(), a)
		if err != nil {
			identityError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, out)
	case "completions":
		if !emptyIdentityJSON(w, r) {
			return
		}
		out, err := s.identity.Complete(r.Context(), a, s.clientIP(r), r.UserAgent())
		if err != nil {
			identityError(w, err)
			return
		}
		if out.SessionToken != "" {
			cookieName, csrfName := domain.LoginSessionCookieName, domain.LoginCSRFCookieName
			if out.Session.Audience == domain.SessionAudienceManagement {
				cookieName, csrfName = domain.ManagementSessionCookieName, domain.ManagementCSRFCookieName
			}
			http.SetCookie(w, sessionCookie(cookieName, out.SessionToken, out.Session.ExpiresAt, true))
			http.SetCookie(w, csrfCookie(csrfName, out.CSRFToken, out.Session.ExpiresAt, true))
		}
		http.SetCookie(w, sessionCookie(flowBindingCookie, "", time.Unix(0, 0), true))
		writeJSON(w, http.StatusOK, out.View)
	case "cancellations":
		if !emptyIdentityJSON(w, r) {
			return
		}
		view, err := s.identity.Cancel(r.Context(), a)
		if err != nil {
			identityError(w, err)
			return
		}
		http.SetCookie(w, sessionCookie(flowBindingCookie, "", time.Unix(0, 0), true))
		writeJSON(w, http.StatusOK, view)
	default:
		identityProblem(w, http.StatusNotFound, "not_found")
	}
}

func emptyIdentityJSON(w http.ResponseWriter, r *http.Request) bool {
	if r.ContentLength == 0 && r.Header.Get("Content-Type") == "" {
		return true
	}
	var input struct{}
	return strictIdentityJSON(w, r, &input)
}

func (s *Server) identityAuthorize(w http.ResponseWriter, r *http.Request, audience string) {
	if audience != domain.SessionAudienceLogin {
		identityProblem(w, http.StatusForbidden, "login_origin_required")
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(q) != 5 {
		identityProblem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	for _, name := range []string{"gatewayId", "redirectUri", "state", "codeChallenge", "codeChallengeMethod"} {
		if len(q[name]) != 1 || q.Get(name) == "" {
			identityProblem(w, http.StatusBadRequest, "invalid_request")
			return
		}
	}
	token, present := uniqueIdentityCookie(r, domain.LoginSessionCookieName)
	if !present {
		http.Redirect(w, r, "/auth-ui/login?return="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	redirect, err := s.identity.Authorize(r.Context(), auth.TokenHash(token), identity.AuthorizeRequest{GatewayID: q.Get("gatewayId"), RedirectURI: q.Get("redirectUri"), State: q.Get("state"), Challenge: q.Get("codeChallenge"), Method: q.Get("codeChallengeMethod")})
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			http.Redirect(w, r, "/auth-ui/login?return="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		identityError(w, err)
		return
	}
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}
