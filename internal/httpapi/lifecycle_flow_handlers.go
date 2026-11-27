package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/netwizd/agp/internal/identity"
)

func exactLifecycleFields(m map[string]json.RawMessage, keys ...string) bool {
	if len(m) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}
func lifecycleString(m map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := m[key]
	if !ok || string(raw) == "null" {
		return "", false
	}
	var out string
	e := json.Unmarshal(raw, &out)
	return out, e == nil
}
func (s *Server) lifecyclePrimaryProof(w http.ResponseWriter, r *http.Request, a identity.FlowAuth) {
	var in map[string]json.RawMessage
	if !strictIdentityJSON(w, r, &in) {
		return
	}
	method, ok := lifecycleString(in, "method")
	if !ok {
		identityProblem(w, 400, "invalid_proof")
		return
	}
	var out identity.Transition
	var err error
	switch method {
	case "invitation":
		raw, ok := lifecycleString(in, "token")
		if !ok || !exactLifecycleFields(in, "method", "token") || !validFlowToken(raw) {
			identityProblem(w, 400, "invalid_proof")
			return
		}
		out, err = s.identity.BindLifecycleInvitation(r.Context(), a, raw, s.clientIP(r))
	case "local_password", "directory_password":
		keys := []string{"method", "username", "password"}
		limit := 128
		if method == "directory_password" {
			keys = append(keys, "providerId")
			limit = 256
		}
		username, usernameOK := lifecycleString(in, "username")
		password, passwordOK := lifecycleString(in, "password")
		if !exactLifecycleFields(in, keys...) || !usernameOK || username == "" || utf8.RuneCountInString(username) > limit || !passwordOK || len(password) == 0 || len(password) > 1024 {
			identityProblem(w, 400, "invalid_proof")
			return
		}
		if method == "directory_password" {
			provider, ok := lifecycleString(in, "providerId")
			if !ok || !validIdentityID(provider) {
				identityProblem(w, 400, "invalid_proof")
				return
			}
			out, err = s.identity.PrimaryDirectory(r.Context(), a, provider, username, password, s.clientIP(r))
		} else {
			out, err = s.identity.Primary(r.Context(), a, strings.ToLower(strings.TrimSpace(username)), password, s.clientIP(r))
		}
	default:
		identityProblem(w, 400, "invalid_proof")
		return
	}
	if err != nil {
		identityError(w, err)
		return
	}
	http.SetCookie(w, sessionCookie(flowBindingCookie, out.Binding, out.View.ExpiresAt, true))
	writeJSON(w, 200, out.View)
}
func (s *Server) lifecycleRecoveryProof(w http.ResponseWriter, r *http.Request, a identity.FlowAuth) {
	var in map[string]json.RawMessage
	if !strictIdentityJSON(w, r, &in) {
		return
	}
	method, ok := lifecycleString(in, "method")
	if !ok {
		identityProblem(w, 400, "invalid_proof")
		return
	}
	switch method {
	case "supervised_ticket":
		ticket, ok := lifecycleString(in, "ticket")
		if !ok || !exactLifecycleFields(in, "method", "ticket") || !validFlowToken(ticket) {
			identityProblem(w, 400, "invalid_proof")
			return
		}
		out, e := s.identity.SupervisedRecoveryProof(r.Context(), a, ticket, s.clientIP(r))
		if e != nil {
			identityError(w, e)
			return
		}
		http.SetCookie(w, sessionCookie(flowBindingCookie, out.Binding, out.View.ExpiresAt, true))
		writeJSON(w, 200, out.View)
	case "recovery_code":
		code, ok := lifecycleString(in, "code")
		if !ok || !exactLifecycleFields(in, "method", "code") || len(code) < 16 || len(code) > 64 {
			identityProblem(w, 400, "invalid_proof")
			return
		}
		out, e := s.identity.RecoveryProof(r.Context(), a, code)
		if e != nil {
			identityError(w, e)
			return
		}
		writeJSON(w, 200, out)
	default:
		identityProblem(w, 400, "invalid_proof")
	}
}
