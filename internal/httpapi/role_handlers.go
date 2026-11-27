package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/rolescope"
)

func (s *Server) withRoles(write bool, next lifecycleHandler) http.HandlerFunc {
	return s.withSession(func(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
		w.Header().Set("Cache-Control", "no-store")
		if !s.cfg.SecureProfile || s.identity == nil || !s.managementRequest(r) {
			identityProblem(w, 403, "permission_required")
			return
		}
		if id := r.PathValue("id"); id != "" && !validIdentityID(id) {
			identityProblem(w, 400, "invalid_identity_request")
			return
		}
		if r.URL.RawQuery != "" && (r.Method != "GET" || r.URL.Path != "/api/v2/role-bindings") {
			identityProblem(w, 400, "invalid_query")
			return
		}
		if write {
			if len(r.Header.Values("X-CSRF-Token")) != 1 {
				identityProblem(w, 403, "csrf_required")
				return
			}
			ok := false
			s.requireCSRF(func(http.ResponseWriter, *http.Request, *domain.SessionContext) { ok = true })(w, r, session)
			if !ok {
				return
			}
		}
		next(w, r, identity.LifecycleActor{TokenHash: session.TokenHash, Origin: s.cfg.ManagementOrigin, SourceIP: s.clientIP(r)})
	})
}
func (s *Server) roleRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v2/permissions", s.withRoles(false, func(w http.ResponseWriter, r *http.Request, a identity.LifecycleActor) {
		manager := s.identity.RoleBindingService()
		if manager == nil {
			roleError(w, identity.ErrLifecycleUnavailable)
			return
		}
		out, e := manager.Permissions(r.Context(), a)
		if e != nil {
			roleError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("GET /api/v2/roles", s.withRoles(false, func(w http.ResponseWriter, r *http.Request, a identity.LifecycleActor) {
		manager := s.identity.RoleBindingService()
		if manager == nil {
			roleError(w, identity.ErrLifecycleUnavailable)
			return
		}
		out, e := manager.Catalog(r.Context(), a)
		if e != nil {
			roleError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("GET /api/v2/role-bindings", s.withRoles(false, func(w http.ResponseWriter, r *http.Request, a identity.LifecycleActor) {
		limit, cursor, ok := oidcPage(w, r)
		if !ok {
			return
		}
		manager := s.identity.RoleBindingService()
		if manager == nil {
			roleError(w, identity.ErrLifecycleUnavailable)
			return
		}
		out, e := manager.Bindings(r.Context(), a, limit, cursor)
		if e != nil {
			roleError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("POST /api/v2/role-bindings", s.withRoles(true, func(w http.ResponseWriter, r *http.Request, a identity.LifecycleActor) {
		key, ok := configKey(w, r)
		if !ok {
			return
		}
		// Decode the union before the typed DTO: global must omit scopeId;
		// absent/null/empty non-global scope IDs never select a broader scope.
		var raw map[string]json.RawMessage
		if !strictIdentityJSON(w, r, &raw) {
			return
		}
		in, valid := roleBindingInput(raw)
		if !valid {
			roleError(w, identity.ErrLifecycleInvalid)
			return
		}
		manager := s.identity.RoleBindingService()
		if manager == nil {
			roleError(w, identity.ErrLifecycleUnavailable)
			return
		}
		out, e := manager.Create(r.Context(), a, key, in)
		if e != nil {
			roleError(w, e)
			return
		}
		roleAccepted(w, out)
	}))
	mux.HandleFunc("DELETE /api/v2/role-bindings/{id}", s.withRoles(true, func(w http.ResponseWriter, r *http.Request, a identity.LifecycleActor) {
		key, ok := configKey(w, r)
		if !ok {
			return
		}
		revision, ok := directoryRevision(w, r)
		if !ok {
			return
		}
		var in struct {
			Reason string `json:"reason"`
		}
		if !configBody(w, r, &in, 16<<10) {
			return
		}
		manager := s.identity.RoleBindingService()
		if manager == nil {
			roleError(w, identity.ErrLifecycleUnavailable)
			return
		}
		out, e := manager.Revoke(r.Context(), a, r.PathValue("id"), key, revision, in.Reason)
		if errors.Is(e, identity.ErrLifecycleStale) {
			identityProblem(w, 412, "identity_preconditions_changed")
			return
		}
		if e != nil {
			roleError(w, e)
			return
		}
		roleAccepted(w, out)
	}))
}
func roleAccepted(w http.ResponseWriter, o *identity.RoleSecurityOperation) {
	w.Header().Set("Location", "/api/v2/security/operations/"+o.ID)
	resourceID := o.SubjectID
	if o.RoleGrantRequest != nil {
		resourceID = o.RoleGrantRequest.BindingID
	} else if o.RoleBindingRevokeRequest != nil {
		resourceID = o.RoleBindingRevokeRequest.BindingID
	}
	writeJSON(w, 202, map[string]any{"operationId": o.ID, "resourceId": resourceID, "statusUrl": "/api/v2/security/operations/" + o.ID, "submittedAt": o.CreatedAt})
}
func (s *Server) roleOperation(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor, mode, key, digest, reason string) bool {
	id := r.PathValue("id")
	if !strings.HasPrefix(id, "roleop_") {
		return false
	}
	manager := s.identity.RoleBindingService()
	if manager == nil {
		roleError(w, identity.ErrLifecycleUnavailable)
		return true
	}
	actor := identity.LifecycleActor{TokenHash: a.TokenHash, Origin: a.Origin, SourceIP: s.clientIP(r)}
	switch mode {
	case "get":
		out, e := manager.GetOperation(r.Context(), actor, id)
		if e != nil {
			roleError(w, e)
		} else {
			writeJSON(w, 200, out)
		}
	case "approve":
		out, e := manager.ApproveOperationRequest(r.Context(), actor, id, key, digest, reason)
		if e != nil {
			roleError(w, e)
		} else {
			writeJSON(w, 201, out)
		}
	case "execute":
		out, e := manager.ExecuteOperationRequest(r.Context(), actor, id, key, digest, reason)
		if e != nil {
			roleError(w, e)
		} else {
			roleAccepted(w, out)
		}
	}
	return true
}

func roleBindingInput(fields map[string]json.RawMessage) (identity.RoleBindingRequest, bool) {
	var in identity.RoleBindingRequest
	if len(fields) != 3 && len(fields) != 4 {
		return in, false
	}
	for key, raw := range fields {
		var v string
		if string(raw) == "null" || json.Unmarshal(raw, &v) != nil {
			return in, false
		}
		switch key {
		case "principalId":
			in.PrincipalID = v
		case "roleId":
			in.RoleID = v
		case "scopeType":
			in.ScopeType = v
		case "scopeId":
			in.ScopeID = v
		default:
			return in, false
		}
	}
	for _, key := range []string{"principalId", "roleId", "scopeType"} {
		if _, ok := fields[key]; !ok {
			return in, false
		}
	}
	_, hasID := fields["scopeId"]
	if in.ScopeType == "global" {
		return in, !hasID
	}
	return in, hasID && in.ScopeID != ""
}

func roleError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, rolescope.ErrUnavailable):
		identityProblem(w, 503, "role_scope_unavailable")
	case errors.Is(e, rolescope.ErrInvalid):
		identityProblem(w, 400, "invalid_role_scope")
	default:
		lifecycleError(w, e)
	}
}
