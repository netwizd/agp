package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/storage"
)

type lifecycleHandler func(http.ResponseWriter, *http.Request, identity.LifecycleActor)

func (s *Server) withLifecycle(write bool, next lifecycleHandler) http.HandlerFunc {
	return s.withSession(func(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
		w.Header().Set("Cache-Control", "no-store")
		if !s.cfg.SecureProfile || s.identity == nil || !s.managementRequest(r) {
			identityProblem(w, 403, "permission_required")
			return
		}
		for _, key := range []string{"id"} {
			if value := r.PathValue(key); value != "" && !validIdentityID(value) {
				identityProblem(w, 400, "invalid_identity_request")
				return
			}
		}
		if r.URL.RawQuery != "" && r.URL.Path != "/api/v2/users" {
			identityProblem(w, 400, "invalid_query")
			return
		}
		if write {
			if len(r.Header.Values("X-CSRF-Token")) != 1 {
				identityProblem(w, 403, "csrf_required")
				return
			}
			verified := false
			s.requireCSRF(func(http.ResponseWriter, *http.Request, *domain.SessionContext) { verified = true })(w, r, session)
			if !verified {
				return
			}
		}
		next(w, r, identity.LifecycleActor{TokenHash: session.TokenHash, Origin: s.cfg.ManagementOrigin, SourceIP: s.clientIP(r)})
	})
}
func lifecycleError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, identity.ErrLifecycleInvalid):
		identityProblem(w, 400, "invalid_identity_request")
	case errors.Is(e, identity.ErrLifecycleStale):
		identityProblem(w, 409, "identity_preconditions_changed")
	case errors.Is(e, identity.ErrLifecycleReauthRequired):
		identityProblem(w, 403, "step_up_required")
	case errors.Is(e, identity.ErrLifecycleUnavailable), errors.Is(e, identity.ErrEmailUnavailable):
		identityProblem(w, 503, "identity_lifecycle_unavailable")
	case errors.Is(e, storage.ErrApprovalRequired):
		identityProblem(w, 403, "approval_required")
	default:
		directoryError(w, e)
	}
}
func (s *Server) lifecycleRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v2/identity-access", s.withLifecycle(false, func(w http.ResponseWriter, r *http.Request, a identity.LifecycleActor) {
		out, e := s.identity.LifecycleAccess(r.Context(), a)
		if e != nil {
			lifecycleError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("GET /api/v2/users", s.withLifecycle(false, func(w http.ResponseWriter, r *http.Request, a identity.LifecycleActor) {
		limit, cursor, ok := oidcPage(w, r)
		if !ok {
			return
		}
		out, e := s.identity.LifecycleUsers(r.Context(), a, limit, cursor)
		if e != nil {
			lifecycleError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("GET /api/v2/users/{id}", s.withLifecycle(false, func(w http.ResponseWriter, r *http.Request, a identity.LifecycleActor) {
		out, e := s.identity.LifecycleUser(r.Context(), a, r.PathValue("id"))
		if e != nil {
			lifecycleError(w, e)
			return
		}
		directoryTag(w, out.Revision)
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("POST /api/v2/users", s.withLifecycle(true, func(w http.ResponseWriter, r *http.Request, a identity.LifecycleActor) {
		key, ok := configKey(w, r)
		if !ok {
			return
		}
		var in identity.PendingUserInput
		if !strictIdentityJSON(w, r, &in) {
			return
		}
		manager := s.identity.InvitationService()
		if manager == nil {
			lifecycleError(w, identity.ErrLifecycleUnavailable)
			return
		}
		out, e := manager.CreatePending(r.Context(), a, key, in)
		if e != nil {
			lifecycleError(w, e)
			return
		}
		directoryTag(w, out.Revision)
		w.Header().Set("Location", "/api/v2/users/"+out.ID)
		writeJSON(w, 201, out)
	}))
	mux.HandleFunc("POST /api/v2/users/{id}/invites", s.withLifecycle(true, func(w http.ResponseWriter, r *http.Request, a identity.LifecycleActor) {
		key, ok := configKey(w, r)
		if !ok {
			return
		}
		rev, ok := directoryRevision(w, r)
		if !ok {
			return
		}
		var in identity.InviteRequest
		if !strictIdentityJSON(w, r, &in) {
			return
		}
		manager := s.identity.InvitationService()
		if manager == nil {
			lifecycleError(w, identity.ErrLifecycleUnavailable)
			return
		}
		out, e := manager.CreateInvite(r.Context(), a, r.PathValue("id"), key, rev, in)
		if errors.Is(e, identity.ErrLifecycleStale) {
			identityProblem(w, 412, "identity_preconditions_changed")
			return
		}
		if e != nil {
			lifecycleError(w, e)
			return
		}
		w.Header().Set("Location", "/api/v2/identity-deliveries/"+out.DeliveryOperationID)
		writeJSON(w, 201, out)
	}))
	mux.HandleFunc("GET /api/v2/identity-deliveries/{id}", s.withLifecycle(false, func(w http.ResponseWriter, r *http.Request, a identity.LifecycleActor) {
		manager := s.identity.InvitationService()
		if manager == nil {
			lifecycleError(w, identity.ErrLifecycleUnavailable)
			return
		}
		out, e := manager.GetDelivery(r.Context(), a, r.PathValue("id"))
		if e != nil {
			lifecycleError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	for path, action := range map[string]string{"mfa-recovery-plans": "replace_mfa", "password-reset-plans": "reset_password", "activation-recovery-plans": "restart_activation"} {
		mux.HandleFunc("POST /api/v2/users/{id}/"+path, s.withLifecycle(true, func(w http.ResponseWriter, r *http.Request, a identity.LifecycleActor) {
			key, ok := configKey(w, r)
			if !ok {
				return
			}
			var in identity.RecoveryPlanRequest
			if !strictIdentityJSON(w, r, &in) {
				return
			}
			if in.TargetPrincipalID != r.PathValue("id") || in.AllowedAction != action {
				lifecycleError(w, identity.ErrLifecycleInvalid)
				return
			}
			manager := s.identity.RecoveryService()
			if manager == nil {
				lifecycleError(w, identity.ErrLifecycleUnavailable)
				return
			}
			out, e := manager.Plan(r.Context(), a, r.PathValue("id"), key, in)
			if e != nil {
				lifecycleError(w, e)
				return
			}
			w.Header().Set("Location", "/api/v2/security/operations/"+out.ID)
			writeJSON(w, 202, out)
		}))
	}
	mux.HandleFunc("POST /api/v2/security/operations/{id}/recovery-tickets", s.withLifecycle(true, func(w http.ResponseWriter, r *http.Request, a identity.LifecycleActor) {
		if !emptyIdentityJSON(w, r) {
			return
		}
		manager := s.identity.RecoveryService()
		if manager == nil {
			lifecycleError(w, identity.ErrLifecycleUnavailable)
			return
		}
		out, e := manager.IssueTicket(r.Context(), a, r.PathValue("id"))
		if e != nil {
			lifecycleError(w, e)
			return
		}
		writeJSON(w, 201, out)
	}))
}

// Operation namespaces select a single authority path before any mutation.
func (s *Server) withSecurityOperation(write bool, next directoryHandler) http.HandlerFunc {
	ordinary := s.withDirectory(write, next)
	recovery := s.withLifecycle(write, func(w http.ResponseWriter, r *http.Request, a identity.LifecycleActor) {
		next(w, r, identity.DirectoryActor{TokenHash: a.TokenHash, Origin: a.Origin})
	})
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.PathValue("id"), "recoveryop_") || strings.HasPrefix(r.PathValue("id"), "roleop_") {
			recovery(w, r)
		} else {
			ordinary(w, r)
		}
	}
}
func (s *Server) lifecycleOperation(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor, mode, key, digest, reason string) bool {
	id := r.PathValue("id")
	if !strings.HasPrefix(id, "recoveryop_") {
		return false
	}
	manager := s.identity.RecoveryService()
	if manager == nil {
		lifecycleError(w, identity.ErrLifecycleUnavailable)
		return true
	}
	actor := identity.LifecycleActor{TokenHash: a.TokenHash, Origin: a.Origin, SourceIP: s.clientIP(r)}
	switch mode {
	case "get":
		out, e := manager.GetOperation(r.Context(), actor, id)
		if e != nil {
			lifecycleError(w, e)
		} else {
			writeJSON(w, 200, out)
		}
	case "approve":
		out, e := manager.ApproveOperationRequest(r.Context(), actor, id, key, digest, reason)
		if e != nil {
			lifecycleError(w, e)
		} else {
			writeJSON(w, 201, out)
		}
	case "execute":
		out, e := manager.ExecuteOperationRequest(r.Context(), actor, id, key, digest, reason)
		if e != nil {
			lifecycleError(w, e)
		} else {
			writeJSON(w, 202, map[string]any{"operationId": out.ID, "resourceId": out.SubjectID, "statusUrl": "/api/v2/security/operations/" + out.ID, "submittedAt": out.CreatedAt})
		}
	default:
		identityProblem(w, 400, "invalid_identity_request")
	}
	return true
}
