package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// SetDirectory is startup-only. A nil connector keeps provider tests/enable
// unavailable; no browser supplied validation or credentials are accepted.
func (s *Server) SetDirectory(service *identity.DirectoryService) { s.directory = service }

type directoryHandler func(http.ResponseWriter, *http.Request, identity.DirectoryActor)

func (s *Server) withDirectory(write bool, next directoryHandler) http.HandlerFunc {
	return s.withSession(func(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
		w.Header().Set("Cache-Control", "no-store")
		if !s.cfg.SecureProfile || !s.managementRequest(r) {
			identityProblem(w, 403, "permission_required")
			return
		}
		if s.directory == nil {
			identityProblem(w, 503, "identity_provider_unavailable")
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
		// The service repeats permission, session, fresh MFA and independent
		// journal checks in the same transaction as every operation/replay.
		next(w, r, identity.DirectoryActor{TokenHash: session.TokenHash, Origin: s.cfg.ManagementOrigin})
	})
}

func directoryError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, identity.ErrProof):
		identityProblem(w, 403, "permission_required")
	case errors.Is(err, identity.ErrLimited):
		identityProblem(w, 429, "rate_limited")
	case errors.Is(err, identity.ErrDirectoryInvalid):
		identityProblem(w, 400, "invalid_directory_request")
	case errors.Is(err, storage.ErrPermissionDenied):
		identityProblem(w, 403, "permission_required")
	case errors.Is(err, storage.ErrNotFound):
		identityProblem(w, 404, "not_found")
	case errors.Is(err, storage.ErrConflict):
		identityProblem(w, 409, "conflict")
	case errors.Is(err, identity.ErrDirectoryStale):
		identityProblem(w, 409, "directory_preconditions_changed")
	case errors.Is(err, securitystate.ErrBarrier), errors.Is(err, securitystate.ErrUnavailable), errors.Is(err, securityjournal.ErrUnavailable):
		identityProblem(w, 503, "security_state_unavailable")
	default:
		identityProblem(w, 503, "identity_provider_unavailable")
	}
}

func directoryRevision(w http.ResponseWriter, r *http.Request) (securityjournal.UInt63, bool) {
	raw, ok := configETag(w, r)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(raw, 10, 63)
	if err != nil || n == 0 {
		identityProblem(w, 400, "invalid_if_match")
		return 0, false
	}
	return securityjournal.UInt63(n), true
}

func directoryTag(w http.ResponseWriter, rev securityjournal.UInt63) {
	w.Header().Set("ETag", `"`+strconv.FormatUint(uint64(rev), 10)+`"`)
}

func (s *Server) directoryRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v2/directory-access", s.withDirectory(false, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		out, err := s.directory.Access(r.Context(), a)
		if err != nil {
			directoryError(w, err)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("POST /api/v2/directory-providers/{id}/identities", s.withDirectory(true, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		var in struct {
			ObjectGUID string `json:"objectGuid"`
		}
		if !configBody(w, r, &in, 4096) {
			return
		}
		out, err := s.directory.ProvisionIdentity(r.Context(), a, r.PathValue("id"), in.ObjectGUID)
		if err != nil {
			directoryError(w, err)
			return
		}
		writeJSON(w, 201, out)
	}))
	mux.HandleFunc("GET /api/v2/directory-providers/{id}/identities", s.withDirectory(false, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		q := r.URL.Query()
		limit := 50
		for key, values := range q {
			if (key != "limit" && key != "cursor") || len(values) != 1 {
				identityProblem(w, 400, "invalid_directory_request")
				return
			}
		}
		if raw, exists := q["limit"]; exists {
			n, err := strconv.Atoi(raw[0])
			if err != nil || n < 1 || n > 200 {
				identityProblem(w, 400, "invalid_directory_request")
				return
			}
			limit = n
		}
		out, err := s.directory.ListIdentities(r.Context(), a, r.PathValue("id"), limit, q.Get("cursor"))
		if err != nil {
			directoryError(w, err)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("POST /api/v2/directory-providers", s.withDirectory(true, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		var in identity.DirectoryCreate
		if !configBody(w, r, &in, 4096) {
			return
		}
		out, err := s.directory.CreateProvider(r.Context(), a, in)
		if err != nil {
			directoryError(w, err)
			return
		}
		directoryTag(w, out.Revision)
		w.Header().Set("Location", "/api/v2/directory-providers/"+out.ID)
		writeJSON(w, 201, out)
	}))
	mux.HandleFunc("GET /api/v2/directory-providers", s.withDirectory(false, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		q := r.URL.Query()
		limit := 50
		for key, values := range q {
			if (key != "limit" && key != "cursor") || len(values) != 1 {
				identityProblem(w, 400, "invalid_directory_request")
				return
			}
		}
		if raw, ok := q["limit"]; ok {
			n, err := strconv.Atoi(raw[0])
			if err != nil || n < 1 || n > 200 {
				identityProblem(w, 400, "invalid_directory_request")
				return
			}
			limit = n
		}
		out, err := s.directory.ListProviders(r.Context(), a, limit, q.Get("cursor"))
		if err != nil {
			directoryError(w, err)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("GET /api/v2/directory-providers/{id}", s.withDirectory(false, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		out, err := s.directory.GetProvider(r.Context(), a, r.PathValue("id"))
		if err != nil {
			directoryError(w, err)
			return
		}
		directoryTag(w, out.Revision)
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("PUT /api/v2/directory-providers/{id}", s.withDirectory(true, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		rev, ok := directoryRevision(w, r)
		if !ok {
			return
		}
		var in identity.DirectoryProviderDocument
		if !configBody(w, r, &in, identity.DirectoryDocumentLimit) {
			return
		}
		out, err := s.directory.ProposeVersion(r.Context(), a, r.PathValue("id"), rev, in)
		if errors.Is(err, identity.ErrDirectoryStale) {
			identityProblem(w, 412, "directory_preconditions_changed")
			return
		}
		if err != nil {
			directoryError(w, err)
			return
		}
		directoryTag(w, rev+1)
		writeJSON(w, 201, out.Configuration)
	}))
	mux.HandleFunc("GET /api/v2/directory-providers/{id}/versions/{versionId}", s.withDirectory(false, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		out, err := s.directory.GetVersion(r.Context(), a, r.PathValue("id"), r.PathValue("versionId"))
		if err != nil {
			directoryError(w, err)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("POST /api/v2/directory-providers/{id}/tests", s.withDirectory(true, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		var in struct {
			VersionID string `json:"versionId"`
		}
		if !configBody(w, r, &in, 4096) {
			return
		}
		out, err := s.directory.TestProvider(r.Context(), a, r.PathValue("id"), in.VersionID)
		if err != nil {
			directoryError(w, err)
			return
		}
		w.Header().Set("Location", "/api/v2/directory-providers/"+r.PathValue("id")+"/tests/"+out.OperationID)
		writeJSON(w, 202, out)
	}))
	mux.HandleFunc("GET /api/v2/directory-providers/{id}/tests/{testId}", s.withDirectory(false, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		out, err := s.directory.GetTest(r.Context(), a, r.PathValue("id"), r.PathValue("testId"))
		if err != nil {
			directoryError(w, err)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("POST /api/v2/directory-providers/{id}/activations", s.withDirectory(true, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		rev, ok := directoryRevision(w, r)
		if !ok {
			return
		}
		key := securitystate.ID("activation_request")
		if _, exists := r.Header["Idempotency-Key"]; exists {
			var valid bool
			key, valid = configKey(w, r)
			if !valid {
				return
			}
		}
		var in identity.DirectoryActivation
		if !configBody(w, r, &in, 4096) {
			return
		}
		out, err := s.directory.PlanActivationAtRevision(r.Context(), a, r.PathValue("id"), key, rev, in)
		if errors.Is(err, identity.ErrDirectoryStale) {
			identityProblem(w, 412, "directory_preconditions_changed")
			return
		}
		if err != nil {
			directoryError(w, err)
			return
		}
		w.Header().Set("Location", "/api/v2/security/operations/"+out.ID)
		writeJSON(w, 202, out)
	}))
	mux.HandleFunc("GET /api/v2/security/operations/{id}", s.withSecurityOperation(false, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		if s.roleOperation(w, r, a, "get", "", "", "") {
			return
		}
		if s.lifecycleOperation(w, r, a, "get", "", "", "") {
			return
		}
		if strings.HasPrefix(r.PathValue("id"), "oidcop_") {
			if s.oidc == nil {
				identityProblem(w, 503, "identity_provider_unavailable")
				return
			}
			out, err := s.oidc.GetOperation(r.Context(), a, r.PathValue("id"))
			if err != nil {
				oidcError(w, err)
				return
			}
			writeJSON(w, 200, out)
			return
		}
		out, err := s.directory.GetOperation(r.Context(), a, r.PathValue("id"))
		if err != nil {
			directoryError(w, err)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("POST /api/v2/security/operations/{id}/approvals", s.withSecurityOperation(true, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		key, ok := configKey(w, r)
		if !ok {
			return
		}
		var in struct {
			RequestDigest string `json:"requestDigest"`
			Reason        string `json:"reason"`
		}
		if !configBody(w, r, &in, 16384) {
			return
		}
		if s.roleOperation(w, r, a, "approve", key, in.RequestDigest, in.Reason) {
			return
		}
		if s.lifecycleOperation(w, r, a, "approve", key, in.RequestDigest, in.Reason) {
			return
		}
		if strings.HasPrefix(r.PathValue("id"), "oidcop_") {
			if s.oidc == nil {
				identityProblem(w, 503, "identity_provider_unavailable")
				return
			}
			out, err := s.oidc.ApproveOperationRequest(r.Context(), a, r.PathValue("id"), key, in.RequestDigest, in.Reason)
			if err != nil {
				oidcError(w, err)
				return
			}
			writeJSON(w, 201, out)
			return
		}
		out, err := s.directory.ApproveOperationRequest(r.Context(), a, r.PathValue("id"), key, in.RequestDigest, in.Reason)
		if err != nil {
			directoryError(w, err)
			return
		}
		writeJSON(w, 201, out)
	}))
	mux.HandleFunc("POST /api/v2/security/operations/{id}/executions", s.withSecurityOperation(true, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		key, ok := configKey(w, r)
		if !ok {
			return
		}
		var in struct {
			RequestDigest string `json:"requestDigest"`
			Reason        string `json:"reason"`
		}
		if !configBody(w, r, &in, 16384) {
			return
		}
		if s.roleOperation(w, r, a, "execute", key, in.RequestDigest, in.Reason) {
			return
		}
		if s.lifecycleOperation(w, r, a, "execute", key, in.RequestDigest, in.Reason) {
			return
		}
		if strings.HasPrefix(r.PathValue("id"), "oidcop_") {
			if s.oidc == nil {
				identityProblem(w, 503, "identity_provider_unavailable")
				return
			}
			out, err := s.oidc.ExecuteOperationRequest(r.Context(), a, r.PathValue("id"), key, in.RequestDigest, in.Reason)
			if err != nil {
				oidcError(w, err)
				return
			}
			writeJSON(w, 202, map[string]any{"operationId": out.ID, "resourceId": out.SubjectID, "statusUrl": "/api/v2/security/operations/" + out.ID, "submittedAt": out.CreatedAt})
			return
		}
		out, err := s.directory.ExecuteOperationRequest(r.Context(), a, r.PathValue("id"), key, in.RequestDigest, in.Reason)
		if err != nil {
			directoryError(w, err)
			return
		}
		writeJSON(w, 202, map[string]any{"operationId": out.ID, "resourceId": out.SubjectID, "statusUrl": "/api/v2/security/operations/" + out.ID, "submittedAt": out.CreatedAt})
	}))
}
