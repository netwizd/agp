package httpapi

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/netwizd/agp/internal/identity"
)

func (s *Server) SetOIDC(service *identity.OIDCService) { s.oidc = service }

func oidcError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, identity.ErrOIDCReauthRequired):
		identityProblem(w, 403, "step_up_required")
	case errors.Is(err, identity.ErrOIDCInvalid):
		identityProblem(w, 400, "invalid_oidc_request")
	case errors.Is(err, identity.ErrOIDCStale):
		identityProblem(w, 409, "oidc_preconditions_changed")
	default:
		directoryError(w, err)
	}
}
func (s *Server) withOIDC(write bool, next directoryHandler) http.HandlerFunc {
	return s.withDirectory(write, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		if s.oidc == nil {
			identityProblem(w, 503, "identity_provider_unavailable")
			return
		}
		for _, name := range []string{"id", "versionId", "testId", "linkId"} {
			if value := r.PathValue(name); value != "" && !validIdentityID(value) {
				identityProblem(w, 400, "invalid_oidc_request")
				return
			}
		}
		page := r.Method == http.MethodGet && (r.URL.Path == "/api/v2/identity-providers" || strings.HasSuffix(r.URL.Path, "/links"))
		if !page && r.URL.RawQuery != "" {
			identityProblem(w, 400, "invalid_query")
			return
		}
		next(w, r, a)
	})
}
func oidcPage(w http.ResponseWriter, r *http.Request) (int, string, bool) {
	query, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		identityProblem(w, 400, "invalid_query")
		return 0, "", false
	}
	for key, values := range query {
		if (key != "limit" && key != "cursor") || len(values) != 1 {
			identityProblem(w, 400, "invalid_query")
			return 0, "", false
		}
	}
	limit := 50
	if raw, exists := query["limit"]; exists {
		n, e := strconv.Atoi(raw[0])
		if e != nil || n < 1 || n > 200 {
			identityProblem(w, 400, "invalid_query")
			return 0, "", false
		}
		limit = n
	}
	cursor := query.Get("cursor")
	if cursor != "" && !validIdentityID(cursor) {
		identityProblem(w, 400, "invalid_query")
		return 0, "", false
	}
	return limit, cursor, true
}
func (s *Server) oidcRoutes(mux *http.ServeMux) {
	const base = "/api/v2/identity-providers"
	mux.HandleFunc("GET "+base, s.withOIDC(false, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		limit, cursor, ok := oidcPage(w, r)
		if !ok {
			return
		}
		out, e := s.oidc.ListProviders(r.Context(), a, limit, cursor)
		if e != nil {
			oidcError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("POST "+base, s.withOIDC(true, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		var in identity.OIDCProviderCreate
		if !configBody(w, r, &in, 4096) {
			return
		}
		out, e := s.oidc.CreateProvider(r.Context(), a, in)
		if e != nil {
			oidcError(w, e)
			return
		}
		directoryTag(w, out.Revision)
		writeJSON(w, 201, out)
	}))
	mux.HandleFunc("GET "+base+"/{id}", s.withOIDC(false, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		out, e := s.oidc.GetProvider(r.Context(), a, r.PathValue("id"))
		if e != nil {
			oidcError(w, e)
			return
		}
		directoryTag(w, out.Revision)
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("PUT "+base+"/{id}", s.withOIDC(true, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		expected, ok := directoryRevision(w, r)
		if !ok {
			return
		}
		var in identity.OIDCProviderDocument
		if !configBody(w, r, &in, 64<<10) {
			return
		}
		out, e := s.oidc.ProposeVersion(r.Context(), a, r.PathValue("id"), expected, in)
		if errors.Is(e, identity.ErrOIDCStale) {
			identityProblem(w, 412, "oidc_preconditions_changed")
			return
		}
		if e != nil {
			oidcError(w, e)
			return
		}
		directoryTag(w, expected+1)
		writeJSON(w, 201, out.Configuration)
	}))
	mux.HandleFunc("GET "+base+"/{id}/versions/{versionId}", s.withOIDC(false, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		out, e := s.oidc.GetVersion(r.Context(), a, r.PathValue("id"), r.PathValue("versionId"))
		if e != nil {
			oidcError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("POST "+base+"/{id}/tests", s.withOIDC(true, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		var in struct {
			VersionID string `json:"versionId"`
		}
		if !configBody(w, r, &in, 4096) {
			return
		}
		out, e := s.oidc.TestProvider(r.Context(), a, r.PathValue("id"), in.VersionID)
		if e != nil {
			oidcError(w, e)
			return
		}
		w.Header().Set("Location", base+"/"+r.PathValue("id")+"/tests/"+out.OperationID)
		writeJSON(w, 202, out)
	}))
	mux.HandleFunc("GET "+base+"/{id}/tests/{testId}", s.withOIDC(false, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		out, e := s.oidc.GetTest(r.Context(), a, r.PathValue("id"), r.PathValue("testId"))
		if e != nil {
			oidcError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("POST "+base+"/{id}/activations", s.withOIDC(true, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		expected, ok := directoryRevision(w, r)
		if !ok {
			return
		}
		key, ok := configKey(w, r)
		if !ok {
			return
		}
		var in identity.DirectoryActivation
		if !configBody(w, r, &in, 16384) {
			return
		}
		out, e := s.oidc.PlanActivationAtRevision(r.Context(), a, r.PathValue("id"), key, expected, in)
		if errors.Is(e, identity.ErrOIDCStale) {
			identityProblem(w, 412, "oidc_preconditions_changed")
			return
		}
		if e != nil {
			oidcError(w, e)
			return
		}
		w.Header().Set("Location", "/api/v2/security/operations/"+out.ID)
		writeJSON(w, 202, out)
	}))
	mux.HandleFunc("GET "+base+"/{id}/links", s.withOIDC(false, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		limit, cursor, ok := oidcPage(w, r)
		if !ok {
			return
		}
		out, e := s.oidc.ListLinks(r.Context(), a, r.PathValue("id"), limit, cursor)
		if e != nil {
			oidcError(w, e)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("POST "+base+"/{id}/links", s.withOIDC(true, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		key, ok := configKey(w, r)
		if !ok {
			return
		}
		var in identity.OIDCLinkCreate
		if !configBody(w, r, &in, 16384) {
			return
		}
		out, e := s.oidc.PlanLink(r.Context(), a, r.PathValue("id"), key, in)
		if e != nil {
			oidcError(w, e)
			return
		}
		w.Header().Set("Location", "/api/v2/security/operations/"+out.ID)
		writeJSON(w, 202, out)
	}))
	mux.HandleFunc("GET "+base+"/{id}/links/{linkId}", s.withOIDC(false, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		out, e := s.oidc.GetLink(r.Context(), a, r.PathValue("id"), r.PathValue("linkId"))
		if e != nil {
			oidcError(w, e)
			return
		}
		directoryTag(w, out.Revision)
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("POST "+base+"/{id}/links/{linkId}/changes", s.withOIDC(true, func(w http.ResponseWriter, r *http.Request, a identity.DirectoryActor) {
		expected, ok := directoryRevision(w, r)
		if !ok {
			return
		}
		key, ok := configKey(w, r)
		if !ok {
			return
		}
		var in identity.OIDCLinkSuccessor
		if !configBody(w, r, &in, 16384) {
			return
		}
		out, e := s.oidc.PlanLinkChange(r.Context(), a, r.PathValue("id"), r.PathValue("linkId"), key, expected, in)
		if errors.Is(e, identity.ErrOIDCStale) {
			identityProblem(w, 412, "oidc_preconditions_changed")
			return
		}
		if e != nil {
			oidcError(w, e)
			return
		}
		w.Header().Set("Location", "/api/v2/security/operations/"+out.ID)
		writeJSON(w, 202, out)
	}))
}
