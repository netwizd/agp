package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/configuration"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/repository"
	"github.com/netwizd/agp/internal/rolescope"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
	"github.com/netwizd/agp/internal/wafnative"
)

func (s *Server) SetConfiguration(service *configuration.Service) { s.configuration = service }

type configHandler func(http.ResponseWriter, *http.Request, configuration.Actor)

func (s *Server) withConfiguration(write bool, next configHandler) http.HandlerFunc {
	permission := "config.read"
	if write {
		permission = "config.edit"
	}
	return s.withConfigurationPermission(permission, write, next)
}

func (s *Server) withConfigurationPermission(permission string, write bool, next configHandler) http.HandlerFunc {
	return s.withConfigurationAdmission(permission, write, "", next)
}

func (s *Server) withGatewayConfiguration(write bool, next configHandler) http.HandlerFunc {
	permission := "config.read"
	if write {
		permission = "config.edit"
	}
	return s.withConfigurationAdmission(permission, write, "gateway", next)
}

func (s *Server) withResourceConfiguration(write bool, next configHandler) http.HandlerFunc {
	permission := "config.read"
	if write {
		permission = "config.edit"
	}
	return s.withConfigurationAdmission(permission, write, "resource", next)
}

func (s *Server) withConfigurationAdmission(permission string, write bool, scope string, next configHandler) http.HandlerFunc {
	return s.withSession(func(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
		if !s.cfg.ConfigurationEnabled || s.configuration == nil {
			configurationProblem(w, http.StatusNotFound, "configuration_disabled", nil)
			return
		}
		if !s.cfg.SecureProfile || !s.managementRequest(r) {
			configurationProblem(w, http.StatusForbidden, "permission_required", nil)
			return
		}
		if write {
			if session.MFAAt == nil || time.Since(*session.MFAAt) > 5*time.Minute {
				configurationProblem(w, http.StatusForbidden, "step_up_required", nil)
				return
			}
			values := r.Header.Values("X-CSRF-Token")
			if len(values) != 1 {
				configurationProblem(w, http.StatusForbidden, "csrf_required", nil)
				return
			}
			// Reuse the existing constant-time session CSRF verifier.
			verified := false
			s.requireCSRF(func(_ http.ResponseWriter, _ *http.Request, _ *domain.SessionContext) { verified = true })(w, r, session)
			if !verified {
				return
			}
		}
		actor := configuration.Actor{TokenHash: session.TokenHash, Origin: s.cfg.ManagementOrigin}
		var err error
		switch scope {
		case "resource":
			err = s.configuration.AuthorizeResource(r.Context(), actor, write)
		case "gateway":
			err = s.configuration.AuthorizeGateway(r.Context(), actor, write)
		default:
			err = s.configuration.AuthorizePermission(r.Context(), actor, permission, write)
		}
		if err != nil {
			configurationError(w, err)
			return
		}
		next(w, r, actor)
	})
}
func (s *Server) configurationRoutes(mux *http.ServeMux) {
	s.executionRoutes(mux)
	s.planProposalRoutes(mux)
	s.wafZoneRoutes(mux)
	s.wafPolicyRoutes(mux)
	for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		mux.HandleFunc(method+" /api/v2/", func(w http.ResponseWriter, _ *http.Request) { configurationProblem(w, 404, "not_found", nil) })
	}
	mux.HandleFunc("GET /api/v2/config/access", s.withResourceConfiguration(false, s.configurationAccess))
	mux.HandleFunc("GET /api/v2/gateways", s.withGatewayConfiguration(false, s.configurationListGateways))
	mux.HandleFunc("GET /api/v2/config/resources", s.withResourceConfiguration(false, s.configurationListResources))
	mux.HandleFunc("GET /api/v2/config/resources/{resourceId}/routes/{gatewayId}/{routeId}", s.withResourceConfiguration(false, s.configurationGetResource))
	mux.HandleFunc("GET /api/v2/config/profile", s.withConfiguration(false, s.configurationProfile))
	mux.HandleFunc("POST /api/v2/config/documents", s.withConfiguration(true, s.configurationDocument))
	mux.HandleFunc("POST /api/v2/config/drafts", s.withConfiguration(true, s.configurationCreateDraft))
	mux.HandleFunc("GET /api/v2/config/drafts/{id}", s.withConfiguration(false, s.configurationGetDraft))
	mux.HandleFunc("PUT /api/v2/config/drafts/{id}", s.withConfiguration(true, s.configurationUpdateDraft))
	mux.HandleFunc("POST /api/v2/config/drafts/{id}/revisions", s.withConfiguration(true, s.configurationSealDraft))
	mux.HandleFunc("POST /api/v2/config/drafts/{id}/previews", s.withConfiguration(true, s.configurationPreviewDraft))
	mux.HandleFunc("POST /api/v2/config/revisions", s.withResourceConfiguration(true, s.configurationCreateRevision))
	mux.HandleFunc("GET /api/v2/config/revisions", s.withConfiguration(false, s.configurationListRevisions))
	mux.HandleFunc("GET /api/v2/config/revisions/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("gatewayId") != "" {
			s.withGatewayConfiguration(false, s.configurationGetRevision)(w, r)
			return
		}
		s.withConfiguration(false, s.configurationGetRevision)(w, r)
	})
	mux.HandleFunc("POST /api/v2/config/revisions/{id}/validations", s.withConfiguration(true, s.configurationValidateRevision))
	mux.HandleFunc("GET /api/v2/config/validations/{id}", s.withConfiguration(false, s.configurationGetReport))
	mux.HandleFunc("GET /api/v2/operations/{id}", s.withConfiguration(false, s.configurationGetOperation))
	mux.HandleFunc("POST /api/v2/config/catalog-snapshots", s.withConfiguration(true, s.configurationImportCatalog))
	mux.HandleFunc("GET /api/v2/config/catalog-snapshots", s.withConfiguration(false, s.configurationListCatalogs))
}
func configurationProblem(w http.ResponseWriter, status int, code string, issues []configmodel.Issue) {
	if len(issues) > 100 {
		issues = issues[:100]
	}
	if issues == nil {
		issues = []configmodel.Issue{}
	}
	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "urn:agp:problem:" + code, "title": code, "status": status, "code": code, "traceId": securitystate.ID("trace"), "retryable": status == 503, "issues": issues})
}
func configurationError(w http.ResponseWriter, err error) {
	var validation *configmodel.ValidationError
	switch {
	case errors.Is(err, identity.ErrDirectoryUnavailable):
		configurationProblem(w, 503, "identity_provider_unavailable", nil)
	case errors.Is(err, identity.ErrProof):
		configurationProblem(w, 403, "permission_required", nil)
	case errors.Is(err, inventory.ErrNotFresh), errors.Is(err, inventory.ErrIdentity):
		configurationProblem(w, 409, "current_inventory_required", nil)
	case errors.Is(err, inventory.ErrUnavailable):
		configurationProblem(w, 503, "inventory_unavailable", nil)
	case errors.Is(err, wafnative.ErrBusy):
		w.Header().Set("Retry-After", "1")
		configurationProblem(w, 503, "native_waf_busy", nil)
	case errors.Is(err, repository.ErrUntrusted):
		configurationProblem(w, 409, "native_qualification_required", nil)
	case errors.As(err, &validation):
		for _, issue := range validation.Issues {
			if issue.Code == "native_qualification_required" || issue.Code == "trusted_inventory_required" {
				configurationProblem(w, 409, issue.Code, validation.Issues)
				return
			}
			if issue.Code == "unsupported_derivation" || issue.Code == "unsupported_exceptions" || issue.Code == "unsupported_profile_assignments" || issue.Code == "unsupported_gateway_onboarding" || issue.Code == "zone_change_required" || issue.Code == "zone_resolution_required" || issue.Code == "native_profile_mismatch" {
				configurationProblem(w, 422, issue.Code, validation.Issues)
				return
			}
		}
		configurationProblem(w, 400, "invalid_document", validation.Issues)
	case errors.Is(err, configuration.ErrRevisionMismatch):
		configurationProblem(w, 412, "revision_mismatch", nil)
	case errors.Is(err, configuration.ErrIdempotencyConflict):
		configurationProblem(w, 409, "idempotency_conflict", nil)
	case errors.Is(err, configuration.ErrInvalidRequest):
		configurationProblem(w, 400, "invalid_request", nil)
	case errors.Is(err, storage.ErrPermissionDenied):
		configurationProblem(w, 403, "permission_required", nil)
	case errors.Is(err, storage.ErrNotFound):
		configurationProblem(w, 404, "not_found", nil)
	case errors.Is(err, storage.ErrConflict):
		configurationProblem(w, 409, "conflict", nil)
	case errors.Is(err, rolescope.ErrUnavailable), errors.Is(err, securitystate.ErrBarrier), errors.Is(err, securitystate.ErrUnavailable), errors.Is(err, securityjournal.ErrUnavailable), errors.Is(err, configuration.ErrUnavailable):
		configurationProblem(w, 503, "security_state_unavailable", nil)
	default:
		configurationProblem(w, 500, "configuration_failed", nil)
	}
}
func configBody(w http.ResponseWriter, r *http.Request, out any, max int64) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		configurationProblem(w, 415, "json_required", nil)
		return false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, max))
	if err != nil {
		configurationProblem(w, 413, "document_too_large", nil)
		return false
	}
	err = configmodel.DecodeEnvelopeJSON(raw, out)
	if err != nil {
		configurationProblem(w, 400, "invalid_document", []configmodel.Issue{{Path: "", Code: "invalid_document", Message: "Expected a single strict JSON object with known fields", Severity: "error"}})
		return false
	}
	return true
}
func configKey(w http.ResponseWriter, r *http.Request) (string, bool) {
	v := r.Header.Values("Idempotency-Key")
	if len(v) != 1 || len(v[0]) < 16 || len(v[0]) > 128 || strings.IndexFunc(v[0], func(c rune) bool {
		return !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-')
	}) != -1 {
		configurationProblem(w, 400, "idempotency_key_required", nil)
		return "", false
	}
	return v[0], true
}
func configETag(w http.ResponseWriter, r *http.Request) (string, bool) {
	v := r.Header.Values("If-Match")
	if len(v) != 1 {
		configurationProblem(w, 428, "if_match_required", nil)
		return "", false
	}
	s := v[0]
	if len(s) < 3 || s[0] != '"' || s[len(s)-1] != '"' {
		configurationProblem(w, 400, "invalid_if_match", nil)
		return "", false
	}
	s = s[1 : len(s)-1]
	n, e := strconv.ParseInt(s, 10, 64)
	if e != nil || n < 0 || strconv.FormatInt(n, 10) != s {
		configurationProblem(w, 400, "invalid_if_match", nil)
		return "", false
	}
	return s, true
}
func configFormat(value string) (configmodel.Format, bool) {
	switch value {
	case "json":
		return configmodel.JSON, true
	case "yaml":
		return configmodel.YAML, true
	}
	return configmodel.JSON, false
}
func configurationWrite(w http.ResponseWriter, status int, value any, version string) {
	if version != "" {
		w.Header().Set("ETag", strconv.Quote(version))
	}
	writeJSON(w, status, value)
}

const configRequestMax int64 = (64 << 20) + 8192

func (s *Server) configurationProfile(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	p, e := s.configuration.Profile(r.Context(), a)
	if e != nil {
		configurationError(w, e)
		return
	}
	writeJSON(w, 200, p)
}
func (s *Server) configurationDocument(w http.ResponseWriter, r *http.Request, _ configuration.Actor) {
	var in struct {
		Format   string `json:"format"`
		Document string `json:"document"`
	}
	if !configBody(w, r, &in, 128<<20) {
		return
	}
	format, ok := configFormat(in.Format)
	if !ok {
		configurationProblem(w, 400, "unsupported_format", nil)
		return
	}
	doc, e := configmodel.ParseConfiguration(strings.NewReader(in.Document), format)
	if e != nil {
		configurationError(w, e)
		return
	}
	yaml, e := configmodel.YAMLDocument(doc.Configuration)
	if e != nil {
		configurationError(w, e)
		return
	}
	writeJSON(w, 200, map[string]any{"content": json.RawMessage(doc.Canonical), "contentDigest": doc.Digest, "canonicalJSON": string(doc.Canonical), "yaml": string(yaml)})
}
func (s *Server) configurationCreateDraft(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	key, ok := configKey(w, r)
	if !ok {
		return
	}
	var in configuration.CreateDraft
	if !configBody(w, r, &in, configRequestMax) {
		return
	}
	d, e := s.configuration.CreateDraft(r.Context(), a, key, in)
	if e != nil {
		configurationError(w, e)
		return
	}
	configurationWrite(w, 201, d, d.Revision)
}
func (s *Server) configurationGetDraft(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	d, e := s.configuration.GetDraft(r.Context(), a, r.PathValue("id"))
	if e != nil {
		configurationError(w, e)
		return
	}
	configurationWrite(w, 200, d, d.Revision)
}
func (s *Server) configurationUpdateDraft(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	key, ok := configKey(w, r)
	if !ok {
		return
	}
	version, ok := configETag(w, r)
	if !ok {
		return
	}
	var in struct {
		Content json.RawMessage `json:"content"`
	}
	if !configBody(w, r, &in, configRequestMax) {
		return
	}
	d, e := s.configuration.UpdateDraft(r.Context(), a, r.PathValue("id"), version, key, in.Content)
	if e != nil {
		configurationError(w, e)
		return
	}
	configurationWrite(w, 200, d, d.Revision)
}
func (s *Server) configurationSealDraft(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	key, ok := configKey(w, r)
	if !ok {
		return
	}
	version, ok := configETag(w, r)
	if !ok {
		return
	}
	var in struct{}
	if !configBody(w, r, &in, 1024) {
		return
	}
	rev, e := s.configuration.SealDraft(r.Context(), a, r.PathValue("id"), version, key)
	if e != nil {
		configurationError(w, e)
		return
	}
	configurationWrite(w, 201, rev, rev.Revision)
}
func (s *Server) configurationCreateRevision(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	key, ok := configKey(w, r)
	if !ok {
		return
	}
	var in configuration.CreateRevision
	if !configBody(w, r, &in, configRequestMax) {
		return
	}
	var rev *configuration.Revision
	var e error
	if in.ResourceChange != nil {
		rev, e = s.configuration.ChangeResource(r.Context(), a, key, in)
	} else if in.GatewayChange != nil {
		rev, e = s.configuration.ChangeGateway(r.Context(), a, key, in)
	} else {
		rev, e = s.configuration.CreateRevision(r.Context(), a, key, in)
	}
	if e != nil {
		configurationError(w, e)
		return
	}
	configurationWrite(w, 201, rev, rev.Revision)
}

func (s *Server) configurationListResources(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	limit := 50
	if value := r.URL.Query().Get("limit"); value != "" {
		var err error
		limit, err = strconv.Atoi(value)
		if err != nil {
			configurationProblem(w, 400, "invalid_limit", nil)
			return
		}
	}
	out, err := s.configuration.ListResources(r.Context(), a, r.URL.Query().Get("revisionId"), limit, r.URL.Query().Get("cursor"))
	if err != nil {
		configurationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) configurationGetResource(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	out, err := s.configuration.ResourceRevision(r.Context(), a, r.URL.Query().Get("revisionId"), r.PathValue("resourceId"), r.PathValue("gatewayId"), r.PathValue("routeId"))
	if err != nil {
		configurationError(w, err)
		return
	}
	configurationWrite(w, http.StatusOK, out, out.Revision)
}

func (s *Server) configurationListGateways(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	limit := 50
	if value := r.URL.Query().Get("limit"); value != "" {
		var err error
		limit, err = strconv.Atoi(value)
		if err != nil {
			configurationProblem(w, 400, "invalid_limit", nil)
			return
		}
	}
	out, err := s.configuration.ListGateways(r.Context(), a, r.URL.Query().Get("revisionId"), limit, r.URL.Query().Get("cursor"))
	if err != nil {
		configurationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
func (s *Server) configurationGetRevision(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	if r.URL.Query().Get("gatewayId") != "" {
		rev, e := s.configuration.GatewayRevision(r.Context(), a, r.PathValue("id"), r.URL.Query().Get("gatewayId"))
		if e != nil {
			configurationError(w, e)
			return
		}
		configurationWrite(w, 200, rev, rev.Revision)
		return
	}
	rev, e := s.configuration.GetRevision(r.Context(), a, r.PathValue("id"))
	if e != nil {
		configurationError(w, e)
		return
	}
	configurationWrite(w, 200, rev, rev.Revision)
}
func (s *Server) configurationListRevisions(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		var e error
		limit, e = strconv.Atoi(v)
		if e != nil {
			configurationProblem(w, 400, "invalid_limit", nil)
			return
		}
	}
	out, e := s.configuration.ListRevisions(r.Context(), a, limit, r.URL.Query().Get("cursor"))
	if e != nil {
		configurationError(w, e)
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) configurationImportCatalog(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	key, ok := configKey(w, r)
	if !ok {
		return
	}
	var in struct {
		Format   string `json:"format"`
		Document string `json:"document"`
	}
	if !configBody(w, r, &in, 128<<20) {
		return
	}
	format, ok := configFormat(in.Format)
	if !ok {
		configurationProblem(w, 400, "unsupported_format", nil)
		return
	}
	out, e := s.configuration.ImportCatalog(r.Context(), a, key, []byte(in.Document), format)
	if e != nil {
		configurationError(w, e)
		return
	}
	writeJSON(w, 201, out)
}
func (s *Server) configurationListCatalogs(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	items, e := s.configuration.ListCatalogs(r.Context(), a)
	if e != nil {
		configurationError(w, e)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (s *Server) configurationPreviewDraft(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	key, ok := configKey(w, r)
	if !ok {
		return
	}
	var in struct {
		CatalogSnapshotID string `json:"catalogSnapshotId,omitempty"`
	}
	if !configBody(w, r, &in, 1024) {
		return
	}
	report, e := s.configuration.PreviewDraft(r.Context(), a, r.PathValue("id"), in.CatalogSnapshotID, key)
	if e != nil {
		configurationError(w, e)
		return
	}
	writeJSON(w, 200, report)
}
func (s *Server) configurationValidateRevision(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	key, ok := configKey(w, r)
	if !ok {
		return
	}
	var in struct{}
	if !configBody(w, r, &in, 1024) {
		return
	}
	out, e := s.configuration.ValidateRevision(r.Context(), a, r.PathValue("id"), key)
	if e != nil {
		configurationError(w, e)
		return
	}
	w.Header().Set("Location", out.StatusURL)
	writeJSON(w, 202, out)
}
func (s *Server) configurationGetReport(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	out, e := s.configuration.GetReport(r.Context(), a, r.PathValue("id"))
	if e != nil {
		configurationError(w, e)
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) configurationGetOperation(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	out, e := s.configuration.GetWafPolicyOperation(r.Context(), a, r.PathValue("id"))
	if errors.Is(e, storage.ErrNotFound) {
		out, e = s.configuration.GetZoneOperation(r.Context(), a, r.PathValue("id"))
	}
	if errors.Is(e, storage.ErrNotFound) {
		access, accessErr := s.configuration.Access(r.Context(), a)
		if accessErr != nil {
			e = accessErr
		} else if access.GlobalRead {
			out, e = s.configuration.GetOperation(r.Context(), a, r.PathValue("id"))
		}
	}
	if e != nil {
		configurationError(w, e)
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) configurationAccess(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	out, e := s.configuration.Access(r.Context(), a)
	if e != nil {
		configurationError(w, e)
		return
	}
	writeJSON(w, 200, out)
}
