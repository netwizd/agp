package httpapi

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/diagnostics"
	"github.com/netwizd/agp/internal/domain"
	nginxgen "github.com/netwizd/agp/internal/reverseproxy/nginx"
	"github.com/netwizd/agp/internal/storage"
)

type adminCreateUserRequest struct {
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	DisplayName string   `json:"display_name"`
	IsAdmin     bool     `json:"is_admin"`
	GroupIDs    []string `json:"group_ids"`
}

type adminUpdateUserRequest struct {
	DisplayName *string   `json:"display_name"`
	IsAdmin     *bool     `json:"is_admin"`
	Blocked     *bool     `json:"blocked"`
	Password    *string   `json:"password"`
	GroupIDs    *[]string `json:"group_ids"`
}

type adminGroupRequest struct {
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	PermissionIDs []string `json:"permission_ids"`
}

type adminCreateResourceRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Icon        string   `json:"icon"`
	InternalURL string   `json:"internal_url"`
	PublicHost  string   `json:"public_host"`
	PublicPath  string   `json:"public_path"`
	Enabled     *bool    `json:"enabled"`
	GroupIDs    []string `json:"group_ids"`
	AllowCIDRs  []string `json:"allow_cidrs"`
}

type adminUpdateResourceRequest struct {
	Name        *string   `json:"name"`
	Description *string   `json:"description"`
	Category    *string   `json:"category"`
	Icon        *string   `json:"icon"`
	InternalURL *string   `json:"internal_url"`
	PublicHost  *string   `json:"public_host"`
	PublicPath  *string   `json:"public_path"`
	Enabled     *bool     `json:"enabled"`
	GroupIDs    *[]string `json:"group_ids"`
	AllowCIDRs  *[]string `json:"allow_cidrs"`
}

func (s *Server) adminDashboard(w http.ResponseWriter, r *http.Request, _ *domain.SessionContext) {
	stats, err := s.store.DashboardStats(r.Context())
	if err != nil {
		s.logger.Error("admin dashboard failed", "error", err)
		writeError(w, http.StatusInternalServerError, "dashboard_failed")
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) adminListUsers(w http.ResponseWriter, r *http.Request, _ *domain.SessionContext) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.logger.Error("admin list users failed", "error", err)
		writeError(w, http.StatusInternalServerError, "users_list_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

func (s *Server) adminCreateUser(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
	var req adminCreateUserRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	username := normalizeUsername(req.Username)
	if username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "invalid_user")
		return
	}
	if req.IsAdmin && !canManageSuperAdmin(session) {
		s.auditWithMetadata(r, "admin.user.superadmin_denied", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "failure", "missing_permission", map[string]any{
			"target_username": username,
			"requested":       true,
		})
		writeError(w, http.StatusForbidden, "superadmin_permission_required")
		return
	}
	passwordHash, err := auth.HashPassword(req.Password, auth.DefaultArgon2idParams)
	if err != nil {
		writeError(w, http.StatusBadRequest, "weak_password")
		return
	}
	user, err := s.store.CreateUser(r.Context(), domain.UserInput{
		Username:     username,
		PasswordHash: passwordHash,
		DisplayName:  strings.TrimSpace(req.DisplayName),
		IsAdmin:      req.IsAdmin,
		GroupIDs:     normalizeIDs(req.GroupIDs),
	})
	if err != nil {
		writeStorageError(w, err, "user_create_failed")
		return
	}
	s.auditWithMetadata(r, "admin.user.created", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "success", user.ID, map[string]any{
		"target_user_id": user.ID,
		"username":       user.Username,
		"is_admin":       user.IsAdmin,
		"group_ids":      user.GroupIDs,
	})
	writeJSON(w, http.StatusCreated, map[string]any{"user": user})
}

func (s *Server) adminUpdateUser(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
	var req adminUpdateUserRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	targetID := r.PathValue("id")
	if req.IsAdmin != nil {
		if targetID == session.User.ID {
			s.auditWithMetadata(r, "admin.user.superadmin_denied", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "failure", "self_admin_change", map[string]any{
				"target_user_id": targetID,
				"requested":      *req.IsAdmin,
			})
			writeError(w, http.StatusBadRequest, "cannot_change_own_admin_status")
			return
		}
		if !canManageSuperAdmin(session) {
			s.auditWithMetadata(r, "admin.user.superadmin_denied", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "failure", "missing_permission", map[string]any{
				"target_user_id": targetID,
				"requested":      *req.IsAdmin,
			})
			writeError(w, http.StatusForbidden, "superadmin_permission_required")
			return
		}
	}
	update := domain.UserUpdate{
		DisplayName: req.DisplayName,
		IsAdmin:     req.IsAdmin,
		Blocked:     req.Blocked,
	}
	if req.Password != nil {
		passwordHash, err := auth.HashPassword(*req.Password, auth.DefaultArgon2idParams)
		if err != nil {
			writeError(w, http.StatusBadRequest, "weak_password")
			return
		}
		update.PasswordHash = &passwordHash
	}
	if req.GroupIDs != nil {
		update.UpdateGroups = true
		update.GroupIDs = normalizeIDs(*req.GroupIDs)
	}
	user, err := s.store.UpdateUser(r.Context(), targetID, update)
	if err != nil {
		writeStorageError(w, err, "user_update_failed")
		return
	}
	changed := map[string]any{}
	if req.DisplayName != nil {
		changed["display_name"] = *req.DisplayName
	}
	if req.IsAdmin != nil {
		changed["is_admin"] = *req.IsAdmin
	}
	if req.Blocked != nil {
		changed["blocked"] = *req.Blocked
	}
	if req.Password != nil {
		changed["password"] = "changed"
	}
	if req.GroupIDs != nil {
		changed["group_ids"] = normalizeIDs(*req.GroupIDs)
	}
	s.auditWithMetadata(r, "admin.user.updated", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "success", user.ID, map[string]any{
		"target_user_id": user.ID,
		"username":       user.Username,
		"changed":        changed,
	})
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

func (s *Server) adminDeleteUser(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
	id := r.PathValue("id")
	if id == session.User.ID {
		writeError(w, http.StatusBadRequest, "cannot_delete_self")
		return
	}
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		writeStorageError(w, err, "user_delete_failed")
		return
	}
	s.auditWithMetadata(r, "admin.user.deleted", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "success", id, map[string]any{"target_user_id": id})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminListGroups(w http.ResponseWriter, r *http.Request, _ *domain.SessionContext) {
	groups, err := s.store.ListGroups(r.Context())
	if err != nil {
		s.logger.Error("admin list groups failed", "error", err)
		writeError(w, http.StatusInternalServerError, "groups_list_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": groups})
}

func (s *Server) adminCreateGroup(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
	var req adminGroupRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	input, ok := groupInputFromRequest(req)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_group")
		return
	}
	group, err := s.store.CreateGroup(r.Context(), input)
	if err != nil {
		writeStorageError(w, err, "group_create_failed")
		return
	}
	s.auditWithMetadata(r, "admin.group.created", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "success", group.ID, map[string]any{
		"target_group_id": group.ID,
		"name":            group.Name,
		"permission_ids":  group.PermissionIDs,
	})
	writeJSON(w, http.StatusCreated, map[string]any{"group": group})
}

func (s *Server) adminUpdateGroup(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
	var req adminGroupRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	input, ok := groupInputFromRequest(req)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_group")
		return
	}
	group, err := s.store.UpdateGroup(r.Context(), r.PathValue("id"), input)
	if err != nil {
		writeStorageError(w, err, "group_update_failed")
		return
	}
	s.auditWithMetadata(r, "admin.group.updated", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "success", group.ID, map[string]any{
		"target_group_id": group.ID,
		"name":            group.Name,
		"permission_ids":  group.PermissionIDs,
	})
	writeJSON(w, http.StatusOK, map[string]any{"group": group})
}

func (s *Server) adminDeleteGroup(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
	id := r.PathValue("id")
	if err := s.store.DeleteGroup(r.Context(), id); err != nil {
		writeStorageError(w, err, "group_delete_failed")
		return
	}
	s.auditWithMetadata(r, "admin.group.deleted", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "success", id, map[string]any{"target_group_id": id})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminListResources(w http.ResponseWriter, r *http.Request, _ *domain.SessionContext) {
	resources, err := s.store.ListResources(r.Context())
	if err != nil {
		s.logger.Error("admin list resources failed", "error", err)
		writeError(w, http.StatusInternalServerError, "resources_list_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"resources": resources})
}

func (s *Server) adminGetResource(w http.ResponseWriter, r *http.Request, _ *domain.SessionContext) {
	resource, err := s.store.FindResourceByID(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStorageError(w, err, "resource_get_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"resource": resource})
}

func (s *Server) adminCreateResource(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
	var req adminCreateResourceRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	input, ok := s.resourceInputFromCreate(req)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_resource")
		return
	}
	resource, err := s.store.CreateResource(r.Context(), input)
	if err != nil {
		writeStorageError(w, err, "resource_create_failed")
		return
	}
	s.auditWithMetadata(r, "admin.resource.created", session.User.ID, session.User.Username, resource.ID, s.clientIP(r), r.UserAgent(), "success", "", map[string]any{
		"resource_id":  resource.ID,
		"public_host":  resource.PublicHost,
		"public_path":  resource.PublicPath,
		"internal_url": resource.InternalURL,
		"group_ids":    resource.GroupIDs,
		"allow_cidrs":  resource.AllowCIDRs,
	})
	writeJSON(w, http.StatusCreated, map[string]any{"resource": resource})
}

func (s *Server) adminUpdateResource(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
	var req adminUpdateResourceRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	update, ok := s.resourceUpdateFromRequest(req)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_resource")
		return
	}
	resource, err := s.store.UpdateResource(r.Context(), r.PathValue("id"), update)
	if err != nil {
		writeStorageError(w, err, "resource_update_failed")
		return
	}
	s.auditWithMetadata(r, "admin.resource.updated", session.User.ID, session.User.Username, resource.ID, s.clientIP(r), r.UserAgent(), "success", "", map[string]any{
		"resource_id":  resource.ID,
		"public_host":  resource.PublicHost,
		"public_path":  resource.PublicPath,
		"internal_url": resource.InternalURL,
		"group_ids":    resource.GroupIDs,
		"allow_cidrs":  resource.AllowCIDRs,
	})
	writeJSON(w, http.StatusOK, map[string]any{"resource": resource})
}

func (s *Server) adminDeleteResource(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
	id := r.PathValue("id")
	if err := s.store.DeleteResource(r.Context(), id); err != nil {
		writeStorageError(w, err, "resource_delete_failed")
		return
	}
	s.auditWithMetadata(r, "admin.resource.deleted", session.User.ID, session.User.Username, id, s.clientIP(r), r.UserAgent(), "success", "", map[string]any{"resource_id": id})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminResourceNginx(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
	resource, err := s.store.FindResourceByID(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStorageError(w, err, "resource_get_failed")
		return
	}
	recommendation, err := nginxgen.GenerateResourceServer(*resource, s.cfg.PortalHost)
	if err != nil {
		writeError(w, http.StatusBadRequest, "nginx_generation_failed")
		return
	}
	s.audit(r, "admin.nginx.generated", session.User.ID, session.User.Username, resource.ID, s.clientIP(r), r.UserAgent(), "success", "")
	writeJSON(w, http.StatusOK, map[string]any{"nginx": recommendation})
}

func (s *Server) adminNginxBundle(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
	resources, err := s.store.ListResources(r.Context())
	if err != nil {
		s.logger.Error("admin nginx bundle resources failed", "error", err)
		writeError(w, http.StatusInternalServerError, "nginx_generation_failed")
		return
	}
	bundle, err := nginxgen.GenerateBundle(resources, s.cfg.PortalHost)
	if err != nil {
		writeError(w, http.StatusBadRequest, "nginx_generation_failed")
		return
	}
	s.auditWithMetadata(r, "admin.nginx.bundle_generated", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "success", "", map[string]any{
		"portal_host":    bundle.PortalHost,
		"resource_count": len(resources),
	})
	writeJSON(w, http.StatusOK, map[string]any{"nginx": bundle})
}

func (s *Server) adminResourceDiagnostics(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
	resource, err := s.store.FindResourceByID(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStorageError(w, err, "resource_get_failed")
		return
	}
	if !s.diagnosticsLimiter.Allow(session.User.ID+"|"+resource.ID, time.Now()) {
		s.auditWithMetadata(r, "admin.resource.diagnostics", session.User.ID, session.User.Username, resource.ID, s.clientIP(r), r.UserAgent(), "failure", "rate_limited", map[string]any{
			"resource_id": resource.ID,
		})
		writeError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	policy, err := diagnostics.NewNetworkPolicy(s.cfg.DiagnosticsAllowCIDRs, s.cfg.DiagnosticsDenyCIDRs)
	if err != nil {
		s.logger.Error("invalid diagnostics policy", "error", err)
		writeError(w, http.StatusInternalServerError, "diagnostics_policy_invalid")
		return
	}
	result, err := diagnostics.Prober{Policy: policy}.ProbeResource(r.Context(), *resource)
	if err != nil {
		writeError(w, http.StatusBadRequest, "diagnostics_failed")
		return
	}
	outcome := "failure"
	if result.DNS.OK && result.TCP.OK && result.HTTP.OK {
		outcome = "success"
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "diagnostics_store_failed")
		return
	}
	if err := s.store.AppendResourceDiagnostics(r.Context(), domain.ResourceDiagnosticsRun{
		ResourceID: resource.ID,
		Outcome:    outcome,
		ResultJSON: string(resultJSON),
		CreatedBy:  session.User.ID,
	}); err != nil {
		s.logger.Error("resource diagnostics history append failed", "error", err, "resource_id", resource.ID)
		writeError(w, http.StatusInternalServerError, "diagnostics_store_failed")
		return
	}
	s.auditWithMetadata(r, "admin.resource.diagnostics", session.User.ID, session.User.Username, resource.ID, s.clientIP(r), r.UserAgent(), outcome, "", map[string]any{
		"resource_id": resource.ID,
		"outcome":     outcome,
		"dns_ok":      result.DNS.OK,
		"tcp_ok":      result.TCP.OK,
		"http_ok":     result.HTTP.OK,
	})
	history, err := s.store.ListResourceDiagnostics(r.Context(), resource.ID, 10)
	if err != nil {
		s.logger.Error("resource diagnostics history list failed", "error", err, "resource_id", resource.ID)
		writeError(w, http.StatusInternalServerError, "diagnostics_history_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"diagnostics": result, "history": history})
}

func (s *Server) adminResourceDiagnosticsHistory(w http.ResponseWriter, r *http.Request, _ *domain.SessionContext) {
	limit := queryLimit(r, 20, 100)
	history, err := s.store.ListResourceDiagnostics(r.Context(), r.PathValue("id"), limit)
	if err != nil {
		s.logger.Error("resource diagnostics history failed", "error", err)
		writeError(w, http.StatusInternalServerError, "diagnostics_history_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"history": history})
}

func (s *Server) adminListSessions(w http.ResponseWriter, r *http.Request, _ *domain.SessionContext) {
	sessions, err := s.store.ListActiveSessions(r.Context())
	if err != nil {
		s.logger.Error("admin list sessions failed", "error", err)
		writeError(w, http.StatusInternalServerError, "sessions_list_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

func (s *Server) adminRevokeSession(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
	id := r.PathValue("id")
	if id == session.ID {
		writeError(w, http.StatusBadRequest, "cannot_revoke_current_session")
		return
	}
	if err := s.store.RevokeSession(r.Context(), id); err != nil {
		writeStorageError(w, err, "session_revoke_failed")
		return
	}
	s.auditWithMetadata(r, "admin.session.revoked", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "success", id, map[string]any{"target_session_id": id})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminListAudit(w http.ResponseWriter, r *http.Request, _ *domain.SessionContext) {
	filter, ok := auditFilterFromRequest(w, r, 100, 1000)
	if !ok {
		return
	}
	events, err := s.store.ListAuditEvents(r.Context(), filter)
	if err != nil {
		s.logger.Error("admin list audit failed", "error", err)
		writeError(w, http.StatusInternalServerError, "audit_list_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) adminExportAudit(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
	filter, ok := auditFilterFromRequest(w, r, 500, 5000)
	if !ok {
		return
	}
	events, err := s.store.ListAuditEvents(r.Context(), filter)
	if err != nil {
		s.logger.Error("admin export audit failed", "error", err)
		writeError(w, http.StatusInternalServerError, "audit_export_failed")
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format != "json" {
		format = "csv"
	}
	s.auditWithMetadata(r, "admin.audit.exported", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "success", "", map[string]any{
		"format":      format,
		"limit":       filter.Limit,
		"type":        filter.EventType,
		"username":    filter.Username,
		"resource_id": filter.ResourceID,
		"outcome":     filter.Outcome,
		"from":        auditTimeForMetadata(filter.From),
		"to":          auditTimeForMetadata(filter.To),
		"event_count": len(events),
	})
	switch format {
	case "json":
		w.Header().Set("Content-Disposition", `attachment; filename="agp-audit.json"`)
		writeJSON(w, http.StatusOK, map[string]any{"events": events})
	default:
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="agp-audit.csv"`)
		writer := csv.NewWriter(w)
		_ = writer.Write([]string{"created_at", "type", "username", "subject_user_id", "resource_id", "ip", "outcome", "reason", "metadata_json"})
		for _, event := range events {
			_ = writer.Write([]string{
				event.CreatedAt.Format(time.RFC3339),
				safeCSVCell(event.Type),
				safeCSVCell(event.Username),
				safeCSVCell(event.SubjectUserID),
				safeCSVCell(event.ResourceID),
				safeCSVCell(event.IP),
				safeCSVCell(event.Outcome),
				safeCSVCell(event.Reason),
				safeCSVCell(event.MetadataJSON),
			})
		}
		writer.Flush()
	}
}

func auditTimeForMetadata(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.Format(time.RFC3339)
}

func safeCSVCell(value string) string {
	cleaned := strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(value)
	trimmed := strings.TrimLeft(cleaned, " ")
	if trimmed == "" {
		return cleaned
	}
	switch trimmed[0] {
	case '=', '+', '-', '@':
		return "'" + cleaned
	default:
		return cleaned
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	return true
}

func queryLimit(r *http.Request, fallback int, max int) int {
	limit := fallback
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	if limit <= 0 || limit > max {
		return fallback
	}
	return limit
}

func auditFilterFromRequest(w http.ResponseWriter, r *http.Request, fallbackLimit int, maxLimit int) (domain.AuditFilter, bool) {
	values := r.URL.Query()
	filter := domain.AuditFilter{
		Limit:      queryLimit(r, fallbackLimit, maxLimit),
		EventType:  strings.TrimSpace(values.Get("type")),
		Username:   strings.TrimSpace(values.Get("username")),
		ResourceID: strings.TrimSpace(values.Get("resource_id")),
		Outcome:    strings.TrimSpace(values.Get("outcome")),
	}
	if raw := strings.TrimSpace(values.Get("from")); raw != "" {
		parsed, err := parseAuditTime(raw, false)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_from")
			return domain.AuditFilter{}, false
		}
		filter.From = &parsed
	}
	if raw := strings.TrimSpace(values.Get("to")); raw != "" {
		parsed, err := parseAuditTime(raw, true)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_to")
			return domain.AuditFilter{}, false
		}
		filter.To = &parsed
	}
	return filter, true
}

func parseAuditTime(raw string, endOfDay bool) (time.Time, error) {
	if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
		return parsed.UTC(), nil
	}
	parsed, err := time.Parse("2006-01-02", raw)
	if err != nil {
		return time.Time{}, err
	}
	if endOfDay {
		parsed = parsed.Add(24*time.Hour - time.Nanosecond)
	}
	return parsed.UTC(), nil
}

func writeStorageError(w http.ResponseWriter, err error, fallback string) {
	switch {
	case errors.Is(err, storage.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found")
	case errors.Is(err, storage.ErrConflict):
		writeError(w, http.StatusConflict, "conflict")
	default:
		writeError(w, http.StatusInternalServerError, fallback)
	}
}

func normalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func canManageSuperAdmin(session *domain.SessionContext) bool {
	if session.User.IsAdmin {
		return true
	}
	return authz.HasPermission(session.Permissions, authz.PermUsersSuperAdminManage)
}

func groupInputFromRequest(req adminGroupRequest) (domain.GroupInput, bool) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return domain.GroupInput{}, false
	}
	return domain.GroupInput{
		Name:          name,
		Description:   strings.TrimSpace(req.Description),
		PermissionIDs: normalizeIDs(req.PermissionIDs),
	}, true
}

func (s *Server) resourceInputFromCreate(req adminCreateResourceRequest) (domain.ResourceInput, bool) {
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	publicHost := normalizeHostInput(req.PublicHost)
	if publicHost == "" {
		publicHost = normalizeHostInput(s.cfg.PortalHost)
	}
	publicPath, ok := normalizePublicPath(req.PublicPath)
	if !ok {
		return domain.ResourceInput{}, false
	}
	internalURL := strings.TrimSpace(req.InternalURL)
	if strings.TrimSpace(req.Name) == "" || publicHost == "" || !validInternalURL(internalURL) || !validCIDRs(req.AllowCIDRs) {
		return domain.ResourceInput{}, false
	}
	return domain.ResourceInput{
		Name:        strings.TrimSpace(req.Name),
		Description: strings.TrimSpace(req.Description),
		Category:    strings.TrimSpace(req.Category),
		Icon:        strings.TrimSpace(req.Icon),
		InternalURL: internalURL,
		PublicHost:  publicHost,
		PublicPath:  publicPath,
		Enabled:     enabled,
		GroupIDs:    normalizeIDs(req.GroupIDs),
		AllowCIDRs:  normalizeIDs(req.AllowCIDRs),
	}, true
}

func (s *Server) resourceUpdateFromRequest(req adminUpdateResourceRequest) (domain.ResourceUpdate, bool) {
	update := domain.ResourceUpdate{
		Name:        trimStringPointer(req.Name),
		Description: trimStringPointer(req.Description),
		Category:    trimStringPointer(req.Category),
		Icon:        trimStringPointer(req.Icon),
		InternalURL: trimStringPointer(req.InternalURL),
		PublicHost:  trimHostPointer(req.PublicHost),
		Enabled:     req.Enabled,
	}
	if update.PublicHost != nil && *update.PublicHost == "" {
		defaultHost := normalizeHostInput(s.cfg.PortalHost)
		update.PublicHost = &defaultHost
	}
	if req.PublicPath != nil {
		publicPath, ok := normalizePublicPath(*req.PublicPath)
		if !ok {
			return domain.ResourceUpdate{}, false
		}
		update.PublicPath = &publicPath
	}
	if update.InternalURL != nil && !validInternalURL(*update.InternalURL) {
		return domain.ResourceUpdate{}, false
	}
	if update.PublicHost != nil && *update.PublicHost == "" {
		return domain.ResourceUpdate{}, false
	}
	if update.Name != nil && *update.Name == "" {
		return domain.ResourceUpdate{}, false
	}
	if req.GroupIDs != nil {
		update.UpdateGroups = true
		update.GroupIDs = normalizeIDs(*req.GroupIDs)
	}
	if req.AllowCIDRs != nil {
		if !validCIDRs(*req.AllowCIDRs) {
			return domain.ResourceUpdate{}, false
		}
		update.UpdateAllowCIDRs = true
		update.AllowCIDRs = normalizeIDs(*req.AllowCIDRs)
	}
	return update, true
}

func normalizeIDs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func trimStringPointer(value *string) *string {
	if value == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*value)
	return &trimmed
}

func trimHostPointer(value *string) *string {
	if value == nil {
		return nil
	}
	normalized := normalizeHostInput(*value)
	return &normalized
}

func normalizeHostInput(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if strings.Contains(host, "/") || strings.ContainsAny(host, " \t\r\n;{}") {
		return ""
	}
	if strings.Contains(host, ":") {
		parsed, _, err := net.SplitHostPort(host)
		if err != nil {
			return ""
		}
		host = parsed
	}
	return host
}

func normalizePublicPath(path string) (string, bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", true
	}
	if !strings.HasPrefix(path, "/") || path == "/" {
		return "", false
	}
	if strings.Contains(path, "..") || strings.ContainsAny(path, " \t\r\n;{}") {
		return "", false
	}
	if _, err := url.ParseRequestURI(path); err != nil {
		return "", false
	}
	for len(path) > 1 && strings.HasSuffix(path, "/") {
		path = strings.TrimSuffix(path, "/")
	}
	return path, true
}

func validInternalURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	if parsed.Host == "" {
		return false
	}
	return !strings.ContainsAny(raw, " \t\r\n;{}")
}

func validCIDRs(cidrs []string) bool {
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return false
		}
	}
	return true
}
