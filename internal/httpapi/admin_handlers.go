package httpapi

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/netwizd/agp/internal/auth"
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
	Icon        string   `json:"icon"`
	InternalURL string   `json:"internal_url"`
	PublicHost  string   `json:"public_host"`
	Enabled     *bool    `json:"enabled"`
	GroupIDs    []string `json:"group_ids"`
	AllowCIDRs  []string `json:"allow_cidrs"`
}

type adminUpdateResourceRequest struct {
	Name        *string   `json:"name"`
	Description *string   `json:"description"`
	Icon        *string   `json:"icon"`
	InternalURL *string   `json:"internal_url"`
	PublicHost  *string   `json:"public_host"`
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
	s.audit(r, "admin.user.created", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "success", user.ID)
	writeJSON(w, http.StatusCreated, map[string]any{"user": user})
}

func (s *Server) adminUpdateUser(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
	var req adminUpdateUserRequest
	if !decodeJSON(w, r, &req) {
		return
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
	user, err := s.store.UpdateUser(r.Context(), r.PathValue("id"), update)
	if err != nil {
		writeStorageError(w, err, "user_update_failed")
		return
	}
	s.audit(r, "admin.user.updated", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "success", user.ID)
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
	s.audit(r, "admin.user.deleted", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "success", id)
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
	s.audit(r, "admin.group.created", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "success", group.ID)
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
	s.audit(r, "admin.group.updated", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "success", group.ID)
	writeJSON(w, http.StatusOK, map[string]any{"group": group})
}

func (s *Server) adminDeleteGroup(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
	id := r.PathValue("id")
	if err := s.store.DeleteGroup(r.Context(), id); err != nil {
		writeStorageError(w, err, "group_delete_failed")
		return
	}
	s.audit(r, "admin.group.deleted", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "success", id)
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
	input, ok := resourceInputFromCreate(req)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_resource")
		return
	}
	resource, err := s.store.CreateResource(r.Context(), input)
	if err != nil {
		writeStorageError(w, err, "resource_create_failed")
		return
	}
	s.audit(r, "admin.resource.created", session.User.ID, session.User.Username, resource.ID, s.clientIP(r), r.UserAgent(), "success", "")
	writeJSON(w, http.StatusCreated, map[string]any{"resource": resource})
}

func (s *Server) adminUpdateResource(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
	var req adminUpdateResourceRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	update, ok := resourceUpdateFromRequest(req)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_resource")
		return
	}
	resource, err := s.store.UpdateResource(r.Context(), r.PathValue("id"), update)
	if err != nil {
		writeStorageError(w, err, "resource_update_failed")
		return
	}
	s.audit(r, "admin.resource.updated", session.User.ID, session.User.Username, resource.ID, s.clientIP(r), r.UserAgent(), "success", "")
	writeJSON(w, http.StatusOK, map[string]any{"resource": resource})
}

func (s *Server) adminDeleteResource(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
	id := r.PathValue("id")
	if err := s.store.DeleteResource(r.Context(), id); err != nil {
		writeStorageError(w, err, "resource_delete_failed")
		return
	}
	s.audit(r, "admin.resource.deleted", session.User.ID, session.User.Username, id, s.clientIP(r), r.UserAgent(), "success", "")
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

func (s *Server) adminResourceDiagnostics(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
	resource, err := s.store.FindResourceByID(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStorageError(w, err, "resource_get_failed")
		return
	}
	result, err := diagnostics.Prober{}.ProbeResource(r.Context(), *resource)
	if err != nil {
		writeError(w, http.StatusBadRequest, "diagnostics_failed")
		return
	}
	outcome := "failure"
	if result.DNS.OK && result.TCP.OK && result.HTTP.OK {
		outcome = "success"
	}
	s.audit(r, "admin.resource.diagnostics", session.User.ID, session.User.Username, resource.ID, s.clientIP(r), r.UserAgent(), outcome, "")
	writeJSON(w, http.StatusOK, map[string]any{"diagnostics": result})
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
	s.audit(r, "admin.session.revoked", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "success", id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminListAudit(w http.ResponseWriter, r *http.Request, _ *domain.SessionContext) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_limit")
			return
		}
		limit = parsed
	}
	events, err := s.store.ListAuditEvents(r.Context(), limit)
	if err != nil {
		s.logger.Error("admin list audit failed", "error", err)
		writeError(w, http.StatusInternalServerError, "audit_list_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
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

func resourceInputFromCreate(req adminCreateResourceRequest) (domain.ResourceInput, bool) {
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	publicHost := normalizeHostInput(req.PublicHost)
	internalURL := strings.TrimSpace(req.InternalURL)
	if strings.TrimSpace(req.Name) == "" || publicHost == "" || !validInternalURL(internalURL) || !validCIDRs(req.AllowCIDRs) {
		return domain.ResourceInput{}, false
	}
	return domain.ResourceInput{
		Name:        strings.TrimSpace(req.Name),
		Description: strings.TrimSpace(req.Description),
		Icon:        strings.TrimSpace(req.Icon),
		InternalURL: internalURL,
		PublicHost:  publicHost,
		Enabled:     enabled,
		GroupIDs:    normalizeIDs(req.GroupIDs),
		AllowCIDRs:  normalizeIDs(req.AllowCIDRs),
	}, true
}

func resourceUpdateFromRequest(req adminUpdateResourceRequest) (domain.ResourceUpdate, bool) {
	update := domain.ResourceUpdate{
		Name:        trimStringPointer(req.Name),
		Description: trimStringPointer(req.Description),
		Icon:        trimStringPointer(req.Icon),
		InternalURL: trimStringPointer(req.InternalURL),
		PublicHost:  trimHostPointer(req.PublicHost),
		Enabled:     req.Enabled,
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
