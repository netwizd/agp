package httpapi

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/netwizd/agp/internal/domain"
)

type portalSettingsRequest struct {
	BrandName      string `json:"brand_name"`
	LogoText       string `json:"logo_text"`
	PortalTitle    string `json:"portal_title"`
	PortalSubtitle string `json:"portal_subtitle"`
	WelcomeTitle   string `json:"welcome_title"`
	WelcomeBody    string `json:"welcome_body"`
	FooterText     string `json:"footer_text"`
	SupportText    string `json:"support_text"`
	SupportURL     string `json:"support_url"`
}

func (s *Server) publicPortalSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := s.store.GetPortalSettings(r.Context())
	if err != nil {
		s.logger.Error("public portal settings failed", "error", err)
		writeError(w, http.StatusInternalServerError, "portal_settings_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": publicPortalSettings(*settings)})
}

func (s *Server) adminGetPortalSettings(w http.ResponseWriter, r *http.Request, _ *domain.SessionContext) {
	settings, err := s.store.GetPortalSettings(r.Context())
	if err != nil {
		s.logger.Error("admin portal settings failed", "error", err)
		writeError(w, http.StatusInternalServerError, "portal_settings_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": settings})
}

func (s *Server) adminUpdatePortalSettings(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
	var req portalSettingsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	settings, ok := portalSettingsFromRequest(req)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_portal_settings")
		return
	}
	updated, err := s.store.UpdatePortalSettings(r.Context(), settings)
	if err != nil {
		writeStorageError(w, err, "portal_settings_update_failed")
		return
	}
	s.audit(r, "admin.portal_settings.updated", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "success", "")
	writeJSON(w, http.StatusOK, map[string]any{"settings": updated})
}

func portalSettingsFromRequest(req portalSettingsRequest) (domain.PortalSettings, bool) {
	settings := domain.PortalSettings{
		BrandName:      trimText(req.BrandName, 80),
		LogoText:       trimText(req.LogoText, 8),
		PortalTitle:    trimText(req.PortalTitle, 120),
		PortalSubtitle: trimText(req.PortalSubtitle, 240),
		WelcomeTitle:   trimText(req.WelcomeTitle, 120),
		WelcomeBody:    trimText(req.WelcomeBody, 1000),
		FooterText:     trimText(req.FooterText, 240),
		SupportText:    trimText(req.SupportText, 160),
		SupportURL:     trimText(req.SupportURL, 500),
	}
	if settings.BrandName == "" || settings.LogoText == "" || settings.PortalTitle == "" {
		return domain.PortalSettings{}, false
	}
	if settings.SupportURL != "" && !validPublicURL(settings.SupportURL) {
		return domain.PortalSettings{}, false
	}
	return settings, true
}

func publicPortalSettings(settings domain.PortalSettings) map[string]any {
	return map[string]any{
		"brand_name":      settings.BrandName,
		"logo_text":       settings.LogoText,
		"portal_title":    settings.PortalTitle,
		"portal_subtitle": settings.PortalSubtitle,
		"welcome_title":   settings.WelcomeTitle,
		"welcome_body":    settings.WelcomeBody,
		"footer_text":     settings.FooterText,
		"support_text":    settings.SupportText,
		"support_url":     settings.SupportURL,
	}
}

func trimText(value string, maxLen int) string {
	value = strings.TrimSpace(value)
	if len(value) > maxLen {
		value = value[:maxLen]
	}
	return value
}

func trimOptionalText(value *string, maxLen int) *string {
	if value == nil {
		return nil
	}
	trimmed := trimText(*value, maxLen)
	return &trimmed
}

func validPublicURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if parsed.Scheme == "mailto" {
		return parsed.Opaque != ""
	}
	return parsed.Scheme == "https" && parsed.Host != ""
}
