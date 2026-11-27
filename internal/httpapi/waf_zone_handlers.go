package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/configuration"
)

func (s *Server) wafZoneRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v2/waf/authoring-zones", s.withConfiguration(false, s.wafZoneList))
	mux.HandleFunc("POST /api/v2/waf/zone-revisions", s.withConfiguration(true, s.wafZoneCreate))
	mux.HandleFunc("GET /api/v2/waf/zone-revisions/{id}", s.withConfiguration(false, s.wafZoneGet))
	mux.HandleFunc("POST /api/v2/waf/zone-revisions/{id}/previews", s.withConfiguration(true, s.wafZonePreview))
	mux.HandleFunc("GET /api/v2/waf/zone-previews/{id}", s.withConfiguration(false, s.wafZoneGetPreview))
	mux.HandleFunc("POST /api/v2/waf/zone-previews/{id}/authoring-reviews", s.withConfiguration(true, s.wafZoneReview))
	mux.HandleFunc("GET /api/v2/waf/zone-previews/{id}/authoring-reviews", s.withConfiguration(false, s.wafZoneReviews))
	mux.HandleFunc("POST /api/v2/waf/zone-revisions/{id}/validations", s.withConfiguration(true, s.wafZoneValidate))
	mux.HandleFunc("GET /api/v2/waf/zone-validations/{id}", s.withConfiguration(false, s.wafZoneValidation))
	mux.HandleFunc("POST /api/v2/waf/zone-revisions/{id}/approvals", s.withConfigurationPermission("config.approve", true, s.wafZoneApprove))
	mux.HandleFunc("POST /api/v2/waf/zone-revisions/{id}/publications", s.withConfigurationPermission("config.approve", true, s.wafZonePublish))
	mux.HandleFunc("POST /api/v2/waf/zone-revisions/{id}/resolutions", s.withConfiguration(true, s.wafZoneResolve))
	mux.HandleFunc("GET /api/v2/waf/zone-resolutions/{id}", s.withConfiguration(false, s.wafZoneResolution))
	mux.HandleFunc("POST /api/v2/waf/zone-changes", s.withConfiguration(true, s.wafZoneChange))
	mux.HandleFunc("GET /api/v2/waf/zone-changes/{id}", s.withConfiguration(false, s.wafZoneGetChange))
}
func (s *Server) wafZoneList(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	limit := 50
	var e error
	if v := r.URL.Query().Get("limit"); v != "" {
		limit, e = strconv.Atoi(v)
		if e != nil {
			configurationProblem(w, 400, "invalid_limit", nil)
			return
		}
	}
	out, e := s.configuration.ListZones(r.Context(), a, limit, r.URL.Query().Get("cursor"), r.URL.Query().Get("siteId"))
	if e != nil {
		configurationError(w, e)
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) wafZoneCreate(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	key, ok := configKey(w, r)
	if !ok {
		return
	}
	var in configuration.ZoneCreate
	if !configBody(w, r, &in, 4<<20) {
		return
	}
	out, e := s.configuration.CreateZoneRevision(r.Context(), a, key, in)
	if e != nil {
		configurationError(w, e)
		return
	}
	configurationWrite(w, 201, zoneRevisionDTO(out), out.Revision)
}
func (s *Server) wafZoneGet(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	out, e := s.configuration.GetZoneRevision(r.Context(), a, r.PathValue("id"))
	if e != nil {
		configurationError(w, e)
		return
	}
	configurationWrite(w, 200, zoneRevisionDTO(out), out.Revision)
}
func (s *Server) wafZonePreview(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	key, ok := configKey(w, r)
	if !ok {
		return
	}
	var in configuration.ZonePreviewRequest
	if !configBody(w, r, &in, 4<<20) {
		return
	}
	out, e := s.configuration.PreviewZone(r.Context(), a, r.PathValue("id"), key, in)
	if e != nil {
		configurationError(w, e)
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) wafZoneGetPreview(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	out, e := s.configuration.GetZonePreview(r.Context(), a, r.PathValue("id"))
	if e != nil {
		configurationError(w, e)
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) wafZoneReview(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	key, ok := configKey(w, r)
	if !ok {
		return
	}
	var in struct {
		PreviewDigest string `json:"previewDigest"`
		Reason        string `json:"reason"`
	}
	if !configBody(w, r, &in, 8192) {
		return
	}
	out, e := s.configuration.ReviewZonePreview(r.Context(), a, r.PathValue("id"), key, in.PreviewDigest, in.Reason)
	if e != nil {
		configurationError(w, e)
		return
	}
	writeJSON(w, 201, out)
}
func (s *Server) wafZoneReviews(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	out, e := s.configuration.ZoneReviews(r.Context(), a, r.PathValue("id"))
	if e != nil {
		configurationError(w, e)
		return
	}
	writeJSON(w, 200, map[string]any{"items": out})
}
func (s *Server) wafZoneValidate(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	key, ok := configKey(w, r)
	if !ok {
		return
	}
	var in struct{}
	if !configBody(w, r, &in, 1024) {
		return
	}
	out, err := s.configuration.ValidateZoneRevision(r.Context(), a, r.PathValue("id"), key)
	if err != nil {
		configurationError(w, err)
		return
	}
	w.Header().Set("Location", out.StatusURL)
	writeJSON(w, 202, out)
}
func (s *Server) wafZoneValidation(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	out, err := s.configuration.GetZoneValidation(r.Context(), a, r.PathValue("id"))
	if err != nil {
		configurationError(w, err)
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) wafZoneApprove(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	key, ok := configKey(w, r)
	if !ok {
		return
	}
	var in configuration.WafPolicyApprovalRequest
	if !configBody(w, r, &in, 8192) {
		return
	}
	out, err := s.configuration.ApproveZoneRevision(r.Context(), a, r.PathValue("id"), key, in)
	if err != nil {
		configurationError(w, err)
		return
	}
	writeJSON(w, 201, out)
}
func (s *Server) wafZonePublish(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	key, ok := configKey(w, r)
	if !ok {
		return
	}
	var in configuration.WafPolicyPublicationRequest
	if !configBody(w, r, &in, 8192) {
		return
	}
	out, err := s.configuration.PublishZoneRevision(r.Context(), a, r.PathValue("id"), key, in)
	if err != nil {
		configurationError(w, err)
		return
	}
	configurationWrite(w, 200, zoneRevisionDTO(out), out.Revision)
}
func (s *Server) wafZoneResolve(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	key, ok := configKey(w, r)
	if !ok {
		return
	}
	var in configuration.ZoneResolutionRequest
	if !configBody(w, r, &in, 4<<20) {
		return
	}
	out, err := s.configuration.ResolveZoneAccepted(r.Context(), a, r.PathValue("id"), key, in)
	if err != nil {
		configurationError(w, err)
		return
	}
	w.Header().Set("Location", out.StatusURL)
	writeJSON(w, 202, out)
}
func (s *Server) wafZoneResolution(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	out, err := s.configuration.GetZoneResolution(r.Context(), a, r.PathValue("id"))
	if err != nil {
		configurationError(w, err)
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) wafZoneChange(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	key, ok := configKey(w, r)
	if !ok {
		return
	}
	var in configmodel.WafZoneChange
	if !configBody(w, r, &in, 8192) {
		return
	}
	out, err := s.configuration.CreateZoneChange(r.Context(), a, key, in)
	if err != nil {
		configurationError(w, err)
		return
	}
	w.Header().Set("Location", out.StatusURL)
	writeJSON(w, 202, out)
}
func (s *Server) wafZoneGetChange(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	out, err := s.configuration.GetZoneChange(r.Context(), a, r.PathValue("id"))
	if err != nil {
		configurationError(w, err)
		return
	}
	configurationWrite(w, 200, out, out.Revision)
}

func zoneRevisionDTO(r *configuration.ZoneRevision) any {
	return struct {
		ID            string          `json:"id"`
		Content       json.RawMessage `json:"content"`
		ContentDigest string          `json:"contentDigest"`
		State         string          `json:"state"`
		Revision      string          `json:"revision"`
	}{r.ID, r.Content, r.ContentDigest, r.State, r.Revision}
}
