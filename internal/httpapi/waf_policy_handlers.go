package httpapi

import (
	"github.com/netwizd/agp/internal/configuration"
	"net/http"
)

func (s *Server) wafPolicyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v2/waf/policy-revisions", s.withConfigurationPermission("config.edit", true, s.wafPolicyCreate))
	mux.HandleFunc("GET /api/v2/waf/policy-revisions/{id}", s.withConfigurationPermission("config.read", false, s.wafPolicyGet))
	mux.HandleFunc("POST /api/v2/waf/policy-revisions/{id}/validations", s.withConfigurationPermission("config.edit", true, s.wafPolicyValidate))
	mux.HandleFunc("POST /api/v2/waf/policy-revisions/{id}/approvals", s.withConfigurationPermission("config.approve", true, s.wafPolicyApprove))
	mux.HandleFunc("POST /api/v2/waf/policy-revisions/{id}/publications", s.withConfigurationPermission("config.approve", true, s.wafPolicyPublish))
	mux.HandleFunc("GET /api/v2/waf/validations/{id}", s.withConfigurationPermission("config.read", false, s.wafPolicyValidation))
}
func (s *Server) wafPolicyCreate(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	key, ok := configKey(w, r)
	if !ok {
		return
	}
	var in configuration.WafPolicyCreate
	if !configBody(w, r, &in, 4<<20) {
		return
	}
	out, e := s.configuration.CreateWafPolicyRevision(r.Context(), a, key, in)
	if e != nil {
		configurationError(w, e)
		return
	}
	configurationWrite(w, 201, out, out.Revision)
}
func (s *Server) wafPolicyGet(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	out, e := s.configuration.GetWafPolicyRevision(r.Context(), a, r.PathValue("id"))
	if e != nil {
		configurationError(w, e)
		return
	}
	configurationWrite(w, 200, out, out.Revision)
}
func (s *Server) wafPolicyValidate(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	key, ok := configKey(w, r)
	if !ok {
		return
	}
	var in struct{}
	if !configBody(w, r, &in, 8192) {
		return
	}
	out, e := s.configuration.ValidateWafPolicyRevision(r.Context(), a, r.PathValue("id"), key)
	if e != nil {
		configurationError(w, e)
		return
	}
	writeJSON(w, 202, out)
}
func (s *Server) wafPolicyApprove(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	key, ok := configKey(w, r)
	if !ok {
		return
	}
	var in configuration.WafPolicyApprovalRequest
	if !configBody(w, r, &in, 8192) {
		return
	}
	out, e := s.configuration.ApproveWafPolicyRevision(r.Context(), a, r.PathValue("id"), key, in)
	if e != nil {
		configurationError(w, e)
		return
	}
	writeJSON(w, 201, out)
}
func (s *Server) wafPolicyPublish(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	key, ok := configKey(w, r)
	if !ok {
		return
	}
	var in configuration.WafPolicyPublicationRequest
	if !configBody(w, r, &in, 8192) {
		return
	}
	out, e := s.configuration.PublishWafPolicyRevision(r.Context(), a, r.PathValue("id"), key, in)
	if e != nil {
		configurationError(w, e)
		return
	}
	configurationWrite(w, 200, out, out.Revision)
}
func (s *Server) wafPolicyValidation(w http.ResponseWriter, r *http.Request, a configuration.Actor) {
	out, e := s.configuration.GetWafPolicyValidation(r.Context(), a, r.PathValue("id"))
	if e != nil {
		configurationError(w, e)
		return
	}
	writeJSON(w, 200, out)
}
