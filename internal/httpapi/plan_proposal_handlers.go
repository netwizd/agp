package httpapi

import (
	"net/http"
	"strconv"

	"github.com/netwizd/agp/internal/configuration"
)

// These are planning-review resources, deliberately separate from the TARGET
// deployment-plans/approvals and rollout endpoints. They allocate no sequence.
func (s *Server) planProposalRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v2/config/plan-proposals", s.withConfiguration(true, s.planProposalCreate))
	mux.HandleFunc("GET /api/v2/config/plan-proposals", s.withConfiguration(false, s.planProposalList))
	mux.HandleFunc("GET /api/v2/config/plan-proposals/{id}", s.withConfiguration(false, s.planProposalGet))
	mux.HandleFunc("GET /api/v2/config/plan-proposals/{id}/reviews", s.withConfiguration(false, s.planProposalReviews))
	mux.HandleFunc("POST /api/v2/config/plan-proposals/{id}/reviews", s.withConfigurationPermission("config.approve", true, s.planProposalReview))
	mux.HandleFunc("POST /api/v2/config/plan-proposals/{id}/reviews/{reviewId}/signatures", s.withConfigurationPermission("config.approve", true, s.planProposalSign))
}

func (s *Server) planProposalCreate(w http.ResponseWriter, r *http.Request, actor configuration.Actor) {
	var in configuration.PlanProposalCreate
	if !configBody(w, r, &in, 128<<10) {
		return
	}
	key, ok := configKey(w, r)
	if !ok {
		return
	}
	out, err := s.configuration.CreatePlanProposal(r.Context(), actor, key, in)
	if err != nil {
		configurationError(w, err)
		return
	}
	w.Header().Set("Location", "/api/v2/config/plan-proposals/"+out.ID)
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) planProposalList(w http.ResponseWriter, r *http.Request, actor configuration.Actor) {
	limit := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		var err error
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 50 {
			configurationProblem(w, 400, "invalid_limit", nil)
			return
		}
	}
	out, err := s.configuration.ListPlanProposals(r.Context(), actor, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		configurationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) planProposalGet(w http.ResponseWriter, r *http.Request, actor configuration.Actor) {
	out, err := s.configuration.GetPlanProposal(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		configurationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) planProposalReviews(w http.ResponseWriter, r *http.Request, actor configuration.Actor) {
	out, err := s.configuration.PlanProposalReviews(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		configurationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) planProposalReview(w http.ResponseWriter, r *http.Request, actor configuration.Actor) {
	var in configuration.PlanProposalReviewRequest
	if !configBody(w, r, &in, 8192) {
		return
	}
	key, ok := configKey(w, r)
	if !ok {
		return
	}
	out, err := s.configuration.ReviewPlanProposal(r.Context(), actor, r.PathValue("id"), key, in)
	if err != nil {
		configurationError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) planProposalSign(w http.ResponseWriter, r *http.Request, actor configuration.Actor) {
	var in struct{}
	if !configBody(w, r, &in, 1024) {
		return
	}
	key, ok := configKey(w, r)
	if !ok {
		return
	}
	out, err := s.configuration.SignPlanProposalReview(r.Context(), actor, r.PathValue("id"), r.PathValue("reviewId"), key)
	if err != nil {
		configurationError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}
