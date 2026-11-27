package httpapi

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"time"

	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/executionsources"
	"github.com/netwizd/agp/internal/helper"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/rolloutexecution"
	"github.com/netwizd/agp/internal/securityjournal"
)

// Execution is explicitly installed with qualified sources and separate keys.
// A configured authoring/planning service does not enable these operations.
func (s *Server) SetExecution(service *rolloutexecution.Service) { s.execution = service }

type ExecutionBaselines interface {
	ChallengePeer(context.Context, *tls.ConnectionState) (*helper.BaselineChallenge, error)
	CapturePeer(context.Context, *tls.ConnectionState, helper.BaselineCapture) error
}

func (s *Server) SetExecutionBaselines(source ExecutionBaselines) { s.executionBaselines = source }

type executionHandler func(http.ResponseWriter, *http.Request, rolloutexecution.Actor)

func executionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, inventory.ErrIdentity):
		configurationProblem(w, 403, "agent_identity_required", nil)
	case errors.Is(err, rolloutexecution.ErrInvalid):
		configurationProblem(w, 400, "execution_invalid_request", nil)
	case errors.Is(err, rolloutexecution.ErrUnsupported):
		configurationProblem(w, 422, "execution_policy_unsupported", nil)
	case errors.Is(err, rolloutexecution.ErrStale):
		configurationProblem(w, 409, "execution_precondition_changed", nil)
	case errors.Is(err, rolloutexecution.ErrConflict):
		configurationProblem(w, 409, "execution_conflict", nil)
	case errors.Is(err, rolloutexecution.ErrUnavailable):
		configurationProblem(w, 503, "execution_source_unavailable", nil)
	case errors.Is(err, executionsources.ErrStale), errors.Is(err, executionsources.ErrCapture):
		configurationProblem(w, 409, "execution_precondition_changed", nil)
	case errors.Is(err, executionsources.ErrUnavailable):
		configurationProblem(w, 503, "execution_source_unavailable", nil)
	default:
		configurationError(w, err)
	}
}

func (s *Server) withExecution(write bool, next executionHandler) http.HandlerFunc {
	return s.withSession(func(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
		if !s.cfg.ConfigurationEnabled || s.execution == nil {
			configurationProblem(w, 404, "execution_disabled", nil)
			return
		}
		if !s.cfg.SecureProfile || !s.managementRequest(r) {
			configurationProblem(w, 403, "permission_required", nil)
			return
		}
		if write {
			origins := r.Header.Values("Origin")
			if len(origins) != 1 || origins[0] != s.cfg.ManagementOrigin {
				configurationProblem(w, http.StatusForbidden, "origin_not_allowed", nil)
				return
			}
			now := time.Now()
			if session.MFAAt == nil || session.MFAAt.After(now) || now.Sub(*session.MFAAt) > 5*time.Minute {
				configurationProblem(w, 403, "step_up_required", nil)
				return
			}
			if len(r.Header.Values("X-CSRF-Token")) != 1 {
				configurationProblem(w, http.StatusForbidden, "csrf_required", nil)
				return
			}
			verified := false
			s.requireCSRF(func(http.ResponseWriter, *http.Request, *domain.SessionContext) { verified = true })(w, r, session)
			if !verified {
				return
			}
		}
		next(w, r, rolloutexecution.Actor{TokenHash: session.TokenHash, Origin: s.cfg.ManagementOrigin})
	})
}

// The current sequential execution workflow has its own wire contract. TARGET
// deployment-plans/rollouts retain their asynchronous, fleet-wide contract.
func (s *Server) executionRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v2/config/execution-plans", s.withExecution(true, func(w http.ResponseWriter, r *http.Request, actor rolloutexecution.Actor) {
		var in rolloutexecution.Create
		if !configBody(w, r, &in, 128<<10) {
			return
		}
		key, ok := configKey(w, r)
		if !ok {
			return
		}
		out, err := s.execution.Create(r.Context(), actor, key, in)
		if err != nil {
			executionError(w, err)
			return
		}
		writeJSON(w, 201, out)
	}))
	mux.HandleFunc("GET /api/v2/config/execution-plans/{id}", s.withExecution(false, func(w http.ResponseWriter, r *http.Request, actor rolloutexecution.Actor) {
		out, err := s.execution.Get(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			executionError(w, err)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("POST /api/v2/config/execution-plans/{id}/approvals", s.withExecution(true, func(w http.ResponseWriter, r *http.Request, actor rolloutexecution.Actor) {
		var in struct {
			PlanDigest string `json:"planDigest"`
		}
		if !configBody(w, r, &in, 1024) {
			return
		}
		key, ok := configKey(w, r)
		if !ok {
			return
		}
		out, err := s.execution.Approve(r.Context(), actor, r.PathValue("id"), key, in.PlanDigest)
		if err != nil {
			executionError(w, err)
			return
		}
		writeJSON(w, 201, out)
	}))
	mux.HandleFunc("POST /api/v2/config/execution-plans/{id}/dispatch", s.withExecution(true, func(w http.ResponseWriter, r *http.Request, actor rolloutexecution.Actor) {
		var in struct {
			PlanDigest string `json:"planDigest"`
		}
		if !configBody(w, r, &in, 1024) {
			return
		}
		key, ok := configKey(w, r)
		if !ok {
			return
		}
		plan, err := s.execution.Get(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			executionError(w, err)
			return
		}
		if plan.Plan.PlanDigest != in.PlanDigest {
			executionError(w, rolloutexecution.ErrStale)
			return
		}
		requests, err := s.execution.Dispatch(r.Context(), actor, r.PathValue("id"), key)
		if err != nil {
			executionError(w, err)
			return
		}
		// This acknowledges dispatch, not a native execution outcome. Agent
		// receipts and the plan GET supply the current task state.
		type dispatchedTask struct {
			ID       string                 `json:"id"`
			NodeID   string                 `json:"nodeId"`
			Sequence securityjournal.UInt63 `json:"nodeDeploymentSequence"`
		}
		items := make([]dispatchedTask, 0, len(requests))
		for _, request := range requests {
			items = append(items, dispatchedTask{ID: request.Task.ID, NodeID: request.Task.NodeID, Sequence: request.Task.NodeDeploymentSequence})
		}
		writeJSON(w, 201, map[string]any{"items": items})
	}))
	mux.HandleFunc("POST /api/v2/config/execution-plans/{id}/cancel", s.withExecution(true, func(w http.ResponseWriter, r *http.Request, actor rolloutexecution.Actor) {
		var in struct{}
		if !configBody(w, r, &in, 1024) {
			return
		}
		key, ok := configKey(w, r)
		if !ok {
			return
		}
		if err := s.execution.Cancel(r.Context(), actor, r.PathValue("id"), key); err != nil {
			executionError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("POST /api/v2/config/execution-plans/{id}/rollback-plans", s.withExecution(true, func(w http.ResponseWriter, r *http.Request, actor rolloutexecution.Actor) {
		var in rolloutexecution.Create
		if !configBody(w, r, &in, 128<<10) {
			return
		}
		key, ok := configKey(w, r)
		if !ok {
			return
		}
		out, err := s.execution.Rollback(r.Context(), actor, key, r.PathValue("id"), in)
		if err != nil {
			executionError(w, err)
			return
		}
		writeJSON(w, 201, out)
	}))
}

func (s *Server) executionAgentRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /agent/v1/execution/baseline-challenges", func(w http.ResponseWriter, r *http.Request) {
		if s.executionBaselines == nil {
			configurationProblem(w, 503, "execution_disabled", nil)
			return
		}
		var in struct{}
		if !configBody(w, r, &in, 1024) {
			return
		}
		out, err := s.executionBaselines.ChallengePeer(r.Context(), r.TLS)
		if err != nil {
			executionError(w, err)
			return
		}
		writeJSON(w, 201, out)
	})
	mux.HandleFunc("POST /agent/v1/execution/baselines", func(w http.ResponseWriter, r *http.Request) {
		if s.executionBaselines == nil {
			configurationProblem(w, 503, "execution_disabled", nil)
			return
		}
		var in helper.BaselineCapture
		if !configBody(w, r, &in, 64<<10) {
			return
		}
		if err := s.executionBaselines.CapturePeer(r.Context(), r.TLS, in); err != nil {
			executionError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	available := func(w http.ResponseWriter) bool {
		if s.execution == nil {
			configurationProblem(w, 503, "execution_disabled", nil)
			return false
		}
		return true
	}
	mux.HandleFunc("POST /agent/v1/execution/start-proofs", func(w http.ResponseWriter, r *http.Request) {
		if !available(w) {
			return
		}
		var in helper.StartQuery
		if !configBody(w, r, &in, 16<<10) {
			return
		}
		out, err := s.execution.AuthorizeStartPeer(r.Context(), r.TLS, in)
		if err != nil {
			executionError(w, err)
			return
		}
		writeJSON(w, 200, out)
	})
	mux.HandleFunc("POST /agent/v1/execution/receipts", func(w http.ResponseWriter, r *http.Request) {
		if !available(w) {
			return
		}
		var in helper.ExecutionReceipt
		if !configBody(w, r, &in, 64<<10) {
			return
		}
		if err := s.execution.RecordReceiptPeer(r.Context(), r.TLS, in); err != nil {
			executionError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /agent/v1/execution/tasks", func(w http.ResponseWriter, r *http.Request) {
		if !available(w) {
			return
		}
		var in struct{}
		if !configBody(w, r, &in, 1024) {
			return
		}
		out, err := s.execution.PendingForPeer(r.Context(), r.TLS)
		if err != nil {
			executionError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": out})
	})
}
