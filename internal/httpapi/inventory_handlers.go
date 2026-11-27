package httpapi

import (
	"errors"
	"net/http"

	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/nodeidentity"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func (s *Server) SetInventory(service *inventory.Service) { s.inventory = service }

func inventoryError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, identity.ErrDirectoryUnavailable):
		configurationProblem(w, 503, "identity_provider_unavailable", nil)
	case errors.Is(err, identity.ErrProof):
		configurationProblem(w, 403, "permission_required", nil)
	case errors.Is(err, inventory.ErrInvalid):
		configurationProblem(w, 400, "invalid_inventory", nil)
	case errors.Is(err, inventory.ErrIdentity), errors.Is(err, storage.ErrPermissionDenied):
		configurationProblem(w, 403, "agent_identity_required", nil)
	case errors.Is(err, inventory.ErrChallenge):
		configurationProblem(w, 409, "inventory_challenge_rejected", nil)
	case errors.Is(err, inventory.ErrConflict):
		configurationProblem(w, 409, "inventory_conflict", nil)
	case errors.Is(err, inventory.ErrNotFresh):
		configurationProblem(w, 409, "current_inventory_required", nil)
	case errors.Is(err, inventory.ErrUnavailable), errors.Is(err, securitystate.ErrBarrier), errors.Is(err, securitystate.ErrUnavailable), errors.Is(err, securityjournal.ErrUnavailable):
		configurationProblem(w, 503, "security_state_unavailable", nil)
	default:
		configurationProblem(w, 503, "inventory_unavailable", nil)
	}
}

// AgentHandler is mounted only on the dedicated TLS 1.3 client-auth listener.
// Browser sessions and forwarded identity headers confer no agent authority.
func (s *Server) AgentHandler() http.Handler {
	mux := http.NewServeMux()
	s.executionAgentRoutes(mux)
	mux.HandleFunc("POST /agent/v1/identities/renew", func(w http.ResponseWriter, r *http.Request) {
		if s.nodeIdentity == nil {
			configurationProblem(w, 503, "node_identity_disabled", nil)
			return
		}
		var in nodeidentity.RenewalRequest
		if !configBody(w, r, &in, 20<<10) {
			return
		}
		out, err := s.nodeIdentity.Renew(r.Context(), r.TLS, in)
		if err != nil {
			nodeIdentityError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, nodeCertificateWire(out))
	})
	mux.HandleFunc("POST /agent/v1/inventory-challenges", func(w http.ResponseWriter, r *http.Request) {
		var in struct{}
		if !configBody(w, r, &in, 1024) {
			return
		}
		out, err := s.inventory.Challenge(r.Context(), r.TLS)
		if err != nil {
			inventoryError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, out)
	})
	mux.HandleFunc("POST /agent/v1/inventories", func(w http.ResponseWriter, r *http.Request) {
		var in inventory.Submission
		if !configBody(w, r, &in, inventory.MaxObservationBytes+8192) {
			return
		}
		out, err := s.inventory.Submit(r.Context(), r.TLS, in)
		if err != nil {
			inventoryError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, out)
	})
	return s.securityHeaders(s.recoverPanic(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.inventory == nil || !s.cfg.SecureProfile || !s.cfg.ConfigurationEnabled {
			configurationProblem(w, 503, "inventory_disabled", nil)
			return
		}
		if r.URL.RawQuery != "" || len(r.Header.Values("Origin")) != 0 || len(r.Header.Values("Cookie")) != 0 {
			configurationProblem(w, 400, "invalid_agent_request", nil)
			return
		}
		mux.ServeHTTP(w, r)
	})))
}

func (s *Server) inventoryRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v2/agent-inventory", s.withSession(func(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
		if !s.cfg.SecureProfile || !s.cfg.ConfigurationEnabled || !s.managementRequest(r) {
			configurationProblem(w, 403, "permission_required", nil)
			return
		}
		if s.inventory == nil {
			configurationProblem(w, 503, "inventory_disabled", nil)
			return
		}
		out, err := s.inventory.ListForAdmin(r.Context(), session.TokenHash, s.cfg.ManagementOrigin)
		if err != nil {
			inventoryError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": out})
	}))
}
