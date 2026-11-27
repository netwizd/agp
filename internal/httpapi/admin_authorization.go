package httpapi

import (
	"errors"
	"net/http"

	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/storage"
)

func (s *Server) applyIdentityMutation(r *http.Request, session *domain.SessionContext, mutation storage.IdentityMutation) (*storage.IdentityMutationResult, error) {
	mutation.ManagementOrigin = s.cfg.ManagementOrigin
	result, err := s.store.ApplyIdentityMutation(r.Context(), session.TokenHash, mutation)
	if errors.Is(err, storage.ErrPermissionDenied) || errors.Is(err, storage.ErrLastAdmin) {
		s.auditWithMetadata(r, "admin.identity.denied", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "failure", err.Error(), map[string]any{
			"mutation":  mutation.Kind,
			"target_id": mutation.ID,
		})
	}
	return result, err
}
