package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/storage"
)

type sessionContextKey struct{}

func (s *Server) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("panic recovered", "error", recovered, "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, "internal_error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withSession(next func(http.ResponseWriter, *http.Request, *domain.SessionContext)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := s.lookupSession(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		ctx := context.WithValue(r.Context(), sessionContextKey{}, session)
		next(w, r.WithContext(ctx), session)
	}
}

func (s *Server) withPermission(permission string, next func(http.ResponseWriter, *http.Request, *domain.SessionContext)) http.HandlerFunc {
	return s.withSession(func(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
		if !authz.HasPermission(session.Permissions, permission) {
			s.audit(r, "admin.access", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "failure", "permission_required:"+permission)
			writeError(w, http.StatusForbidden, "permission_required")
			return
		}
		next(w, r, session)
	})
}

func (s *Server) lookupSession(r *http.Request) (*domain.SessionContext, error) {
	cookie, err := r.Cookie(s.cfg.SessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil, storage.ErrNotFound
	}
	session, err := s.store.FindSessionByTokenHash(r.Context(), auth.TokenHash(cookie.Value))
	if err != nil {
		return nil, err
	}
	if session.User.BlockedAt != nil {
		return nil, errors.New("user is blocked")
	}
	return session, nil
}

func (s *Server) requireCSRF(next func(http.ResponseWriter, *http.Request, *domain.SessionContext)) func(http.ResponseWriter, *http.Request, *domain.SessionContext) {
	return func(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
		token := r.Header.Get("X-CSRF-Token")
		if token == "" || !auth.ConstantTimeEqualHash(token, session.CSRFHash) {
			writeError(w, http.StatusForbidden, "csrf_required")
			return
		}
		next(w, r, session)
	}
}
