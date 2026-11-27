package httpapi

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/identity"
)

// SetEmail is startup-only, after the identity writer and encrypted outbox have
// recovered. Addresses, keyrings and SMTP configuration never come from HTTP.
func (s *Server) SetEmail(service *identity.EmailService) { s.email = service }
func (s *Server) withEmail(write bool, next func(http.ResponseWriter, *http.Request, identity.EmailActor)) http.HandlerFunc {
	return s.withSession(func(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
		origin, audience, ok := s.secureOrigin(r)
		if !s.cfg.SecureProfile || !ok {
			identityProblem(w, 403, "origin_required")
			return
		}
		if s.email == nil {
			identityProblem(w, 503, "email_unavailable")
			return
		}
		if write {
			origins := r.Header.Values("Origin")
			if len(origins) != 1 || origins[0] != origin {
				identityProblem(w, 403, "origin_required")
				return
			}
			if len(r.Header.Values("X-CSRF-Token")) != 1 {
				identityProblem(w, 403, "csrf_required")
				return
			}
			valid := false
			s.requireCSRF(func(http.ResponseWriter, *http.Request, *domain.SessionContext) { valid = true })(w, r, session)
			if !valid {
				return
			}
		}
		next(w, r, identity.EmailActor{TokenHash: session.TokenHash, Audience: audience, Origin: origin, SourceIP: s.clientIP(r)})
	})
}
func emailError(w http.ResponseWriter, err error) {
	if errors.Is(err, identity.ErrContactStale) {
		identityProblem(w, 412, "contact_revision_mismatch")
		return
	}
	if errors.Is(err, identity.ErrEmailUnavailable) {
		identityProblem(w, 503, "email_unavailable")
		return
	}
	identityError(w, err)
}
func (s *Server) emailRoutes(mux *http.ServeMux) {
	const contacts = "/api/v2/me/contacts"
	mux.HandleFunc("GET "+contacts, s.withEmail(false, func(w http.ResponseWriter, r *http.Request, a identity.EmailActor) {
		if r.URL.RawQuery != "" {
			identityProblem(w, 400, "invalid_query")
			return
		}
		out, err := s.email.Contacts(r.Context(), a)
		if err != nil {
			emailError(w, err)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("POST "+contacts, s.withEmail(true, func(w http.ResponseWriter, r *http.Request, a identity.EmailActor) {
		var in struct {
			Email string `json:"email"`
		}
		if !strictIdentityJSON(w, r, &in) {
			return
		}
		out, err := s.email.CreateContact(r.Context(), a, in.Email)
		if err != nil {
			emailError(w, err)
			return
		}
		directoryTag(w, out.Revision)
		writeJSON(w, 201, out)
	}))
	mux.HandleFunc("PUT "+contacts+"/{id}", s.withEmail(true, func(w http.ResponseWriter, r *http.Request, a identity.EmailActor) {
		id := r.PathValue("id")
		if !validIdentityID(id) {
			identityProblem(w, 400, "invalid_contact")
			return
		}
		expected, ok := directoryRevision(w, r)
		if !ok {
			return
		}
		var in struct {
			Email string `json:"email"`
		}
		if !strictIdentityJSON(w, r, &in) {
			return
		}
		out, err := s.email.ReplaceContact(r.Context(), a, id, expected, in.Email)
		if err != nil {
			emailError(w, err)
			return
		}
		w.Header().Set("ETag", `"`+strconv.FormatUint(uint64(out.Revision), 10)+`"`)
		writeJSON(w, 200, out)
	}))
}
