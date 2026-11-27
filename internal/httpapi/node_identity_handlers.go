package httpapi

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/nodeidentity"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func (s *Server) SetNodeIdentity(service *nodeidentity.Service) { s.nodeIdentity = service }

func nodeIdentityError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, identity.ErrDirectoryUnavailable):
		configurationProblem(w, 503, "identity_provider_unavailable", nil)
	case errors.Is(err, identity.ErrProof):
		configurationProblem(w, 403, "permission_required", nil)
	case errors.Is(err, nodeidentity.ErrInvalid):
		configurationProblem(w, 400, "invalid_node_identity_request", nil)
	case errors.Is(err, nodeidentity.ErrDenied), errors.Is(err, inventory.ErrIdentity), errors.Is(err, storage.ErrPermissionDenied):
		configurationProblem(w, 403, "node_identity_required", nil)
	case errors.Is(err, nodeidentity.ErrConflict), errors.Is(err, storage.ErrConflict):
		configurationProblem(w, 409, "node_identity_conflict", nil)
	case errors.Is(err, nodeidentity.ErrLimited):
		w.Header().Set("Retry-After", "60")
		configurationProblem(w, 429, "enrollment_rate_limited", nil)
	case errors.Is(err, storage.ErrNotFound):
		configurationProblem(w, 404, "not_found", nil)
	case errors.Is(err, securitystate.ErrBarrier), errors.Is(err, securitystate.ErrUnavailable), errors.Is(err, securityjournal.ErrUnavailable):
		configurationProblem(w, 503, "security_state_unavailable", nil)
	default:
		configurationProblem(w, 503, "node_identity_unavailable", nil)
	}
}

// enrollmentAdmission limits work before CSR parsing, journal calls or the
// fenced CP transaction. Only the actual TLS peer address selects its bucket.
type enrollmentAdmission struct {
	mu      sync.Mutex
	sources map[string]rateItem
	slots   chan struct{}
}

func newEnrollmentAdmission() *enrollmentAdmission {
	return &enrollmentAdmission{sources: make(map[string]rateItem), slots: make(chan struct{}, 4)}
}
func (a *enrollmentAdmission) allow(addr string, now time.Time) bool {
	ip, _, err := net.SplitHostPort(addr)
	parsed := net.ParseIP(ip)
	if err != nil || parsed == nil {
		return false
	}
	ip = parsed.String()
	a.mu.Lock()
	defer a.mu.Unlock()
	for key, item := range a.sources {
		if !now.Before(item.resetTime) {
			delete(a.sources, key)
		}
	}
	item, exists := a.sources[ip]
	if !exists {
		if len(a.sources) >= 1024 {
			return false
		}
		item = rateItem{resetTime: now.Add(time.Minute)}
	}
	if item.count >= 12 {
		return false
	}
	item.count++
	a.sources[ip] = item
	return true
}

func nodeCertificateWire(out nodeidentity.CertificateResult) map[string]any {
	return map[string]any{"nodeId": out.NodeID, "certificateChainPem": out.CertificateChainPEM, "serial": out.Serial, "expiresAt": out.ExpiresAt}
}

// EnrollmentHandler is served on its own server-authenticated TLS listener.
// It never reads browser sessions, client role certificates or proxy identity.
func (s *Server) EnrollmentHandler() http.Handler {
	return s.securityHeaders(s.recoverPanic(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || (r.URL.Path != "/agent/v1/enroll" && r.URL.Path != "/agent/v1/enrollment-requests") {
			configurationProblem(w, 404, "not_found", nil)
			return
		}
		if !s.cfg.SecureProfile || !s.cfg.ConfigurationEnabled || s.cfg.NodeIdentityConfig == "" || s.nodeIdentity == nil {
			configurationProblem(w, 503, "node_identity_disabled", nil)
			return
		}
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || !r.TLS.HandshakeComplete || r.URL.RawQuery != "" || r.URL.RawPath != "" || len(r.Header.Values("Origin"))+len(r.Header.Values("Cookie"))+len(r.Header.Values("Authorization")) != 0 {
			configurationProblem(w, 400, "invalid_enrollment_request", nil)
			return
		}
		if !s.enrollmentAdmission.allow(r.RemoteAddr, time.Now()) {
			w.Header().Set("Retry-After", "60")
			configurationProblem(w, 429, "enrollment_rate_limited", nil)
			return
		}
		select {
		case s.enrollmentAdmission.slots <- struct{}{}:
			defer func() { <-s.enrollmentAdmission.slots }()
		default:
			w.Header().Set("Retry-After", "1")
			configurationProblem(w, 503, "enrollment_busy", nil)
			return
		}
		var in nodeidentity.EnrollmentSubmission
		if !configBody(w, r, &in, 20<<10) {
			return
		}
		if r.URL.Path == "/agent/v1/enrollment-requests" {
			out, err := s.nodeIdentity.RequestEnrollment(r.Context(), in)
			if err != nil {
				nodeIdentityError(w, err)
				return
			}
			writeJSON(w, http.StatusAccepted, out)
			return
		}
		out, err := s.nodeIdentity.Enroll(r.Context(), in)
		if err != nil {
			nodeIdentityError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, nodeCertificateWire(out))
	})))
}

type nodeIdentityHandler func(http.ResponseWriter, *http.Request, nodeidentity.Actor)

func (s *Server) withNodeIdentity(write bool, next nodeIdentityHandler) http.HandlerFunc {
	return s.withSession(func(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
		if !s.cfg.SecureProfile || !s.cfg.ConfigurationEnabled || !s.managementRequest(r) {
			configurationProblem(w, 403, "permission_required", nil)
			return
		}
		if s.nodeIdentity == nil {
			configurationProblem(w, 503, "node_identity_disabled", nil)
			return
		}
		if write {
			if session.MFAAt == nil || time.Since(*session.MFAAt) > 5*time.Minute || session.MFAAt.After(time.Now()) {
				configurationProblem(w, 403, "step_up_required", nil)
				return
			}
			if len(r.Header.Values("X-CSRF-Token")) != 1 {
				configurationProblem(w, 403, "csrf_required", nil)
				return
			}
			verified := false
			s.requireCSRF(func(http.ResponseWriter, *http.Request, *domain.SessionContext) { verified = true })(w, r, session)
			if !verified {
				return
			}
		}
		next(w, r, nodeidentity.Actor{TokenHash: session.TokenHash, Origin: s.cfg.ManagementOrigin})
	})
}

func (s *Server) nodeIdentityRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v2/node-identity-profile", s.withSession(func(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
		if !s.cfg.SecureProfile || !s.cfg.ConfigurationEnabled || !s.managementRequest(r) {
			configurationProblem(w, 403, "permission_required", nil)
			return
		}
		writeJSON(w, 200, map[string]any{"enabled": s.nodeIdentity != nil && s.cfg.NodeIdentityConfig != "", "supportedRoles": []string{"agent"}})
	}))
	mux.HandleFunc("POST /api/v2/nodes", s.withNodeIdentity(true, func(w http.ResponseWriter, r *http.Request, a nodeidentity.Actor) {
		var in struct {
			ID     string            `json:"id"`
			SiteID string            `json:"siteId"`
			Name   string            `json:"name"`
			Labels map[string]string `json:"labels"`
		}
		if !configBody(w, r, &in, 16<<10) {
			return
		}
		key, ok := configKey(w, r)
		if !ok {
			return
		}
		out, err := s.nodeIdentity.CreateNode(r.Context(), a, key, nodeidentity.CreateNodeRequest{ID: in.ID, SiteID: in.SiteID, Name: in.Name, Labels: in.Labels})
		if err != nil {
			nodeIdentityError(w, err)
			return
		}
		// The creation receipt is frozen metadata. Returning a current read
		// projection here would require nodes.read in addition to nodes.enroll
		// and would turn an old create key into perpetual inventory access.
		writeJSON(w, 201, nodeidentity.NodeView{ID: out.ID, SiteID: out.SiteID, Name: out.Name, Labels: out.Labels, Connectivity: "unknown", IdentityState: "pending", Revision: 1})
	}))
	mux.HandleFunc("GET /api/v2/nodes", s.withNodeIdentity(false, func(w http.ResponseWriter, r *http.Request, a nodeidentity.Actor) {
		limit, after, ok := nodePage(w, r)
		if !ok {
			return
		}
		out, err := s.nodeIdentity.ListNodeViews(r.Context(), a)
		if err != nil {
			nodeIdentityError(w, err)
			return
		}
		start := sort.Search(len(out), func(i int) bool { return out[i].ID > after })
		end := min(start+limit, len(out))
		wire := map[string]any{"items": out[start:end]}
		if end < len(out) {
			wire["nextCursor"] = base64.RawURLEncoding.EncodeToString([]byte(out[end-1].ID))
		}
		writeJSON(w, 200, wire)
	}))
	mux.HandleFunc("GET /api/v2/nodes/{id}", s.withNodeIdentity(false, func(w http.ResponseWriter, r *http.Request, a nodeidentity.Actor) {
		out, err := s.nodeIdentity.GetNodeView(r.Context(), a, r.PathValue("id"))
		if err != nil {
			nodeIdentityError(w, err)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("POST /api/v2/nodes/{id}/revocations", s.withNodeIdentity(true, func(w http.ResponseWriter, r *http.Request, a nodeidentity.Actor) {
		var in nodeidentity.RevokeNodeRequest
		if !configBody(w, r, &in, 2048) {
			return
		}
		key, ok := configKey(w, r)
		if !ok {
			return
		}
		out, err := s.nodeIdentity.RevokeNode(r.Context(), a, r.PathValue("id"), key, in)
		if err != nil {
			nodeIdentityError(w, err)
			return
		}
		writeJSON(w, 202, map[string]any{"operationId": out.ID, "resourceId": out.NodeID, "statusUrl": "/api/v2/node-identity-operations/" + out.ID, "submittedAt": time.Now().UTC()})
	}))
	mux.HandleFunc("GET /api/v2/node-identity-operations/{id}", s.withNodeIdentity(false, func(w http.ResponseWriter, r *http.Request, a nodeidentity.Actor) {
		out, err := s.nodeIdentity.GetOperation(r.Context(), a, r.PathValue("id"))
		if err != nil {
			nodeIdentityError(w, err)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("POST /api/v2/nodes/{id}/enrollments", s.withNodeIdentity(true, func(w http.ResponseWriter, r *http.Request, a nodeidentity.Actor) {
		var in nodeidentity.EnrollmentRequest
		if !configBody(w, r, &in, 1024) {
			return
		}
		key, ok := configKey(w, r)
		if !ok {
			return
		}
		out, err := s.nodeIdentity.CreateEnrollment(r.Context(), a, r.PathValue("id"), key, in)
		if err != nil {
			nodeIdentityError(w, err)
			return
		}
		wire := map[string]any{"enrollmentId": out.ID, "tokenAvailable": out.TokenAvailable, "expiresAt": out.ExpiresAt}
		if out.TokenAvailable {
			wire["token"] = out.EnrollmentToken
		}
		writeJSON(w, 201, wire)
	}))
	mux.HandleFunc("GET /api/v2/nodes/{id}/enrollments/{enrollmentId}", s.withNodeIdentity(false, func(w http.ResponseWriter, r *http.Request, a nodeidentity.Actor) {
		out, err := s.nodeIdentity.GetEnrollment(r.Context(), a, r.PathValue("id"), r.PathValue("enrollmentId"))
		if err != nil {
			nodeIdentityError(w, err)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("POST /api/v2/nodes/{id}/enrollments/{enrollmentId}/approvals", s.withNodeIdentity(true, func(w http.ResponseWriter, r *http.Request, a nodeidentity.Actor) {
		var in nodeidentity.ApprovalRequest
		if !configBody(w, r, &in, 1024) {
			return
		}
		key, ok := configKey(w, r)
		if !ok {
			return
		}
		out, err := s.nodeIdentity.ApproveEnrollment(r.Context(), a, r.PathValue("id"), r.PathValue("enrollmentId"), key, in)
		if err != nil {
			nodeIdentityError(w, err)
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("POST /api/v2/nodes/{id}/enrollments/{enrollmentId}/revocations", s.withNodeIdentity(true, func(w http.ResponseWriter, r *http.Request, a nodeidentity.Actor) {
		var in struct{}
		if !configBody(w, r, &in, 1024) {
			return
		}
		key, ok := configKey(w, r)
		if !ok {
			return
		}
		out, err := s.nodeIdentity.RevokeEnrollment(r.Context(), a, r.PathValue("id"), r.PathValue("enrollmentId"), key)
		if err != nil {
			nodeIdentityError(w, err)
			return
		}
		writeJSON(w, 200, out)
	}))
}

func nodePage(w http.ResponseWriter, r *http.Request) (int, string, bool) {
	query := r.URL.Query()
	for key, values := range query {
		if (key != "limit" && key != "cursor") || len(values) != 1 {
			configurationProblem(w, 400, "invalid_pagination", nil)
			return 0, "", false
		}
	}
	limit := 50
	if raw := query.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 200 || strconv.Itoa(n) != raw {
			configurationProblem(w, 400, "invalid_pagination", nil)
			return 0, "", false
		}
		limit = n
	}
	after := ""
	if raw := query.Get("cursor"); raw != "" {
		b, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil || len(b) > 128 || len(b) == 0 || base64.RawURLEncoding.EncodeToString(b) != raw {
			configurationProblem(w, 400, "invalid_pagination", nil)
			return 0, "", false
		}
		after = string(b)
		for _, c := range after {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
				configurationProblem(w, 400, "invalid_pagination", nil)
				return 0, "", false
			}
		}
	}
	return limit, after, true
}
