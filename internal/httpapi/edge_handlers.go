package httpapi

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/domain"
)

// edgePeer accepts only the leaf identity verified by this TLS connection.
// Forwarded certificate headers, IP addresses and browser sessions convey no role.
func edgePeer(r *http.Request) (node, gateway string, ok bool) {
	if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return "", "", false
	}
	leaf := r.TLS.PeerCertificates[0]
	if leaf.IsCA || !leaf.Equal(r.TLS.VerifiedChains[0][0]) || len(leaf.URIs) != 1 {
		return "", "", false
	}
	// A verified TLS connection can outlive its certificate. Recheck the whole
	// verified chain on each request, including requests on a keep-alive socket.
	now := time.Now()
	chainCurrent := false
	for _, chain := range r.TLS.VerifiedChains {
		if len(chain) == 0 || !leaf.Equal(chain[0]) {
			continue
		}
		current := true
		for _, cert := range chain {
			if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
				current = false
				break
			}
		}
		if current {
			chainCurrent = true
			break
		}
	}
	if !chainCurrent {
		return "", "", false
	}
	clientAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if !clientAuth {
		return "", "", false
	}
	uri := leaf.URIs[0]
	if uri.Scheme != "spiffe" || uri.Host != "agp" || uri.User != nil || uri.RawQuery != "" || uri.ForceQuery || uri.Fragment != "" || uri.RawPath != "" || uri.Opaque != "" {
		return "", "", false
	}
	parts := strings.Split(uri.Path, "/")
	if len(parts) != 4 || parts[0] != "" || parts[1] != "edge" || !validIdentityID(parts[2]) || !validIdentityID(parts[3]) {
		return "", "", false
	}
	return parts[2], parts[3], true
}

// EdgeHandler must be mounted on the dedicated TLS listener configured with
// RequireAndVerifyClientCert. It still validates the verified leaf role here so
// another certificate trusted by the same CA cannot impersonate an EdgeAuth node.
func (s *Server) EdgeHandler() http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		node, gateway, ok := edgePeer(r)
		if !ok {
			identityProblem(w, http.StatusForbidden, "mtls_required")
			return
		}
		if !s.cfg.SecureProfile || s.identity == nil || s.store == nil || s.store.CheckSessionProfile(r.Context(), s.cfg.SessionProfile()) != nil {
			identityProblem(w, http.StatusServiceUnavailable, "security_state_unavailable")
			return
		}
		if r.Method != http.MethodPost {
			identityProblem(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		if r.URL.RawQuery != "" || len(r.Header.Values("Origin")) != 0 {
			identityProblem(w, http.StatusBadRequest, "invalid_request")
			return
		}
		switch r.URL.Path {
		case "/auth/v2/handoffs/redeem":
			var input domain.HandoffRedeemRequest
			if !strictIdentityJSON(w, r, &input) {
				return
			}
			if input.GatewayID != gateway {
				identityProblem(w, http.StatusForbidden, "gateway_identity_mismatch")
				return
			}
			out, err := s.identity.Redeem(r.Context(), node, gateway, input)
			if err != nil {
				identityError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, out)
		case "/auth/v2/decisions":
			var input domain.EdgeDecisionRequest
			if !strictIdentityJSON(w, r, &input) {
				return
			}
			if input.GatewayID != gateway {
				identityProblem(w, http.StatusForbidden, "gateway_identity_mismatch")
				return
			}
			out, err := s.identity.Decision(r.Context(), node, gateway, input)
			if err != nil {
				identityError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, out)
		case "/auth/v2/logout":
			var input domain.EdgeLogoutRequest
			if !strictIdentityJSON(w, r, &input) {
				return
			}
			if input.GatewayID != gateway {
				identityProblem(w, http.StatusForbidden, "gateway_identity_mismatch")
				return
			}
			if err := s.identity.GatewayLogout(r.Context(), node, gateway, input); err != nil {
				identityError(w, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			identityProblem(w, http.StatusNotFound, "not_found")
		}
	})
	return s.securityHeaders(s.recoverPanic(handler))
}
