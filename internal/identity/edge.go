package identity

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/origin"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type AuthorizeRequest struct{ GatewayID, RedirectURI, State, Challenge, Method string }

func validPKCE(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c)) {
			return false
		}
	}
	return true
}
func gateway(ctx context.Context, tx storage.IdentityTx, id string) (domain.GatewayRegistration, error) {
	var g domain.GatewayRegistration
	var enabled bool
	err := securitystate.One(ctx, tx, `SELECT id,node_id,origin,callback,resource_id,generation,enabled FROM gateways WHERE id=?`, []any{id}, func(r storage.IdentityRows) error {
		return r.Scan(&g.ID, &g.NodeID, &g.Origin, &g.Callback, &g.ResourceID, &g.Generation, &enabled)
	})
	if err != nil || !enabled {
		return g, ErrProof
	}
	return g, nil
}
func (s *Service) RegisterGateway(ctx context.Context, g domain.GatewayRegistration) error {
	if g.ID == "" || g.NodeID == "" || g.Generation == "" {
		return ErrProof
	}
	if _, err := origin.HTTPS(g.Origin); err != nil {
		return err
	}
	if g.Callback != g.Origin+"/_agp/callback" {
		return ErrProof
	}
	host, _ := origin.Hostname(strings.TrimPrefix(g.Origin, "https://"))
	for _, reserved := range []string{s.Profile.ManagementOrigin, s.Profile.LoginOrigin} {
		h, _ := origin.Hostname(strings.TrimPrefix(reserved, "https://"))
		if host == h {
			return ErrProof
		}
	}
	return s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		revoked, err := securitystate.Strings(ctx, tx, `SELECT node_id FROM security_node_revocations WHERE node_id=?`, g.NodeID)
		if err != nil {
			return err
		}
		if len(revoked) > 0 {
			return ErrProof
		}
		var resourceHost string
		var enabled bool
		if err := securitystate.One(ctx, tx, `SELECT public_host,enabled FROM resources WHERE id=?`, []any{g.ResourceID}, func(r storage.IdentityRows) error { return r.Scan(&resourceHost, &enabled) }); err != nil {
			return err
		}
		resourceHostname, err := origin.Hostname(resourceHost)
		if err != nil || resourceHostname != host || !enabled {
			return ErrProof
		}
		rows, err := tx.Query(ctx, `SELECT origin FROM gateways`)
		if err != nil {
			return err
		}
		var origins []string
		for rows.Next() {
			var value string
			if e := rows.Scan(&value); e != nil {
				rows.Close()
				return e
			}
			origins = append(origins, value)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, raw := range origins {
			existing, e := url.Parse(raw)
			if e != nil || strings.EqualFold(existing.Hostname(), host) {
				return storage.ErrConflict
			}
		}
		ids, err := securitystate.Strings(ctx, tx, `SELECT id FROM gateways WHERE id=?`, g.ID)
		if err != nil {
			return err
		}
		if len(ids) > 0 {
			return storage.ErrConflict
		}
		_, err = tx.Exec(ctx, `INSERT INTO gateways(id,node_id,origin,callback,resource_id,generation,enabled) VALUES(?,?,?,?,?,?,?)`, g.ID, g.NodeID, g.Origin, g.Callback, g.ResourceID, g.Generation, true)
		return err
	})
}
func (s *Service) Authorize(ctx context.Context, sourceHash string, in AuthorizeRequest) (string, error) {
	if in.Method != "S256" || len(in.Challenge) != 43 || !validPKCE(in.Challenge) || in.State == "" || len(in.State) > 256 || strings.ContainsAny(in.State, "\r\n") {
		return "", ErrProof
	}
	source, err := s.Session(ctx, sourceHash, domain.SessionAudienceLogin, s.Profile.LoginOrigin)
	if err != nil {
		return "", err
	}
	directoryProof, directoryErr := s.directorySessionObservation(ctx, sourceHash)
	if directoryErr != nil {
		return "", directoryErr
	}
	code, codeHash, err := auth.NewToken()
	if err != nil {
		return "", err
	}
	var redirect string
	err = s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		g, err := gateway(ctx, tx, in.GatewayID)
		if err != nil || g.Callback != in.RedirectURI {
			return ErrProof
		}
		if err := liveSession(ctx, tx, source.ID, source.User.ID, uint64(h.Epoch), s.Now()); err != nil {
			return err
		}
		if err := checkPrincipal(ctx, tx, source.User.ID, source.SecurityVersion, passwordVersion(ctx, tx, source.User.ID)); err != nil {
			return err
		}
		if err := directoryProof.check(ctx, tx, h, source.User.ID, "sessions", source.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO handoffs(code_hash,gateway_id,node_id,redirect_uri,challenge,source_session_id,principal_id,security_version,epoch,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, codeHash, g.ID, g.NodeID, g.Callback, in.Challenge, source.ID, source.User.ID, int64(source.SecurityVersion), int64(h.Epoch), s.Now().Add(time.Minute)); err != nil {
			return err
		}
		parsed, _ := url.Parse(g.Callback)
		query := parsed.Query()
		query.Set("code", code)
		query.Set("state", in.State)
		parsed.RawQuery = query.Encode()
		redirect = parsed.String()
		return nil
	})
	return redirect, err
}
func passwordVersion(ctx context.Context, tx storage.IdentityTx, user string) uint64 {
	var v uint64
	_ = securitystate.One(ctx, tx, `SELECT password_version FROM users WHERE id=?`, []any{user}, func(r storage.IdentityRows) error { return r.Scan(&v) })
	return v
}
func liveSession(ctx context.Context, tx storage.IdentityTx, id, user string, epoch uint64, now time.Time) error {
	var revoked sql.NullTime
	var expires time.Time
	var last sql.NullTime
	var currentEpoch uint64
	var principal string
	err := securitystate.One(ctx, tx, `SELECT revoked_at,expires_at,authority_epoch,user_id,last_seen_at FROM sessions WHERE id=?`, []any{id}, func(r storage.IdentityRows) error {
		return r.Scan(&revoked, &expires, &currentEpoch, &principal, &last)
	})
	if err != nil || revoked.Valid || currentEpoch != epoch || principal != user || !now.Before(expires) || !last.Valid || now.Sub(last.Time) > 30*time.Minute || last.Time.After(now) {
		return ErrProof
	}
	return nil
}
func (s *Service) Redeem(ctx context.Context, node, peerGateway string, in domain.HandoffRedeemRequest) (domain.HandoffRedeemResponse, error) {
	var out domain.HandoffRedeemResponse
	if peerGateway != in.GatewayID || !validPKCE(in.CodeVerifier) || len(in.Code) != 43 {
		return out, ErrProof
	}
	directoryProof, directoryErr := s.directoryRedeemObservation(ctx, node, peerGateway, in)
	if directoryErr != nil {
		return out, directoryErr
	}
	token, hash, err := auth.NewToken()
	if err != nil {
		return out, err
	}
	err = s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		g, err := gateway(ctx, tx, in.GatewayID)
		if err != nil || g.NodeID != node || g.Callback != in.RedirectURI {
			return ErrProof
		}
		var gatewayID, nodeID, redirect, challenge, sourceID, user string
		var securityVersion, epoch uint64
		var expires time.Time
		var consumed sql.NullTime
		err = securitystate.One(ctx, tx, `SELECT gateway_id,node_id,redirect_uri,challenge,source_session_id,principal_id,security_version,epoch,expires_at,consumed_at FROM handoffs WHERE code_hash=?`, []any{auth.TokenHash(in.Code)}, func(r storage.IdentityRows) error {
			return r.Scan(&gatewayID, &nodeID, &redirect, &challenge, &sourceID, &user, &securityVersion, &epoch, &expires, &consumed)
		})
		if err != nil || consumed.Valid || gatewayID != g.ID || nodeID != node || redirect != in.RedirectURI || epoch != uint64(h.Epoch) || !s.Now().Before(expires) {
			return ErrProof
		}
		digest := sha256.Sum256([]byte(in.CodeVerifier))
		actual := base64.RawURLEncoding.EncodeToString(digest[:])
		if subtle.ConstantTimeCompare([]byte(challenge), []byte(actual)) != 1 {
			return ErrProof
		}
		if err := liveSession(ctx, tx, sourceID, user, epoch, s.Now()); err != nil {
			return err
		}
		if err := checkPrincipal(ctx, tx, user, securityVersion, passwordVersion(ctx, tx, user)); err != nil {
			return err
		}
		if err := directoryProof.check(ctx, tx, h, user, "sessions", sourceID); err != nil {
			return err
		}
		var sourceExpiry time.Time
		var mfa, primary sql.NullTime
		var audience, sourceOrigin string
		err = securitystate.One(ctx, tx, `SELECT expires_at,mfa_at,audience,audience_origin,primary_at FROM sessions WHERE id=?`, []any{sourceID}, func(r storage.IdentityRows) error {
			return r.Scan(&sourceExpiry, &mfa, &audience, &sourceOrigin, &primary)
		})
		if err != nil || !mfa.Valid || audience != domain.SessionAudienceLogin || sourceOrigin != s.Profile.LoginOrigin {
			return ErrProof
		}
		now := s.Now()
		session := domain.Session{ID: securitystate.ID("gateway_session"), UserID: user, TokenHash: hash, CSRFHash: auth.TokenHash(securitystate.ID("unused_csrf")), CreatedAt: now, ExpiresAt: sourceExpiry, Audience: domain.SessionAudienceGateway, AudienceOrigin: g.Origin, AuthorityEpoch: epoch, SecurityVersion: securityVersion, MFAAt: &mfa.Time, LastSeenAt: &now, SourceSessionID: sourceID, GatewayID: g.ID, NodeID: node}
		if primary.Valid {
			session.PrimaryAt = &primary.Time
		}
		if err := InsertSession(ctx, tx, session); err != nil {
			return err
		}
		if err := copyDirectoryContext(ctx, tx, "sessions", sourceID, "sessions", session.ID); err != nil {
			return err
		}
		n, err := tx.Exec(ctx, `UPDATE handoffs SET consumed_at=? WHERE code_hash=? AND consumed_at IS NULL`, now, auth.TokenHash(in.Code))
		if err != nil || n != 1 {
			return ErrProof
		}
		out = domain.HandoffRedeemResponse{SessionToken: token, SessionID: session.ID, ExpiresAt: session.ExpiresAt, UserID: user}
		return nil
	})
	return out, err
}
func (s *Service) Decision(ctx context.Context, node, peerGateway string, in domain.EdgeDecisionRequest) (domain.EdgeDecision, error) {
	out := domain.EdgeDecision{Decision: "deny", ReasonCode: "authentication_required"}
	if in.GatewayID != peerGateway {
		return out, ErrProof
	}
	var g domain.GatewayRegistration
	if err := s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		var err error
		g, err = gateway(ctx, tx, in.GatewayID)
		return err
	}); err != nil {
		return out, err
	}
	if g.NodeID != node || g.ResourceID != in.RouteID || g.Generation != in.DeploymentGeneration {
		return out, ErrProof
	}
	session, err := s.Session(ctx, auth.TokenHash(in.SessionToken), domain.SessionAudienceGateway, g.Origin)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			err = s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
				out.SecuritySequence = h.Sequence
				return nil
			})
			return out, err
		}
		return out, err
	}
	if session.GatewayID != g.ID || session.NodeID != node {
		return out, ErrProof
	}
	directoryProof, directoryErr := s.directorySessionObservation(ctx, auth.TokenHash(in.SessionToken))
	if directoryErr != nil {
		return out, directoryErr
	}
	err = s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		out.SecuritySequence = h.Sequence
		if err := liveSession(ctx, tx, session.ID, session.User.ID, uint64(h.Epoch), s.Now()); err != nil {
			return nil
		}
		if err := liveSession(ctx, tx, session.SourceSessionID, session.User.ID, uint64(h.Epoch), s.Now()); err != nil {
			return nil
		}
		if err := directoryProof.check(ctx, tx, h, session.User.ID, "sessions", session.ID); err != nil {
			return err
		}
		current, err := gateway(ctx, tx, g.ID)
		if err != nil || current.NodeID != node || current.Generation != in.DeploymentGeneration || current.ResourceID != in.RouteID {
			return ErrProof
		}
		var resourceHost, resourcePath string
		var enabled bool
		err = securitystate.One(ctx, tx, `SELECT public_host,public_path,enabled FROM resources WHERE id=?`, []any{in.RouteID}, func(r storage.IdentityRows) error { return r.Scan(&resourceHost, &resourcePath, &enabled) })
		if err != nil {
			return err
		}
		out.ReasonCode = "access_denied"
		if !enabled {
			return nil
		}
		hostname, err := origin.Hostname(resourceHost)
		gatewayHostname, _ := origin.Hostname(strings.TrimPrefix(g.Origin, "https://"))
		if err != nil || hostname != gatewayHostname {
			return ErrProof
		}
		uri, err := url.ParseRequestURI(in.Path)
		if err != nil || uri.Host != "" || uri.Path == "" || strings.Contains(uri.Path, "\\") {
			return ErrProof
		}
		for _, part := range strings.Split(uri.Path, "/") {
			if part == ".." || part == "." {
				return ErrProof
			}
		}
		if resourcePath != "" && uri.Path != resourcePath && !strings.HasPrefix(uri.Path, resourcePath+"/") {
			return nil
		}
		allowed, err := securitystate.Strings(ctx, tx, `SELECT rg.group_id FROM resource_groups rg JOIN user_groups ug ON ug.group_id=rg.group_id WHERE rg.resource_id=? AND ug.user_id=?`, in.RouteID, session.User.ID)
		if err != nil {
			return err
		}
		if len(allowed) == 0 && directoryProof != nil && directoryProof.account != nil {
			resourceGroups, e := securitystate.Strings(ctx, tx, `SELECT group_id FROM resource_groups WHERE resource_id=?`, in.RouteID)
			if e != nil {
				return e
			}
			for _, target := range resourceGroups {
				for _, actual := range directoryProof.account.AccessGroupIDs {
					if target == actual {
						allowed = append(allowed, target)
					}
				}
			}
		}
		if len(allowed) == 0 {
			return nil
		}
		cidrs, err := securitystate.Strings(ctx, tx, `SELECT cidr FROM resource_ip_allowlists WHERE resource_id=?`, in.RouteID)
		if err != nil {
			return err
		}
		if len(cidrs) > 0 {
			ip := net.ParseIP(in.ClientIP)
			if ip == nil {
				return ErrProof
			}
			matched := false
			for _, raw := range cidrs {
				_, network, err := net.ParseCIDR(raw)
				if err != nil {
					return err
				}
				if network.Contains(ip) {
					matched = true
				}
			}
			if !matched {
				return nil
			}
		}
		groups, err := securitystate.Strings(ctx, tx, `SELECT group_id FROM user_groups WHERE user_id=? ORDER BY group_id`, session.User.ID)
		if err != nil {
			return err
		}
		groups = directoryGroups(groups, directoryProof)
		if len(groups) > 100 {
			return errors.New("identity group limit exceeded")
		}
		if groups == nil {
			groups = []string{}
		}
		out.Decision = "allow"
		out.ReasonCode = "allowed"
		out.UserID = session.User.ID
		out.GroupIDs = groups
		return nil
	})
	return out, err
}
func (s *Service) GatewayLogout(ctx context.Context, node, peerGateway string, in domain.EdgeLogoutRequest) error {
	if in.GatewayID != peerGateway {
		return ErrProof
	}
	var hash = auth.TokenHash(in.SessionToken)
	err := s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		var gw, nodeID, audience string
		err := securitystate.One(ctx, tx, `SELECT gateway_id,node_id,audience FROM sessions WHERE token_hash=?`, []any{hash}, func(r storage.IdentityRows) error { return r.Scan(&gw, &nodeID, &audience) })
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		if err != nil || gw != peerGateway || nodeID != node || audience != domain.SessionAudienceGateway {
			return ErrProof
		}
		return nil
	})
	if err != nil {
		return err
	}
	return s.Logout(ctx, hash)
}
