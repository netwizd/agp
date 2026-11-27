package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func (s *Service) Complete(ctx context.Context, a FlowAuth, ip, ua string) (Completion, error) {
	var out Completion
	directoryProof, directoryErr := s.directoryFlowObservation(ctx, a)
	if directoryErr != nil {
		return out, directoryErr
	}
	token, hash, err := auth.NewToken()
	if err != nil {
		return out, err
	}
	csrf, csrfHash, err := auth.NewToken()
	if err != nil {
		return out, err
	}
	view, err := s.Get(ctx, a)
	if err != nil {
		return out, err
	}
	if view.Purpose == "activate" {
		if s.invitations == nil {
			return out, ErrLifecycleUnavailable
		}
		return s.invitations.CompleteActivation(ctx, a)
	}
	if view.Purpose == "recover" && s.recovery != nil {
		// The typed reset service returns ErrProof for a replacement-MFA capability;
		// selection uses persisted authority, never a client-supplied action.
		var reset bool
		err = s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
			f, e := s.checked(ctx, tx, h, a)
			if e != nil {
				return e
			}
			reset, e = s.recovery.IsPasswordResetTx(ctx, tx, f.ID)
			return e
		})
		if err != nil {
			return out, err
		}
		if reset {
			return s.recovery.CompletePasswordReset(ctx, a)
		}
		return s.recovery.CompleteMFAReplacement(ctx, a)
	}
	if view.Purpose == "verify_email" {
		if s.email == nil {
			return out, ErrEmailUnavailable
		}
		return s.email.CompleteFlow(ctx, a)
	}
	if view.Purpose == "step_up" {
		return s.completeStepUp(ctx, a, ip, ua, token, hash, csrf, csrfHash)
	}
	err = s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		f, err := s.checked(ctx, tx, h, a)
		if err != nil {
			return err
		}
		if err := directoryProof.check(ctx, tx, h, f.PrincipalID, "identity_flows", f.ID); err != nil {
			return err
		}
		if f.State != "ready" || !f.Primary {
			return ErrProof
		}
		if f.Purpose == "recover" || f.Purpose == "activate" {
			return ErrProof
		}
		if !f.MFA {
			return ErrProof
		}
		if !f.MFAAt.Valid || s.Now().Sub(f.MFAAt.Time) > 5*time.Minute {
			return ErrExpired
		}
		if f.Purpose == "step_up" {
			if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at=? WHERE (id=? OR source_session_id=?) AND revoked_at IS NULL`, s.Now(), f.SourceSessionID, f.SourceSessionID); err != nil {
				return err
			}
		}
		if f.Audience == "management" {
			allowed, until, e := managementAdmissionWitnessTx(ctx, tx, h, f.PrincipalID)
			if e != nil {
				return e
			}
			if !allowed {
				return ErrProof
			}
			fresh, e := s.Coordinator.Authority.Head(ctx)
			if e != nil {
				return e
			}
			if !fresh.SameState(h) {
				return securitystate.ErrUnavailable
			}
			if until != nil && !fresh.RecordedAt.Before(*until) {
				return ErrProof
			}
			if !fresh.RecordedAt.Before(f.ExpiresAt) || !emailRecent(fresh.RecordedAt, f.MFAAt) {
				return ErrExpired
			}
			if e = directoryProof.check(ctx, tx, fresh, f.PrincipalID, "identity_flows", f.ID); e != nil {
				return e
			}
		}
		now := s.Now()
		session := domain.Session{ID: securitystate.ID("session"), UserID: f.PrincipalID, TokenHash: hash, CSRFHash: csrfHash, IP: ip, UserAgent: ua, CreatedAt: now, ExpiresAt: now.Add(8 * time.Hour), Audience: f.Audience, AudienceOrigin: f.Origin, AuthorityEpoch: uint64(h.Epoch), SecurityVersion: f.SecurityVersion, MFAAt: &f.MFAAt.Time, PrimaryAt: flowPrimaryTime(f), LastSeenAt: &now}
		if err := InsertSession(ctx, tx, session); err != nil {
			return err
		}
		if err := copyDirectoryContext(ctx, tx, "identity_flows", f.ID, "sessions", session.ID); err != nil {
			return err
		}
		n, err := tx.Exec(ctx, `UPDATE identity_flows SET state='completed',next_step='none' WHERE id=? AND state='ready'`, f.ID)
		if err != nil || n != 1 {
			return ErrProof
		}
		f.State = "completed"
		f.NextStep = "none"
		out = Completion{View: f.view(), SessionToken: token, CSRFToken: csrf, Session: session}
		return securitystate.Audit(ctx, tx, "identity.login.completed", f.PrincipalID, map[string]any{"audience": f.Audience})
	})
	return out, err
}
func InsertSession(ctx context.Context, tx storage.IdentityTx, session domain.Session) error {
	_, err := tx.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,csrf_hash,ip,user_agent,expires_at,created_at,audience,audience_origin,authority_epoch,security_version,mfa_at,last_seen_at,source_session_id,gateway_id,node_id,primary_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, session.ID, session.UserID, session.TokenHash, session.CSRFHash, session.IP, session.UserAgent, session.ExpiresAt, session.CreatedAt, session.Audience, session.AudienceOrigin, int64(session.AuthorityEpoch), int64(session.SecurityVersion), session.MFAAt, session.LastSeenAt, session.SourceSessionID, session.GatewayID, session.NodeID, session.PrimaryAt)
	return err
}
func (s *Service) Session(ctx context.Context, hash, audience, origin string) (*domain.SessionContext, error) {
	session, _, err := s.sessionWithDirectoryProof(ctx, hash, audience, origin)
	return session, err
}

func (s *Service) sessionWithDirectoryProof(ctx context.Context, hash, audience, origin string) (*domain.SessionContext, *directoryObservation, error) {
	var out *domain.SessionContext
	directoryProof, directoryErr := s.directorySessionObservation(ctx, hash)
	if directoryErr != nil {
		return nil, nil, directoryErr
	}
	err := s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		var session domain.Session
		var revoked sql.NullTime
		var mfa, last, primary sql.NullTime
		err := securitystate.One(ctx, tx, `SELECT id,user_id,token_hash,csrf_hash,ip,user_agent,expires_at,created_at,audience,audience_origin,authority_epoch,security_version,mfa_at,last_seen_at,source_session_id,gateway_id,node_id,revoked_at,primary_at FROM sessions WHERE token_hash=?`, []any{hash}, func(r storage.IdentityRows) error {
			return r.Scan(&session.ID, &session.UserID, &session.TokenHash, &session.CSRFHash, &session.IP, &session.UserAgent, &session.ExpiresAt, &session.CreatedAt, &session.Audience, &session.AudienceOrigin, &session.AuthorityEpoch, &session.SecurityVersion, &mfa, &last, &session.SourceSessionID, &session.GatewayID, &session.NodeID, &revoked, &primary)
		})
		if err != nil {
			return storage.ErrNotFound
		}
		if revoked.Valid || session.AuthorityEpoch != uint64(h.Epoch) || session.Audience != audience || session.AudienceOrigin != origin || !s.Now().Before(session.ExpiresAt) || !last.Valid || s.Now().Sub(last.Time) > 30*time.Minute || last.Time.After(s.Now()) || !mfa.Valid || mfa.Time.After(s.Now()) {
			return storage.ErrNotFound
		}
		var user domain.User
		var passwordVersion uint64
		var blocked sql.NullTime
		err = securitystate.One(ctx, tx, `SELECT id,username,display_name,is_admin,blocked_at,created_at,updated_at,password_version FROM users WHERE id=?`, []any{session.UserID}, func(r storage.IdentityRows) error {
			return r.Scan(&user.ID, &user.Username, &user.DisplayName, &user.IsAdmin, &blocked, &user.CreatedAt, &user.UpdatedAt, &passwordVersion)
		})
		if err != nil || blocked.Valid {
			return storage.ErrNotFound
		}
		if err := checkPrincipal(ctx, tx, user.ID, session.SecurityVersion, passwordVersion); err != nil {
			return storage.ErrNotFound
		}
		if session.SourceSessionID != "" {
			var sourceRevoked sql.NullTime
			var expiry time.Time
			var sourceSeen sql.NullTime
			err := securitystate.One(ctx, tx, `SELECT revoked_at,expires_at,last_seen_at FROM sessions WHERE id=? AND authority_epoch=?`, []any{session.SourceSessionID, int64(h.Epoch)}, func(r storage.IdentityRows) error { return r.Scan(&sourceRevoked, &expiry, &sourceSeen) })
			if err != nil || sourceRevoked.Valid || !s.Now().Before(expiry) || !sourceSeen.Valid || s.Now().Sub(sourceSeen.Time) > 30*time.Minute {
				return storage.ErrNotFound
			}
		}
		if err := directoryProof.check(ctx, tx, h, user.ID, "sessions", session.ID); err != nil {
			return err
		}
		groups, err := securitystate.Strings(ctx, tx, `SELECT group_id FROM user_groups WHERE user_id=? ORDER BY group_id`, user.ID)
		if err != nil {
			return err
		}
		grants, err := securitystate.ReadEffectiveGrants(ctx, tx, h, user.ID)
		if err != nil {
			return err
		}
		permissions := identityGlobalPermissions(grants.Global, user.IsAdmin)
		if session.Audience == domain.SessionAudienceManagement && !user.IsAdmin && len(grants.Entries) == 0 {
			return storage.ErrNotFound
		}
		groups = directoryGroups(groups, directoryProof)
		user.GroupIDs = groups
		session.MFAAt = &mfa.Time
		if primary.Valid {
			session.PrimaryAt = &primary.Time
		}
		session.LastSeenAt = &last.Time
		if _, err := tx.Exec(ctx, `UPDATE sessions SET last_seen_at=? WHERE id=? OR id=?`, s.Now(), session.ID, session.SourceSessionID); err != nil {
			return err
		}
		out = &domain.SessionContext{Session: session, User: user, Groups: groups, Permissions: permissions}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return out, directoryProof, nil
}
func (s *Service) Logout(ctx context.Context, hash string) error {
	var id, userID string
	err := s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		return securitystate.One(ctx, tx, `SELECT id,user_id FROM sessions WHERE token_hash=? AND revoked_at IS NULL`, []any{hash}, func(r storage.IdentityRows) error { return r.Scan(&id, &userID) })
	})
	if errors.Is(err, storage.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.Coordinator.Execute(ctx, securitystate.Intent{Kind: "logout", Data: []byte(`{}`)}, func(storage.IdentityTx, securityjournal.Head) ([]securityjournal.AppendRequest, error) {
		return []securityjournal.AppendRequest{{Kind: "revoke_session", TargetType: "session", TargetID: id, ActorID: userID, Payload: securityjournal.Payload{SessionID: id}}}, nil
	})
}

type completionIntent struct {
	FlowID, SourceSessionID string
	Session                 domain.Session
}

func (s *Service) completeStepUp(ctx context.Context, a FlowAuth, ip, ua, token, hash, csrf, csrfHash string) (Completion, error) {
	var out Completion
	directoryProof, directoryErr := s.directoryFlowObservation(ctx, a)
	if directoryErr != nil {
		return out, directoryErr
	}
	// Carry the server-minted observation only through this request. Recovery
	// without fresh evidence must retire rather than publish an AD credential.
	if directoryProof != nil && directoryProof.pin != nil {
		proofs := directoryPeopleProofs{}
		if previous, ok := ctx.Value(directoryPeopleProofKey{}).(directoryPeopleProofs); ok {
			for id, p := range previous {
				proofs[id] = p
			}
		}
		proofs[directoryProof.pin.identity.PrincipalID] = directoryProof
		ctx = context.WithValue(ctx, directoryPeopleProofKey{}, proofs)
	}
	var intent completionIntent
	err := s.Coordinator.ExecuteDynamic(ctx, "step_up_completion", func(tx storage.IdentityTx, h securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error) {
		f, err := s.checked(ctx, tx, h, a)
		if err != nil {
			return nil, nil, err
		}
		if err := directoryProof.check(ctx, tx, h, f.PrincipalID, "identity_flows", f.ID); err != nil {
			return nil, nil, err
		}
		if f.Purpose != "step_up" || f.State != "ready" || !f.Primary || !f.MFA || !f.MFAAt.Valid || s.Now().Sub(f.MFAAt.Time) > 5*time.Minute {
			return nil, nil, ErrProof
		}
		if err := liveSession(ctx, tx, f.SourceSessionID, f.PrincipalID, uint64(h.Epoch), s.Now()); err != nil {
			return nil, nil, err
		}
		now := s.Now()
		session := domain.Session{ID: securitystate.ID("session"), UserID: f.PrincipalID, TokenHash: hash, CSRFHash: csrfHash, IP: ip, UserAgent: ua, CreatedAt: now, ExpiresAt: now.Add(8 * time.Hour), Audience: f.Audience, AudienceOrigin: f.Origin, AuthorityEpoch: uint64(h.Epoch), SecurityVersion: f.SecurityVersion, MFAAt: &f.MFAAt.Time, PrimaryAt: flowPrimaryTime(f), LastSeenAt: &now}
		intent = completionIntent{FlowID: f.ID, SourceSessionID: f.SourceSessionID, Session: session}
		raw, err := json.Marshal(intent)
		return raw, []securityjournal.AppendRequest{{Kind: "revoke_session", TargetType: "session", TargetID: f.SourceSessionID, ActorID: f.PrincipalID, Payload: securityjournal.Payload{SessionID: f.SourceSessionID}}}, err
	})
	if err != nil {
		return out, err
	}
	view, err := s.Get(ctx, a)
	if err != nil {
		return out, err
	}
	if view.State != "completed" {
		return out, ErrProof
	}
	return Completion{View: view, SessionToken: token, CSRFToken: csrf, Session: intent.Session}, nil
}
func (s *Service) materializeCompletion(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
	var i completionIntent
	if err := json.Unmarshal(raw, &i); err != nil {
		return err
	}
	f, err := loadFlow(ctx, tx, i.FlowID)
	if err != nil {
		return err
	}
	if f.Purpose != "step_up" || f.State != "ready" || f.SourceSessionID != i.SourceSessionID || f.PrincipalID != i.Session.UserID || f.Epoch != i.Session.AuthorityEpoch {
		return ErrProof
	}
	h, e := s.Coordinator.Authority.Head(ctx)
	if e != nil {
		return e
	}
	var until *time.Time
	if i.Session.Audience == "management" {
		var allowed bool
		allowed, until, e = managementAdmissionWitnessTx(ctx, tx, h, f.PrincipalID)
		if e == nil && !allowed {
			e = ErrProof
		}
	}
	if e == nil {
		var fresh securityjournal.Head
		fresh, e = s.Coordinator.Authority.Head(ctx)
		if e == nil && !fresh.SameState(h) {
			e = securitystate.ErrUnavailable
		}
		if e == nil && until != nil && !fresh.RecordedAt.Before(*until) {
			e = ErrProof
		}
		if e == nil {
			e = finalCompletionAuthority(ctx, tx, fresh, f)
		}
	}
	if e != nil {
		if !errors.Is(e, ErrProof) && !errors.Is(e, ErrExpired) && !errors.Is(e, ErrDirectoryUnavailable) && !errors.Is(e, storage.ErrPermissionDenied) && !errors.Is(e, storage.ErrNotFound) {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE identity_flows SET state='cancelled',next_step='none' WHERE id=?`, f.ID); e != nil {
			return e
		}
		return securitystate.Audit(ctx, tx, "identity.step_up.publication_denied", f.PrincipalID, map[string]any{"reason": "current_authority_unavailable"})
	}
	if err = InsertSession(ctx, tx, i.Session); err != nil {
		return err
	}
	if err := copyDirectoryContext(ctx, tx, "identity_flows", i.FlowID, "sessions", i.Session.ID); err != nil {
		return err
	}
	n, err := tx.Exec(ctx, `UPDATE identity_flows SET state='completed',next_step='none' WHERE id=? AND state='ready'`, f.ID)
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrProof
	}
	return securitystate.Audit(ctx, tx, "identity.step_up.completed", f.PrincipalID, map[string]any{"session": i.Session.ID})
}

// finalCompletionAuthority uses independent authority time and the private live
// directory proof after the receipt, immediately before positive publication.
func finalCompletionAuthority(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, f *flow) error {
	if h.RecordedAt.IsZero() {
		return securitystate.ErrUnavailable
	}
	if f.Epoch != uint64(h.Epoch) || !h.RecordedAt.Before(f.ExpiresAt) || !emailRecent(h.RecordedAt, f.PrimaryAt) || !emailRecent(h.RecordedAt, f.MFAAt) {
		return ErrExpired
	}
	if e := checkPrincipal(ctx, tx, f.PrincipalID, f.SecurityVersion, f.PasswordVersion); e != nil {
		return e
	}
	if e := directoryCheckProjection(ctx, tx, h, f.PrincipalID, "identity_flows", f.ID); e != nil {
		return e
	}
	_, e := DirectorySubjectFingerprint(ctx, tx, h, f.PrincipalID)
	return e
}

func flowPrimaryTime(f *flow) *time.Time {
	if f == nil || !f.PrimaryAt.Valid {
		return nil
	}
	return &f.PrimaryAt.Time
}
