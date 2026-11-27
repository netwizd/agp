package identity

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// InvitationService is installation-owned. Its constructor must run before
// coordinator recovery; optional transports may be attached afterwards.
type InvitationService struct {
	identity *Service
	vault    *emailVault
	slots    chan struct{}
	claims   sync.Map
}

func NewInvitationService(identity *Service) *InvitationService {
	s := &InvitationService{identity: identity, vault: newEmailVault(1024), slots: make(chan struct{}, 4)}
	if identity != nil && identity.Coordinator != nil {
		identity.invitations = s
		identity.Coordinator.Register("invitation_issue", s.materializeIssue)
		identity.Coordinator.Register("invitation_reserve", s.materializeReservation)
		identity.Coordinator.Register("invitation_cancel", s.materializeCancellation)
		identity.Coordinator.Register("invitation_activate", s.materializeActivation)
	}
	return s
}
func (s *InvitationService) Close() {
	if s != nil {
		s.vault.close()
	}
}
func (s *InvitationService) available() bool {
	return s != nil && s.identity != nil && s.identity.Coordinator != nil
}
func (s *InvitationService) withActor(ctx context.Context, a LifecycleActor, fn func(context.Context) error) error {
	if !s.available() {
		return ErrLifecycleUnavailable
	}
	return s.identity.WithCurrentSession(ctx, a.TokenHash, "management", a.Origin, func(fresh context.Context, _ *domain.SessionContext) error { return fn(fresh) })
}
func inviteRequestKey(key string) bool {
	return len(key) >= 1 && len(key) <= 128 && utf8.ValidString(key) && strings.TrimSpace(key) == key && !strings.ContainsAny(key, "\r\n\x00")
}

var errInviteReplay = errors.New("invitation metadata replay")

func inviteReplay(ctx context.Context, tx storage.IdentityTx, actor, action, key, digest string, out any) (bool, error) {
	var prior, raw string
	e := securitystate.One(ctx, tx, `SELECT request_digest,response_json FROM identity_invite_requests WHERE actor_id=? AND action=? AND request_key=?`, []any{actor, action, key}, func(r storage.IdentityRows) error { return r.Scan(&prior, &raw) })
	if errors.Is(e, storage.ErrNotFound) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	if prior != digest {
		return false, ErrLifecycleStale
	}
	if e = json.Unmarshal([]byte(raw), out); e != nil {
		return false, ErrLifecycleUnavailable
	}
	return true, nil
}
func inviteSaveRequest(ctx context.Context, tx storage.IdentityTx, actor, action, key, digest string, out any, at time.Time) error {
	raw, e := json.Marshal(out)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO identity_invite_requests(actor_id,action,request_key,request_digest,response_json,created_at) VALUES(?,?,?,?,?,?)`, actor, action, key, digest, string(raw), at)
	return e
}
func (s *InvitationService) CreatePending(ctx context.Context, a LifecycleActor, key string, in PendingUserInput) (*LifecycleUserView, error) {
	if !utf8.ValidString(in.Username) {
		return nil, ErrLifecycleInvalid
	}
	// Match the existing local-primary lookup policy before validation, digesting
	// and uniqueness checks. Display names and password bytes remain untouched.
	in.Username = strings.ToLower(in.Username)
	if !inviteRequestKey(key) || !configmodel.ValidID(in.ID) || !strings.HasPrefix(in.ID, "usr_") || len(in.Username) < 1 || len(in.Username) > 128 || strings.TrimSpace(in.Username) != in.Username || !utf8.ValidString(in.Username) || strings.ContainsAny(in.Username, "\r\n\x00") || len(in.DisplayName) > 256 || !utf8.ValidString(in.DisplayName) || len(in.GroupIDs) > 100 {
		return nil, ErrLifecycleInvalid
	}
	seen := map[string]bool{}
	for _, id := range in.GroupIDs {
		if !configmodel.ValidID(id) || seen[id] {
			return nil, ErrLifecycleInvalid
		}
		seen[id] = true
	}
	digest, e := configmodel.Digest(in)
	if e != nil {
		return nil, e
	}
	var out LifecycleUserView
	e = s.withActor(ctx, a, func(ctx context.Context) error {
		return s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
			actor, e := s.identity.lifecycleActor(ctx, tx, h, a, authz.PermUsersManage, true, false)
			if e != nil {
				return e
			}
			// Authorization and group checks precede metadata replay.
			for _, id := range in.GroupIDs {
				var count int
				if e = securitystate.One(ctx, tx, `SELECT COUNT(*) FROM groups WHERE id=?`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&count) }); e != nil {
					return e
				}
				if count != 1 {
					return ErrLifecycleInvalid
				}
				if e = securitystate.One(ctx, tx, `SELECT COUNT(*) FROM group_permissions WHERE group_id=?`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&count) }); e != nil {
					return e
				}
				if count > 0 {
					return storage.ErrApprovalRequired
				}
			}
			replay, e := inviteReplay(ctx, tx, actor.ID, "pending", key, digest, &out)
			if e != nil {
				return e
			}
			if replay {
				_, e = s.identity.lifecycleTargetMetadata(ctx, tx, h, actor, out.ID)
				return e
			}
			if e = limitN(ctx, tx, "pending_actor_"+actor.ID, h.RecordedAt, 30); e != nil {
				return e
			}
			var exists int
			if e = securitystate.One(ctx, tx, `SELECT COUNT(*) FROM users WHERE id=? OR username=?`, []any{in.ID, in.Username}, func(r storage.IdentityRows) error { return r.Scan(&exists) }); e != nil {
				return e
			}
			if exists != 0 {
				return storage.ErrConflict
			}
			if _, e = tx.Exec(ctx, `INSERT INTO users(id,username,password_hash,display_name,is_admin,identity_kind,lifecycle_state,security_version,password_version,created_at,updated_at) VALUES(?,?,'',?,FALSE,'local','invited',1,1,?,?)`, in.ID, in.Username, in.DisplayName, h.RecordedAt, h.RecordedAt); e != nil {
				return e
			}
			for _, id := range in.GroupIDs {
				if _, e = tx.Exec(ctx, `INSERT INTO user_groups(user_id,group_id) VALUES(?,?)`, in.ID, id); e != nil {
					return e
				}
			}
			t, e := lifecycleRawUser(ctx, tx, h, in.ID)
			if e != nil {
				return e
			}
			out = t.View
			if e = inviteSaveRequest(ctx, tx, actor.ID, "pending", key, digest, out, h.RecordedAt); e != nil {
				return e
			}
			return securitystate.Audit(ctx, tx, "identity.pending.created", actor.ID, map[string]any{"principalId": in.ID})
		})
	})
	if e != nil {
		return nil, e
	}
	return &out, nil
}

type inviteIssueIntent struct {
	TokenID           string `json:"tokenId"`
	Epoch             uint64 `json:"epoch"`
	IssuerID          string `json:"issuerId"`
	IssuerFingerprint string `json:"issuerFingerprint"`
}

func (s *InvitationService) CreateInvite(ctx context.Context, a LifecycleActor, principal, key string, expected securityjournal.UInt63, in InviteRequest) (*InviteView, error) {
	address, e := emailAddress(in.Email)
	if e != nil || in.TTLSeconds < 300 || in.TTLSeconds > 86400 || !configmodel.ValidID(principal) || !inviteRequestKey(key) {
		return nil, ErrLifecycleInvalid
	}
	digest, e := configmodel.Digest(struct {
		Principal string
		Expected  securityjournal.UInt63
		Input     InviteRequest
	}{principal, expected, in})
	if e != nil {
		return nil, e
	}
	var out InviteView
	e = s.withActor(ctx, a, func(ctx context.Context) error {
		if s.identity.email == nil {
			return ErrLifecycleUnavailable
		}
		return s.identity.Coordinator.ExecuteDynamic(ctx, "invitation_issue", func(tx storage.IdentityTx, h securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error) {
			actor, e := s.identity.lifecycleActor(ctx, tx, h, a, authz.PermUsersManage, true, false)
			if e != nil {
				return nil, nil, e
			}
			target, e := s.identity.lifecycleTarget(ctx, tx, h, actor, principal)
			if e != nil {
				return nil, nil, e
			}
			if expected == 0 || uint64(expected) != target.SecurityVersion {
				return nil, nil, ErrLifecycleStale
			}
			if target.Directory || target.View.LifecycleState != "invited" || target.View.Privileged || len(target.Permissions) > 0 || len(target.Grants) > 0 {
				return nil, nil, storage.ErrApprovalRequired
			}
			replay, e := inviteReplay(ctx, tx, actor.ID, "invite", key, digest, &out)
			if e != nil {
				return nil, nil, e
			}
			if replay {
				return nil, nil, errInviteReplay
			}
			for _, budget := range []struct {
				key string
				max int
			}{{"invite_actor_" + actor.ID, 10}, {"invite_target_" + principal, 3}, {"invite_source_" + auth.TokenHash(a.SourceIP), 20}} {
				if e = limitN(ctx, tx, budget.key, h.RecordedAt, budget.max); e != nil {
					return nil, nil, e
				}
			}
			oldIDs, e := securitystate.Strings(ctx, tx, `SELECT id FROM identity_one_time_tokens WHERE principal_id=? AND purpose='activate' AND consumed_at IS NULL AND revoked_at IS NULL ORDER BY id LIMIT 101`, principal)
			if e != nil {
				return nil, nil, e
			}
			if len(oldIDs) > 100 {
				return nil, nil, ErrLifecycleUnavailable
			}
			requests := []securityjournal.AppendRequest{}
			for _, id := range oldIDs {
				t, e := readLifecycleToken(ctx, tx, id)
				if e != nil {
					return nil, nil, e
				}
				floor, e := securitystate.Floor(ctx, tx, t.GuardID, t.GuardID)
				if e != nil {
					return nil, nil, e
				}
				if floor < t.GuardVersion {
					floor = t.GuardVersion
				}
				if floor >= uint64(securityjournal.MaxUInt63) {
					return nil, nil, ErrProof
				}
				requests = append(requests, securitystate.FloorRequest(actor.ID, t.GuardID, t.GuardID, floor+1))
				if e = s.cancelTokenTx(ctx, tx, t, h.RecordedAt); e != nil {
					return nil, nil, e
				}
			}
			contactID, contactVersion, e := s.approvedContactTx(ctx, tx, h, principal, address)
			if e != nil {
				return nil, nil, e
			}
			var generation uint64
			if e = securitystate.One(ctx, tx, `SELECT COALESCE(MAX(generation),0) FROM identity_one_time_tokens WHERE principal_id=? AND purpose='activate'`, []any{principal}, func(r storage.IdentityRows) error { return r.Scan(&generation) }); e != nil {
				return nil, nil, e
			}
			if generation >= uint64(securityjournal.MaxUInt63) {
				return nil, nil, ErrProof
			}
			raw, hash, e := auth.NewToken()
			if e != nil {
				return nil, nil, e
			}
			t := &lifecycleToken{ID: securitystate.ID("invite"), PrincipalID: principal, Purpose: "activate", ProofKind: "email", TokenHash: hash, GuardID: securitystate.ID("guard_setup"), GuardVersion: 1, Epoch: uint64(h.Epoch), SecurityVersion: target.SecurityVersion, PasswordVersion: target.PasswordVersion, PolicyDigest: lifecyclePolicyDigest(), IssuerID: actor.ID, IssuerFingerprint: actor.Fingerprint, ContactID: contactID, ContactVersion: contactVersion, Generation: generation + 1, AllowedAction: "activate", CreatedAt: h.RecordedAt, ExpiresAt: h.RecordedAt.Add(time.Duration(in.TTLSeconds) * time.Second)}
			if e = insertLifecycleToken(ctx, tx, t); e != nil {
				return nil, nil, e
			}
			out, e = s.QueueEmailTokenTx(ctx, tx, h, t, raw)
			if e != nil {
				return nil, nil, e
			}
			if e = inviteSaveRequest(ctx, tx, actor.ID, "invite", key, digest, out, h.RecordedAt); e != nil {
				return nil, nil, e
			}
			requests = append(requests, securitystate.FloorRequest(actor.ID, t.GuardID, t.GuardID, 1))
			data, e := json.Marshal(inviteIssueIntent{t.ID, uint64(h.Epoch), actor.ID, actor.Fingerprint})
			return data, requests, e
		})
	})
	if errors.Is(e, errInviteReplay) {
		e = nil
	}
	if e != nil {
		return nil, e
	}
	return &out, nil
}
func (s *InvitationService) approvedContactTx(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, principal, address string) (string, uint64, error) {
	if s.identity.email == nil || s.identity.email.keys == nil {
		return "", 0, ErrLifecycleUnavailable
	}
	ids, e := securitystate.Strings(ctx, tx, `SELECT id FROM identity_contacts WHERE principal_id=? ORDER BY id LIMIT 21`, principal)
	if e != nil {
		return "", 0, e
	}
	if len(ids) > 20 {
		return "", 0, ErrLimited
	}
	for _, id := range ids {
		c, e := s.identity.email.readContact(ctx, tx, id, principal)
		if errors.Is(e, ErrProof) {
			continue
		}
		if e != nil {
			return "", 0, e
		}
		raw, e := s.identity.email.address(c)
		if e != nil {
			return "", 0, ErrLifecycleUnavailable
		}
		same := emailEqual(string(raw), address)
		clear(raw)
		if same {
			return id, uint64(c.AuthenticatorVersion), nil
		}
	}
	if len(ids) >= 20 {
		return "", 0, ErrLimited
	}
	id := securitystate.ID("contact")
	keys := s.identity.email.keys
	nonce, ciphertext, e := emailSeal(keys.encryption[keys.activeEncryption], []byte(address), emailContactAAD(principal, id, 1))
	if e != nil {
		return "", 0, ErrLifecycleUnavailable
	}
	_, e = tx.Exec(ctx, `INSERT INTO identity_contacts(id,principal_id,authenticator_version,revision,key_id,nonce,ciphertext,verified,created_at,updated_at) VALUES(?,?,1,1,?,?,?,FALSE,?,?)`, id, principal, keys.activeEncryption, nonce, ciphertext, h.RecordedAt, h.RecordedAt)
	return id, 1, e
}
func (s *InvitationService) materializeIssue(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
	var in inviteIssueIntent
	if e := json.Unmarshal(raw, &in); e != nil {
		return e
	}
	t, e := readLifecycleToken(ctx, tx, in.TokenID)
	if errors.Is(e, storage.ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	h, e := s.identity.Coordinator.Authority.Head(ctx)
	if e != nil {
		return e
	}
	// A restart may lack volatile AD evidence or the delivery DEK. Retire the
	// positive publication while retaining every already committed deny floor.
	if uint64(h.Epoch) != in.Epoch || checkUnconsumedLifecycleToken(ctx, tx, h, t) != nil || s.identity.lifecycleIssuerCurrent(ctx, tx, h, t) != nil {
		return s.cancelTokenTx(ctx, tx, t, h.RecordedAt)
	}
	_, e = tx.Exec(ctx, `UPDATE identity_invite_outbox SET state='queued' WHERE token_id=? AND state='prepared'`, t.ID)
	if e != nil {
		return e
	}
	return securitystate.Audit(ctx, tx, "identity.invitation.created", in.IssuerID, map[string]any{"inviteId": t.ID, "principalId": t.PrincipalID})
}
func (s *InvitationService) cancelTokenTx(ctx context.Context, tx storage.IdentityTx, t *lifecycleToken, at time.Time) error {
	if _, e := tx.Exec(ctx, `UPDATE identity_one_time_tokens SET revoked_at=? WHERE id=? AND consumed_at IS NULL AND revoked_at IS NULL`, at, t.ID); e != nil {
		return e
	}
	if _, e := tx.Exec(ctx, `UPDATE identity_invite_outbox SET state='cancelled' WHERE token_id=? AND state IN ('prepared','queued')`, t.ID); e != nil {
		return e
	}
	if t.ReservedFlowID != "" {
		return s.CancelFlowTx(ctx, tx, t.ReservedFlowID)
	}
	return nil
}
