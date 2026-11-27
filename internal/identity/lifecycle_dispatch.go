package identity

import (
	"context"
	"database/sql"
	"errors"

	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// BindLifecycleInvitation chooses the token purpose only from the authenticated
// flow and immutable server token. A browser cannot name an account or action.
func (s *Service) BindLifecycleInvitation(ctx context.Context, a FlowAuth, raw, sourceIP string) (Transition, error) {
	v, e := s.Get(ctx, a)
	if e != nil {
		return Transition{}, e
	}
	switch v.Purpose {
	case "activate":
		if s.invitations == nil {
			return Transition{}, ErrLifecycleUnavailable
		}
		return s.invitations.BindInvitation(ctx, a, raw, sourceIP)
	case "recover":
		if s.recovery == nil {
			return Transition{}, ErrLifecycleUnavailable
		}
		return s.recovery.BindResetInvitation(ctx, a, raw, sourceIP)
	default:
		return Transition{}, ErrProof
	}
}
func (s *Service) SupervisedRecoveryProof(ctx context.Context, a FlowAuth, raw, sourceIP string) (Transition, error) {
	if s.recovery == nil {
		return Transition{}, ErrLifecycleUnavailable
	}
	return s.recovery.ConsumeSupervisedTicket(ctx, a, raw, sourceIP)
}
func (s *Service) SetPassword(ctx context.Context, a FlowAuth, password string) (FlowView, error) {
	if !lifecyclePasswordValid(password) {
		return FlowView{}, ErrLifecycleInvalid
	}
	v, e := s.Get(ctx, a)
	if e != nil {
		return FlowView{}, e
	}
	switch v.Purpose {
	case "activate":
		if s.invitations == nil {
			return FlowView{}, ErrLifecycleUnavailable
		}
		return s.invitations.SetInitialPassword(ctx, a, password)
	case "recover":
		if s.recovery == nil {
			return FlowView{}, ErrLifecycleUnavailable
		}
		return s.recovery.SetResetPassword(ctx, a, password)
	default:
		return FlowView{}, ErrProof
	}
}

type LifecycleAccessView struct {
	UsersRead        bool                   `json:"usersRead"`
	PrincipalID      string                 `json:"principalId"`
	AuthorityEpoch   securityjournal.UInt63 `json:"authorityEpoch"`
	UsersManage      bool                   `json:"usersManage"`
	PrivilegedManage bool                   `json:"privilegedManage"`
	Approve          bool                   `json:"approve"`
}
type LifecycleUserList struct {
	Items      []LifecycleUserView `json:"items"`
	NextCursor *string             `json:"nextCursor"`
}

func (s *Service) withLifecycleActor(ctx context.Context, a LifecycleActor, fn func(context.Context) error) error {
	if a.Origin != s.Profile.ManagementOrigin {
		return storage.ErrPermissionDenied
	}
	return s.WithCurrentSession(ctx, a.TokenHash, domain.SessionAudienceManagement, a.Origin, func(ctx context.Context, _ *domain.SessionContext) error { return fn(ctx) })
}
func (s *Service) LifecycleAccess(ctx context.Context, a LifecycleActor) (LifecycleAccessView, error) {
	var out LifecycleAccessView
	e := s.withLifecycleActor(ctx, a, func(ctx context.Context) error {
		return s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
			p, e := s.lifecycleActor(ctx, tx, h, a, "", false, false)
			if e != nil {
				return e
			}
			out = LifecycleAccessView{PrincipalID: p.ID, AuthorityEpoch: h.Epoch, UsersRead: lifecycleHas(p.Permissions, authz.PermUsersRead), UsersManage: lifecycleHas(p.Permissions, authz.PermUsersManage), PrivilegedManage: lifecycleHas(p.Permissions, "users.privileged.manage")}
			_, e = s.lifecycleSubject(ctx, tx, h, p.ID, "", true)
			if errors.Is(e, storage.ErrPermissionDenied) {
				return nil
			}
			if e != nil {
				return e
			}
			out.Approve = true
			return nil
		})
	})
	return out, e
}
func (s *Service) LifecycleUser(ctx context.Context, a LifecycleActor, id string) (*LifecycleUserView, error) {
	if !configmodel.ValidID(id) {
		return nil, ErrLifecycleInvalid
	}
	var out *LifecycleUserView
	e := s.withLifecycleActor(ctx, a, func(ctx context.Context) error {
		return s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
			_, e := s.lifecycleActor(ctx, tx, h, a, authz.PermUsersRead, false, false)
			if e != nil {
				return e
			}
			t, e := lifecycleReadUser(ctx, tx, h, id)
			if e != nil {
				return e
			}
			out = t
			return nil
		})
	})
	return out, e
}
func (s *Service) LifecycleUsers(ctx context.Context, a LifecycleActor, limit int, cursor string) (LifecycleUserList, error) {
	out := LifecycleUserList{Items: []LifecycleUserView{}}
	if limit < 1 || limit > 200 || (cursor != "" && !configmodel.ValidID(cursor)) {
		return out, ErrLifecycleInvalid
	}
	e := s.withLifecycleActor(ctx, a, func(ctx context.Context) error {
		return s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
			_, e := s.lifecycleActor(ctx, tx, h, a, authz.PermUsersRead, false, false)
			if e != nil {
				return e
			}
			ids, e := securitystate.Strings(ctx, tx, `SELECT id FROM users WHERE id>? ORDER BY id LIMIT ?`, cursor, limit+1)
			if e != nil {
				return e
			}
			if len(ids) > limit {
				v := ids[limit-1]
				out.NextCursor = &v
				ids = ids[:limit]
			}
			for _, id := range ids {
				t, e := lifecycleReadUser(ctx, tx, h, id)
				if e != nil {
					return e
				}
				out.Items = append(out.Items, *t)
			}
			return nil
		})
	})
	return out, e
}

// These startup-created managers remain guarded by their own transaction-bound
// actor/flow authorization. Returning a pointer grants no caller authority.
func (s *Service) InvitationService() *InvitationService {
	v, _ := s.invitations.(*InvitationService)
	return v
}
func (s *Service) RecoveryService() *RecoveryService { v, _ := s.recovery.(*RecoveryService); return v }

// CleanupLifecycle runs before generic flow deletion and before listeners are
// opened. No deadline or credential publication uses a local-clock fallback.
func (s *Service) CleanupLifecycle(ctx context.Context) error {
	return s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error { return s.cleanupIdentityTx(ctx, tx, h) })
}
func (s *Service) cleanupIdentityTx(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head) error {
	if h.RecordedAt.IsZero() {
		return ErrLifecycleUnavailable
	}
	if s.email != nil {
		if e := s.email.CleanupTx(ctx, tx, h); e != nil {
			return e
		}
	}
	if s.invitations != nil {
		if e := s.invitations.CleanupTx(ctx, tx, h); e != nil {
			return e
		}
	}
	if s.recovery != nil {
		if e := s.recovery.CleanupTx(ctx, tx, h); e != nil {
			return e
		}
	}
	// Typed snapshots must be closed before cascade deletion of their parent
	// flows. This also bounds anonymous activate/verify flows with no stage.
	return Cleanup(ctx, tx, h.RecordedAt)
}
func (s *Service) ProcessLifecycleDeliveryOne(ctx context.Context) (bool, error) {
	manager := s.InvitationService()
	if manager == nil {
		return false, ErrLifecycleUnavailable
	}
	return manager.ProcessDeliveryOne(ctx)
}

// Redacted inventory requires users.read. This is not an authorization snapshot
// for a lifecycle write: disabled/unavailable directory providers must remain
// visible to an operator without granting their principals authority.
func lifecycleReadUser(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, id string) (*LifecycleUserView, error) {
	v := &LifecycleUserView{}
	var blocked sql.NullTime
	e := securitystate.One(ctx, tx, `SELECT id,username,display_name,is_admin,blocked_at,security_version,lifecycle_state FROM users WHERE id=?`, []any{id}, func(r storage.IdentityRows) error {
		return r.Scan(&v.ID, &v.Username, &v.DisplayName, &v.Privileged, &blocked, &v.Revision, &v.LifecycleState)
	})
	if e != nil {
		return nil, e
	}
	v.Blocked = blocked.Valid
	v.GroupIDs, e = securitystate.Strings(ctx, tx, `SELECT group_id FROM user_groups WHERE user_id=? ORDER BY group_id`, id)
	if e != nil {
		return nil, e
	}
	if v.GroupIDs == nil {
		v.GroupIDs = []string{}
	}
	metadata, e := securitystate.ReadPrincipalGrantMetadata(ctx, tx, h, id)
	if e != nil {
		return nil, e
	}
	for _, g := range metadata.Entries {
		v.Privileged = v.Privileged || authz.IsPrivileged([]string{g.Permission})
	}
	return v, nil
}
