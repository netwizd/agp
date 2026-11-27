package securitystate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

type actorKey struct{}

// WithActor binds an already authenticated management token hash to a command.
// The token and its freshness are independently checked in the command tx.
func WithActor(ctx context.Context, hash string) context.Context {
	return context.WithValue(ctx, actorKey{}, hash)
}

type protectedStore struct {
	storage.Store
	c       *Coordinator
	profile domain.SessionProfile
}
type identityCommand struct {
	Actor            string
	Mutation         storage.IdentityMutation
	Versions         map[string]uint64
	PasswordVersions map[string]uint64
}
type grant struct{ ID, Kind, Subject, Object string }

// ProtectStore closes legacy writes that could bypass the journal. The base
// repository remains private to the coordinator and explicit activation CLI.
func ProtectStore(base storage.Store, c *Coordinator, p domain.SessionProfile) storage.Store {
	if !p.SecureProfile {
		return base
	}
	s := &protectedStore{Store: base, c: c, profile: p}
	c.Register("v1_identity", s.materializeIdentity)
	c.Register("v1_resource", s.materializeResource)
	return s
}
func (s *protectedStore) CreateSession(context.Context, domain.Session) error {
	return storage.ErrPermissionDenied
}
func (s *protectedStore) CreateAuthenticatedSession(context.Context, domain.Session, string, time.Time, domain.SessionProfile) error {
	return storage.ErrPermissionDenied
}
func (s *protectedStore) ApplySessionProfile(context.Context, domain.SessionProfile) (int64, error) {
	return 0, storage.ErrPermissionDenied
}
func (s *protectedStore) CreateUser(context.Context, domain.UserInput) (*domain.User, error) {
	return nil, storage.ErrPermissionDenied
}
func (s *protectedStore) UpdateUser(context.Context, string, domain.UserUpdate) (*domain.User, error) {
	return nil, storage.ErrPermissionDenied
}
func (s *protectedStore) DeleteUser(context.Context, string) error {
	return storage.ErrPermissionDenied
}
func (s *protectedStore) CreateGroup(context.Context, domain.GroupInput) (*domain.Group, error) {
	return nil, storage.ErrPermissionDenied
}
func (s *protectedStore) UpdateGroup(context.Context, string, domain.GroupInput) (*domain.Group, error) {
	return nil, storage.ErrPermissionDenied
}
func (s *protectedStore) DeleteGroup(context.Context, string) error {
	return storage.ErrPermissionDenied
}
func (s *protectedStore) RevokeSession(context.Context, string) error {
	return storage.ErrPermissionDenied
}
func (s *protectedStore) DeleteSession(ctx context.Context, hash string) error {
	return s.c.ExecuteDynamic(ctx, "logout", func(tx storage.IdentityTx, h securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error) {
		var id, user string
		err := One(ctx, tx, `SELECT id,user_id FROM sessions WHERE token_hash=? AND revoked_at IS NULL`, []any{hash}, func(r storage.IdentityRows) error { return r.Scan(&id, &user) })
		if errors.Is(err, storage.ErrNotFound) {
			return []byte(`{}`), nil, nil
		}
		if err != nil {
			return nil, nil, err
		}
		return []byte(`{}`), []securityjournal.AppendRequest{{Kind: "revoke_session", TargetType: "session", TargetID: id, ActorID: user, Payload: securityjournal.Payload{SessionID: id}}}, nil
	})
}
func (s *protectedStore) ApplyIdentityMutation(ctx context.Context, hash string, m storage.IdentityMutation) (*storage.IdentityMutationResult, error) {
	if m.Kind == storage.IdentityCreateUser {
		m.ID = ID("usr")
	}
	if m.Kind == storage.IdentityCreateGroup {
		m.ID = ID("grp")
	}
	var result *storage.IdentityMutationResult
	err := s.c.ExecuteDynamic(ctx, "v1_identity", func(tx storage.IdentityTx, h securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error) {
		if err := s.c.CheckManagementSession(ctx, tx, h, hash); err != nil {
			return nil, nil, err
		}
		authorization, witness, err := s.freshIdentityAuthorization(ctx, tx, h, hash)
		if err != nil {
			return nil, nil, err
		}
		permission := identityMutationPermission(m.Kind)
		if permission == "" || !authorization.HasPermission(permission) {
			return nil, nil, storage.ErrPermissionDenied
		}
		actor := authorization.ActorID
		if err := secureLifecycleGuard(ctx, tx, m); err != nil {
			return nil, nil, err
		}
		cmd := identityCommand{Actor: actor, Mutation: m, Versions: map[string]uint64{}, PasswordVersions: map[string]uint64{}}
		affected := []string{}
		switch m.Kind {
		case storage.IdentityUpdateUser, storage.IdentityDeleteUser:
			affected = []string{m.ID}
		case storage.IdentityUpdateGroup, storage.IdentityDeleteGroup:
			affected, err = Strings(ctx, tx, `SELECT user_id FROM user_groups WHERE group_id=?`, m.ID)
		}
		if err != nil {
			return nil, nil, err
		}
		for _, uid := range affected {
			var sv, pv uint64
			if e := One(ctx, tx, `SELECT security_version,password_version FROM users WHERE id=?`, []any{uid}, func(r storage.IdentityRows) error { return r.Scan(&sv, &pv) }); e != nil {
				return nil, nil, e
			}
			cmd.Versions[uid] = sv + 1
			if m.Kind == storage.IdentityUpdateUser && m.UserUpdate.PasswordHash != nil {
				cmd.PasswordVersions[uid] = pv + 1
			}
		}
		if err := SyncGrants(ctx, tx); err != nil {
			return nil, nil, err
		}
		before, err := grants(ctx, tx)
		if err != nil {
			return nil, nil, err
		}
		if _, err = tx.Exec(ctx, `SAVEPOINT authorize_command`); err != nil {
			return nil, nil, err
		}
		result, err = storage.ExecuteIdentityMutationWithAuthorization(ctx, tx, authorization, m)
		if err != nil {
			return nil, nil, err
		}
		removed, err := removedGrants(ctx, tx, before)
		if err != nil {
			return nil, nil, err
		}
		if _, err = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT authorize_command`); err != nil {
			return nil, nil, err
		}
		if _, err = tx.Exec(ctx, `RELEASE SAVEPOINT authorize_command`); err != nil {
			return nil, nil, err
		}
		requests := grantRequests(actor, removed)
		for uid, v := range cmd.Versions {
			requests = append(requests, securityjournal.AppendRequest{Kind: "raise_security_floor", TargetType: "principal", TargetID: uid, ActorID: actor, Payload: securityjournal.Payload{PrincipalID: uid, MinimumVersion: securityjournal.UInt63(v)}})
		}
		for uid, v := range cmd.PasswordVersions {
			requests = append(requests, FloorRequest(actor, uid, "password_"+uid, v))
		}
		if m.Kind == storage.IdentityDeleteUser || (m.Kind == storage.IdentityUpdateUser && m.UserUpdate.Blocked != nil && *m.UserUpdate.Blocked) {
			requests = append(requests, securityjournal.AppendRequest{Kind: "block_principal", TargetType: "principal", TargetID: m.ID, ActorID: actor, Payload: securityjournal.Payload{PrincipalID: m.ID}})
		}
		if m.Kind == storage.IdentityUpdateUser && m.UserUpdate.Blocked != nil && !*m.UserUpdate.Blocked {
			var blocked sql.NullTime
			if e := One(ctx, tx, `SELECT blocked_at FROM users WHERE id=?`, []any{m.ID}, func(r storage.IdentityRows) error { return r.Scan(&blocked) }); e != nil {
				return nil, nil, e
			}
			// A lift requires the independently signed journal workflow; a v1 body
			// cannot authorize it merely by asserting an approver identity.
			if blocked.Valid {
				return nil, nil, storage.ErrPermissionDenied
			}
		}
		if m.Kind == storage.IdentityRevokeSession {
			requests = append(requests, securityjournal.AppendRequest{Kind: "revoke_session", TargetType: "session", TargetID: m.ID, ActorID: actor, Payload: securityjournal.Payload{SessionID: m.ID}})
		}
		raw, err := json.Marshal(cmd)
		if err != nil {
			return nil, nil, err
		}
		if err = s.finalIdentityAuthority(ctx, tx, h, hash, witness); err != nil {
			return nil, nil, err
		}
		return raw, requests, nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
func (s *protectedStore) materializeIdentity(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
	var cmd identityCommand
	if err := json.Unmarshal(raw, &cmd); err != nil {
		return err
	}
	if cmd.Mutation.Kind != storage.IdentityRevokeSession {
		if _, err := storage.ExecuteAuthorizedIdentityMutation(ctx, tx, cmd.Actor, cmd.Mutation); err != nil {
			return err
		}
	}
	for uid, v := range cmd.Versions {
		if _, err := tx.Exec(ctx, `UPDATE users SET security_version=? WHERE id=?`, int64(v), uid); err != nil {
			return err
		}
	}
	for uid, v := range cmd.PasswordVersions {
		if _, err := tx.Exec(ctx, `UPDATE users SET password_version=? WHERE id=?`, int64(v), uid); err != nil {
			return err
		}
	}
	return Audit(ctx, tx, "identity.admin.mutation", cmd.Actor, map[string]any{"kind": cmd.Mutation.Kind, "target": cmd.Mutation.ID})
}
func managementActor(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, hash, permission string) (*managementPrincipal, error) {
	p, err := readManagementPrincipal(ctx, tx, h, hash)
	if err != nil {
		return nil, err
	}
	if permission != "" && !p.allows(permission) {
		return nil, storage.ErrPermissionDenied
	}
	return p, nil
}
func grants(ctx context.Context, tx storage.IdentityTx) ([]grant, error) {
	rows, err := tx.Query(ctx, `SELECT id,kind,subject_id,object_id FROM security_grants WHERE active=?`, true)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []grant
	for rows.Next() {
		var g grant
		if err := rows.Scan(&g.ID, &g.Kind, &g.Subject, &g.Object); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
func removedGrants(ctx context.Context, tx storage.IdentityTx, before []grant) ([]grant, error) {
	var out []grant
	for _, g := range before {
		q := map[string]string{"membership": `SELECT user_id FROM user_groups WHERE user_id=? AND group_id=?`, "permission": `SELECT group_id FROM group_permissions WHERE group_id=? AND permission_id=?`, "resource": `SELECT resource_id FROM resource_groups WHERE resource_id=? AND group_id=?`, "superadmin": `SELECT id FROM users WHERE id=? AND is_admin=?`}[g.Kind]
		var args []any
		if g.Kind == "superadmin" {
			args = []any{g.Subject, true}
		} else {
			args = []any{g.Subject, g.Object}
		}
		ids, err := Strings(ctx, tx, q, args...)
		if err != nil {
			return nil, err
		}
		if len(ids) == 0 {
			out = append(out, g)
		}
	}
	return out, nil
}
func grantRequests(actor string, removed []grant) []securityjournal.AppendRequest {
	out := make([]securityjournal.AppendRequest, 0, len(removed))
	for _, g := range removed {
		kind := "revoke_role_binding"
		if g.Kind == "membership" {
			kind = "remove_membership"
		}
		out = append(out, securityjournal.AppendRequest{Kind: kind, TargetType: "grant", TargetID: g.ID, ActorID: actor, Payload: securityjournal.Payload{GrantID: g.ID}})
	}
	return out
}

// Until canonical invitations and distinct-approver grant commands exist, the
// secure profile cannot fall back to the v1 administrator-selected credential
// or single-actor privilege promotion endpoints.
func secureLifecycleGuard(ctx context.Context, tx storage.IdentityTx, m storage.IdentityMutation) error {
	switch m.Kind {
	case storage.IdentityCreateUser:
		return storage.ErrInviteRequired
	case storage.IdentityUpdateUser:
		if m.UserUpdate.PasswordHash != nil {
			return storage.ErrInviteRequired
		}
		if m.UserUpdate.IsAdmin != nil && *m.UserUpdate.IsAdmin {
			var current bool
			if err := One(ctx, tx, `SELECT is_admin FROM users WHERE id=?`, []any{m.ID}, func(r storage.IdentityRows) error { return r.Scan(&current) }); err != nil {
				return err
			}
			if !current {
				return storage.ErrApprovalRequired
			}
		}
		if m.UserUpdate.UpdateGroups {
			for _, group := range m.UserUpdate.GroupIDs {
				existing, err := Strings(ctx, tx, `SELECT group_id FROM user_groups WHERE user_id=? AND group_id=?`, m.ID, group)
				if err != nil {
					return err
				}
				if len(existing) > 0 {
					continue
				}
				permissions, err := Strings(ctx, tx, `SELECT permission_id FROM group_permissions WHERE group_id=?`, group)
				if err != nil {
					return err
				}
				if len(permissions) > 0 {
					return storage.ErrApprovalRequired
				}
			}
		}
	case storage.IdentityCreateGroup, storage.IdentityUpdateGroup:
		old := map[string]bool{}
		if m.Kind == storage.IdentityUpdateGroup {
			permissions, err := Strings(ctx, tx, `SELECT permission_id FROM group_permissions WHERE group_id=?`, m.ID)
			if err != nil {
				return err
			}
			for _, p := range permissions {
				old[p] = true
			}
		}
		for _, p := range m.GroupInput.PermissionIDs {
			if !old[p] {
				return storage.ErrApprovalRequired
			}
		}
	}
	return nil
}
