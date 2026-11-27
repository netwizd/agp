package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/domain"
)

var (
	ErrPermissionDenied = errString("permission denied")
	ErrApprovalRequired = fmt.Errorf("independent approval required: %w", ErrPermissionDenied)
	ErrInviteRequired   = fmt.Errorf("owner setup invite required: %w", ErrPermissionDenied)
	ErrLastAdmin        = errString("cannot remove last active administrator")
)

type IdentityMutationKind uint8

const (
	IdentityCreateUser IdentityMutationKind = iota + 1
	IdentityUpdateUser
	IdentityDeleteUser
	IdentityCreateGroup
	IdentityUpdateGroup
	IdentityDeleteGroup
	IdentityRevokeSession
)

// IdentityMutation is the baseline administrative identity command. The actor
// is always reloaded from its live session inside the mutation transaction.
type IdentityMutation struct {
	ManagementOrigin string
	Kind             IdentityMutationKind
	ID               string
	UserInput        domain.UserInput
	UserUpdate       domain.UserUpdate
	GroupInput       domain.GroupInput
}

type IdentityMutationResult struct {
	User  *domain.User
	Group *domain.Group
}

// IdentityRows and IdentityTx are the small SQL adapter needed to keep both
// storage backends on the same authorization and mutation implementation.
// Queries use ? placeholders; adapters normalize driver errors and placeholders.
type IdentityRows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close()
}

type IdentityTx interface {
	Exec(context.Context, string, ...any) (int64, error)
	Query(context.Context, string, ...any) (IdentityRows, error)
}

// ExecuteIdentityMutation requires a transaction whose identity tables cannot
// change between these reads and commit. It never commits on behalf of callers.
func ExecuteIdentityMutation(ctx context.Context, tx IdentityTx, tokenHash string, mutation IdentityMutation) (*IdentityMutationResult, error) {
	return executeIdentityMutation(ctx, tx, tokenHash, "", mutation, nil)
}

// IdentityMutationAuthorization is a trusted, transaction-local view supplied
// by the secure coordinator after checking the current session and authority.
// It is never decoded from a request or used for durable restrictive replay.
type IdentityMutationAuthorization struct {
	ActorID       string
	Now           time.Time
	HasPermission func(string) bool
	CheckTarget   func(context.Context, IdentityTx, domain.User, []string) error
}

func ExecuteIdentityMutationWithAuthorization(ctx context.Context, tx IdentityTx, authorization IdentityMutationAuthorization, mutation IdentityMutation) (*IdentityMutationResult, error) {
	if authorization.ActorID == "" || authorization.Now.IsZero() || authorization.HasPermission == nil || authorization.CheckTarget == nil {
		return nil, ErrPermissionDenied
	}
	return executeIdentityMutation(ctx, tx, "", "", mutation, &authorization)
}

// ExecuteAuthorizedIdentityMutation materializes an exact durable command that
// was authorized before the journal barrier. Restrictive replay may already
// have revoked the actor session or removed its grants. Callers must never use
// this function for fresh, unauthenticated commands.
func ExecuteAuthorizedIdentityMutation(ctx context.Context, tx IdentityTx, actorID string, mutation IdentityMutation) (*IdentityMutationResult, error) {
	if actorID == "" {
		return nil, ErrPermissionDenied
	}
	return executeIdentityMutation(ctx, tx, "", actorID, mutation, nil)
}
func executeIdentityMutation(ctx context.Context, tx IdentityTx, tokenHash, authorizedActor string, mutation IdentityMutation, authorization *IdentityMutationAuthorization) (*IdentityMutationResult, error) {
	now := time.Now().UTC()
	if authorization != nil {
		now = authorization.Now.UTC()
	}
	profile, err := ReadSessionProfile(ctx, tx)
	if err != nil {
		return nil, err
	}
	audience, audienceOrigin := domain.SessionAudienceLegacy, ""
	if profile != nil && profile.ManagementOrigin != "" {
		audience = domain.SessionAudienceManagement
		audienceOrigin = profile.ManagementOrigin
	}
	if mutation.ManagementOrigin != audienceOrigin {
		return nil, ErrPermissionDenied
	}
	actorID := authorizedActor
	if authorization != nil {
		actorID = authorization.ActorID
	}
	if actorID == "" {
		q := `SELECT s.user_id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash = ? AND s.revoked_at IS NULL AND s.expires_at > ? AND s.audience = ? AND s.audience_origin = ?`
		args := []any{tokenHash, now, audience, audienceOrigin}
		if profile != nil && profile.SecureProfile {
			q += ` AND s.authority_epoch=(SELECT epoch FROM security_state WHERE id=1 AND enabled=?) AND s.security_version=u.security_version AND s.mfa_at>=? AND s.last_seen_at>=?`
			args = append(args, true, now.Add(-5*time.Minute), now.Add(-30*time.Minute))
		}
		actorIDs, e := identityStrings(ctx, tx, q, args...)
		if e != nil {
			return nil, e
		}
		if len(actorIDs) != 1 {
			return nil, ErrPermissionDenied
		}
		actorID = actorIDs[0]
	}
	readUser := func(id string) (*domain.User, []string, error) {
		return identityUserProjection(ctx, tx, id, authorization == nil)
	}
	actor, permissions, err := readUser(actorID)
	if err != nil {
		return nil, err
	}
	if authorizedActor != "" {
		permissions = authz.AllPermissions()
	} else if actor.BlockedAt != nil {
		return nil, ErrPermissionDenied
	}
	hasPermission := func(permission string) bool {
		if authorization != nil {
			return authorization.HasPermission(permission)
		}
		return authz.HasPermission(permissions, permission)
	}
	canDelegate := func(requested []string) bool {
		for _, permission := range requested {
			if !hasPermission(permission) {
				return false
			}
		}
		return true
	}
	checkTarget := func(target domain.User, proposed []string) error {
		if authorization != nil {
			return authorization.CheckTarget(ctx, tx, target, proposed)
		}
		return identityTargetGuard(actor, permissions, target, proposed)
	}
	required := ""
	switch mutation.Kind {
	case IdentityCreateUser, IdentityUpdateUser, IdentityDeleteUser:
		required = authz.PermUsersManage
	case IdentityCreateGroup, IdentityUpdateGroup, IdentityDeleteGroup:
		required = authz.PermGroupsManage
	case IdentityRevokeSession:
		required = authz.PermSessionsRevoke
	default:
		return nil, fmt.Errorf("unknown identity mutation %d", mutation.Kind)
	}
	if !hasPermission(required) {
		return nil, ErrPermissionDenied
	}
	result := &IdentityMutationResult{}
	switch mutation.Kind {
	case IdentityCreateUser:
		input := mutation.UserInput
		grants, err := identityGroupPermissions(ctx, tx, input.GroupIDs)
		if err != nil {
			return nil, err
		}
		if err := checkTarget(domain.User{IsAdmin: input.IsAdmin}, grants); err != nil {
			return nil, err
		}
		id, err := identityID("usr")
		if mutation.ID != "" {
			id = mutation.ID
			err = nil
		}
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO users(id, username, password_hash, display_name, is_admin, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, id, input.Username, input.PasswordHash, input.DisplayName, input.IsAdmin, now, now); err != nil {
			return nil, err
		}
		if err := identityReplaceUserGroups(ctx, tx, id, input.GroupIDs); err != nil {
			return nil, err
		}
		result.User, _, err = readUser(id)
		return result, err
	case IdentityUpdateUser, IdentityDeleteUser, IdentityRevokeSession:
		id := mutation.ID
		if mutation.Kind == IdentityRevokeSession {
			ids, err := identityStrings(ctx, tx, `SELECT user_id FROM sessions WHERE id = ? AND revoked_at IS NULL`, id)
			if err != nil {
				return nil, err
			}
			if len(ids) != 1 {
				return nil, ErrNotFound
			}
			id = ids[0]
		}
		target, grants, err := readUser(id)
		if err != nil {
			return nil, err
		}
		if err := checkTarget(*target, grants); err != nil {
			return nil, err
		}
		if mutation.Kind == IdentityRevokeSession {
			if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, now, mutation.ID); err != nil {
				return nil, err
			}
			return result, nil
		}
		update := mutation.UserUpdate
		if mutation.Kind == IdentityDeleteUser || (target.IsAdmin && target.BlockedAt == nil && ((update.IsAdmin != nil && !*update.IsAdmin) || (update.Blocked != nil && *update.Blocked))) {
			if err := identityCheckLastAdmin(ctx, tx, target); err != nil {
				return nil, err
			}
		}
		if mutation.Kind == IdentityDeleteUser {
			if actor.ID == id {
				return nil, ErrPermissionDenied
			}
			_, err := tx.Exec(ctx, `DELETE FROM users WHERE id = ?`, id)
			return result, err
		}
		proposed := *target
		if update.IsAdmin != nil {
			if actor.ID == id || !hasPermission(authz.PermUsersSuperAdminManage) {
				return nil, ErrPermissionDenied
			}
			proposed.IsAdmin = *update.IsAdmin
		}
		if update.UpdateGroups {
			grants, err = identityGroupPermissions(ctx, tx, update.GroupIDs)
			if err != nil {
				return nil, err
			}
		}
		if err := checkTarget(proposed, grants); err != nil {
			return nil, err
		}
		if update.DisplayName != nil {
			if _, err := tx.Exec(ctx, `UPDATE users SET display_name = ?, updated_at = ? WHERE id = ?`, *update.DisplayName, now, id); err != nil {
				return nil, err
			}
		}
		if update.IsAdmin != nil {
			if _, err := tx.Exec(ctx, `UPDATE users SET is_admin = ?, updated_at = ? WHERE id = ?`, *update.IsAdmin, now, id); err != nil {
				return nil, err
			}
		}
		if update.Blocked != nil {
			var blockedAt any
			if *update.Blocked {
				blockedAt = now
				if target.BlockedAt != nil {
					blockedAt = *target.BlockedAt
				}
			}
			if _, err := tx.Exec(ctx, `UPDATE users SET blocked_at = ?, updated_at = ? WHERE id = ?`, blockedAt, now, id); err != nil {
				return nil, err
			}
		}
		if update.PasswordHash != nil {
			if _, err := tx.Exec(ctx, `UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`, *update.PasswordHash, now, id); err != nil {
				return nil, err
			}
		}
		if update.UpdateGroups {
			if err := identityReplaceUserGroups(ctx, tx, id, update.GroupIDs); err != nil {
				return nil, err
			}
			if _, err := tx.Exec(ctx, `UPDATE users SET updated_at = ? WHERE id = ?`, now, id); err != nil {
				return nil, err
			}
		}
		if update.PasswordHash != nil || update.IsAdmin != nil || update.Blocked != nil || update.UpdateGroups {
			if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`, now, id); err != nil {
				return nil, err
			}
		}
		result.User, _, err = readUser(id)
		return result, err
	case IdentityCreateGroup, IdentityUpdateGroup, IdentityDeleteGroup:
		input := mutation.GroupInput
		if mutation.Kind != IdentityDeleteGroup && !canDelegate(input.PermissionIDs) {
			return nil, ErrPermissionDenied
		}
		id := mutation.ID
		if mutation.Kind != IdentityCreateGroup {
			group, err := identityGroup(ctx, tx, id)
			if err != nil {
				return nil, err
			}
			if !canDelegate(group.PermissionIDs) {
				return nil, ErrPermissionDenied
			}
			members, err := identityStrings(ctx, tx, `SELECT user_id FROM user_groups WHERE group_id = ?`, id)
			if err != nil {
				return nil, err
			}
			for _, memberID := range members {
				member, grants, err := readUser(memberID)
				if err != nil {
					return nil, err
				}
				if err := checkTarget(*member, grants); err != nil {
					return nil, err
				}
				// Even if the old membership is unprivileged, the replacement
				// can make its members privileged and needs the same guard.
				if mutation.Kind == IdentityUpdateGroup {
					if err := checkTarget(*member, input.PermissionIDs); err != nil {
						return nil, err
					}
				}
			}
			if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = ? WHERE revoked_at IS NULL AND user_id IN (SELECT user_id FROM user_groups WHERE group_id = ?)`, now, id); err != nil {
				return nil, err
			}
			if _, err := tx.Exec(ctx, `UPDATE users SET updated_at = ? WHERE id IN (SELECT user_id FROM user_groups WHERE group_id = ?)`, now, id); err != nil {
				return nil, err
			}
		}
		switch mutation.Kind {
		case IdentityCreateGroup:
			id, err = identityID("grp")
			if mutation.ID != "" {
				id = mutation.ID
				err = nil
			}
			if err == nil {
				_, err = tx.Exec(ctx, `INSERT INTO groups(id, name, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`, id, input.Name, input.Description, now, now)
			}
		case IdentityUpdateGroup:
			_, err = tx.Exec(ctx, `UPDATE groups SET name = ?, description = ?, updated_at = ? WHERE id = ?`, input.Name, input.Description, now, id)
		case IdentityDeleteGroup:
			_, err = tx.Exec(ctx, `DELETE FROM groups WHERE id = ?`, id)
			return result, err
		}
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM group_permissions WHERE group_id = ?`, id); err != nil {
			return nil, err
		}
		for _, permission := range input.PermissionIDs {
			if _, err := tx.Exec(ctx, `INSERT INTO group_permissions(group_id, permission_id) VALUES (?, ?)`, id, permission); err != nil {
				return nil, err
			}
		}
		result.Group, err = identityGroup(ctx, tx, id)
		return result, err
	}
	return nil, fmt.Errorf("unhandled identity mutation %d", mutation.Kind)
}

func identityTargetGuard(actor *domain.User, permissions []string, target domain.User, grants []string) error {
	if target.IsAdmin {
		grants = authz.AllPermissions()
	}
	if (target.IsAdmin || authz.IsPrivileged(grants)) && !authz.HasPermission(permissions, authz.PermUsersSuperAdminManage) {
		return ErrPermissionDenied
	}
	if !authz.CanDelegate(permissions, grants) {
		return ErrPermissionDenied
	}
	return nil
}

func identityCheckLastAdmin(ctx context.Context, tx IdentityTx, target *domain.User) error {
	if !target.IsAdmin || target.BlockedAt != nil {
		return nil
	}
	ids, err := identityStrings(ctx, tx, `SELECT id FROM users WHERE is_admin = ? AND blocked_at IS NULL`, true)
	if err != nil {
		return err
	}
	if len(ids) <= 1 {
		return ErrLastAdmin
	}
	return nil
}

func identityUser(ctx context.Context, tx IdentityTx, id string) (*domain.User, []string, error) {
	return identityUserProjection(ctx, tx, id, true)
}
func identityUserProjection(ctx context.Context, tx IdentityTx, id string, legacyAuthorization bool) (*domain.User, []string, error) {
	rows, err := tx.Query(ctx, `SELECT id, username, display_name, is_admin, blocked_at, created_at, updated_at FROM users WHERE id = ?`, id)
	if err != nil {
		return nil, nil, err
	}
	user := &domain.User{}
	var blockedAt sql.NullTime
	if !rows.Next() {
		err := rows.Err()
		rows.Close()
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, ErrNotFound
	}
	err = rows.Scan(&user.ID, &user.Username, &user.DisplayName, &user.IsAdmin, &blockedAt, &user.CreatedAt, &user.UpdatedAt)
	rows.Close()
	if err != nil {
		return nil, nil, err
	}
	if blockedAt.Valid {
		user.BlockedAt = &blockedAt.Time
	}
	user.GroupIDs, err = identityStrings(ctx, tx, `SELECT group_id FROM user_groups WHERE user_id = ? ORDER BY group_id`, id)
	if err != nil {
		return nil, nil, err
	}
	permissions, err := identityGroupPermissions(ctx, tx, user.GroupIDs)
	if err == nil && legacyAuthorization {
		scoped, e := identityStrings(ctx, tx, `SELECT DISTINCT permission FROM config_scope_grants WHERE principal_id=? AND revoked=FALSE`, id)
		if e != nil {
			return nil, nil, e
		}
		permissions = append(permissions, scoped...)
	}
	if user.IsAdmin && legacyAuthorization {
		permissions = authz.AllPermissions()
	}
	return user, permissions, err
}

func identityGroup(ctx context.Context, tx IdentityTx, id string) (*domain.Group, error) {
	rows, err := tx.Query(ctx, `SELECT id, name, description, created_at, updated_at FROM groups WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	group := &domain.Group{}
	if !rows.Next() {
		err := rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		return nil, ErrNotFound
	}
	err = rows.Scan(&group.ID, &group.Name, &group.Description, &group.CreatedAt, &group.UpdatedAt)
	rows.Close()
	if err != nil {
		return nil, err
	}
	group.PermissionIDs, err = identityStrings(ctx, tx, `SELECT permission_id FROM group_permissions WHERE group_id = ? ORDER BY permission_id`, id)
	return group, err
}

func identityGroupPermissions(ctx context.Context, tx IdentityTx, ids []string) ([]string, error) {
	var permissions []string
	for _, id := range ids {
		group, err := identityGroup(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, group.PermissionIDs...)
	}
	return permissions, nil
}

func identityStrings(ctx context.Context, tx IdentityTx, query string, args ...any) ([]string, error) {
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func identityReplaceUserGroups(ctx context.Context, tx IdentityTx, id string, groups []string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM user_groups WHERE user_id = ?`, id); err != nil {
		return err
	}
	for _, group := range groups {
		if _, err := tx.Exec(ctx, `INSERT INTO user_groups(user_id, group_id) VALUES (?, ?)`, id, group); err != nil {
			return err
		}
	}
	return nil
}

func identityID(prefix string) (string, error) {
	var raw [18]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate identity ID: %w", err)
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
