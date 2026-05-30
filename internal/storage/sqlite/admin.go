package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/storage"
)

func (s *Store) DashboardStats(ctx context.Context) (*domain.DashboardStats, error) {
	var stats domain.DashboardStats
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&stats.UsersCount); err != nil {
		return nil, fmt.Errorf("count users: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE blocked_at IS NOT NULL`).Scan(&stats.BlockedUsersCount); err != nil {
		return nil, fmt.Errorf("count blocked users: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP`).Scan(&stats.ActiveSessionsCount); err != nil {
		return nil, fmt.Errorf("count active sessions: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM resources`).Scan(&stats.ResourcesCount); err != nil {
		return nil, fmt.Errorf("count resources: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events`).Scan(&stats.AuditEventsCount); err != nil {
		return nil, fmt.Errorf("count audit events: %w", err)
	}
	events, err := s.ListAuditEvents(ctx, 20)
	if err != nil {
		return nil, err
	}
	stats.RecentEvents = events
	return &stats, nil
}

func (s *Store) ListUsers(ctx context.Context) ([]domain.User, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, username, display_name, is_admin, blocked_at, created_at, updated_at
FROM users
ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []domain.User
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *Store) CreateUser(ctx context.Context, input domain.UserInput) (*domain.User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin create user: %w", err)
	}
	defer rollbackUnlessCommitted(tx)

	id := storageID("usr")
	now := time.Now().UTC()
	_, err = tx.ExecContext(ctx, `
INSERT INTO users(id, username, password_hash, display_name, is_admin, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, input.Username, input.PasswordHash, input.DisplayName, boolToInt(input.IsAdmin), now, now)
	if err != nil {
		return nil, normalizeSQLiteError("create user", err)
	}
	if err := replaceUserGroups(ctx, tx, id, input.GroupIDs); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit create user: %w", err)
	}
	return s.findUserByID(ctx, id)
}

func (s *Store) UpdateUser(ctx context.Context, id string, update domain.UserUpdate) (*domain.User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin update user: %w", err)
	}
	defer rollbackUnlessCommitted(tx)

	if update.DisplayName != nil {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET display_name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, *update.DisplayName, id); err != nil {
			return nil, normalizeSQLiteError("update user display name", err)
		}
	}
	if update.IsAdmin != nil {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET is_admin = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, boolToInt(*update.IsAdmin), id); err != nil {
			return nil, normalizeSQLiteError("update user admin flag", err)
		}
	}
	if update.Blocked != nil {
		if *update.Blocked {
			_, err = tx.ExecContext(ctx, `UPDATE users SET blocked_at = COALESCE(blocked_at, CURRENT_TIMESTAMP), updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
		} else {
			_, err = tx.ExecContext(ctx, `UPDATE users SET blocked_at = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
		}
		if err != nil {
			return nil, normalizeSQLiteError("update user blocked flag", err)
		}
	}
	if update.PasswordHash != nil {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, *update.PasswordHash, id); err != nil {
			return nil, normalizeSQLiteError("update user password", err)
		}
	}
	if update.UpdateGroups {
		if err := replaceUserGroups(ctx, tx, id, update.GroupIDs); err != nil {
			return nil, err
		}
	}
	if err := ensureAffected(ctx, tx, `SELECT id FROM users WHERE id = ?`, id); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit update user: %w", err)
	}
	return s.findUserByID(ctx, id)
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return normalizeSQLiteError("delete user", err)
	}
	return ensureRowsAffected("delete user", res)
}

func (s *Store) ListGroups(ctx context.Context) ([]domain.Group, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, description, created_at, updated_at FROM groups ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	defer rows.Close()

	var groups []domain.Group
	for rows.Next() {
		var group domain.Group
		if err := rows.Scan(&group.ID, &group.Name, &group.Description, &group.CreatedAt, &group.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan group: %w", err)
		}
		groups = append(groups, group)
	}
	return groups, rows.Err()
}

func (s *Store) CreateGroup(ctx context.Context, input domain.GroupInput) (*domain.Group, error) {
	id := storageID("grp")
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
INSERT INTO groups(id, name, description, created_at, updated_at)
VALUES (?, ?, ?, ?, ?)`, id, input.Name, input.Description, now, now)
	if err != nil {
		return nil, normalizeSQLiteError("create group", err)
	}
	return s.findGroupByID(ctx, id)
}

func (s *Store) UpdateGroup(ctx context.Context, id string, input domain.GroupInput) (*domain.Group, error) {
	res, err := s.db.ExecContext(ctx, `
UPDATE groups SET name = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		input.Name, input.Description, id)
	if err != nil {
		return nil, normalizeSQLiteError("update group", err)
	}
	if err := ensureRowsAffected("update group", res); err != nil {
		return nil, err
	}
	return s.findGroupByID(ctx, id)
}

func (s *Store) DeleteGroup(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM groups WHERE id = ?`, id)
	if err != nil {
		return normalizeSQLiteError("delete group", err)
	}
	return ensureRowsAffected("delete group", res)
}

func (s *Store) ListResources(ctx context.Context) ([]domain.ResourceDetail, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, name, description, icon, internal_url, public_host, enabled, created_at, updated_at
FROM resources
ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list resources: %w", err)
	}
	defer rows.Close()

	var resources []domain.ResourceDetail
	for rows.Next() {
		resource, err := scanResourceDetail(ctx, s.db, rows)
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}
	return resources, rows.Err()
}

func (s *Store) FindResourceByID(ctx context.Context, id string) (*domain.ResourceDetail, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, name, description, icon, internal_url, public_host, enabled, created_at, updated_at
FROM resources
WHERE id = ?`, id)
	resource, err := scanResourceDetail(ctx, s.db, row)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

func (s *Store) CreateResource(ctx context.Context, input domain.ResourceInput) (*domain.ResourceDetail, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin create resource: %w", err)
	}
	defer rollbackUnlessCommitted(tx)

	id := storageID("res")
	now := time.Now().UTC()
	_, err = tx.ExecContext(ctx, `
INSERT INTO resources(id, name, description, icon, internal_url, public_host, enabled, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, input.Name, input.Description, input.Icon, input.InternalURL, input.PublicHost, boolToInt(input.Enabled), now, now)
	if err != nil {
		return nil, normalizeSQLiteError("create resource", err)
	}
	if err := replaceResourceGroups(ctx, tx, id, input.GroupIDs); err != nil {
		return nil, err
	}
	if err := replaceResourceCIDRs(ctx, tx, id, input.AllowCIDRs); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit create resource: %w", err)
	}
	return s.FindResourceByID(ctx, id)
}

func (s *Store) UpdateResource(ctx context.Context, id string, update domain.ResourceUpdate) (*domain.ResourceDetail, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin update resource: %w", err)
	}
	defer rollbackUnlessCommitted(tx)

	if update.Name != nil {
		if _, err := tx.ExecContext(ctx, `UPDATE resources SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, *update.Name, id); err != nil {
			return nil, normalizeSQLiteError("update resource name", err)
		}
	}
	if update.Description != nil {
		if _, err := tx.ExecContext(ctx, `UPDATE resources SET description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, *update.Description, id); err != nil {
			return nil, normalizeSQLiteError("update resource description", err)
		}
	}
	if update.Icon != nil {
		if _, err := tx.ExecContext(ctx, `UPDATE resources SET icon = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, *update.Icon, id); err != nil {
			return nil, normalizeSQLiteError("update resource icon", err)
		}
	}
	if update.InternalURL != nil {
		if _, err := tx.ExecContext(ctx, `UPDATE resources SET internal_url = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, *update.InternalURL, id); err != nil {
			return nil, normalizeSQLiteError("update resource internal url", err)
		}
	}
	if update.PublicHost != nil {
		if _, err := tx.ExecContext(ctx, `UPDATE resources SET public_host = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, *update.PublicHost, id); err != nil {
			return nil, normalizeSQLiteError("update resource public host", err)
		}
	}
	if update.Enabled != nil {
		if _, err := tx.ExecContext(ctx, `UPDATE resources SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, boolToInt(*update.Enabled), id); err != nil {
			return nil, normalizeSQLiteError("update resource enabled flag", err)
		}
	}
	if update.UpdateGroups {
		if err := replaceResourceGroups(ctx, tx, id, update.GroupIDs); err != nil {
			return nil, err
		}
	}
	if update.UpdateAllowCIDRs {
		if err := replaceResourceCIDRs(ctx, tx, id, update.AllowCIDRs); err != nil {
			return nil, err
		}
	}
	if err := ensureAffected(ctx, tx, `SELECT id FROM resources WHERE id = ?`, id); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit update resource: %w", err)
	}
	return s.FindResourceByID(ctx, id)
}

func (s *Store) DeleteResource(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM resources WHERE id = ?`, id)
	if err != nil {
		return normalizeSQLiteError("delete resource", err)
	}
	return ensureRowsAffected("delete resource", res)
}

func (s *Store) ListActiveSessions(ctx context.Context) ([]domain.ActiveSession, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT s.id, s.user_id, u.username, s.ip, s.user_agent, s.expires_at, s.created_at
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.revoked_at IS NULL
ORDER BY s.created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list active sessions: %w", err)
	}
	defer rows.Close()

	now := time.Now().UTC()
	var sessions []domain.ActiveSession
	for rows.Next() {
		var session domain.ActiveSession
		if err := rows.Scan(&session.ID, &session.UserID, &session.Username, &session.IP, &session.UserAgent, &session.ExpiresAt, &session.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan active session: %w", err)
		}
		if now.Before(session.ExpiresAt) {
			sessions = append(sessions, session)
		}
	}
	return sessions, rows.Err()
}

func (s *Store) RevokeSession(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP WHERE id = ? AND revoked_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return ensureRowsAffected("revoke session", res)
}

func (s *Store) ListAuditEvents(ctx context.Context, limit int) ([]domain.AuditEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT event_type, subject_user_id, username, resource_id, ip, user_agent, outcome, reason, metadata_json, created_at
FROM audit_events
ORDER BY created_at DESC
LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()

	var events []domain.AuditEvent
	for rows.Next() {
		var event domain.AuditEvent
		if err := rows.Scan(&event.Type, &event.SubjectUserID, &event.Username, &event.ResourceID, &event.IP, &event.UserAgent, &event.Outcome, &event.Reason, &event.MetadataJSON, &event.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) findUserByID(ctx context.Context, id string) (*domain.User, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, username, display_name, is_admin, blocked_at, created_at, updated_at
FROM users
WHERE id = ?`, id)
	user, err := scanUser(row)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Store) findGroupByID(ctx context.Context, id string) (*domain.Group, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, description, created_at, updated_at FROM groups WHERE id = ?`, id)
	var group domain.Group
	if err := row.Scan(&group.ID, &group.Name, &group.Description, &group.CreatedAt, &group.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("find group: %w", err)
	}
	return &group, nil
}

type scanner interface {
	Scan(dest ...any) error
}

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func scanUser(row scanner) (domain.User, error) {
	var user domain.User
	var blockedAt sql.NullTime
	var isAdmin int
	if err := row.Scan(&user.ID, &user.Username, &user.DisplayName, &isAdmin, &blockedAt, &user.CreatedAt, &user.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.User{}, storage.ErrNotFound
		}
		return domain.User{}, fmt.Errorf("scan user: %w", err)
	}
	user.IsAdmin = intToBool(isAdmin)
	if blockedAt.Valid {
		user.BlockedAt = &blockedAt.Time
	}
	return user, nil
}

func scanResourceDetail(ctx context.Context, q queryer, row scanner) (domain.ResourceDetail, error) {
	var detail domain.ResourceDetail
	var enabled int
	if err := row.Scan(&detail.ID, &detail.Name, &detail.Description, &detail.Icon, &detail.InternalURL, &detail.PublicHost, &enabled, &detail.CreatedAt, &detail.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ResourceDetail{}, storage.ErrNotFound
		}
		return domain.ResourceDetail{}, fmt.Errorf("scan resource: %w", err)
	}
	detail.Enabled = intToBool(enabled)

	groupIDs, err := listStrings(ctx, q, `SELECT group_id FROM resource_groups WHERE resource_id = ? ORDER BY group_id`, detail.ID)
	if err != nil {
		return domain.ResourceDetail{}, err
	}
	cidrs, err := listStrings(ctx, q, `SELECT cidr FROM resource_ip_allowlists WHERE resource_id = ? ORDER BY cidr`, detail.ID)
	if err != nil {
		return domain.ResourceDetail{}, err
	}
	detail.GroupIDs = groupIDs
	detail.AllowCIDRs = cidrs
	return detail, nil
}

func listStrings(ctx context.Context, q queryer, query string, args ...any) ([]string, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list strings: %w", err)
	}
	defer rows.Close()

	var values []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, fmt.Errorf("scan string: %w", err)
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func replaceUserGroups(ctx context.Context, tx *sql.Tx, userID string, groupIDs []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_groups WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("delete user groups: %w", err)
	}
	for _, groupID := range uniqueTrimmed(groupIDs) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO user_groups(user_id, group_id) VALUES (?, ?)`, userID, groupID); err != nil {
			return normalizeSQLiteError("insert user group", err)
		}
	}
	return nil
}

func replaceResourceGroups(ctx context.Context, tx *sql.Tx, resourceID string, groupIDs []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM resource_groups WHERE resource_id = ?`, resourceID); err != nil {
		return fmt.Errorf("delete resource groups: %w", err)
	}
	for _, groupID := range uniqueTrimmed(groupIDs) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO resource_groups(resource_id, group_id) VALUES (?, ?)`, resourceID, groupID); err != nil {
			return normalizeSQLiteError("insert resource group", err)
		}
	}
	return nil
}

func replaceResourceCIDRs(ctx context.Context, tx *sql.Tx, resourceID string, cidrs []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM resource_ip_allowlists WHERE resource_id = ?`, resourceID); err != nil {
		return fmt.Errorf("delete resource cidrs: %w", err)
	}
	for _, cidr := range uniqueTrimmed(cidrs) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO resource_ip_allowlists(resource_id, cidr) VALUES (?, ?)`, resourceID, cidr); err != nil {
			return normalizeSQLiteError("insert resource cidr", err)
		}
	}
	return nil
}

func ensureAffected(ctx context.Context, tx *sql.Tx, query string, args ...any) error {
	var id string
	if err := tx.QueryRowContext(ctx, query, args...).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return storage.ErrNotFound
		}
		return fmt.Errorf("ensure row exists: %w", err)
	}
	return nil
}

func ensureRowsAffected(operation string, result sql.Result) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s affected rows: %w", operation, err)
	}
	if affected == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func rollbackUnlessCommitted(tx *sql.Tx) {
	_ = tx.Rollback()
}

func storageID(prefix string) string {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(raw)
}

func normalizeSQLiteError(operation string, err error) error {
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "constraint") || strings.Contains(msg, "unique") {
		return fmt.Errorf("%s: %w", operation, storage.ErrConflict)
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func uniqueTrimmed(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
