package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/storage"
)

type Store struct {
	pool *pgxpool.Pool
}

func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres dsn: %w", err)
	}
	cfg.MaxConns = 16
	cfg.MinConns = 1
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 15 * time.Minute
	cfg.HealthCheckPeriod = time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open postgres pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() error {
	s.pool.Close()
	return nil
}

func (s *Store) Migrate(ctx context.Context) error {
	files, err := fs.Glob(migrationsFS, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	sort.Strings(files)

	if _, err := s.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("ensure schema migrations table: %w", err)
	}

	for _, file := range files {
		version := filepath.Base(file)
		applied, err := s.migrationApplied(ctx, version)
		if err != nil {
			return err
		}
		if applied {
			continue
		}

		sqlText, err := migrationsFS.ReadFile(file)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", version, err)
		}
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", version, err)
		}
		if _, err := tx.Exec(ctx, string(sqlText)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("execute migration %s: %w", version, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES ($1)`, version); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record migration %s: %w", version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", version, err)
		}
	}
	return nil
}

func (s *Store) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}
	return nil
}

func (s *Store) ApplyRetention(ctx context.Context, now time.Time, auditRetention time.Duration, sessionRetention time.Duration) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM audit_events WHERE created_at < $1`, now.Add(-auditRetention)); err != nil {
		return fmt.Errorf("prune audit events: %w", err)
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < $1 OR revoked_at < $1`, now.Add(-sessionRetention)); err != nil {
		return fmt.Errorf("prune sessions: %w", err)
	}
	return nil
}

func (s *Store) migrationApplied(ctx context.Context, version string) (bool, error) {
	var existing string
	err := s.pool.QueryRow(ctx, `SELECT version FROM schema_migrations WHERE version = $1`, version).Scan(&existing)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check migration %s: %w", version, err)
	}
	return true, nil
}

func (s *Store) FindUserByUsername(ctx context.Context, username string) (*domain.UserWithPassword, error) {
	row := s.pool.QueryRow(ctx, `
SELECT id, username, password_hash, display_name, is_admin, blocked_at, created_at, updated_at
FROM users
WHERE username = $1`, username)

	var user domain.UserWithPassword
	var blockedAt sql.NullTime
	if err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.DisplayName, &user.IsAdmin, &blockedAt, &user.CreatedAt, &user.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("find user by username: %w", err)
	}
	if blockedAt.Valid {
		user.BlockedAt = &blockedAt.Time
	}
	return &user, nil
}

func (s *Store) CreateSession(ctx context.Context, session domain.Session) error {
	_, err := s.pool.Exec(ctx, `
INSERT INTO sessions(id, user_id, token_hash, csrf_hash, ip, user_agent, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		session.ID, session.UserID, session.TokenHash, session.CSRFHash, session.IP, session.UserAgent, session.ExpiresAt, session.CreatedAt)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

func (s *Store) FindSessionByTokenHash(ctx context.Context, tokenHash string) (*domain.SessionContext, error) {
	row := s.pool.QueryRow(ctx, `
SELECT
    s.id, s.user_id, s.token_hash, s.csrf_hash, s.ip, s.user_agent, s.expires_at, s.created_at,
    u.id, u.username, u.display_name, u.is_admin, u.blocked_at, u.created_at, u.updated_at
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.token_hash = $1
  AND s.revoked_at IS NULL
  AND s.expires_at > now()`, tokenHash)

	var session domain.SessionContext
	var blockedAt sql.NullTime
	if err := row.Scan(
		&session.ID,
		&session.UserID,
		&session.TokenHash,
		&session.CSRFHash,
		&session.IP,
		&session.UserAgent,
		&session.ExpiresAt,
		&session.CreatedAt,
		&session.User.ID,
		&session.User.Username,
		&session.User.DisplayName,
		&session.User.IsAdmin,
		&blockedAt,
		&session.User.CreatedAt,
		&session.User.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("find session: %w", err)
	}
	if blockedAt.Valid {
		session.User.BlockedAt = &blockedAt.Time
	}

	groups, err := s.listUserGroups(ctx, session.User.ID)
	if err != nil {
		return nil, err
	}
	permissions, err := s.listUserPermissions(ctx, session.User.ID, session.User.IsAdmin)
	if err != nil {
		return nil, err
	}
	session.Groups = groups
	session.Permissions = permissions
	return &session, nil
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET revoked_at = now() WHERE token_hash = $1`, tokenHash)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (s *Store) ListResourcesForUser(ctx context.Context, userID string) ([]domain.Resource, error) {
	rows, err := s.pool.Query(ctx, `
SELECT DISTINCT r.id, r.name, r.description, r.category, r.icon, r.internal_url, r.public_host, r.enabled, r.created_at, r.updated_at
FROM resources r
JOIN resource_groups rg ON rg.resource_id = r.id
JOIN user_groups ug ON ug.group_id = rg.group_id
WHERE ug.user_id = $1
  AND r.enabled = true
ORDER BY r.name`, userID)
	if err != nil {
		return nil, fmt.Errorf("list resources for user: %w", err)
	}
	defer rows.Close()

	var resources []domain.Resource
	for rows.Next() {
		var resource domain.Resource
		if err := rows.Scan(&resource.ID, &resource.Name, &resource.Description, &resource.Category, &resource.Icon, &resource.InternalURL, &resource.PublicHost, &resource.Enabled, &resource.CreatedAt, &resource.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan resource: %w", err)
		}
		resources = append(resources, resource)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate resources: %w", err)
	}
	return resources, nil
}

func (s *Store) FindResourceByPublicHost(ctx context.Context, host string) (*domain.Resource, error) {
	row := s.pool.QueryRow(ctx, `
SELECT id, name, description, category, icon, internal_url, public_host, enabled, created_at, updated_at
FROM resources
WHERE public_host = $1`, host)

	var resource domain.Resource
	if err := row.Scan(&resource.ID, &resource.Name, &resource.Description, &resource.Category, &resource.Icon, &resource.InternalURL, &resource.PublicHost, &resource.Enabled, &resource.CreatedAt, &resource.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("find resource by public host: %w", err)
	}
	return &resource, nil
}

func (s *Store) UserHasResourceAccess(ctx context.Context, userID string, resourceID string) (bool, error) {
	var exists int
	err := s.pool.QueryRow(ctx, `
SELECT 1
FROM resource_groups rg
JOIN user_groups ug ON ug.group_id = rg.group_id
WHERE ug.user_id = $1
  AND rg.resource_id = $2
LIMIT 1`, userID, resourceID).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check resource access: %w", err)
	}
	return true, nil
}

func (s *Store) ListResourceAllowCIDRs(ctx context.Context, resourceID string) ([]string, error) {
	return s.listStrings(ctx, `SELECT cidr FROM resource_ip_allowlists WHERE resource_id = $1 ORDER BY cidr`, resourceID)
}

func (s *Store) ListPublicDownloads(ctx context.Context, includeDisabled bool) ([]domain.PublicDownload, error) {
	query := `
	SELECT id, title, description, file_name, stored_name, content_type, sha256, size_bytes, enabled, created_at, updated_at
FROM public_downloads`
	if !includeDisabled {
		query += ` WHERE enabled = true`
	}
	query += ` ORDER BY title, file_name`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list public downloads: %w", err)
	}
	defer rows.Close()

	var downloads []domain.PublicDownload
	for rows.Next() {
		download, err := scanPublicDownload(rows)
		if err != nil {
			return nil, err
		}
		downloads = append(downloads, download)
	}
	return downloads, rows.Err()
}

func (s *Store) FindPublicDownloadByID(ctx context.Context, id string) (*domain.PublicDownload, error) {
	row := s.pool.QueryRow(ctx, `
	SELECT id, title, description, file_name, stored_name, content_type, sha256, size_bytes, enabled, created_at, updated_at
FROM public_downloads
WHERE id = $1`, id)
	download, err := scanPublicDownload(row)
	if err != nil {
		return nil, err
	}
	return &download, nil
}

func (s *Store) AppendAudit(ctx context.Context, event domain.AuditEvent) error {
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `
INSERT INTO audit_events(event_type, subject_user_id, username, resource_id, ip, user_agent, outcome, reason, metadata_json, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		event.Type, event.SubjectUserID, event.Username, event.ResourceID, event.IP, event.UserAgent, event.Outcome, event.Reason, event.MetadataJSON, event.CreatedAt)
	if err != nil {
		return fmt.Errorf("append audit: %w", err)
	}
	return nil
}

func (s *Store) AppendResourceDiagnostics(ctx context.Context, run domain.ResourceDiagnosticsRun) error {
	if run.ID == "" {
		run.ID = storageID("diag")
	}
	if run.CreatedAt.IsZero() {
		run.CreatedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `
	INSERT INTO resource_diagnostics(id, resource_id, outcome, result_json, created_by, created_at)
	VALUES ($1, $2, $3, $4, $5, $6)`,
		run.ID, run.ResourceID, run.Outcome, run.ResultJSON, run.CreatedBy, run.CreatedAt)
	if err != nil {
		return fmt.Errorf("append resource diagnostics: %w", err)
	}
	return nil
}

func (s *Store) GetPortalSettings(ctx context.Context) (*domain.PortalSettings, error) {
	row := s.pool.QueryRow(ctx, `
SELECT brand_name, logo_text, portal_title, portal_subtitle, welcome_title, welcome_body, footer_text, support_text, support_url, updated_at
FROM portal_settings
WHERE id = 1`)
	settings, err := scanPortalSettings(row)
	if err != nil {
		return nil, err
	}
	return &settings, nil
}

func (s *Store) DashboardStats(ctx context.Context) (*domain.DashboardStats, error) {
	var stats domain.DashboardStats
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&stats.UsersCount); err != nil {
		return nil, fmt.Errorf("count users: %w", err)
	}
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE blocked_at IS NOT NULL`).Scan(&stats.BlockedUsersCount); err != nil {
		return nil, fmt.Errorf("count blocked users: %w", err)
	}
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL AND expires_at > now()`).Scan(&stats.ActiveSessionsCount); err != nil {
		return nil, fmt.Errorf("count active sessions: %w", err)
	}
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM resources`).Scan(&stats.ResourcesCount); err != nil {
		return nil, fmt.Errorf("count resources: %w", err)
	}
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM public_downloads`).Scan(&stats.PublicDownloadsCount); err != nil {
		return nil, fmt.Errorf("count public downloads: %w", err)
	}
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events`).Scan(&stats.AuditEventsCount); err != nil {
		return nil, fmt.Errorf("count audit events: %w", err)
	}
	events, err := s.ListAuditEvents(ctx, domain.AuditFilter{Limit: 20})
	if err != nil {
		return nil, err
	}
	stats.RecentEvents = events
	return &stats, nil
}

func (s *Store) ListUsers(ctx context.Context) ([]domain.User, error) {
	rows, err := s.pool.Query(ctx, `
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
		groupIDs, err := s.listUserGroupIDs(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		user.GroupIDs = groupIDs
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *Store) CreateUser(ctx context.Context, input domain.UserInput) (*domain.User, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin create user: %w", err)
	}
	defer rollback(ctx, tx)

	id := storageID("usr")
	now := time.Now().UTC()
	_, err = tx.Exec(ctx, `
INSERT INTO users(id, username, password_hash, display_name, is_admin, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id, input.Username, input.PasswordHash, input.DisplayName, input.IsAdmin, now, now)
	if err != nil {
		return nil, normalizePostgresError("create user", err)
	}
	if err := replaceUserGroups(ctx, tx, id, input.GroupIDs); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit create user: %w", err)
	}
	return s.findUserByID(ctx, id)
}

func (s *Store) UpdateUser(ctx context.Context, id string, update domain.UserUpdate) (*domain.User, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin update user: %w", err)
	}
	defer rollback(ctx, tx)

	if update.DisplayName != nil {
		if _, err := tx.Exec(ctx, `UPDATE users SET display_name = $1, updated_at = now() WHERE id = $2`, *update.DisplayName, id); err != nil {
			return nil, normalizePostgresError("update user display name", err)
		}
	}
	if update.IsAdmin != nil {
		if _, err := tx.Exec(ctx, `UPDATE users SET is_admin = $1, updated_at = now() WHERE id = $2`, *update.IsAdmin, id); err != nil {
			return nil, normalizePostgresError("update user admin flag", err)
		}
	}
	if update.Blocked != nil {
		if *update.Blocked {
			_, err = tx.Exec(ctx, `UPDATE users SET blocked_at = COALESCE(blocked_at, now()), updated_at = now() WHERE id = $1`, id)
		} else {
			_, err = tx.Exec(ctx, `UPDATE users SET blocked_at = NULL, updated_at = now() WHERE id = $1`, id)
		}
		if err != nil {
			return nil, normalizePostgresError("update user blocked flag", err)
		}
	}
	if update.PasswordHash != nil {
		if _, err := tx.Exec(ctx, `UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2`, *update.PasswordHash, id); err != nil {
			return nil, normalizePostgresError("update user password", err)
		}
	}
	if update.UpdateGroups {
		if err := replaceUserGroups(ctx, tx, id, update.GroupIDs); err != nil {
			return nil, err
		}
	}
	if err := ensureExists(ctx, tx, `SELECT id FROM users WHERE id = $1`, id); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit update user: %w", err)
	}
	return s.findUserByID(ctx, id)
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return normalizePostgresError("delete user", err)
	}
	return ensureCommandAffected("delete user", tag)
}

func (s *Store) ListGroups(ctx context.Context) ([]domain.Group, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name, description, created_at, updated_at FROM groups ORDER BY name`)
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
		if err := s.populateGroupPermissions(ctx, &group); err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, rows.Err()
}

func (s *Store) CreateGroup(ctx context.Context, input domain.GroupInput) (*domain.Group, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin create group: %w", err)
	}
	defer rollback(ctx, tx)

	id := storageID("grp")
	now := time.Now().UTC()
	_, err = tx.Exec(ctx, `
INSERT INTO groups(id, name, description, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5)`, id, input.Name, input.Description, now, now)
	if err != nil {
		return nil, normalizePostgresError("create group", err)
	}
	if err := replaceGroupPermissions(ctx, tx, id, input.PermissionIDs); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit create group: %w", err)
	}
	return s.findGroupByID(ctx, id)
}

func (s *Store) UpdateGroup(ctx context.Context, id string, input domain.GroupInput) (*domain.Group, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin update group: %w", err)
	}
	defer rollback(ctx, tx)

	tag, err := tx.Exec(ctx, `
UPDATE groups SET name = $1, description = $2, updated_at = now() WHERE id = $3`,
		input.Name, input.Description, id)
	if err != nil {
		return nil, normalizePostgresError("update group", err)
	}
	if err := ensureCommandAffected("update group", tag); err != nil {
		return nil, err
	}
	if err := replaceGroupPermissions(ctx, tx, id, input.PermissionIDs); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit update group: %w", err)
	}
	return s.findGroupByID(ctx, id)
}

func (s *Store) DeleteGroup(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM groups WHERE id = $1`, id)
	if err != nil {
		return normalizePostgresError("delete group", err)
	}
	return ensureCommandAffected("delete group", tag)
}

func (s *Store) ListResources(ctx context.Context) ([]domain.ResourceDetail, error) {
	rows, err := s.pool.Query(ctx, `
SELECT id, name, description, category, icon, internal_url, public_host, enabled, created_at, updated_at
FROM resources
ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list resources: %w", err)
	}
	defer rows.Close()

	var resources []domain.ResourceDetail
	for rows.Next() {
		resource, err := s.scanResourceDetail(ctx, rows)
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}
	return resources, rows.Err()
}

func (s *Store) FindResourceByID(ctx context.Context, id string) (*domain.ResourceDetail, error) {
	row := s.pool.QueryRow(ctx, `
SELECT id, name, description, category, icon, internal_url, public_host, enabled, created_at, updated_at
FROM resources
WHERE id = $1`, id)
	resource, err := s.scanResourceDetail(ctx, row)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

func (s *Store) CreateResource(ctx context.Context, input domain.ResourceInput) (*domain.ResourceDetail, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin create resource: %w", err)
	}
	defer rollback(ctx, tx)

	id := storageID("res")
	now := time.Now().UTC()
	_, err = tx.Exec(ctx, `
INSERT INTO resources(id, name, description, category, icon, internal_url, public_host, enabled, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		id, input.Name, input.Description, input.Category, input.Icon, input.InternalURL, input.PublicHost, input.Enabled, now, now)
	if err != nil {
		return nil, normalizePostgresError("create resource", err)
	}
	if err := replaceResourceGroups(ctx, tx, id, input.GroupIDs); err != nil {
		return nil, err
	}
	if err := replaceResourceCIDRs(ctx, tx, id, input.AllowCIDRs); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit create resource: %w", err)
	}
	return s.FindResourceByID(ctx, id)
}

func (s *Store) UpdateResource(ctx context.Context, id string, update domain.ResourceUpdate) (*domain.ResourceDetail, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin update resource: %w", err)
	}
	defer rollback(ctx, tx)

	if update.Name != nil {
		if _, err := tx.Exec(ctx, `UPDATE resources SET name = $1, updated_at = now() WHERE id = $2`, *update.Name, id); err != nil {
			return nil, normalizePostgresError("update resource name", err)
		}
	}
	if update.Description != nil {
		if _, err := tx.Exec(ctx, `UPDATE resources SET description = $1, updated_at = now() WHERE id = $2`, *update.Description, id); err != nil {
			return nil, normalizePostgresError("update resource description", err)
		}
	}
	if update.Category != nil {
		if _, err := tx.Exec(ctx, `UPDATE resources SET category = $1, updated_at = now() WHERE id = $2`, *update.Category, id); err != nil {
			return nil, normalizePostgresError("update resource category", err)
		}
	}
	if update.Icon != nil {
		if _, err := tx.Exec(ctx, `UPDATE resources SET icon = $1, updated_at = now() WHERE id = $2`, *update.Icon, id); err != nil {
			return nil, normalizePostgresError("update resource icon", err)
		}
	}
	if update.InternalURL != nil {
		if _, err := tx.Exec(ctx, `UPDATE resources SET internal_url = $1, updated_at = now() WHERE id = $2`, *update.InternalURL, id); err != nil {
			return nil, normalizePostgresError("update resource internal url", err)
		}
	}
	if update.PublicHost != nil {
		if _, err := tx.Exec(ctx, `UPDATE resources SET public_host = $1, updated_at = now() WHERE id = $2`, *update.PublicHost, id); err != nil {
			return nil, normalizePostgresError("update resource public host", err)
		}
	}
	if update.Enabled != nil {
		if _, err := tx.Exec(ctx, `UPDATE resources SET enabled = $1, updated_at = now() WHERE id = $2`, *update.Enabled, id); err != nil {
			return nil, normalizePostgresError("update resource enabled flag", err)
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
	if err := ensureExists(ctx, tx, `SELECT id FROM resources WHERE id = $1`, id); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit update resource: %w", err)
	}
	return s.FindResourceByID(ctx, id)
}

func (s *Store) DeleteResource(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM resources WHERE id = $1`, id)
	if err != nil {
		return normalizePostgresError("delete resource", err)
	}
	return ensureCommandAffected("delete resource", tag)
}

func (s *Store) CreatePublicDownload(ctx context.Context, input domain.PublicDownloadInput) (*domain.PublicDownload, error) {
	id := storageID("dl")
	now := time.Now().UTC()
	_, err := s.pool.Exec(ctx, `
	INSERT INTO public_downloads(id, title, description, file_name, stored_name, content_type, sha256, size_bytes, enabled, created_at, updated_at)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		id, input.Title, input.Description, input.FileName, input.StoredName, input.ContentType, input.SHA256, input.SizeBytes, input.Enabled, now, now)
	if err != nil {
		return nil, normalizePostgresError("create public download", err)
	}
	return s.FindPublicDownloadByID(ctx, id)
}

func (s *Store) UpdatePublicDownload(ctx context.Context, id string, update domain.PublicDownloadUpdate) (*domain.PublicDownload, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin update public download: %w", err)
	}
	defer rollback(ctx, tx)

	if update.Title != nil {
		if _, err := tx.Exec(ctx, `UPDATE public_downloads SET title = $1, updated_at = now() WHERE id = $2`, *update.Title, id); err != nil {
			return nil, normalizePostgresError("update public download title", err)
		}
	}
	if update.Description != nil {
		if _, err := tx.Exec(ctx, `UPDATE public_downloads SET description = $1, updated_at = now() WHERE id = $2`, *update.Description, id); err != nil {
			return nil, normalizePostgresError("update public download description", err)
		}
	}
	if update.Enabled != nil {
		if _, err := tx.Exec(ctx, `UPDATE public_downloads SET enabled = $1, updated_at = now() WHERE id = $2`, *update.Enabled, id); err != nil {
			return nil, normalizePostgresError("update public download enabled", err)
		}
	}
	if err := ensureExists(ctx, tx, `SELECT id FROM public_downloads WHERE id = $1`, id); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit update public download: %w", err)
	}
	return s.FindPublicDownloadByID(ctx, id)
}

func (s *Store) DeletePublicDownload(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM public_downloads WHERE id = $1`, id)
	if err != nil {
		return normalizePostgresError("delete public download", err)
	}
	return ensureCommandAffected("delete public download", tag)
}

func (s *Store) UpdatePortalSettings(ctx context.Context, settings domain.PortalSettings) (*domain.PortalSettings, error) {
	_, err := s.pool.Exec(ctx, `
INSERT INTO portal_settings(
    id, brand_name, logo_text, portal_title, portal_subtitle, welcome_title, welcome_body, footer_text, support_text, support_url, updated_at
) VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, $9, now())
ON CONFLICT (id) DO UPDATE SET
    brand_name = EXCLUDED.brand_name,
    logo_text = EXCLUDED.logo_text,
    portal_title = EXCLUDED.portal_title,
    portal_subtitle = EXCLUDED.portal_subtitle,
    welcome_title = EXCLUDED.welcome_title,
    welcome_body = EXCLUDED.welcome_body,
    footer_text = EXCLUDED.footer_text,
    support_text = EXCLUDED.support_text,
    support_url = EXCLUDED.support_url,
    updated_at = now()`,
		settings.BrandName,
		settings.LogoText,
		settings.PortalTitle,
		settings.PortalSubtitle,
		settings.WelcomeTitle,
		settings.WelcomeBody,
		settings.FooterText,
		settings.SupportText,
		settings.SupportURL,
	)
	if err != nil {
		return nil, normalizePostgresError("update portal settings", err)
	}
	return s.GetPortalSettings(ctx)
}

func (s *Store) ListActiveSessions(ctx context.Context) ([]domain.ActiveSession, error) {
	rows, err := s.pool.Query(ctx, `
SELECT s.id, s.user_id, u.username, s.ip, s.user_agent, s.expires_at, s.created_at
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.revoked_at IS NULL
  AND s.expires_at > now()
ORDER BY s.created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list active sessions: %w", err)
	}
	defer rows.Close()

	var sessions []domain.ActiveSession
	for rows.Next() {
		var session domain.ActiveSession
		if err := rows.Scan(&session.ID, &session.UserID, &session.Username, &session.IP, &session.UserAgent, &session.ExpiresAt, &session.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan active session: %w", err)
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

func (s *Store) RevokeSession(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return ensureCommandAffected("revoke session", tag)
}

func (s *Store) ListAuditEvents(ctx context.Context, filter domain.AuditFilter) ([]domain.AuditEvent, error) {
	if filter.Limit <= 0 || filter.Limit > 1000 {
		filter.Limit = 100
	}
	where, args := auditFilterSQL(filter, 1)
	args = append(args, filter.Limit)
	query := `
	SELECT event_type, subject_user_id, username, resource_id, ip, user_agent, outcome, reason, metadata_json, created_at
	FROM audit_events` + where + `
	ORDER BY created_at DESC
	LIMIT $` + fmt.Sprint(len(args))
	rows, err := s.pool.Query(ctx, query, args...)
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

func (s *Store) ListResourceDiagnostics(ctx context.Context, resourceID string, limit int) ([]domain.ResourceDiagnosticsRun, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.pool.Query(ctx, `
	SELECT d.id, d.resource_id, r.name, d.outcome, d.result_json, d.created_by, d.created_at
	FROM resource_diagnostics d
	JOIN resources r ON r.id = d.resource_id
	WHERE d.resource_id = $1
	ORDER BY d.created_at DESC
	LIMIT $2`, resourceID, limit)
	if err != nil {
		return nil, fmt.Errorf("list resource diagnostics: %w", err)
	}
	defer rows.Close()

	var runs []domain.ResourceDiagnosticsRun
	for rows.Next() {
		var run domain.ResourceDiagnosticsRun
		if err := rows.Scan(&run.ID, &run.ResourceID, &run.ResourceName, &run.Outcome, &run.ResultJSON, &run.CreatedBy, &run.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan resource diagnostics: %w", err)
		}
		runs = append(runs, run)
	}
	return runs, rows.Err()
}

func (s *Store) findUserByID(ctx context.Context, id string) (*domain.User, error) {
	row := s.pool.QueryRow(ctx, `
SELECT id, username, display_name, is_admin, blocked_at, created_at, updated_at
FROM users
WHERE id = $1`, id)
	user, err := scanUser(row)
	if err != nil {
		return nil, err
	}
	groupIDs, err := s.listUserGroupIDs(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	user.GroupIDs = groupIDs
	return &user, nil
}

func (s *Store) findGroupByID(ctx context.Context, id string) (*domain.Group, error) {
	row := s.pool.QueryRow(ctx, `SELECT id, name, description, created_at, updated_at FROM groups WHERE id = $1`, id)
	var group domain.Group
	if err := row.Scan(&group.ID, &group.Name, &group.Description, &group.CreatedAt, &group.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("find group: %w", err)
	}
	if err := s.populateGroupPermissions(ctx, &group); err != nil {
		return nil, err
	}
	return &group, nil
}

func (s *Store) listUserGroups(ctx context.Context, userID string) ([]string, error) {
	return s.listStrings(ctx, `
SELECT g.name
FROM groups g
JOIN user_groups ug ON ug.group_id = g.id
WHERE ug.user_id = $1
	ORDER BY g.name`, userID)
}

func (s *Store) listUserGroupIDs(ctx context.Context, userID string) ([]string, error) {
	return s.listStrings(ctx, `
	SELECT group_id
	FROM user_groups
	WHERE user_id = $1
	ORDER BY group_id`, userID)
}

func auditFilterSQL(filter domain.AuditFilter, firstArg int) (string, []any) {
	var conditions []string
	var args []any
	add := func(condition string, value any) {
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf(condition, firstArg+len(args)-1))
	}
	if strings.TrimSpace(filter.EventType) != "" {
		add("event_type = $%d", strings.TrimSpace(filter.EventType))
	}
	if strings.TrimSpace(filter.Username) != "" {
		add("username ILIKE $%d", "%"+strings.TrimSpace(filter.Username)+"%")
	}
	if strings.TrimSpace(filter.ResourceID) != "" {
		add("resource_id = $%d", strings.TrimSpace(filter.ResourceID))
	}
	if strings.TrimSpace(filter.Outcome) != "" {
		add("outcome = $%d", strings.TrimSpace(filter.Outcome))
	}
	if filter.From != nil {
		add("created_at >= $%d", *filter.From)
	}
	if filter.To != nil {
		add("created_at <= $%d", *filter.To)
	}
	if len(conditions) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conditions, " AND "), args
}

func (s *Store) listUserPermissions(ctx context.Context, userID string, isAdmin bool) ([]string, error) {
	if isAdmin {
		return authz.AllPermissions(), nil
	}
	return s.listStrings(ctx, `
SELECT DISTINCT gp.permission_id
FROM group_permissions gp
JOIN user_groups ug ON ug.group_id = gp.group_id
WHERE ug.user_id = $1
ORDER BY gp.permission_id`, userID)
}

func (s *Store) listStrings(ctx context.Context, query string, args ...any) ([]string, error) {
	rows, err := s.pool.Query(ctx, query, args...)
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

type scanner interface {
	Scan(dest ...any) error
}

func scanUser(row scanner) (domain.User, error) {
	var user domain.User
	var blockedAt sql.NullTime
	if err := row.Scan(&user.ID, &user.Username, &user.DisplayName, &user.IsAdmin, &blockedAt, &user.CreatedAt, &user.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, storage.ErrNotFound
		}
		return domain.User{}, fmt.Errorf("scan user: %w", err)
	}
	if blockedAt.Valid {
		user.BlockedAt = &blockedAt.Time
	}
	return user, nil
}

func scanPublicDownload(row scanner) (domain.PublicDownload, error) {
	var download domain.PublicDownload
	if err := row.Scan(
		&download.ID,
		&download.Title,
		&download.Description,
		&download.FileName,
		&download.StoredName,
		&download.ContentType,
		&download.SHA256,
		&download.SizeBytes,
		&download.Enabled,
		&download.CreatedAt,
		&download.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.PublicDownload{}, storage.ErrNotFound
		}
		return domain.PublicDownload{}, fmt.Errorf("scan public download: %w", err)
	}
	return download, nil
}

func scanPortalSettings(row scanner) (domain.PortalSettings, error) {
	var settings domain.PortalSettings
	if err := row.Scan(
		&settings.BrandName,
		&settings.LogoText,
		&settings.PortalTitle,
		&settings.PortalSubtitle,
		&settings.WelcomeTitle,
		&settings.WelcomeBody,
		&settings.FooterText,
		&settings.SupportText,
		&settings.SupportURL,
		&settings.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.PortalSettings{}, storage.ErrNotFound
		}
		return domain.PortalSettings{}, fmt.Errorf("scan portal settings: %w", err)
	}
	return settings, nil
}

func (s *Store) scanResourceDetail(ctx context.Context, row scanner) (domain.ResourceDetail, error) {
	var detail domain.ResourceDetail
	if err := row.Scan(&detail.ID, &detail.Name, &detail.Description, &detail.Category, &detail.Icon, &detail.InternalURL, &detail.PublicHost, &detail.Enabled, &detail.CreatedAt, &detail.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ResourceDetail{}, storage.ErrNotFound
		}
		return domain.ResourceDetail{}, fmt.Errorf("scan resource: %w", err)
	}
	groupIDs, err := s.listStrings(ctx, `SELECT group_id FROM resource_groups WHERE resource_id = $1 ORDER BY group_id`, detail.ID)
	if err != nil {
		return domain.ResourceDetail{}, err
	}
	cidrs, err := s.listStrings(ctx, `SELECT cidr FROM resource_ip_allowlists WHERE resource_id = $1 ORDER BY cidr`, detail.ID)
	if err != nil {
		return domain.ResourceDetail{}, err
	}
	detail.GroupIDs = groupIDs
	detail.AllowCIDRs = cidrs
	return detail, nil
}

func replaceUserGroups(ctx context.Context, tx pgx.Tx, userID string, groupIDs []string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM user_groups WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("delete user groups: %w", err)
	}
	for _, groupID := range uniqueTrimmed(groupIDs) {
		if _, err := tx.Exec(ctx, `INSERT INTO user_groups(user_id, group_id) VALUES ($1, $2)`, userID, groupID); err != nil {
			return normalizePostgresError("insert user group", err)
		}
	}
	return nil
}

func replaceGroupPermissions(ctx context.Context, tx pgx.Tx, groupID string, permissionIDs []string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM group_permissions WHERE group_id = $1`, groupID); err != nil {
		return fmt.Errorf("delete group permissions: %w", err)
	}
	for _, permissionID := range uniqueTrimmed(permissionIDs) {
		if _, err := tx.Exec(ctx, `INSERT INTO group_permissions(group_id, permission_id) VALUES ($1, $2)`, groupID, permissionID); err != nil {
			return normalizePostgresError("insert group permission", err)
		}
	}
	return nil
}

func (s *Store) populateGroupPermissions(ctx context.Context, group *domain.Group) error {
	permissionIDs, err := s.listStrings(ctx, `SELECT permission_id FROM group_permissions WHERE group_id = $1 ORDER BY permission_id`, group.ID)
	if err != nil {
		return err
	}
	group.PermissionIDs = permissionIDs
	return nil
}

func replaceResourceGroups(ctx context.Context, tx pgx.Tx, resourceID string, groupIDs []string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM resource_groups WHERE resource_id = $1`, resourceID); err != nil {
		return fmt.Errorf("delete resource groups: %w", err)
	}
	for _, groupID := range uniqueTrimmed(groupIDs) {
		if _, err := tx.Exec(ctx, `INSERT INTO resource_groups(resource_id, group_id) VALUES ($1, $2)`, resourceID, groupID); err != nil {
			return normalizePostgresError("insert resource group", err)
		}
	}
	return nil
}

func replaceResourceCIDRs(ctx context.Context, tx pgx.Tx, resourceID string, cidrs []string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM resource_ip_allowlists WHERE resource_id = $1`, resourceID); err != nil {
		return fmt.Errorf("delete resource cidrs: %w", err)
	}
	for _, cidr := range uniqueTrimmed(cidrs) {
		if _, err := tx.Exec(ctx, `INSERT INTO resource_ip_allowlists(resource_id, cidr) VALUES ($1, $2)`, resourceID, cidr); err != nil {
			return normalizePostgresError("insert resource cidr", err)
		}
	}
	return nil
}

func ensureExists(ctx context.Context, tx pgx.Tx, query string, args ...any) error {
	var id string
	if err := tx.QueryRow(ctx, query, args...).Scan(&id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.ErrNotFound
		}
		return fmt.Errorf("ensure row exists: %w", err)
	}
	return nil
}

func ensureCommandAffected(operation string, tag pgconn.CommandTag) error {
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func rollback(ctx context.Context, tx pgx.Tx) {
	_ = tx.Rollback(ctx)
}

func storageID(prefix string) string {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(raw)
}

func normalizePostgresError(operation string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505", "23503":
			return fmt.Errorf("%s: %w", operation, storage.ErrConflict)
		}
	}
	return fmt.Errorf("%s: %w", operation, err)
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
