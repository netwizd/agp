package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"time"

	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/storage"
	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Hour)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Migrate(ctx context.Context) error {
	files, err := fs.Glob(migrationsFS, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	sort.Strings(files)

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
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", version, err)
		}
		if _, err := tx.ExecContext(ctx, string(sqlText)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("execute migration %s: %w", version, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version) VALUES (?)`, version); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %s: %w", version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", version, err)
		}
	}
	return s.ensureCompatibilityColumns(ctx)
}

func (s *Store) ensureCompatibilityColumns(ctx context.Context) error {
	hasSHA256 := false
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(public_downloads)`)
	if err != nil {
		return fmt.Errorf("inspect public_downloads columns: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, columnType string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &pk); err != nil {
			return fmt.Errorf("scan public_downloads column: %w", err)
		}
		if name == "sha256" {
			hasSHA256 = true
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate public_downloads columns: %w", err)
	}
	if !hasSHA256 {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE public_downloads ADD COLUMN sha256 TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add public_downloads sha256 column: %w", err)
		}
	}
	return nil
}

func (s *Store) Ping(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping sqlite: %w", err)
	}
	return nil
}

func (s *Store) ApplyRetention(ctx context.Context, now time.Time, auditRetention time.Duration, sessionRetention time.Duration) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM audit_events WHERE created_at < ?`, now.Add(-auditRetention)); err != nil {
		return fmt.Errorf("prune audit events: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ? OR revoked_at < ?`, now.Add(-sessionRetention), now.Add(-sessionRetention)); err != nil {
		return fmt.Errorf("prune sessions: %w", err)
	}
	return nil
}

func (s *Store) migrationApplied(ctx context.Context, version string) (bool, error) {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		return false, fmt.Errorf("ensure schema migrations table: %w", err)
	}
	var existing string
	err := s.db.QueryRowContext(ctx, `SELECT version FROM schema_migrations WHERE version = ?`, version).Scan(&existing)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check migration %s: %w", version, err)
	}
	return true, nil
}

func (s *Store) FindUserByUsername(ctx context.Context, username string) (*domain.UserWithPassword, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, username, password_hash, display_name, is_admin, blocked_at, created_at, updated_at
FROM users
WHERE username = ?`, username)

	var user domain.UserWithPassword
	var blockedAt sql.NullTime
	var isAdmin int
	if err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.DisplayName, &isAdmin, &blockedAt, &user.CreatedAt, &user.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("find user by username: %w", err)
	}
	user.IsAdmin = intToBool(isAdmin)
	if blockedAt.Valid {
		user.BlockedAt = &blockedAt.Time
	}
	return &user, nil
}

func (s *Store) CreateSession(ctx context.Context, session domain.Session) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO sessions(id, user_id, token_hash, csrf_hash, ip, user_agent, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		session.ID, session.UserID, session.TokenHash, session.CSRFHash, session.IP, session.UserAgent, session.ExpiresAt, session.CreatedAt)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

func (s *Store) FindSessionByTokenHash(ctx context.Context, tokenHash string) (*domain.SessionContext, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT
    s.id, s.user_id, s.token_hash, s.csrf_hash, s.ip, s.user_agent, s.expires_at, s.created_at,
    u.id, u.username, u.display_name, u.is_admin, u.blocked_at, u.created_at, u.updated_at
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.token_hash = ?
  AND s.revoked_at IS NULL`, tokenHash)

	var session domain.SessionContext
	var blockedAt sql.NullTime
	var isAdmin int
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
		&isAdmin,
		&blockedAt,
		&session.User.CreatedAt,
		&session.User.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("find session: %w", err)
	}
	if time.Now().UTC().After(session.ExpiresAt) {
		return nil, storage.ErrNotFound
	}
	session.User.IsAdmin = intToBool(isAdmin)
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
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP WHERE token_hash = ?`, tokenHash)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (s *Store) ListResourcesForUser(ctx context.Context, userID string) ([]domain.Resource, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT DISTINCT r.id, r.name, r.description, r.category, r.icon, r.internal_url, r.public_host, r.enabled, r.created_at, r.updated_at
FROM resources r
JOIN resource_groups rg ON rg.resource_id = r.id
JOIN user_groups ug ON ug.group_id = rg.group_id
WHERE ug.user_id = ?
  AND r.enabled = 1
ORDER BY r.name`, userID)
	if err != nil {
		return nil, fmt.Errorf("list resources for user: %w", err)
	}
	defer rows.Close()

	var resources []domain.Resource
	for rows.Next() {
		var resource domain.Resource
		var enabled int
		if err := rows.Scan(&resource.ID, &resource.Name, &resource.Description, &resource.Category, &resource.Icon, &resource.InternalURL, &resource.PublicHost, &enabled, &resource.CreatedAt, &resource.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan resource: %w", err)
		}
		resource.Enabled = intToBool(enabled)
		resources = append(resources, resource)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate resources: %w", err)
	}
	return resources, nil
}

func (s *Store) FindResourceByPublicHost(ctx context.Context, host string) (*domain.Resource, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, name, description, category, icon, internal_url, public_host, enabled, created_at, updated_at
FROM resources
WHERE public_host = ?`, host)

	var resource domain.Resource
	var enabled int
	if err := row.Scan(&resource.ID, &resource.Name, &resource.Description, &resource.Category, &resource.Icon, &resource.InternalURL, &resource.PublicHost, &enabled, &resource.CreatedAt, &resource.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("find resource by public host: %w", err)
	}
	resource.Enabled = intToBool(enabled)
	return &resource, nil
}

func (s *Store) UserHasResourceAccess(ctx context.Context, userID string, resourceID string) (bool, error) {
	var exists int
	err := s.db.QueryRowContext(ctx, `
SELECT 1
FROM resource_groups rg
JOIN user_groups ug ON ug.group_id = rg.group_id
WHERE ug.user_id = ?
  AND rg.resource_id = ?
LIMIT 1`, userID, resourceID).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check resource access: %w", err)
	}
	return true, nil
}

func (s *Store) ListResourceAllowCIDRs(ctx context.Context, resourceID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT cidr FROM resource_ip_allowlists WHERE resource_id = ? ORDER BY cidr`, resourceID)
	if err != nil {
		return nil, fmt.Errorf("list resource allow cidrs: %w", err)
	}
	defer rows.Close()

	var cidrs []string
	for rows.Next() {
		var cidr string
		if err := rows.Scan(&cidr); err != nil {
			return nil, fmt.Errorf("scan cidr: %w", err)
		}
		cidrs = append(cidrs, cidr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cidrs: %w", err)
	}
	return cidrs, nil
}

func (s *Store) ListPublicDownloads(ctx context.Context, includeDisabled bool) ([]domain.PublicDownload, error) {
	query := `
	SELECT id, title, description, file_name, stored_name, content_type, sha256, size_bytes, enabled, created_at, updated_at
FROM public_downloads`
	if !includeDisabled {
		query += ` WHERE enabled = 1`
	}
	query += ` ORDER BY title, file_name`
	rows, err := s.db.QueryContext(ctx, query)
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
	row := s.db.QueryRowContext(ctx, `
	SELECT id, title, description, file_name, stored_name, content_type, sha256, size_bytes, enabled, created_at, updated_at
FROM public_downloads
WHERE id = ?`, id)
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
	_, err := s.db.ExecContext(ctx, `
INSERT INTO audit_events(event_type, subject_user_id, username, resource_id, ip, user_agent, outcome, reason, metadata_json, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
	_, err := s.db.ExecContext(ctx, `
	INSERT INTO resource_diagnostics(id, resource_id, outcome, result_json, created_by, created_at)
	VALUES (?, ?, ?, ?, ?, ?)`,
		run.ID, run.ResourceID, run.Outcome, run.ResultJSON, run.CreatedBy, run.CreatedAt)
	if err != nil {
		return fmt.Errorf("append resource diagnostics: %w", err)
	}
	return nil
}

func (s *Store) GetPortalSettings(ctx context.Context) (*domain.PortalSettings, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT brand_name, logo_text, portal_title, portal_subtitle, welcome_title, welcome_body, footer_text, support_text, support_url, updated_at
FROM portal_settings
WHERE id = 1`)
	settings, err := scanPortalSettings(row)
	if err != nil {
		return nil, err
	}
	return &settings, nil
}

func (s *Store) listUserGroups(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT g.name
FROM groups g
JOIN user_groups ug ON ug.group_id = g.id
WHERE ug.user_id = ?
ORDER BY g.name`, userID)
	if err != nil {
		return nil, fmt.Errorf("list user groups: %w", err)
	}
	defer rows.Close()

	var groups []string
	for rows.Next() {
		var group string
		if err := rows.Scan(&group); err != nil {
			return nil, fmt.Errorf("scan group: %w", err)
		}
		groups = append(groups, group)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate groups: %w", err)
	}
	return groups, nil
}

func (s *Store) listUserPermissions(ctx context.Context, userID string, isAdmin bool) ([]string, error) {
	if isAdmin {
		return authz.AllPermissions(), nil
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT DISTINCT gp.permission_id
FROM group_permissions gp
JOIN user_groups ug ON ug.group_id = gp.group_id
WHERE ug.user_id = ?
ORDER BY gp.permission_id`, userID)
	if err != nil {
		return nil, fmt.Errorf("list user permissions: %w", err)
	}
	defer rows.Close()

	var permissions []string
	for rows.Next() {
		var permission string
		if err := rows.Scan(&permission); err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		permissions = append(permissions, permission)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate permissions: %w", err)
	}
	return permissions, nil
}

func intToBool(value int) bool {
	return value != 0
}
