package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/storage"
)

type identityTx struct{ tx *sql.Tx }
type identityRows struct{ *sql.Rows }

func (r identityRows) Close() { _ = r.Rows.Close() }

func (t identityTx) Exec(ctx context.Context, query string, args ...any) (int64, error) {
	result, err := t.tx.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, normalizeSQLiteError("identity mutation", err)
	}
	return result.RowsAffected()
}

func (t identityTx) Query(ctx context.Context, query string, args ...any) (storage.IdentityRows, error) {
	rows, err := t.tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query identity: %w", err)
	}
	return identityRows{rows}, nil
}

func (s *Store) ApplyIdentityMutation(ctx context.Context, tokenHash string, mutation storage.IdentityMutation) (*storage.IdentityMutationResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin identity mutation: %w", err)
	}
	defer rollbackUnlessCommitted(tx)
	// Obtain the SQLite writer reservation before reading authorization. This
	// also serializes independent Store instances using the same database file.
	if _, err := tx.ExecContext(ctx, `UPDATE users SET id = id WHERE 0`); err != nil {
		return nil, fmt.Errorf("lock identity mutation: %w", err)
	}
	result, err := storage.ExecuteIdentityMutation(ctx, identityTx{tx}, tokenHash, mutation)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit identity mutation: %w", err)
	}
	return result, nil
}

// CreateAuthenticatedSession rejects credentials checked before a concurrent
// password, block or privilege change. Compare timestamps as instants because
// legacy SQLite rows may use CURRENT_TIMESTAMP's different text encoding.
func (s *Store) CreateAuthenticatedSession(ctx context.Context, session domain.Session, passwordHash string, updatedAt time.Time, profile domain.SessionProfile) error {
	var normalizeErr error
	session, normalizeErr = storage.NormalizeSessionAudience(session)
	if normalizeErr != nil {
		return normalizeErr
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin authenticated session: %w", err)
	}
	defer rollbackUnlessCommitted(tx)
	if _, err := tx.ExecContext(ctx, `UPDATE users SET id = id WHERE 0`); err != nil {
		return fmt.Errorf("lock authenticated session: %w", err)
	}
	if err := storage.AuthorizeSessionCreation(ctx, identityTx{tx}, session, profile); err != nil {
		return err
	}
	var currentHash string
	var currentUpdatedAt time.Time
	var blockedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT password_hash, updated_at, blocked_at FROM users WHERE id = ?`, session.UserID).Scan(&currentHash, &currentUpdatedAt, &blockedAt)
	if err == sql.ErrNoRows {
		return storage.ErrPermissionDenied
	}
	if err != nil {
		return fmt.Errorf("check session credentials: %w", err)
	}
	if currentHash != passwordHash || !currentUpdatedAt.Equal(updatedAt) || blockedAt.Valid {
		return storage.ErrPermissionDenied
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO sessions(id, user_id, token_hash, csrf_hash, ip, user_agent, expires_at, created_at, audience, audience_origin)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		session.ID, session.UserID, session.TokenHash, session.CSRFHash, session.IP, session.UserAgent, session.ExpiresAt, session.CreatedAt, session.Audience, session.AudienceOrigin)
	if err != nil {
		return fmt.Errorf("create authenticated session: %w", err)
	}
	return tx.Commit()
}

func (s *Store) GetSessionProfile(ctx context.Context) (*domain.SessionProfile, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer rollbackUnlessCommitted(tx)
	return storage.ReadSessionProfile(ctx, identityTx{tx})
}

func (s *Store) CheckSessionProfile(ctx context.Context, expected domain.SessionProfile) error {
	current, err := s.GetSessionProfile(ctx)
	if err != nil {
		return err
	}
	return storage.MatchSessionProfile(current, expected)
}

func (s *Store) ApplySessionProfile(ctx context.Context, profile domain.SessionProfile) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer rollbackUnlessCommitted(tx)
	if _, err := tx.ExecContext(ctx, `UPDATE users SET id = id WHERE 0`); err != nil {
		return 0, err
	}
	revoked, err := storage.ExecuteSessionProfileReset(ctx, identityTx{tx}, profile)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return revoked, nil
}

func (s *Store) WriteIdentity(ctx context.Context, fn func(storage.IdentityTx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollbackUnlessCommitted(tx)
	if _, err := tx.ExecContext(ctx, `UPDATE users SET id=id WHERE 0`); err != nil {
		return err
	}
	if err := fn(identityTx{tx}); err != nil {
		return err
	}
	return tx.Commit()
}
