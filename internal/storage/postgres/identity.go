package postgres

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/storage"
)

type identityTx struct{ tx pgx.Tx }

func identitySQL(query string) string {
	var result strings.Builder
	position := 0
	for _, part := range strings.Split(query, "?") {
		if position > 0 {
			result.WriteByte('$')
			result.WriteString(strconv.Itoa(position))
		}
		result.WriteString(part)
		position++
	}
	return result.String()
}

func (t identityTx) Exec(ctx context.Context, query string, args ...any) (int64, error) {
	result, err := t.tx.Exec(ctx, identitySQL(query), args...)
	if err != nil {
		return 0, normalizePostgresError("identity mutation", err)
	}
	return result.RowsAffected(), nil
}

func (t identityTx) Query(ctx context.Context, query string, args ...any) (storage.IdentityRows, error) {
	rows, err := t.tx.Query(ctx, identitySQL(query), args...)
	if err != nil {
		return nil, fmt.Errorf("query identity: %w", err)
	}
	return rows, nil
}

func (s *Store) beginIdentityMutation(ctx context.Context) (pgx.Tx, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin identity mutation: %w", err)
	}
	// The baseline has one global permission scope. Serialize its infrequent
	// identity writes, including legacy SQL writes, while allowing plain reads.
	// Row/table locks prevent membership and phantom grant changes during guard.
	if _, err := tx.Exec(ctx, `LOCK TABLE users, groups, user_groups, group_permissions, sessions, session_profiles, resources IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		rollback(ctx, tx)
		return nil, fmt.Errorf("lock identity mutation: %w", err)
	}
	return tx, nil
}

func (s *Store) ApplyIdentityMutation(ctx context.Context, tokenHash string, mutation storage.IdentityMutation) (*storage.IdentityMutationResult, error) {
	tx, err := s.beginIdentityMutation(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx)
	result, err := storage.ExecuteIdentityMutation(ctx, identityTx{tx}, tokenHash, mutation)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit identity mutation: %w", err)
	}
	return result, nil
}

func (s *Store) CreateAuthenticatedSession(ctx context.Context, session domain.Session, passwordHash string, updatedAt time.Time, profile domain.SessionProfile) error {
	var normalizeErr error
	session, normalizeErr = storage.NormalizeSessionAudience(session)
	if normalizeErr != nil {
		return normalizeErr
	}
	tx, err := s.beginIdentityMutation(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx)
	if err := storage.AuthorizeSessionCreation(ctx, identityTx{tx}, session, profile); err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `
INSERT INTO sessions(id, user_id, token_hash, csrf_hash, ip, user_agent, expires_at, created_at, audience, audience_origin)
SELECT $1, id, $2, $3, $4, $5, $6, $7, $11, $12 FROM users
WHERE id = $8 AND password_hash = $9 AND updated_at = $10 AND blocked_at IS NULL`,
		session.ID, session.TokenHash, session.CSRFHash, session.IP, session.UserAgent, session.ExpiresAt, session.CreatedAt,
		session.UserID, passwordHash, updatedAt, session.Audience, session.AudienceOrigin)
	if err != nil {
		return fmt.Errorf("create authenticated session: %w", err)
	}
	if result.RowsAffected() != 1 {
		return storage.ErrPermissionDenied
	}
	return tx.Commit(ctx)
}

func (s *Store) GetSessionProfile(ctx context.Context) (*domain.SessionProfile, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx)
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
	tx, err := s.beginIdentityMutation(ctx)
	if err != nil {
		return 0, err
	}
	defer rollback(ctx, tx)
	revoked, err := storage.ExecuteSessionProfileReset(ctx, identityTx{tx}, profile)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return revoked, nil
}

func (s *Store) WriteIdentity(ctx context.Context, fn func(storage.IdentityTx) error) error {
	s.identityMu.Lock()
	defer s.identityMu.Unlock()
	var tx pgx.Tx
	var err error
	if s.identityLeaseUsed {
		if s.identityConn == nil {
			return fmt.Errorf("secure identity writer lease released")
		}
		tx, err = s.identityConn.Begin(ctx)
		if err == nil {
			_, err = tx.Exec(ctx, `LOCK TABLE users, groups, user_groups, group_permissions, sessions, session_profiles, resources IN SHARE ROW EXCLUSIVE MODE`)
			if err != nil {
				rollback(ctx, tx)
			}
		}
	} else {
		tx, err = s.beginIdentityMutation(ctx)
	}
	if err != nil {
		return err
	}
	defer rollback(ctx, tx)
	if err := fn(identityTx{tx}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AcquireIdentityLease fences concurrent secure CP processes for this database.
// The held connection is dedicated until release; SQL mutations also serialize
// independently, so losing a lease cannot publish an unguarded mutation.
func (s *Store) AcquireIdentityLease(ctx context.Context) (func(), error) {
	s.identityMu.Lock()
	defer s.identityMu.Unlock()
	if s.identityLeaseUsed {
		return nil, fmt.Errorf("secure identity lease already acquired or released")
	}
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	var acquired bool
	if err = conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(731470142911)`).Scan(&acquired); err != nil || !acquired {
		conn.Release()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("secure identity writer already active")
	}
	s.identityConn = conn
	s.identityLeaseUsed = true
	return func() {
		s.identityMu.Lock()
		defer s.identityMu.Unlock()
		if s.identityConn == nil {
			return
		}
		s.identityConn = nil
		releaseCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = conn.Exec(releaseCtx, `SELECT pg_advisory_unlock(731470142911)`)
		conn.Release()
	}, nil
}
