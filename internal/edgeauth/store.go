package edgeauth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

var ErrPending = errors.New("pending handoff is unavailable")

type Pending struct {
	State, Binding, Verifier, ReturnPath, Profile string
	ExpiresAt                                     time.Time
}

type PendingStore interface {
	Create(context.Context, Pending) error
	Consume(context.Context, string, string, string, time.Time) (Pending, error)
}

// StateStore contains only short-lived PKCE transactions, never passwords,
// factors or an authoritative access cache. Losing it restarts login safely.
type StateStore struct{ db *sql.DB }

func OpenStateStore(ctx context.Context, filename string) (*StateStore, error) {
	if !filepath.IsAbs(filename) {
		return nil, fmt.Errorf("state path must be absolute")
	}
	parent, err := os.Stat(filepath.Dir(filename))
	if err != nil {
		return nil, err
	}
	if !parent.IsDir() || parent.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("state directory must not be writable by other accounts")
	}
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		f, e := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return nil, e
		}
		if e = f.Close(); e != nil {
			return nil, e
		}
	} else if err != nil {
		return nil, err
	} else if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("state file must be a private regular file")
	}
	// Refuse accidentally pointing this service at a control-plane SQLite file.
	// Inspect before enabling WAL or creating any EdgeAuth table.
	inspectURL := url.URL{Scheme: "file", Path: filename}
	inspect, err := sql.Open("sqlite", inspectURL.String())
	if err != nil {
		return nil, err
	}
	var foreignTables int
	err = inspect.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name<>'agp_edge_pending_v1'`).Scan(&foreignTables)
	closeErr := inspect.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if foreignTables != 0 {
		return nil, fmt.Errorf("EdgeAuth requires its own pending-state database")
	}
	u := url.URL{Scheme: "file", Path: filename}
	q := u.Query()
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(FULL)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS agp_edge_pending_v1 (
state_hash TEXT PRIMARY KEY, binding_hash TEXT NOT NULL, verifier TEXT NOT NULL,
return_path TEXT NOT NULL, profile TEXT NOT NULL, expires_at INTEGER NOT NULL
); CREATE INDEX IF NOT EXISTS agp_edge_pending_expiry_v1 ON agp_edge_pending_v1(expires_at)`); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &StateStore{db: db}, nil
}

func (s *StateStore) Close() error { return s.db.Close() }
func hashToken(v string) string    { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }

func (s *StateStore) Create(ctx context.Context, p Pending) error {
	if !validToken(p.State) || !validToken(p.Binding) || !validToken(p.Verifier) || !safePath(p.ReturnPath) || len(p.Profile) != 64 || !p.ExpiresAt.After(time.Now()) || p.ExpiresAt.After(time.Now().Add(5*time.Minute+time.Second)) {
		return ErrPending
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM agp_edge_pending_v1 WHERE expires_at<=?`, time.Now().UnixMilli()); err != nil {
		return err
	}
	var n int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM agp_edge_pending_v1`).Scan(&n); err != nil {
		return err
	}
	if n >= 4096 {
		return fmt.Errorf("pending handoff capacity reached")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO agp_edge_pending_v1(state_hash,binding_hash,verifier,return_path,profile,expires_at) VALUES(?,?,?,?,?,?)`, hashToken(p.State), hashToken(p.Binding), p.Verifier, p.ReturnPath, p.Profile, p.ExpiresAt.UnixMilli())
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *StateStore) Consume(ctx context.Context, state, binding, profile string, now time.Time) (Pending, error) {
	if !validToken(state) || !validToken(binding) {
		return Pending{}, ErrPending
	}
	var p Pending
	var expires int64
	// DELETE RETURNING is one atomic consume. Binding mismatch cannot burn
	// another browser's transaction, and a consumed code is never re-delivered.
	err := s.db.QueryRowContext(ctx, `DELETE FROM agp_edge_pending_v1 WHERE state_hash=? AND binding_hash=? AND profile=? AND expires_at>? RETURNING verifier,return_path,profile,expires_at`, hashToken(state), hashToken(binding), profile, now.UnixMilli()).Scan(&p.Verifier, &p.ReturnPath, &p.Profile, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return Pending{}, ErrPending
	}
	if err != nil {
		return Pending{}, err
	}
	p.ExpiresAt = time.UnixMilli(expires).UTC()
	return p, nil
}
