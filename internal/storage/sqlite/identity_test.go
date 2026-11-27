package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/domain"
)

func TestAuthenticatedSessionLegacySQLTimestamp(t *testing.T) {
	ctx := context.Background()
	store, err := Open(t.TempDir() + "/legacy.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO users(id, username, password_hash) VALUES ('legacy', 'legacy', 'hash')`); err != nil {
		t.Fatal(err)
	}
	user, err := store.FindUserByUsername(ctx, "legacy")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	session := domain.Session{ID: "session", UserID: user.ID, TokenHash: "token", CSRFHash: "csrf", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := store.CreateAuthenticatedSession(ctx, session, user.PasswordHash, user.UpdatedAt, domain.SessionProfile{}); err != nil {
		t.Fatalf("legacy CURRENT_TIMESTAMP must authenticate: %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, "token"); err != nil {
		t.Fatalf("issued legacy-user session is invalid: %v", err)
	}
}

func TestListUsersSingleConnection(t *testing.T) {
	ctx := context.Background()
	store, err := Open(t.TempDir() + "/users.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	group, err := store.CreateGroup(ctx, domain.GroupInput{Name: "users"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateUser(ctx, domain.UserInput{Username: "user", PasswordHash: "hash", GroupIDs: []string{group.ID}}); err != nil {
		t.Fatal(err)
	}
	queryCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	users, err := store.ListUsers(queryCtx)
	if err != nil {
		t.Fatalf("nested membership query stalled on the single connection: %v", err)
	}
	if len(users) != 1 || len(users[0].GroupIDs) != 1 || users[0].GroupIDs[0] != group.ID {
		t.Fatalf("missing memberships: %#v", users)
	}
}
