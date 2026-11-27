package storage_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/storage"
	"github.com/netwizd/agp/internal/storage/postgres"
	"github.com/netwizd/agp/internal/storage/sqlite"
)

type identityFixture struct {
	store                                                   storage.Store
	ctx                                                     context.Context
	root, manager, privileged, ordinary                     *domain.User
	rootToken, managerToken, privilegedToken, ordinaryToken string
	rootGroup, managerGroup, privilegedGroup, ordinaryGroup *domain.Group
}

func newIdentityFixture(t *testing.T, driver string) *identityFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	var store storage.Store
	if driver == "sqlite" {
		s, err := sqlite.Open(t.TempDir() + "/identity.db")
		if err != nil {
			t.Fatal(err)
		}
		store = s
	} else {
		dsn := os.Getenv("AGP_TEST_POSTGRES_DSN")
		if dsn == "" {
			t.Skip("AGP_TEST_POSTGRES_DSN is not set")
		}
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		schema := fmt.Sprintf("agp_identity_%d", time.Now().UnixNano())
		if _, err := pool.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cleanupCancel()
			if _, err := pool.Exec(cleanupCtx, `DROP SCHEMA `+schema+` CASCADE`); err != nil {
				t.Errorf("drop test schema: %v", err)
			}
		})
		if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
			u, err := url.Parse(dsn)
			if err != nil {
				t.Fatal(err)
			}
			query := u.Query()
			query.Set("search_path", schema)
			u.RawQuery = query.Encode()
			dsn = u.String()
		} else {
			dsn += " search_path=" + schema
		}
		s, err := postgres.Open(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		store = s
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	f := &identityFixture{store: store, ctx: ctx}
	f.rootGroup = f.group(t, "root", nil)
	f.managerGroup = f.group(t, "manager", []string{authz.PermUsersManage, authz.PermGroupsManage, authz.PermSessionsRevoke, authz.PermResourcesManage})
	f.privilegedGroup = f.group(t, "privileged", []string{authz.PermResourcesManage})
	f.ordinaryGroup = f.group(t, "ordinary", nil)
	f.root = f.user(t, "root", true, f.rootGroup.ID)
	f.manager = f.user(t, "manager", false, f.managerGroup.ID)
	f.privileged = f.user(t, "privileged", false, f.privilegedGroup.ID)
	f.ordinary = f.user(t, "ordinary", false, f.ordinaryGroup.ID)
	f.rootToken = f.session(t, f.root, "root-session")
	f.managerToken = f.session(t, f.manager, "manager-session")
	f.privilegedToken = f.session(t, f.privileged, "privileged-session")
	f.ordinaryToken = f.session(t, f.ordinary, "ordinary-session")
	return f
}

func (f *identityFixture) group(t *testing.T, name string, permissions []string) *domain.Group {
	t.Helper()
	group, err := f.store.CreateGroup(f.ctx, domain.GroupInput{Name: name, PermissionIDs: permissions})
	if err != nil {
		t.Fatal(err)
	}
	return group
}
func (f *identityFixture) user(t *testing.T, name string, admin bool, group string) *domain.User {
	t.Helper()
	user, err := f.store.CreateUser(f.ctx, domain.UserInput{Username: name, PasswordHash: "old-password-hash", IsAdmin: admin, GroupIDs: []string{group}})
	if err != nil {
		t.Fatal(err)
	}
	return user
}
func (f *identityFixture) session(t *testing.T, user *domain.User, id string) string {
	t.Helper()
	now := time.Now().UTC()
	if err := f.store.CreateSession(f.ctx, domain.Session{ID: id, UserID: user.ID, TokenHash: id, CSRFHash: "csrf", ExpiresAt: now.Add(time.Hour), CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	return id
}
func (f *identityFixture) active(t *testing.T, token string, want bool) {
	t.Helper()
	_, err := f.store.FindSessionByTokenHash(f.ctx, token)
	if want && err != nil {
		t.Fatalf("session %s unexpectedly invalid: %v", token, err)
	}
	if !want && !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("session %s must be revoked, got %v", token, err)
	}
}
func (f *identityFixture) apply(t *testing.T, token string, mutation storage.IdentityMutation) *storage.IdentityMutationResult {
	t.Helper()
	result, err := f.store.ApplyIdentityMutation(f.ctx, token, mutation)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestIdentityMutationStorage(t *testing.T) {
	for _, driver := range []string{"sqlite", "postgres"} {
		t.Run(driver, func(t *testing.T) {
			t.Run("protect_current_privileged_principals", func(t *testing.T) {
				f := newIdentityFixture(t, driver)
				password, blocked, admin := "new-password-hash", true, false
				for _, target := range []*domain.User{f.root, f.privileged} {
					for _, update := range []domain.UserUpdate{{PasswordHash: &password}, {Blocked: &blocked}, {DisplayName: &password}, {UpdateGroups: true}, {IsAdmin: &admin}} {
						_, err := f.store.ApplyIdentityMutation(f.ctx, f.managerToken, storage.IdentityMutation{Kind: storage.IdentityUpdateUser, ID: target.ID, UserUpdate: update})
						if !errors.Is(err, storage.ErrPermissionDenied) {
							t.Fatalf("manager changed privileged %s: %v", target.Username, err)
						}
					}
					for _, kind := range []storage.IdentityMutationKind{storage.IdentityDeleteUser, storage.IdentityRevokeSession} {
						id := target.ID
						if kind == storage.IdentityRevokeSession {
							id = target.Username + "-session"
						}
						_, err := f.store.ApplyIdentityMutation(f.ctx, f.managerToken, storage.IdentityMutation{Kind: kind, ID: id})
						if !errors.Is(err, storage.ErrPermissionDenied) {
							t.Fatalf("manager mutation %d on %s: %v", kind, target.Username, err)
						}
					}
					got, err := f.store.FindUserByUsername(f.ctx, target.Username)
					if err != nil || got.PasswordHash != "old-password-hash" || got.BlockedAt != nil || got.IsAdmin != target.IsAdmin {
						t.Fatalf("denied mutation changed target: %#v, %v", got, err)
					}
				}
				f.active(t, f.rootToken, true)
				f.active(t, f.privilegedToken, true)
			})
			t.Run("delegation_and_group_indirection", func(t *testing.T) {
				f := newIdentityFixture(t, driver)
				high := f.group(t, "high", []string{authz.PermAuditExport})
				cases := []storage.IdentityMutation{
					{Kind: storage.IdentityCreateUser, UserInput: domain.UserInput{Username: "elevated", PasswordHash: "hash", IsAdmin: true}},
					{Kind: storage.IdentityCreateUser, UserInput: domain.UserInput{Username: "elevated", PasswordHash: "hash", GroupIDs: []string{high.ID}}},
					{Kind: storage.IdentityCreateUser, UserInput: domain.UserInput{Username: "elevated", PasswordHash: "hash", GroupIDs: []string{f.privilegedGroup.ID}}},
					{Kind: storage.IdentityUpdateUser, ID: f.ordinary.ID, UserUpdate: domain.UserUpdate{UpdateGroups: true, GroupIDs: []string{high.ID}}},
					{Kind: storage.IdentityUpdateUser, ID: f.ordinary.ID, UserUpdate: domain.UserUpdate{UpdateGroups: true, GroupIDs: []string{f.privilegedGroup.ID}}},
					{Kind: storage.IdentityCreateGroup, GroupInput: domain.GroupInput{Name: "elevation", PermissionIDs: []string{authz.PermUsersSuperAdminManage}}},
					{Kind: storage.IdentityUpdateGroup, ID: f.managerGroup.ID, GroupInput: domain.GroupInput{Name: "manager", PermissionIDs: append([]string{authz.PermUsersSuperAdminManage}, f.managerGroup.PermissionIDs...)}},
					{Kind: storage.IdentityUpdateGroup, ID: high.ID, GroupInput: domain.GroupInput{Name: "high"}},
					{Kind: storage.IdentityDeleteGroup, ID: high.ID},
					{Kind: storage.IdentityUpdateGroup, ID: f.rootGroup.ID, GroupInput: domain.GroupInput{Name: "root"}},
					{Kind: storage.IdentityDeleteGroup, ID: f.rootGroup.ID},
					{Kind: storage.IdentityUpdateGroup, ID: f.privilegedGroup.ID, GroupInput: domain.GroupInput{Name: "privileged"}},
					{Kind: storage.IdentityDeleteGroup, ID: f.privilegedGroup.ID},
					{Kind: storage.IdentityUpdateGroup, ID: f.ordinaryGroup.ID, GroupInput: domain.GroupInput{Name: "ordinary", PermissionIDs: []string{authz.PermResourcesManage}}},
				}
				for _, mutation := range cases {
					if _, err := f.store.ApplyIdentityMutation(f.ctx, f.managerToken, mutation); !errors.Is(err, storage.ErrPermissionDenied) {
						t.Fatalf("delegation bypass kind=%d id=%s: %v", mutation.Kind, mutation.ID, err)
					}
				}
				f.active(t, f.managerToken, true)
				f.active(t, f.rootToken, true)
				f.active(t, f.ordinaryToken, true)
				// Manage implies read, so an operator may delegate its implied read right.
				group := f.apply(t, f.managerToken, storage.IdentityMutation{Kind: storage.IdentityCreateGroup, GroupInput: domain.GroupInput{Name: "readers", PermissionIDs: []string{authz.PermResourcesRead}}}).Group
				f.apply(t, f.managerToken, storage.IdentityMutation{Kind: storage.IdentityCreateUser, UserInput: domain.UserInput{Username: "reader", PasswordHash: "hash", GroupIDs: []string{group.ID}}})
			})
			t.Run("superadmin_permission_does_not_override_ceiling", func(t *testing.T) {
				f := newIdentityFixture(t, driver)
				group := f.group(t, "partial privileged manager", []string{authz.PermUsersManage, authz.PermUsersSuperAdminManage})
				actor := f.user(t, "partial", false, group.ID)
				token := f.session(t, actor, "partial-session")
				password := "new"
				if _, err := f.store.ApplyIdentityMutation(f.ctx, token, storage.IdentityMutation{Kind: storage.IdentityUpdateUser, ID: f.privileged.ID, UserUpdate: domain.UserUpdate{PasswordHash: &password}}); !errors.Is(err, storage.ErrPermissionDenied) {
					t.Fatalf("superadmin permission bypassed target ceiling: %v", err)
				}
				if _, err := f.store.ApplyIdentityMutation(f.ctx, token, storage.IdentityMutation{Kind: storage.IdentityCreateUser, UserInput: domain.UserInput{Username: "super", PasswordHash: "hash", IsAdmin: true}}); !errors.Is(err, storage.ErrPermissionDenied) {
					t.Fatalf("superadmin creation bypassed ceiling: %v", err)
				}
			})
			t.Run("user_security_changes_revoke_only_target", func(t *testing.T) {
				f := newIdentityFixture(t, driver)
				name := "new name"
				f.apply(t, f.managerToken, storage.IdentityMutation{Kind: storage.IdentityUpdateUser, ID: f.ordinary.ID, UserUpdate: domain.UserUpdate{DisplayName: &name}})
				f.active(t, f.ordinaryToken, true)
				password, yes, no := "new hash", true, false
				for i, update := range []domain.UserUpdate{{PasswordHash: &password}, {Blocked: &yes}, {Blocked: &no}, {IsAdmin: &yes}, {IsAdmin: &no}, {UpdateGroups: true, GroupIDs: []string{f.ordinaryGroup.ID}}} {
					token := f.session(t, f.ordinary, fmt.Sprintf("target-%d", i))
					f.apply(t, f.rootToken, storage.IdentityMutation{Kind: storage.IdentityUpdateUser, ID: f.ordinary.ID, UserUpdate: update})
					f.active(t, token, false)
					f.active(t, f.rootToken, true)
					f.active(t, f.managerToken, true)
				}
			})
			t.Run("group_changes_revoke_members", func(t *testing.T) {
				f := newIdentityFixture(t, driver)
				second := f.user(t, "second", false, f.ordinaryGroup.ID)
				secondToken := f.session(t, second, "second-session")
				f.apply(t, f.rootToken, storage.IdentityMutation{Kind: storage.IdentityUpdateGroup, ID: f.ordinaryGroup.ID, GroupInput: domain.GroupInput{Name: "ordinary", PermissionIDs: []string{authz.PermResourcesRead}}})
				f.active(t, f.ordinaryToken, false)
				f.active(t, secondToken, false)
				f.active(t, f.managerToken, true)
				token := f.session(t, f.ordinary, "after-group-update")
				f.apply(t, f.rootToken, storage.IdentityMutation{Kind: storage.IdentityDeleteGroup, ID: f.ordinaryGroup.ID})
				f.active(t, token, false)
			})
			t.Run("last_active_admin", func(t *testing.T) {
				f := newIdentityFixture(t, driver)
				full := f.group(t, "full", authz.AllPermissions())
				actor := f.user(t, "full-actor", false, full.ID)
				token := f.session(t, actor, "full-session")
				yes, no := true, false
				for _, mutation := range []storage.IdentityMutation{{Kind: storage.IdentityDeleteUser, ID: f.root.ID}, {Kind: storage.IdentityUpdateUser, ID: f.root.ID, UserUpdate: domain.UserUpdate{Blocked: &yes}}, {Kind: storage.IdentityUpdateUser, ID: f.root.ID, UserUpdate: domain.UserUpdate{IsAdmin: &no}}} {
					if _, err := f.store.ApplyIdentityMutation(f.ctx, token, mutation); !errors.Is(err, storage.ErrLastAdmin) {
						t.Fatalf("last admin guard failed: %v", err)
					}
				}
				f.user(t, "second-root", true, f.rootGroup.ID)
				f.apply(t, token, storage.IdentityMutation{Kind: storage.IdentityDeleteUser, ID: f.root.ID})
				f.active(t, f.rootToken, false)
			})
			t.Run("rollback_restores_sessions_and_grants", func(t *testing.T) {
				f := newIdentityFixture(t, driver)
				_, err := f.store.ApplyIdentityMutation(f.ctx, f.rootToken, storage.IdentityMutation{Kind: storage.IdentityUpdateGroup, ID: f.ordinaryGroup.ID, GroupInput: domain.GroupInput{Name: "invalid group", PermissionIDs: []string{authz.PermResourcesRead, authz.PermResourcesRead}}})
				if !errors.Is(err, storage.ErrConflict) {
					t.Fatalf("expected duplicate grant conflict, got %v", err)
				}
				f.active(t, f.ordinaryToken, true)
				groups, err := f.store.ListGroups(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, group := range groups {
					if group.ID == f.ordinaryGroup.ID && (group.Name != "ordinary" || len(group.PermissionIDs) != 0) {
						t.Fatalf("partial group update survived rollback: %#v", group)
					}
				}
			})
			t.Run("actor_is_reloaded_inside_transaction", func(t *testing.T) {
				f := newIdentityFixture(t, driver)
				f.apply(t, f.rootToken, storage.IdentityMutation{Kind: storage.IdentityUpdateGroup, ID: f.managerGroup.ID, GroupInput: domain.GroupInput{Name: "manager", PermissionIDs: []string{authz.PermResourcesRead}}})
				f.active(t, f.managerToken, false)
				mutation := storage.IdentityMutation{Kind: storage.IdentityDeleteUser, ID: f.ordinary.ID}
				if _, err := f.store.ApplyIdentityMutation(f.ctx, f.managerToken, mutation); !errors.Is(err, storage.ErrPermissionDenied) {
					t.Fatalf("revoked actor retained mutation access: %v", err)
				}
				token := f.session(t, f.manager, "no-longer-manager")
				if _, err := f.store.ApplyIdentityMutation(f.ctx, token, mutation); !errors.Is(err, storage.ErrPermissionDenied) {
					t.Fatalf("current permissions not checked: %v", err)
				}
			})
			t.Run("credential_check_and_session_issue_are_atomic", func(t *testing.T) {
				f := newIdentityFixture(t, driver)
				for i := 0; i < 8; i++ {
					user, err := f.store.FindUserByUsername(f.ctx, f.ordinary.Username)
					if err != nil {
						t.Fatal(err)
					}
					now := time.Now().UTC()
					session := domain.Session{ID: fmt.Sprintf("race-%d", i), UserID: user.ID, TokenHash: fmt.Sprintf("race-%d", i), CSRFHash: "csrf", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
					start := make(chan struct{})
					var wg sync.WaitGroup
					var issueErr, mutationErr error
					wg.Add(2)
					go func() {
						defer wg.Done()
						<-start
						issueErr = f.store.CreateAuthenticatedSession(f.ctx, session, user.PasswordHash, user.UpdatedAt, domain.SessionProfile{})
					}()
					go func() {
						defer wg.Done()
						<-start
						password := fmt.Sprintf("new hash %d", i)
						_, mutationErr = f.store.ApplyIdentityMutation(f.ctx, f.rootToken, storage.IdentityMutation{Kind: storage.IdentityUpdateUser, ID: user.ID, UserUpdate: domain.UserUpdate{PasswordHash: &password}})
					}()
					close(start)
					wg.Wait()
					if issueErr != nil && !errors.Is(issueErr, storage.ErrPermissionDenied) {
						t.Fatalf("issue session: %v", issueErr)
					}
					if mutationErr != nil {
						t.Fatal(mutationErr)
					}
					f.active(t, session.TokenHash, false)
					if err := f.store.CreateAuthenticatedSession(f.ctx, session, user.PasswordHash, user.UpdatedAt, domain.SessionProfile{}); !errors.Is(err, storage.ErrPermissionDenied) {
						t.Fatalf("stale credentials issued session after reset: %v", err)
					}
				}
			})
			t.Run("legacy_storage_changes_revoke_atomically", func(t *testing.T) {
				f := newIdentityFixture(t, driver)
				password := "new hash"
				if _, err := f.store.UpdateUser(f.ctx, f.ordinary.ID, domain.UserUpdate{PasswordHash: &password}); err != nil {
					t.Fatal(err)
				}
				f.active(t, f.ordinaryToken, false)
				token := f.session(t, f.ordinary, "legacy-group-update")
				if _, err := f.store.UpdateGroup(f.ctx, f.ordinaryGroup.ID, domain.GroupInput{Name: "ordinary"}); err != nil {
					t.Fatal(err)
				}
				f.active(t, token, false)
				token = f.session(t, f.ordinary, "legacy-group-delete")
				if err := f.store.DeleteGroup(f.ctx, f.ordinaryGroup.ID); err != nil {
					t.Fatal(err)
				}
				f.active(t, token, false)
			})
		})
	}
}
