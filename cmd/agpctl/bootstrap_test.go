package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/config"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/runtime"
	"github.com/netwizd/agp/internal/storage"
)

func TestCreateAdminBootstrap(t *testing.T) {
	for _, driver := range []string{"sqlite", "postgres"} {
		t.Run(driver, func(t *testing.T) {
			ctx, store := bootstrapTestStore(t, driver)
			if err := runCreateAdmin(t, "initial-password", "-username", " Admin "); err != nil {
				t.Fatalf("bootstrap empty database: %v", err)
			}
			user, err := store.FindUserByUsername(ctx, "admin")
			if err != nil || !user.IsAdmin {
				t.Fatalf("bootstrap administrator/membership: user=%+v err=%v", user, err)
			}
			valid, err := auth.VerifyPassword("initial-password", user.PasswordHash)
			if err != nil || !valid {
				t.Fatalf("bootstrap password: valid=%v err=%v", valid, err)
			}
			groups, err := store.ListGroups(ctx)
			if err != nil || len(groups) != 1 {
				t.Fatalf("bootstrap groups: groups=%+v err=%v", groups, err)
			}
			users, err := store.ListUsers(ctx)
			if err != nil || len(users) != 1 || !slices.Equal(users[0].GroupIDs, []string{groups[0].ID}) {
				t.Fatalf("bootstrap membership: users=%+v err=%v", users, err)
			}
			requireBootstrapPermissions(t, groups[0].PermissionIDs)
			if err := runCreateAdmin(t, "replacement-password", "-username", "admin"); err == nil || !strings.Contains(err.Error(), "already exists") {
				t.Fatalf("duplicate bootstrap must fail without resetting credentials: %v", err)
			}
			after, err := store.FindUserByUsername(ctx, "admin")
			if err != nil || after.ID != user.ID || after.PasswordHash != user.PasswordHash {
				t.Fatalf("duplicate bootstrap changed existing administrator: %v", err)
			}
			if err := store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
				_, err := tx.Exec(ctx, `INSERT INTO security_state(id,authority_id,epoch,sequence,digest,enabled) VALUES(1,'bootstrap-test',1,0,'digest',true)`)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := runCreateAdmin(t, "new-password", "-username", "second", "-group-name", "Forbidden"); err == nil || !strings.Contains(err.Error(), "forbidden after secure activation") {
				t.Fatalf("secure activation must permanently close bootstrap: %v", err)
			}
			if _, err := store.FindUserByUsername(ctx, "second"); !errors.Is(err, storage.ErrNotFound) {
				t.Fatalf("closed bootstrap created a user: %v", err)
			}
			groups, err = store.ListGroups(ctx)
			if err != nil || len(groups) != 1 {
				t.Fatalf("closed bootstrap changed group graph: groups=%+v err=%v", groups, err)
			}
		})
	}
}

func TestExecutionPermissionCatalogUpgrade(t *testing.T) {
	for _, driver := range []string{"sqlite", "postgres"} {
		t.Run(driver, func(t *testing.T) {
			ctx, store := bootstrapTestStore(t, driver)
			group, err := store.CreateGroup(ctx, domain.GroupInput{Name: "Existing", PermissionIDs: []string{authz.PermDashboardRead}})
			if err != nil {
				t.Fatal(err)
			}
			// Reconstruct an installed 036 catalog, including a locally registered
			// identifier. Migration must fill missing identifiers without grants.
			if err := store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
				for _, query := range []string{
					`DELETE FROM schema_migrations WHERE version='037_execution_permissions.sql'`,
					`DELETE FROM permissions WHERE id IN ('rollouts.create','rollouts.cancel','rollouts.rollback')`,
					`INSERT INTO permissions(id,description) VALUES('rollouts.create','Existing description')`,
				} {
					if _, err := tx.Exec(ctx, query); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := store.Migrate(ctx); err != nil {
					t.Fatalf("upgrade/repeated migration: %v", err)
				}
			}
			groups, err := store.ListGroups(ctx)
			if err != nil || len(groups) != 1 || groups[0].ID != group.ID || !slices.Equal(groups[0].PermissionIDs, []string{authz.PermDashboardRead}) {
				t.Fatalf("catalog migration must not grant permissions: groups=%+v err=%v", groups, err)
			}
			permissions := append(authz.AllPermissions(), " rollouts.create ", authz.PermRolloutsCancel, "")
			all, err := store.CreateGroup(ctx, domain.GroupInput{Name: "All", PermissionIDs: permissions})
			if err != nil {
				t.Fatalf("complete catalog with duplicate identifiers: %v", err)
			}
			requireBootstrapPermissions(t, all.PermissionIDs)
			if _, err := store.CreateGroup(ctx, domain.GroupInput{Name: "Unknown", PermissionIDs: []string{"unknown.permission"}}); !errors.Is(err, storage.ErrConflict) {
				t.Fatalf("unknown identifiers must still fail closed: %v", err)
			}
			groups, err = store.ListGroups(ctx)
			if err != nil || len(groups) != 2 {
				t.Fatalf("invalid permission must roll back the new group: groups=%+v err=%v", groups, err)
			}
		})
	}
}

func requireBootstrapPermissions(t *testing.T, got []string) {
	t.Helper()
	want := authz.AllPermissions()
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("bootstrap permission catalog: got=%v want=%v", got, want)
	}
}

func runCreateAdmin(t *testing.T, password string, args ...string) error {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteString(password + "\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	previous := os.Stdin
	os.Stdin = file
	defer func() { os.Stdin = previous }()
	return createAdmin(args)
}

func bootstrapTestStore(t *testing.T, driver string) (context.Context, storage.Store) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	t.Setenv("AGP_SECURE_PROFILE", "false")
	t.Setenv("AGP_CONFIGURATION_ENABLED", "false")
	t.Setenv("AGP_EMAIL_CONFIG_FILE", "")
	t.Setenv("AGP_OIDC_CONNECTOR_FILE", "")
	t.Setenv("AGP_DATABASE_DRIVER", driver)
	t.Setenv("AGP_DATABASE_PATH", filepath.Join(t.TempDir(), "bootstrap.db"))
	if driver == "postgres" {
		dsn := os.Getenv("AGP_TEST_POSTGRES_DSN")
		if dsn == "" {
			t.Skip("AGP_TEST_POSTGRES_DSN is not set")
		}
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		schema := fmt.Sprintf("agp_bootstrap_%d", time.Now().UnixNano())
		if _, err := pool.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if _, err := pool.Exec(cleanup, `DROP SCHEMA `+schema+` CASCADE`); err != nil {
				t.Errorf("drop bootstrap test schema: %v", err)
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
		t.Setenv("AGP_DATABASE_DSN", dsn)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	store, err := runtime.OpenStore(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return ctx, store
}
