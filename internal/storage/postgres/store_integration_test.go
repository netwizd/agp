package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/netwizd/agp/internal/domain"
)

func TestStoreIntegration(t *testing.T) {
	dsn := os.Getenv("AGP_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("AGP_TEST_POSTGRES_DSN is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	schema := "agp_it_" + randomHex(t)
	adminPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open admin pool: %v", err)
	}
	defer adminPool.Close()
	if _, err := adminPool.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		dropCtx, dropCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer dropCancel()
		_, _ = adminPool.Exec(dropCtx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	})

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open schema pool: %v", err)
	}
	store := &Store{pool: pool}
	defer func() { _ = store.Close() }()

	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	group, err := store.CreateGroup(ctx, domain.GroupInput{Name: "Administrators"})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	user, err := store.CreateUser(ctx, domain.UserInput{
		Username:     "admin",
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$M2hhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g",
		DisplayName:  "Administrator",
		IsAdmin:      true,
		GroupIDs:     []string{group.ID},
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	resource, err := store.CreateResource(ctx, domain.ResourceInput{
		Name:        "Wiki",
		InternalURL: "http://wiki.internal",
		PublicHost:  "wiki.company.ru",
		Enabled:     true,
		GroupIDs:    []string{group.ID},
		AllowCIDRs:  []string{"10.50.0.0/16"},
	})
	if err != nil {
		t.Fatalf("create resource: %v", err)
	}
	allowed, err := store.UserHasResourceAccess(ctx, user.ID, resource.ID)
	if err != nil {
		t.Fatalf("check access: %v", err)
	}
	if !allowed {
		t.Fatal("expected user to have resource access")
	}
	if err := store.AppendAudit(ctx, domain.AuditEvent{
		Type:          "test.event",
		SubjectUserID: user.ID,
		Username:      user.Username,
		Outcome:       "success",
	}); err != nil {
		t.Fatalf("append audit: %v", err)
	}
	events, err := store.ListAuditEvents(ctx, domain.AuditFilter{Limit: 10})
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 1 || events[0].Type != "test.event" {
		t.Fatalf("unexpected audit events: %#v", events)
	}
}

func randomHex(t *testing.T) string {
	t.Helper()
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatalf("read random: %v", err)
	}
	return hex.EncodeToString(buf[:])
}
