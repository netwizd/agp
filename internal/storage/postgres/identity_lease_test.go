package postgres

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/netwizd/agp/internal/storage"
)

func TestIdentityLeasePostgres(t *testing.T) {
	dsn := os.Getenv("AGP_TEST_IDENTITY_DSN")
	if dsn == "" {
		dsn = os.Getenv("AGP_TEST_POSTGRES_DSN")
	}
	if dsn == "" {
		t.Skip("AGP_TEST_IDENTITY_DSN / AGP_TEST_POSTGRES_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "lease_" + randomHex(t)
	if _, err = admin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
	u, err := url.Parse(dsn)
	if err == nil && u.Scheme != "" {
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		dsn = u.String()
	} else {
		dsn += " search_path=" + schema
	}
	first, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if err = first.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	second, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	release, err := first.AcquireIdentityLease(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if other, e := second.AcquireIdentityLease(ctx); e == nil {
		other()
		t.Fatal("second writer acquired held lease")
	}
	var pid int
	if err = first.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		rows, e := tx.Query(ctx, `SELECT pg_backend_pid()`)
		if e != nil {
			return e
		}
		defer rows.Close()
		if !rows.Next() {
			return rows.Err()
		}
		return rows.Scan(&pid)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.Exec(ctx, `SELECT pg_terminate_backend($1)`, pid); err != nil {
		t.Fatal(err)
	}
	if err = first.WriteIdentity(ctx, func(storage.IdentityTx) error { return nil }); err == nil {
		t.Fatal("lost lease fell back to pool")
	}
	var releaseSecond func()
	for attempts := 0; attempts < 50; attempts++ {
		releaseSecond, err = second.AcquireIdentityLease(ctx)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("new writer could not acquire released database lock: %v", err)
	}
	releaseSecond()
	if err = second.WriteIdentity(ctx, func(storage.IdentityTx) error { return nil }); err == nil {
		t.Fatal("released writer fell back to pool")
	}
}
