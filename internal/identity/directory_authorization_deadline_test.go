package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

func TestDirectoryAuthorizationDeadlineSQLite(t *testing.T) { directoryAuthorizationDeadline(t, false) }
func TestDirectoryAuthorizationDeadlinePostgres(t *testing.T) {
	directoryAuthorizationDeadline(t, true)
}

func directoryAuthorizationDeadline(t *testing.T, pg bool) {
	f := newDirectoryAuthFixture(t, pg, false)
	link := f.provision(t)
	if err := f.s.Coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		if deadline, err := DirectorySubjectProofDeadline(f.ctx, tx, h, f.user.ID); err != nil || !deadline.IsZero() {
			t.Fatalf("local subject acquired a directory deadline: %v %v", deadline, err)
		}
		if _, err := DirectorySubjectProofDeadline(f.ctx, tx, h, link.PrincipalID); !errors.Is(err, ErrDirectoryUnavailable) {
			t.Fatalf("missing private proof supplied a deadline: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	beforeBinds := f.wire.serviceBinds.Load()
	err := f.directory.WithCurrentSubjects(f.ctx, []string{link.PrincipalID}, func(ctx context.Context) error {
		return f.s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
			deadline, err := DirectorySubjectProofDeadline(ctx, tx, h, link.PrincipalID)
			if err != nil || deadline.IsZero() || !deadline.After(h.RecordedAt) || deadline.After(h.RecordedAt.Add(10*time.Second)) {
				t.Fatalf("live TLS LDAP evidence has invalid deadline: %v %v", deadline, err)
			}
			for _, when := range []time.Time{deadline, deadline.Add(time.Nanosecond), deadline.Add(-20 * time.Second)} {
				changed := h
				changed.RecordedAt = when
				if _, err := DirectorySubjectProofDeadline(ctx, tx, changed, link.PrincipalID); !errors.Is(err, ErrDirectoryUnavailable) {
					t.Fatalf("expired/future observation retained authority at %v: %v", when, err)
				}
			}
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.wire.serviceBinds.Load() <= beforeBinds {
		t.Fatal("actual TLS LDAP observation was not exercised")
	}
}
