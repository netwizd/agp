package identity

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

type oidcAtomicClock struct {
	securityjournal.Authority
	now atomic.Int64
}

func (j *oidcAtomicClock) Head(ctx context.Context) (securityjournal.Head, error) {
	h, e := j.Authority.Head(ctx)
	h.RecordedAt = time.Unix(j.now.Load(), 0).UTC()
	return h, e
}
func TestOIDCFinalTimeSQLite(t *testing.T)   { testOIDCFinalTime(t, false) }
func TestOIDCFinalTimePostgres(t *testing.T) { testOIDCFinalTime(t, true) }
func testOIDCFinalTime(t *testing.T, pg bool) {
	t.Run("purpose_AAD_and_final_expiry", func(t *testing.T) {
		f := newOIDCFixture(t, pg)
		f.activateOIDC(t)
		f.linkOIDC(t)
		now := time.Now().UTC().Truncate(time.Second)
		f.clock(now)
		clock := &oidcAtomicClock{Authority: f.j}
		clock.now.Store(now.Unix())
		f.s.Coordinator.Authority = clock
		a := f.startDirectory(t, "login")
		state, code := f.beginOIDC(t, a)
		var record *oidcAuthorization
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			var e error
			record, e = readOIDCAuthorization(f.ctx, tx, state)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if record.Purpose != "login" {
			t.Fatal("purpose absent")
		}
		altered := *record
		altered.Purpose = "step_up"
		if _, e := f.oidc.stateKeys.ring.Open(record.Sealed, oidcAuthorizationAAD(altered)); e == nil {
			t.Fatal("ciphertext reused across purpose")
		}
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE identity_flows SET purpose='step_up' WHERE id=?`, a.ID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if _, e := f.oidc.Callback(f.ctx, a, f.p.ID, state, code, "", ""); !errors.Is(e, ErrProof) {
			t.Fatal("changed flow purpose accepted", e)
		}
		if f.tokenCalls.Load() != 0 {
			t.Fatal("changed purpose sent code")
		}
		if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			_, e := tx.Exec(f.ctx, `UPDATE identity_flows SET purpose='login' WHERE id=?`, a.ID)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		f.setOIDCMode("short_expiry")
		f.mu.Lock()
		f.tokenHook = func() error { clock.now.Store(now.Add(7 * time.Second).Unix()); return nil }
		f.mu.Unlock()
		if _, e := f.oidc.Callback(f.ctx, a, f.p.ID, state, code, "", ""); !errors.Is(e, ErrProof) {
			t.Fatal("token expired between exchange and final projection", e)
		}
		if f.tokenCalls.Load() != 1 {
			t.Fatal("expired exchange retried")
		}
	})
}
