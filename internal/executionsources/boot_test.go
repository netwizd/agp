package executionsources

import (
	"context"
	"testing"

	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/storage"
)

func TestSourceBootFenceSQLite(t *testing.T)   { testSourceBootFence(t, false) }
func TestSourceBootFencePostgres(t *testing.T) { testSourceBootFence(t, true) }
func testSourceBootFence(t *testing.T, pg bool) {
	f := newFixture(t, pg)
	ctx := context.Background()
	if _, e := f.capture(f.baseline, 1, 0); e != nil {
		t.Fatal(e)
	}
	f.qualify()
	snapshot, e := f.resolve()
	if e != nil {
		t.Fatal(e)
	}
	materialSignature := f.cfg.Materials[0].Attestation.Signature
	f.observation.BootID = "55555555-1111-2222-3333-444444444444"
	ch, e := f.service.inventory.Challenge(ctx, f.peer)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.service.inventory.Submit(ctx, f.peer, inventory.Submission{RequestID: "inventory_reboot_00001", ChallengeID: ch.ID, Challenge: ch.Challenge, Observation: f.observation}); e != nil {
		t.Fatal(e)
	}
	if _, e = f.resolve(); e == nil {
		t.Fatal("old boot capture authorized new boot")
	}
	if e = f.tx(func(tx storage.IdentityTx) error {
		return f.service.Recheck(ctx, tx, f.current.head, snapshot.Targets[0])
	}); e == nil {
		t.Fatal("old plan survived a reboot without root verification")
	}
	if _, e = f.capture(f.baseline, 1, 0); e != nil {
		t.Fatal("new boot healthy root capture", e)
	}
	after, e := f.resolve()
	if e != nil {
		t.Fatal("same materialization required requalification after healthy reboot", e)
	}
	if f.cfg.Materials[0].Attestation.Signature != materialSignature || after.Targets[0].SourceDigest == snapshot.Targets[0].SourceDigest {
		t.Fatal("runtime boot fence mixed with immutable bundle qualification")
	}
}
