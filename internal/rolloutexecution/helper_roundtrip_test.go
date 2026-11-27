//go:build linux

package rolloutexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"testing"

	"github.com/netwizd/agp/internal/helper"
	"github.com/netwizd/agp/internal/storage"
)

// An explicit controlled driver proves CP/helper wire agreement, not native
// reload, a qualified bundle, service health or a production capture baseline.
type roundtripDriver struct {
	active, base, target helper.ExecutionGeneration
	activations          int
}

func (d *roundtripDriver) Snapshot(context.Context) (helper.ExecutionGeneration, error) {
	return d.active, nil
}
func (d *roundtripDriver) Prepare(_ context.Context, r helper.Request, base helper.ExecutionGeneration) (helper.ExecutionGeneration, error) {
	if d.active != base {
		return helper.ExecutionGeneration{}, helper.ErrStale
	}
	d.base = base
	d.target = helper.ExecutionGeneration{Baseline: helper.Baseline{RevisionID: r.Task.Payload.TargetRevisionID, BundleDigest: r.Task.Payload.BundleDigest, NodeDeploymentSequence: r.Task.NodeDeploymentSequence}, GenerationID: r.Task.Payload.DeploymentGeneration, TreeDigest: digest("tree_" + r.Task.Payload.TargetRevisionID)}
	return d.target, nil
}
func (d *roundtripDriver) Validate(_ context.Context, g helper.ExecutionGeneration) error {
	if g != d.target {
		return helper.ErrStale
	}
	return nil
}
func (d *roundtripDriver) Activate(_ context.Context, base, target helper.ExecutionGeneration) error {
	if d.active != base || target != d.target {
		return helper.ErrStale
	}
	d.active = target
	d.activations++
	return nil
}
func (d *roundtripDriver) Reload(_ context.Context, target helper.ExecutionGeneration) error {
	if d.active != target {
		return helper.ErrStale
	}
	return nil
}
func (d *roundtripDriver) Verify(_ context.Context, g helper.ExecutionGeneration) error {
	if d.active != g {
		return helper.ErrStale
	}
	return nil
}
func (d *roundtripDriver) Recover(_ context.Context, target, base helper.ExecutionGeneration) error {
	if target != d.target || base != d.base {
		return helper.ErrStale
	}
	d.active = base
	return nil
}
func (d *roundtripDriver) Contain(context.Context) error { return nil }

type roundtripSources struct{ f *executionFixture }

func (s roundtripSources) Head(ctx context.Context, challenge string) ([]byte, error) {
	h, err := (fixtureAuthority{}).Head(ctx)
	if err != nil {
		return nil, err
	}
	h.Challenge = challenge
	h.KeyID = s.f.trust.JournalKeyID
	h.Signature = sign(h, "AGP-JOURNAL-HEAD-v1", s.f.journalKey)
	return canonical(h)
}
func (s roundtripSources) Authorize(ctx context.Context, q helper.StartQuery) ([]byte, error) {
	p, err := s.f.service.AuthorizeStartPeer(ctx, s.f.peer, q)
	if err != nil {
		return nil, err
	}
	return canonical(p)
}

func TestExecutionHelperRoundtripSQLite(t *testing.T)   { testExecutionHelperRoundtrip(t, false) }
func TestExecutionHelperRoundtripPostgres(t *testing.T) { testExecutionHelperRoundtrip(t, true) }
func testExecutionHelperRoundtrip(t *testing.T, pg bool) {
	f := newExecutionFixture(t, pg)
	p := f.approved(t, "roundtrip_create_0001")
	request := f.dispatched(t, p)
	var base helper.ExecutionGeneration
	if err := f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		var err error
		base, err = f.sources.baseline(f.ctx, tx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	driver := &roundtripDriver{active: base}
	dir, err := os.MkdirTemp("/tmp", "agp-cp-helper-roundtrip-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	anchor := helper.ExecutionAnchor{APIVersion: helper.ExecutionAnchorVersion, Installation: f.sources.installation, LayoutDigest: f.sources.installation.OwnershipDigest, ReceiptKeyID: "receipt_key", ReceiptPublicKey: base64.RawURLEncoding.EncodeToString(f.sources.receiptKey.Public().(ed25519.PublicKey))}
	ledger, err := helper.CreateExecutionStore(f.ctx, dir, anchor, driver)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ledger.Close(); err != nil {
			t.Error(err)
		}
	})
	executor, err := helper.NewExecutor(ledger, f.trust, roundtripSources{f}, driver, f.sources.receiptKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := canonical(request)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := executor.Execute(f.ctx, bytes.NewReader(raw))
	if err != nil || receipt == nil || receipt.State != "succeeded" {
		t.Fatalf("CP request rejected by real helper engine: %#v %v", receipt, err)
	}
	if err = f.service.RecordReceiptPeer(f.ctx, f.peer, *receipt); err != nil {
		t.Fatal(err)
	}
	replayed, err := executor.Execute(f.ctx, bytes.NewReader(raw))
	if err != nil || digest(replayed) != digest(receipt) || driver.activations != 1 {
		t.Fatalf("terminal replay repeated effect: calls=%d err=%v", driver.activations, err)
	}
	if err = f.service.RecordReceiptPeer(f.ctx, f.peer, *replayed); err != nil {
		t.Fatal(err)
	}
	if f.count(t, `SELECT accepted_sequence FROM execution_node_counters WHERE node_id='node_one'`) != 8 || f.count(t, `SELECT COUNT(*) FROM execution_receipts`) != 1 {
		t.Fatal("signed helper outcome did not project exactly once")
	}
}
