//go:build linux

package helper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
)

func baselineQuery(t *testing.T, f *admissionFixture, s *ExecutionStore) BaselineChallenge {
	t.Helper()
	value, err := challenge()
	if err != nil {
		t.Fatal(err)
	}
	return BaselineChallenge{APIVersion: BaselineChallengeVersion, ID: "baseline-challenge-a", Challenge: value, NodeID: f.i.NodeID, AnchorDigest: s.digest, AuthorityID: f.i.AuthorityID, AuthorityEpoch: f.sources.epoch, IssuedAt: f.sources.now.Add(-time.Second).Format(time.RFC3339Nano), ExpiresAt: f.sources.now.Add(time.Minute).Format(time.RFC3339Nano)}
}

func TestBaselineCaptureSignsActualServingStateAndPersistsOnlySecurityFloors(t *testing.T) {
	f, s, e, d, dir := executionFixture(t)
	q := baselineQuery(t, f, s)
	before, err := s.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c, err := e.CaptureBaseline(context.Background(), q)
	if err != nil || c == nil {
		t.Fatal(c, err)
	}
	key := executionTestKey().Public().(ed25519.PublicKey)
	if err = VerifyBaselineCapture(*c, s.anchor.ReceiptKeyID, key); err != nil {
		t.Fatal(err)
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || c.BootDigest != configmodel.DigestBytes([]byte(strings.TrimSpace(string(boot)))) {
		t.Fatal("capture did not bind actual OS boot", err)
	}
	if c.Query != q || c.Active != before.Active || c.HighWater != before.HighWater || c.ReceiptSequence != 0 || c.MinimumDenySequence != f.sources.sequence || f.sources.heads != 3 || f.sources.starts != 0 {
		t.Fatalf("incomplete baseline capture: %+v heads=%d starts=%d", c, f.sources.heads, f.sources.starts)
	}
	for _, name := range []string{"prepare", "validate", "activate", "reload", "recover", "contain"} {
		if d.calls[name] != 0 {
			t.Fatalf("read-only capture performed %s", name)
		}
	}
	after, err := s.Status(context.Background())
	if err != nil || after.Active != before.Active || after.LastHealthy != before.LastHealthy || after.HighWater != before.HighWater || after.ReceiptSequence != before.ReceiptSequence || after.Attempt != nil || len(after.Records) != 0 || after.MinimumDenySequence != f.sources.sequence {
		t.Fatal("capture changed execution state or failed to persist floor", after, err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenExecutionStore(dir, s.anchor)
	if err != nil {
		t.Fatal("raised floor cannot reopen", err)
	}
	defer reopened.Close()
	persisted, err := reopened.Status(context.Background())
	if err != nil || persisted == nil || persisted.MinimumDenySequence != after.MinimumDenySequence {
		t.Fatal("raised floor lost after reopen", persisted, err)
	}
	// Historical signature verification has no hidden dependency on today's TTL.
	f.sources.now = f.sources.now.Add(24 * time.Hour)
	if err = VerifyBaselineCapture(*c, s.anchor.ReceiptKeyID, key); err != nil {
		t.Fatal("historical receipt rejected", err)
	}
}

func TestBaselineCaptureSignaturePurposeShapeAndBoundFields(t *testing.T) {
	f, s, e, _, _ := executionFixture(t)
	c, err := e.CaptureBaseline(context.Background(), baselineQuery(t, f, s))
	if err != nil {
		t.Fatal(err)
	}
	key := executionTestKey().Public().(ed25519.PublicKey)
	for name, change := range map[string]func(*BaselineCapture){
		"wrong purpose": func(x *BaselineCapture) { x.Purpose = "local_execution_outcome" },
		"wrong node":    func(x *BaselineCapture) { x.Query.NodeID = "foreign-node" },
		"wrong anchor":  func(x *BaselineCapture) { x.Query.AnchorDigest = testDigest("other") },
		"wrong key":     func(x *BaselineCapture) { x.KeyID = "foreign-key" },
		"wrong tree":    func(x *BaselineCapture) { x.Active.TreeDigest = testDigest("other") },
		"wrong nonce": func(x *BaselineCapture) {
			x.Query.Challenge = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
		},
		"wrong boot":            func(x *BaselineCapture) { x.BootDigest = testDigest("foreign-boot") },
		"wrong head":            func(x *BaselineCapture) { x.Head.Digest = testDigest("foreign-head") },
		"counter overflow":      func(x *BaselineCapture) { x.HighWater = UInt63(1) << 63 },
		"recorded after expiry": func(x *BaselineCapture) { x.RecordedAt = x.Query.ExpiresAt },
	} {
		t.Run(name, func(t *testing.T) {
			x := *c
			change(&x)
			if VerifyBaselineCapture(x, s.anchor.ReceiptKeyID, key) == nil {
				t.Fatal("tampered capture accepted")
			}
		})
	}
	x := *c
	x.Signature = ""
	x.Signature = testSign(t, x, "AGP-HELPER-EXECUTION-RECEIPT-v1", executionTestKey())
	if VerifyBaselineCapture(x, s.anchor.ReceiptKeyID, key) == nil {
		t.Fatal("receipt signature crossed purpose boundary")
	}
	x = *c
	x.Purpose = "local_execution_outcome"
	x.Signature = ""
	x.Signature = testSign(t, x, baselineCaptureDomain, executionTestKey())
	if VerifyBaselineCapture(x, s.anchor.ReceiptKeyID, key) == nil {
		t.Fatal("wrong-purpose signed payload accepted")
	}
}

func TestBaselineCaptureRejectsWrongOrExpiredChallengeBeforeObservation(t *testing.T) {
	for name, change := range map[string]func(*BaselineChallenge, time.Time){
		"wrong node":      func(q *BaselineChallenge, _ time.Time) { q.NodeID = "foreign-node" },
		"wrong anchor":    func(q *BaselineChallenge, _ time.Time) { q.AnchorDigest = testDigest("other") },
		"wrong authority": func(q *BaselineChallenge, _ time.Time) { q.AuthorityID = "foreign-journal" },
		"wrong version":   func(q *BaselineChallenge, _ time.Time) { q.APIVersion = "future" },
		"bad nonce":       func(q *BaselineChallenge, _ time.Time) { q.Challenge = "caller-boolean" },
		"future issued":   func(q *BaselineChallenge, now time.Time) { q.IssuedAt = now.Add(time.Second).Format(time.RFC3339Nano) },
		"expired":         func(q *BaselineChallenge, now time.Time) { q.ExpiresAt = now.Format(time.RFC3339Nano) },
		"excessive ttl": func(q *BaselineChallenge, now time.Time) {
			q.ExpiresAt = now.Add(MaxBaselineChallengeTTL).Format(time.RFC3339Nano)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, s, e, d, _ := executionFixture(t)
			q := baselineQuery(t, f, s)
			change(&q, f.sources.now)
			before := d.calls["snapshot"]
			if c, err := e.CaptureBaseline(context.Background(), q); c != nil || err == nil || f.sources.heads != 0 || d.calls["snapshot"] != before {
				t.Fatal("invalid query observed/signed", c, err)
			}
		})
	}
}

func TestBaselineCaptureRejectsDriftRevokeOfflineAndLateDurability(t *testing.T) {
	for _, kind := range []string{"unhealthy", "drift", "revoke", "offline", "epoch", "late expiry", "fsync revoke", "fsync drift", "fsync expiry", "fsync failure"} {
		t.Run(kind, func(t *testing.T) {
			f, s, e, d, _ := executionFixture(t)
			q := baselineQuery(t, f, s)
			snapshots := 0
			switch kind {
			case "unhealthy":
				d.healthy[d.pointer.GenerationID] = false
			case "drift":
				d.hook = func(name string) error {
					if name == "snapshot" {
						snapshots++
						if snapshots == 2 {
							d.pointer.GenerationID = "foreign-generation"
							d.runtime = d.pointer
						}
					}
					return nil
				}
			case "revoke":
				f.sources.headHook = func(h *securityjournal.Head, n int) {
					if n == 2 {
						h.Sequence++
						h.Digest = testDigest("new-deny")
					}
				}
			case "offline":
				f.sources.offline = true
			case "epoch":
				q.AuthorityEpoch++
			case "late expiry":
				d.hook = func(name string) error {
					if name == "verify" {
						f.sources.now, _ = utc(q.ExpiresAt)
					}
					return nil
				}
			default:
				s.fault = func(point string) error {
					if point != "directory_sync" {
						return nil
					}
					switch kind {
					case "fsync revoke":
						f.sources.sequence++
					case "fsync drift":
						d.pointer.GenerationID = "foreign-generation"
						d.runtime = d.pointer
					case "fsync expiry":
						f.sources.now, _ = utc(q.ExpiresAt)
					case "fsync failure":
						return errors.New("disk unavailable")
					}
					return nil
				}
			}
			if c, err := e.CaptureBaseline(context.Background(), q); c != nil || err == nil {
				t.Fatal("unsafe baseline signed", c, err)
			}
			if d.calls["activate"] != 0 || d.calls["recover"] != 0 || d.calls["contain"] != 0 || f.sources.starts != 0 {
				t.Fatal("rejected capture performed an effect", d.calls)
			}
		})
	}
}

func TestBaselineCaptureRequiresNoPendingRecoveryAndRetainsFailedHighWater(t *testing.T) {
	f, s, e, d, _ := executionFixture(t)
	d.hook = func(name string) error {
		if name == "activated" {
			d.pointer.GenerationID = "unknown-third"
			d.runtime = d.pointer
			return errors.New("unknown switch")
		}
		return nil
	}
	if c, err := e.Execute(context.Background(), bytes.NewReader(testBytes(t, f.r))); c != nil || !errors.Is(err, ErrPending) {
		t.Fatal(c, err)
	}
	before := f.sources.heads
	if c, err := e.CaptureBaseline(context.Background(), baselineQuery(t, f, s)); c != nil || !errors.Is(err, ErrPending) || f.sources.heads != before {
		t.Fatal("unresolved attempt captured as healthy", c, err)
	}
	d.hook = nil
	d.pointer, d.runtime = d.base, d.base
	if _, err := e.RecoverPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	c, err := e.CaptureBaseline(context.Background(), baselineQuery(t, f, s))
	if err != nil || c == nil || c.HighWater != 8 || c.Active.Baseline.NodeDeploymentSequence != 7 || c.ReceiptSequence != 1 {
		t.Fatal("capture erased failed accepted sequence", c, err)
	}
}

func TestBaselineCapturePersistsNewAuthorityEpochAndRejectsOldFloor(t *testing.T) {
	f, s, e, _, dir := executionFixture(t)
	f.sources.epoch = 2
	c, err := e.CaptureBaseline(context.Background(), baselineQuery(t, f, s))
	if err != nil || c == nil || c.AuthorityEpoch != 2 {
		t.Fatal(c, err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenExecutionStore(dir, s.anchor)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	e.store = reopened
	f.sources.epoch = 1
	if c, err = e.CaptureBaseline(context.Background(), baselineQuery(t, f, reopened)); c != nil || err == nil {
		t.Fatal("old authority epoch passed persisted floor", c, err)
	}
}
