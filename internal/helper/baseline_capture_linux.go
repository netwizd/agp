//go:build linux

package helper

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"golang.org/x/sys/unix"
)

const (
	BaselineChallengeVersion = "agp.helper-baseline-challenge/v1alpha1"
	BaselineCaptureVersion   = "agp.helper-baseline-capture/v1alpha1"
	MaxBaselineChallengeTTL  = 2 * time.Minute
	baselineCapturePurpose   = "verified_baseline_capture"
	baselineCaptureDomain    = "AGP-HELPER-BASELINE-CAPTURE-v1"
)

// BaselineChallenge is the control plane's bounded single-use request. The
// transport authenticates its issuer; the helper independently checks its
// installation, authority and the actual local serving generation.
type BaselineChallenge struct {
	APIVersion     string `json:"apiVersion"`
	ID             string `json:"id"`
	Challenge      string `json:"challenge"`
	NodeID         string `json:"nodeId"`
	AnchorDigest   string `json:"anchorDigest"`
	AuthorityID    string `json:"authorityId"`
	AuthorityEpoch UInt63 `json:"authorityEpoch"`
	IssuedAt       string `json:"issuedAt"`
	ExpiresAt      string `json:"expiresAt"`
}

// BaselineCapture is a root receipt of a read-only, verified serving baseline.
// It cannot initialize a ledger, admit work, qualify a bundle or prove future
// health. The receiver must bind it to its unused challenge and current source
// state; verification of its signature alone is not that admission decision.
type BaselineCapture struct {
	APIVersion          string              `json:"apiVersion"`
	Purpose             string              `json:"purpose"`
	Query               BaselineChallenge   `json:"query"`
	Active              ExecutionGeneration `json:"active"`
	HighWater           UInt63              `json:"highWater"`
	ReceiptSequence     UInt63              `json:"receiptSequence"`
	AuthorityEpoch      UInt63              `json:"authorityEpoch"`
	WriterEpoch         UInt63              `json:"writerEpoch"`
	MinimumDenySequence UInt63              `json:"minimumDenySequence"`
	Head                HeadPin             `json:"head"`
	BootDigest          string              `json:"bootDigest"`
	RecordedAt          string              `json:"recordedAt"`
	KeyID               string              `json:"keyId"`
	Signature           string              `json:"signature"`
}

func baselineChallengeWindow(q BaselineChallenge) (time.Time, time.Time, error) {
	issued, ie := utc(q.IssuedAt)
	expires, ee := utc(q.ExpiresAt)
	value, ce := base64.RawURLEncoding.DecodeString(q.Challenge)
	if q.APIVersion != BaselineChallengeVersion || !configmodel.ValidID(q.ID) || !configmodel.ValidID(q.NodeID) || !configmodel.ValidID(q.AuthorityID) || !configmodel.ValidDigest(q.AnchorDigest) || q.AuthorityEpoch == 0 || !validCounters(q.AuthorityEpoch) || ce != nil || len(value) != 32 || base64.RawURLEncoding.EncodeToString(value) != q.Challenge || ie != nil || ee != nil || !expires.After(issued) || expires.Sub(issued) > MaxBaselineChallengeTTL {
		return time.Time{}, time.Time{}, ErrInvalid
	}
	return issued, expires, nil
}

// VerifyBaselineCapture authenticates a historical signed observation without
// imposing today's TTL. Consumers must separately check their live challenge's
// identity, expiry, uniqueness, boot and all current authorization/source pins.
func VerifyBaselineCapture(c BaselineCapture, keyID string, key ed25519.PublicKey) error {
	issued, expires, err := baselineChallengeWindow(c.Query)
	recorded, recordedErr := utc(c.RecordedAt)
	if err != nil || recordedErr != nil || recorded.Before(issued) || !recorded.Before(expires) || c.APIVersion != BaselineCaptureVersion || c.Purpose != baselineCapturePurpose || !configmodel.ValidID(keyID) || c.KeyID != keyID || validateGeneration(c.Active) != nil || !configmodel.ValidDigest(c.BootDigest) || c.Active.Baseline.NodeDeploymentSequence > c.HighWater || c.ReceiptSequence > c.HighWater || c.AuthorityEpoch != c.Query.AuthorityEpoch || c.AuthorityEpoch == 0 || c.WriterEpoch == 0 || !validCounters(c.HighWater, c.ReceiptSequence, c.AuthorityEpoch, c.WriterEpoch, c.MinimumDenySequence, c.Head.Sequence) || c.Head.AuthorityID != c.Query.AuthorityID || c.Head.Epoch != c.AuthorityEpoch || c.Head.Sequence != c.MinimumDenySequence || (c.Head.Sequence == 0) != (c.Head.Digest == "") || c.Head.Sequence > 0 && !configmodel.ValidDigest(c.Head.Digest) {
		return ErrUnauthorized
	}
	signature := c.Signature
	c.Signature = ""
	if !verifySignature(c, signature, baselineCaptureDomain, key) {
		return ErrUnauthorized
	}
	return nil
}

var baselineBootPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\n$`)

// baselineBootDigest reads the fixed kernel source, never a path or boolean
// chosen by an agent/task. The digest matches inventory's canonical boot UUID.
func baselineBootDigest() (string, error) {
	fd, err := unix.Open("/proc/sys/kernel/random/boot_id", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", ErrOwnedTree
	}
	f := os.NewFile(uintptr(fd), "kernel-boot-id")
	defer f.Close()
	var st unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(fd, &st) != nil || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC || st.Uid != 0 || st.Mode != unix.S_IFREG|0444 {
		return "", ErrOwnedTree
	}
	boot, err := io.ReadAll(io.LimitReader(f, 128))
	if err != nil || !baselineBootPattern.Match(boot) {
		return "", ErrOwnedTree
	}
	return configmodel.DigestBytes([]byte(strings.TrimSuffix(string(boot), "\n"))), nil
}

func (e *Executor) captureLive(ctx context.Context, q BaselineChallenge, issued, expires time.Time) error {
	if ctx.Err() != nil || e.now().UTC().Before(issued) || !e.now().UTC().Before(expires) || q.NodeID != e.store.anchor.Installation.NodeID || q.AnchorDigest != e.store.digest || q.AuthorityID != e.store.anchor.Installation.AuthorityID {
		return ErrUnauthorized
	}
	return nil
}

func captureHeadMatches(h securityjournal.Head, q BaselineChallenge, s ExecutionState) bool {
	return h.AuthorityID == q.AuthorityID && h.Epoch == q.AuthorityEpoch && h.Epoch >= s.AuthorityEpoch && h.Sequence >= s.MinimumDenySequence
}

// CaptureBaseline signs only an existing healthy execution ledger. The complete
// serving tree/runtime check is bracketed by independently challenged journal
// heads. Any raised deny/authority floor is durable before the final live fence.
// No deployment sequence, receipt counter, task or runtime effect is created.
func (e *Executor) CaptureBaseline(ctx context.Context, q BaselineChallenge) (*BaselineCapture, error) {
	if e == nil || e.store == nil || e.gate == nil || e.driver == nil || e.now == nil || ctx == nil {
		return nil, ErrState
	}
	issued, expires, err := baselineChallengeWindow(q)
	if err != nil {
		return nil, err
	}
	if err = e.captureLive(ctx, q, issued, expires); err != nil {
		return nil, err
	}
	run, cancel := context.WithTimeout(ctx, expires.Sub(e.now().UTC()))
	defer cancel()
	s, err := e.store.lockState(run)
	if err != nil {
		return nil, err
	}
	defer e.store.mu.Unlock()
	if s.Attempt != nil || s.RecoveryRequired {
		return nil, ErrPending
	}
	if err = e.captureLive(run, q, issued, expires); err != nil {
		return nil, err
	}
	e.gate.now = e.now
	boot, err := baselineBootDigest()
	if err != nil {
		return nil, err
	}
	h1, err := e.gate.head(run)
	if err != nil || !captureHeadMatches(h1, q, s) {
		return nil, ErrUnauthorized
	}
	if err = e.verifiedCurrent(run, s.Active); err != nil {
		return nil, err
	}
	h2, err := e.gate.head(run)
	if err != nil || !h2.SameState(h1) || h2.RecordedAt.Before(h1.RecordedAt) {
		return nil, ErrStale
	}
	if err = e.captureLive(run, q, issued, expires); err != nil {
		return nil, err
	}
	if s.AuthorityEpoch != h2.Epoch || s.MinimumDenySequence != h2.Sequence {
		s.AuthorityEpoch, s.MinimumDenySequence = h2.Epoch, h2.Sequence
		if err = e.store.writeSnapshot(s); err != nil {
			return nil, err
		}
	}
	// A revoke, drift, cancellation or expiry during fsync must invalidate the
	// capture. No signature follows a stale pre-durability observation.
	if err = e.verifiedCurrent(run, s.Active); err != nil {
		return nil, err
	}
	bootAfter, err := baselineBootDigest()
	if err != nil || bootAfter != boot {
		return nil, ErrOwnedTree
	}
	h3, err := e.gate.head(run)
	if err != nil || !h3.SameState(h2) || h3.RecordedAt.Before(h2.RecordedAt) || !captureHeadMatches(h3, q, s) {
		return nil, ErrStale
	}
	if err = e.captureLive(run, q, issued, expires); err != nil {
		return nil, err
	}
	c := BaselineCapture{APIVersion: BaselineCaptureVersion, Purpose: baselineCapturePurpose, Query: q, Active: s.Active, HighWater: s.HighWater, ReceiptSequence: s.ReceiptSequence, AuthorityEpoch: s.AuthorityEpoch, WriterEpoch: s.WriterEpoch, MinimumDenySequence: s.MinimumDenySequence, Head: pin(h3), BootDigest: boot, RecordedAt: e.now().UTC().Format(time.RFC3339Nano), KeyID: e.store.anchor.ReceiptKeyID}
	digest, err := configmodel.Digest(c)
	if err != nil {
		return nil, ErrState
	}
	c.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(e.receiptKey, []byte(baselineCaptureDomain+"\n"+digest)))
	key, err := executionReceiptKey(e.store.anchor)
	if err != nil || VerifyBaselineCapture(c, e.store.anchor.ReceiptKeyID, key) != nil {
		return nil, ErrState
	}
	return &c, nil
}
