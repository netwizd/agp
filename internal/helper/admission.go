package helper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/ownedtree"
	"github.com/netwizd/agp/internal/securityjournal"
)

// Gate only admits an intent to its local journal. There is deliberately no
// executor capability or completion API. The accepted intent blocks new work
// until a separately qualified future reconciler can prove its outcome.
type Gate struct {
	store   *Store
	trust   Trust
	sources Sources
	now     func() time.Time
	tree    *ownedtree.Tree
}

// TrustDigest pins all three distinct key purposes into the installation.
// Replacing any anchor requires a future explicit installation/key lifecycle;
// it cannot silently reset the ledger or reuse a deployment sequence.
func TrustDigest(t Trust) (string, error) {
	if !configmodel.ValidID(t.PermitKeyID) || !configmodel.ValidID(t.ControlKeyID) || !configmodel.ValidID(t.JournalKeyID) || t.PermitKeyID == t.ControlKeyID || t.PermitKeyID == t.JournalKeyID || t.ControlKeyID == t.JournalKeyID || len(t.PermitKey) != ed25519.PublicKeySize || len(t.ControlKey) != ed25519.PublicKeySize || len(t.JournalKey) != ed25519.PublicKeySize || bytes.Equal(t.PermitKey, t.ControlKey) || bytes.Equal(t.PermitKey, t.JournalKey) || bytes.Equal(t.ControlKey, t.JournalKey) {
		return "", ErrInvalid
	}
	return configmodel.Digest(t)
}

func NewGate(s *Store, trust Trust, sources Sources) (*Gate, error) {
	d, err := TrustDigest(trust)
	if s == nil || sources == nil || err != nil || d != s.installation.TrustDigest {
		return nil, ErrInvalid
	}
	trust.PermitKey = bytes.Clone(trust.PermitKey)
	trust.ControlKey = bytes.Clone(trust.ControlKey)
	trust.JournalKey = bytes.Clone(trust.JournalKey)
	return &Gate{store: s, trust: trust, sources: sources, now: time.Now}, nil
}

func checkInstallation(r Request, i Installation, digest string) error {
	t, p := r.Task, r.Permit
	if t.NodeID != i.NodeID || p.InstallationDigest != digest || p.IdentityDigest != i.IdentityDigest || p.OwnershipDigest != i.OwnershipDigest || p.ComponentProfileDigest != i.ComponentProfileDigest || p.ReleaseManifestDigest != i.ReleaseManifestDigest || p.TupleDigest != i.TupleDigest || p.CompilerDigest != i.CompilerDigest || p.Approval.SiteID != i.SiteID || t.Preconditions.CapabilityDigest != i.CapabilityDigest || t.Preconditions.BaseRevisionID != i.Baseline.RevisionID || t.Payload.RecoveryBaseBundleDigest != i.Baseline.BundleDigest || p.Recovery.BaseRevisionID != i.Baseline.RevisionID || p.Recovery.BaseBundleDigest != i.Baseline.BundleDigest || p.Recovery.OwnershipDigest != i.OwnershipDigest || t.Payload.MinimumDenySequence < i.MinimumDenySequence || p.Recovery.MinimumDenySequence < t.Payload.MinimumDenySequence {
		return ErrStale
	}
	return nil
}

func challenge() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", ErrUnauthorized
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func (g *Gate) head(ctx context.Context) (securityjournal.Head, error) {
	c, err := challenge()
	if err != nil {
		return securityjournal.Head{}, err
	}
	raw, err := g.sources.Head(ctx, c)
	var h securityjournal.Head
	if err != nil || decodeClosed(raw, &h, 16<<10) != nil || securityjournal.VerifyHead(h, c, g.store.installation.AuthorityID, g.trust.JournalKeyID, g.trust.JournalKey, g.now().UTC()) != nil || h.RecordedAt.Before(h.ReleaseAfter) || g.now().Before(h.ReleaseAfter) {
		return securityjournal.Head{}, ErrUnauthorized
	}
	return h, nil
}

func liveWindow(t Task, h securityjournal.Head, now time.Time) bool {
	issued, e1 := utc(t.IssuedAt)
	expires, e2 := utc(t.ExpiresAt)
	return e1 == nil && e2 == nil && !issued.After(now) && now.Before(expires) && h.RecordedAt.Before(expires) && h.Epoch == t.AuthorityEpoch
}

func (g *Gate) liveProof(raw []byte, q StartQuery, t Task) (StartProof, error) {
	var p StartProof
	if decodeClosed(raw, &p, 16<<10) != nil || p.Query != q || p.WriterEpoch != t.WriterEpoch || !verifyProof(p, g.trust) {
		return StartProof{}, ErrUnauthorized
	}
	checked, e1 := utc(p.CheckedAt)
	expires, e2 := utc(p.ExpiresAt)
	now := g.now().UTC()
	if e1 != nil || e2 != nil || checked.After(now.Add(5*time.Second)) || checked.Before(now.Add(-MaxStartTTL)) || !expires.After(checked) || expires.Sub(checked) > MaxStartTTL || !now.Before(expires) {
		return StartProof{}, ErrUnauthorized
	}
	return p, nil
}

// Admit returns a historical noExecution receipt only after the exact intent
// and high-water have been durably persisted together. An exact retry does not
// consult the network and never starts an operation, including after expiry.
func (g *Gate) Admit(ctx context.Context, input io.Reader) (*Receipt, error) {
	if g == nil || g.store == nil || g.sources == nil || g.now == nil {
		return nil, ErrState
	}
	r, err := Decode(input)
	if err != nil {
		return nil, err
	}
	digest, err := configmodel.Digest(*r)
	if err != nil {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, MaxStartTTL)
	defer cancel()
	var result Receipt
	err = g.store.transaction(ctx, func(s *diskState) (bool, error) {
		if s.Intent != nil {
			old := s.Intent
			if old.Request.Task.ID == r.Task.ID || old.Request.Task.IdempotencyKey == r.Task.IdempotencyKey {
				if old.Request.Task.ID != r.Task.ID || old.Request.Task.IdempotencyKey != r.Task.IdempotencyKey || old.RequestDigest != digest {
					return false, ErrConflict
				}
				result = old.Receipt
				return false, nil
			}
			return false, ErrPending
		}
		t := r.Task
		if err := checkPlan(*r, g.store.installation, g.trust, g.now().UTC()); err != nil {
			return false, err
		}
		if !verifyPermit(r.Permit, g.trust) {
			return false, ErrUnauthorized
		}
		if err := checkInstallation(*r, g.store.installation, g.store.digest); err != nil {
			return false, err
		}
		if t.NodeDeploymentSequence <= s.HighWater || t.Preconditions.ExpectedNodeDeploymentSequence != s.HighWater || t.AuthorityEpoch < s.AuthorityEpoch || t.WriterEpoch < s.WriterEpoch {
			return false, ErrStale
		}
		if err := g.checkOwnedTree(ctx); err != nil {
			return false, err
		}
		started := g.now()
		h1, err := g.head(ctx)
		if err != nil {
			return false, err
		}
		if !liveWindow(t, h1, g.now().UTC()) || h1.Sequence < s.MinimumDenySequence || h1.Sequence < t.Payload.MinimumDenySequence || h1.Sequence < r.Permit.Recovery.MinimumDenySequence {
			return false, ErrStale
		}
		c, err := challenge()
		if err != nil {
			return false, err
		}
		q := StartQuery{APIVersion: StartVersion, Challenge: c, RequestDigest: digest, InstallationDigest: g.store.digest, Head: pin(h1)}
		raw, err := g.sources.Authorize(ctx, q)
		if err != nil {
			return false, ErrUnauthorized
		}
		proof, err := g.liveProof(raw, q, t)
		if err != nil {
			return false, err
		}
		h2, err := g.head(ctx)
		if err != nil {
			return false, err
		}
		// Bracket the current control proof with independent same-state heads.
		// An interposed revoke/epoch/floor change rejects even a signed proof.
		// This bounds authorization collection, not subsequent filesystem fsync.
		// An executor would need a separate effect-boundary authorization check;
		// this package only returns immutable noExecution admission evidence.
		if !h2.SameState(h1) || h2.RecordedAt.Before(h1.RecordedAt) || !h2.RecordedAt.Before(h1.RecordedAt.Add(MaxStartTTL)) || !liveWindow(t, h2, g.now().UTC()) || !g.now().Before(started.Add(MaxStartTTL)) {
			return false, ErrStale
		}
		if _, err := g.liveProof(raw, q, t); err != nil || ctx.Err() != nil {
			return false, ErrUnauthorized
		}
		// A slow authorization round trip cannot leave the filesystem check
		// solely before the network boundary. This remains admission evidence;
		// an executor must verify again at its actual effect boundary.
		if err := g.checkOwnedTree(ctx); err != nil {
			return false, err
		}
		if _, err := g.liveProof(raw, q, t); err != nil || ctx.Err() != nil || !liveWindow(t, h2, g.now().UTC()) || !g.now().Before(started.Add(MaxStartTTL)) {
			return false, ErrUnauthorized
		}
		result = Receipt{APIVersion: AdmissionVersion, TaskID: t.ID, NodeID: t.NodeID, RequestDigest: digest, NodeDeploymentSequence: t.NodeDeploymentSequence, AuthorityEpoch: t.AuthorityEpoch, WriterEpoch: t.WriterEpoch, State: "accepted", NoExecution: true, RecordedAt: h2.RecordedAt.UTC().Format(time.RFC3339Nano)}
		s.HighWater, s.AuthorityEpoch, s.WriterEpoch, s.MinimumDenySequence = t.NodeDeploymentSequence, t.AuthorityEpoch, t.WriterEpoch, h2.Sequence
		s.Intent = &Intent{Request: *r, RequestDigest: digest, Head: h2, Proof: proof, Receipt: result}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// Status distinguishes current reconciliation state from immutable admission
// evidence. It never reports active generation, applied or healthy.
func (s *Store) Status(ctx context.Context) (*Status, error) {
	var out Status
	err := s.transaction(ctx, func(state *diskState) (bool, error) {
		out = Status{HighWater: state.HighWater, State: "baseline", NoExecution: true}
		if state.Intent != nil {
			r := state.Intent.Receipt
			out.Admission = &r
			out.State = "reconciliation_required"
			if state.RecoveryRequired {
				out.State = "recovery_required"
			}
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// RequireRecovery may only strengthen an already-accepted blocker. It cannot
// clear the intent, decrease a counter, authorize rollback or claim completion.
func (s *Store) RequireRecovery(ctx context.Context) error {
	return s.transaction(ctx, func(state *diskState) (bool, error) {
		if state.Intent == nil {
			return false, ErrPending
		}
		if state.RecoveryRequired {
			return false, nil
		}
		state.RecoveryRequired = true
		return true, nil
	})
}
