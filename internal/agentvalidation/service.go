package agentvalidation

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"sync"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type nativeChecker interface {
	current(context.Context, Pins) (*qualified, error)
	Check(context.Context, Request) error
}

type Service struct {
	current Current
	agents  Agents
	native  nativeChecker
	mu      sync.Mutex
	active  bool
}

func New(current Current, agents Agents, native *Native) (*Service, error) {
	if current == nil || agents == nil || native == nil || native.Clock == nil {
		return nil, ErrUnavailable
	}
	return &Service{current: current, agents: agents, native: native}, nil
}

// Validate performs a Control Plane local probe bound to an admitted agent's
// fresh observation. It does not dispatch a task or execute on that agent.
func (s *Service) Validate(ctx context.Context, peer *tls.ConnectionState, in Request) (out *Result, err error) {
	s.mu.Lock()
	if s.active {
		s.mu.Unlock()
		return nil, ErrBusy
	}
	s.active = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.active = false; s.mu.Unlock() }()
	raw, fp, e := normalize(in)
	if e != nil {
		return nil, e
	}
	if json.Unmarshal(raw, &in) != nil {
		return nil, ErrInvalid
	}
	var initialNode inventory.Node
	var identity, nodeID, id string
	var created, expires time.Time
	err = s.agents.WithFreshAgent(ctx, peer, func(tx storage.IdentityTx, h securityjournal.Head, node inventory.Node) error {
		if node.CapabilityDigest != in.CapabilityDigest || h.Epoch != in.AuthorityEpoch {
			return ErrStale
		}
		if node.SiteID != in.Policy.Metadata.SiteID {
			return storage.ErrPermissionDenied
		}
		identity, nodeID = node.IdentityDigest, node.ID
		initialNode = node
		var prior, requestID string
		e := securitystate.One(ctx, tx, `SELECT id,request_fingerprint FROM agent_local_validation_requests WHERE node_id=? AND identity_digest=? AND request_id=?`, []any{nodeID, identity, in.RequestID}, func(r storage.IdentityRows) error { return r.Scan(&requestID, &prior) })
		if e == nil {
			if prior != fp {
				return ErrConflict
			}
			out, e = readResult(ctx, tx, requestID)
			if e == storage.ErrNotFound {
				return ErrPending
			}
			return e
		}
		if e != storage.ErrNotFound {
			return e
		}
		var total, recent, active int64
		if e = securitystate.One(ctx, tx, `SELECT COUNT(*) FROM agent_local_validation_requests`, nil, func(r storage.IdentityRows) error { return r.Scan(&total) }); e != nil {
			return e
		}
		if e = securitystate.One(ctx, tx, `SELECT COUNT(*) FROM agent_local_validation_requests WHERE node_id=? AND created_at>?`, []any{nodeID, h.RecordedAt.Add(-time.Minute)}, func(r storage.IdentityRows) error { return r.Scan(&recent) }); e != nil {
			return e
		}
		if e = securitystate.One(ctx, tx, `SELECT COUNT(*) FROM agent_local_validation_requests r WHERE node_id=? AND NOT EXISTS(SELECT 1 FROM agent_local_validation_results v WHERE v.request_fact_id=r.id)`, []any{nodeID}, func(r storage.IdentityRows) error { return r.Scan(&active) }); e != nil {
			return e
		}
		if total >= 100000 || recent >= 10 || active >= 1 {
			return ErrBusy
		}
		id = securitystate.ID("lvr")
		created = h.RecordedAt.UTC()
		expires = created.Add(RequestTTL)
		_, e = tx.Exec(ctx, `INSERT INTO agent_local_validation_requests(id,node_id,identity_digest,authority_epoch,request_id,request_fingerprint,request_json,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)`, id, nodeID, identity, int64(h.Epoch), in.RequestID, fp, string(raw), created, expires)
		return e
	})
	if err != nil || out != nil {
		return out, err
	}
	q, validationErr := s.native.current(ctx, in.Pins)
	if validationErr == nil {
		validationErr = matchNode(initialNode, q)
	}
	if validationErr == nil {
		validationErr = s.native.Check(ctx, in)
	}
	// Native.Check itself repeats signed release/profile/floor verification.
	// Fresh identity/capability/epoch are repeated after the expensive work in
	// the exact transaction that stores the terminal fact.
	err = s.agents.WithFreshAgent(ctx, peer, func(tx storage.IdentityTx, h securityjournal.Head, node inventory.Node) error {
		if node.ID != nodeID || node.IdentityDigest != identity || node.CapabilityDigest != in.CapabilityDigest || h.Epoch != in.AuthorityEpoch || h.RecordedAt.Before(created) || !h.RecordedAt.Before(expires) {
			return ErrStale
		}
		if q != nil {
			if e = matchNode(node, q); e != nil {
				return e
			}
		}
		policyDigest, _ := configmodel.Digest(in.Policy)
		out = &Result{APIVersion: ResultVersion, ID: id, RequestID: in.RequestID, NodeID: nodeID, AuthorityEpoch: h.Epoch, RequestDigest: fp, IdentityDigest: identity, CapabilityDigest: in.CapabilityDigest, PolicyDigest: policyDigest, Pins: in.Pins, State: resultState(validationErr), NativeSyntaxOnly: true, ExecutionLocation: "control_plane", Isolation: "unprivileged_private_workspace", CreatedAt: created, RecordedAt: h.RecordedAt, ErrorCode: safeError(validationErr)}
		b, e := configmodel.CanonicalJSON(out)
		if e != nil || len(b) > MaxResultBytes {
			return ErrUnavailable
		}
		_, e = tx.Exec(ctx, `INSERT INTO agent_local_validation_results(id,request_fact_id,result_json,recorded_at) VALUES(?,?,?,?)`, id, id, string(b), h.RecordedAt)
		return e
	})
	return out, err
}

func readResult(ctx context.Context, tx storage.IdentityTx, id string) (*Result, error) {
	var raw string
	e := securitystate.One(ctx, tx, `SELECT result_json FROM agent_local_validation_results WHERE id=?`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&raw) })
	if e != nil {
		return nil, e
	}
	if len(raw) > MaxResultBytes {
		return nil, ErrUnavailable
	}
	var out Result
	if decodeLocal([]byte(raw), &out) != nil || !validResult(out) || out.ID != id || out.ExecutionLocation != "control_plane" {
		return nil, ErrUnavailable
	}
	return &out, nil
}

func validResult(out Result) bool {
	return out.APIVersion == ResultVersion && out.NativeSyntaxOnly && out.NodeDeploymentSequence == 0 && (out.State == "validated" || out.State == "rejected" || out.State == "failed") && out.Isolation == "unprivileged_private_workspace" && !out.CreatedAt.IsZero() && !out.RecordedAt.Before(out.CreatedAt) && (out.State != "validated" || out.ErrorCode == "")
}

// Get replays an immutable diagnostic fact only to the same currently admitted
// agent identity. A fact is historical; reading it never refreshes a permit.
func (s *Service) Get(ctx context.Context, peer *tls.ConnectionState, id string) (out *Result, err error) {
	if !idPattern.MatchString(id) {
		return nil, ErrInvalid
	}
	err = s.agents.WithFreshAgent(ctx, peer, func(tx storage.IdentityTx, h securityjournal.Head, node inventory.Node) error {
		var e error
		out, e = readResult(ctx, tx, id)
		if e != nil {
			return e
		}
		if out.NodeID != node.ID || out.IdentityDigest != node.IdentityDigest || out.AuthorityEpoch != h.Epoch {
			return storage.ErrPermissionDenied
		}
		return nil
	})
	return
}

func (s *Service) GetForAdmin(ctx context.Context, tokenHash, origin, id string) (out *Result, err error) {
	if tokenHash == "" || origin == "" || !idPattern.MatchString(id) {
		return nil, storage.ErrPermissionDenied
	}
	err = s.current.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		var actor string
		e := securitystate.One(ctx, tx, `SELECT s.user_id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>? AND s.last_seen_at>=? AND s.audience='management' AND s.audience_origin=? AND s.authority_epoch=? AND s.security_version=u.security_version AND u.blocked_at IS NULL AND u.is_admin=TRUE AND s.mfa_at IS NOT NULL`, []any{tokenHash, h.RecordedAt, h.RecordedAt.Add(-30 * time.Minute), origin, int64(h.Epoch)}, func(r storage.IdentityRows) error { return r.Scan(&actor) })
		if e == storage.ErrNotFound {
			return storage.ErrPermissionDenied
		}
		if e != nil {
			return e
		}
		out, e = readResult(ctx, tx, id)
		return e
	})
	return
}
