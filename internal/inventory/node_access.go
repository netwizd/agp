package inventory

import (
	"context"
	"database/sql"
	"sort"
	"time"

	"github.com/netwizd/agp/internal/rolescope"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// NodeAccess is transaction-local authorization evidence. Typed scopes remain
// typed; neither a registry label nor a caller-supplied site grants ownership.
// It must not be retained beyond the surrounding Current callback.
type NodeAccess struct {
	ID                 string
	admin              bool
	sv, pv             uint64
	permission         string
	entries            []securitystate.EffectiveGrant
	head               securityjournal.Head
	snapshots          map[string]rolescope.Snapshot
	resolved           bool
	deadline           time.Time
	sessionFingerprint string
	global             bool
	nodes              map[string]bool
}

func nodePermissionScope(permission, kind string) bool {
	switch permission {
	case "nodes.enroll":
		return kind == "global" || kind == "site"
	case "nodes.read", "nodes.revoke":
		return kind == "global" || kind == "site" || kind == "node_group" || kind == "node"
	}
	return false
}

// ReadNodeSubjectAccess checks a historical approver without inventing a new
// session. A positive issuance must additionally pin this evidence to the
// approval and repeat it at an independently obtained current head.
func ReadNodeSubjectAccess(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, id, permission string) (*NodeAccess, error) {
	if h.Epoch == 0 || h.RecordedAt.IsZero() || !nodePermissionScope(permission, "global") {
		return nil, ErrUnavailable
	}
	p := &NodeAccess{ID: id, permission: permission, head: h, snapshots: map[string]rolescope.Snapshot{}}
	err := securitystate.One(ctx, tx, `SELECT is_admin,security_version,password_version FROM users WHERE id=? AND blocked_at IS NULL AND lifecycle_state='active'`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&p.admin, &p.sv, &p.pv) })
	if err == storage.ErrNotFound {
		return nil, storage.ErrPermissionDenied
	}
	if err != nil {
		return nil, err
	}
	grants, err := securitystate.ReadEffectiveGrants(ctx, tx, h, id)
	if err != nil {
		return nil, err
	}
	for _, g := range grants.Entries {
		if g.Permission != permission {
			continue
		}
		if !nodePermissionScope(permission, g.ScopeType) {
			return nil, storage.ErrPermissionDenied
		}
		p.entries = append(p.entries, g)
	}
	if !p.admin && len(p.entries) == 0 {
		return nil, storage.ErrPermissionDenied
	}
	return p, nil
}

type nodeSessionWitness struct {
	id          string
	deadline    time.Time
	fingerprint string
	primary     sql.NullTime
}

func nodeSession(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, current any, token, origin string, write bool) (nodeSessionWitness, error) {
	var out nodeSessionWitness
	if token == "" || origin == "" || h.RecordedAt.IsZero() {
		return out, storage.ErrPermissionDenied
	}
	if err := securitystate.CheckManagementSession(ctx, tx, h, token, current); err != nil {
		return out, err
	}
	now := h.RecordedAt.UTC()
	var expires, last, mfa time.Time
	var source, sessionID string
	q := `SELECT s.user_id,s.id,s.expires_at,s.last_seen_at,s.mfa_at,s.primary_at,s.source_session_id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>? AND s.last_seen_at>=? AND s.last_seen_at<=? AND s.audience='management' AND s.audience_origin=? AND s.authority_epoch=? AND s.security_version=u.security_version AND u.blocked_at IS NULL AND u.lifecycle_state='active' AND s.mfa_at IS NOT NULL AND s.mfa_at<=? AND (s.source_session_id='' OR EXISTS(SELECT 1 FROM sessions source WHERE source.id=s.source_session_id AND source.user_id=s.user_id AND source.revoked_at IS NULL AND source.authority_epoch=s.authority_epoch AND source.security_version=u.security_version AND source.expires_at>? AND source.last_seen_at>=? AND source.last_seen_at<=?))`
	args := []any{token, now, now.Add(-30 * time.Minute), now, origin, int64(h.Epoch), now, now, now.Add(-30 * time.Minute), now}
	if write {
		q += ` AND s.mfa_at>=?`
		args = append(args, now.Add(-5*time.Minute))
	}
	err := securitystate.One(ctx, tx, q, args, func(r storage.IdentityRows) error {
		return r.Scan(&out.id, &sessionID, &expires, &last, &mfa, &out.primary, &source)
	})
	if err == storage.ErrNotFound {
		return out, storage.ErrPermissionDenied
	}
	if err != nil {
		return out, err
	}
	out.deadline = expires
	bound := func(t time.Time) {
		if t.Before(out.deadline) {
			out.deadline = t
		}
	}
	bound(last.Add(30 * time.Minute))
	if write {
		bound(mfa.Add(5 * time.Minute))
		if out.primary.Valid {
			bound(out.primary.Time.Add(5 * time.Minute))
		}
	}
	if source != "" {
		err = securitystate.One(ctx, tx, `SELECT expires_at,last_seen_at FROM sessions WHERE id=?`, []any{source}, func(r storage.IdentityRows) error { return r.Scan(&expires, &last) })
		if err != nil {
			return out, err
		}
		bound(expires)
		bound(last.Add(30 * time.Minute))
	}
	if !now.Before(out.deadline) {
		return out, storage.ErrPermissionDenied
	}
	out.fingerprint, err = Digest([]any{"node-session-v1", token, sessionID, out.id, source, mfa, out.primary})
	if err != nil {
		return out, ErrUnavailable
	}
	return out, nil
}

// ReadNodeAccess preserves the existing full management session boundary while
// accepting only the explicit nodes.* permission needed by the operation.
func ReadNodeAccess(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, current any, token, origin, permission string, write bool) (*NodeAccess, error) {
	witness, err := nodeSession(ctx, tx, h, current, token, origin, write)
	if err != nil {
		return nil, err
	}
	p, err := ReadNodeSubjectAccess(ctx, tx, h, witness.id, permission)
	if err != nil {
		return nil, err
	}
	if write && !p.admin && (!witness.primary.Valid || witness.primary.Time.After(h.RecordedAt) || !h.RecordedAt.Before(witness.primary.Time.Add(5*time.Minute))) {
		return nil, storage.ErrPermissionDenied
	}
	p.deadline = witness.deadline
	p.sessionFingerprint = witness.fingerprint
	return p, nil
}

// Resolve verifies every relevant scoped grant, even for an empty list. It is
// intentionally delayed until after a newly created node has been stored: only
// then can the sealed graph cross-check that node's real site and membership.
func (p *NodeAccess) Resolve(ctx context.Context, tx storage.IdentityTx) error {
	if p.resolved {
		return nil
	}
	p.global = p.admin
	p.nodes = map[string]bool{}
	for _, g := range p.entries {
		if g.ScopeType == "global" {
			p.global = true
			continue
		}
		key := g.ScopeType + "\x00" + g.ScopeID
		if _, ok := p.snapshots[key]; ok {
			continue
		}
		resolve := rolescope.ResolveNodeManagement
		if p.permission == "nodes.enroll" {
			resolve = rolescope.Resolve
		}
		snapshot, err := resolve(ctx, tx, p.head, g.ScopeType, g.ScopeID)
		if err != nil {
			return err
		}
		p.snapshots[key] = snapshot
		for _, ref := range snapshot.Closure {
			if ref.ScopeType == "node" {
				p.nodes[ref.ScopeID] = true
			}
		}
	}
	p.resolved = true
	return nil
}

func (p *NodeAccess) AllowsNode(ctx context.Context, tx storage.IdentityTx, node string) (bool, error) {
	if !idPattern.MatchString(node) {
		return false, ErrInvalid
	}
	if err := p.Resolve(ctx, tx); err != nil {
		return false, err
	}
	return p.global || p.nodes[node], nil
}

// Fingerprint includes immutable grant incarnation, expiry and all consulted
// ownership sources. Call Resolve/AllowsNode before storing it in an approval.
func (p *NodeAccess) Fingerprint() string {
	keys := make([]string, 0, len(p.snapshots))
	for key := range p.snapshots {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	snapshots := make([]rolescope.Snapshot, 0, len(keys))
	for _, key := range keys {
		snapshots = append(snapshots, p.snapshots[key])
	}
	fp, _ := Digest([]any{"node-access-v2", p.ID, p.admin, p.sv, p.pv, p.permission, p.entries, snapshots, p.sessionFingerprint})
	return fp
}

func nodeCurrentHead(ctx context.Context, current any, previous securityjournal.Head) (securityjournal.Head, error) {
	source, ok := current.(Authority)
	if !ok {
		return securityjournal.Head{}, ErrUnavailable
	}
	h, err := source.Head(ctx)
	if err != nil {
		return h, err
	}
	if !previous.SameState(h) || h.RecordedAt.IsZero() || h.RecordedAt.Before(previous.RecordedAt) {
		return h, ErrUnavailable
	}
	return h, nil
}

func (p *NodeAccess) final(ctx context.Context, tx storage.IdentityTx, current any, token, origin string, write bool) error {
	if err := p.Resolve(ctx, tx); err != nil {
		return err
	}
	h, err := nodeCurrentHead(ctx, current, p.head)
	if err != nil {
		return err
	}
	var next *NodeAccess
	if token == "" {
		next, err = ReadNodeSubjectAccess(ctx, tx, h, p.ID, p.permission)
	} else {
		next, err = ReadNodeAccess(ctx, tx, h, current, token, origin, p.permission, write)
	}
	if err != nil {
		return err
	}
	if err = next.Resolve(ctx, tx); err != nil {
		return err
	}
	if p.Fingerprint() == "" || p.Fingerprint() != next.Fingerprint() {
		return storage.ErrPermissionDenied
	}
	last, err := nodeCurrentHead(ctx, current, h)
	if err != nil {
		return err
	}
	for _, g := range next.entries {
		if g.ExpiresAt != nil && !last.RecordedAt.Before(*g.ExpiresAt) {
			return storage.ErrPermissionDenied
		}
	}
	if token != "" {
		witness, err := nodeSession(ctx, tx, last, current, token, origin, write)
		if err != nil {
			return err
		}
		if witness.id != p.ID || witness.fingerprint != p.sessionFingerprint || !last.RecordedAt.Before(p.deadline) || !last.RecordedAt.Before(next.deadline) {
			return storage.ErrPermissionDenied
		}
	}
	return nil
}

// Finish repeats the actor, incarnation, ownership and expiry checks after I/O
// while the caller still owns its original Current transaction. Never retry the
// callback automatically after a failed witness.
func (p *NodeAccess) Finish(ctx context.Context, tx storage.IdentityTx, current any, token, origin string, write bool) error {
	if token == "" {
		return storage.ErrPermissionDenied
	}
	return p.final(ctx, tx, current, token, origin, write)
}
func (p *NodeAccess) FinishSubject(ctx context.Context, tx storage.IdentityTx, current any) error {
	return p.final(ctx, tx, current, "", "", false)
}

// AuthorizationDeadline bounds an external positive action by the immutable
// evidence already checked in this transaction. The upper bound is the existing
// enrollment expiry; a caller cannot extend it with an HTTP request value.
func (p *NodeAccess) AuthorizationDeadline(upper time.Time) time.Time {
	if !p.deadline.IsZero() && p.deadline.Before(upper) {
		upper = p.deadline
	}
	for _, g := range p.entries {
		if g.ExpiresAt != nil && g.ExpiresAt.Before(upper) {
			upper = *g.ExpiresAt
		}
	}
	return upper
}
