package rolloutexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type subject struct {
	id          string
	fingerprint string
	grants      []securitystate.EffectiveGrant
	mfa         time.Time
}

func (s *Service) subject(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, id string) (*subject, error) {
	var sv, pv int64
	err := securitystate.One(ctx, tx, `SELECT security_version,password_version FROM users WHERE id=? AND blocked_at IS NULL AND lifecycle_state='active'`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&sv, &pv) })
	if err != nil {
		return nil, err
	}
	for _, v := range []struct {
		key     string
		version int64
	}{{"principal_" + id, sv}, {"password_" + id, pv}} {
		floor, err := securitystate.Floor(ctx, tx, id, v.key)
		if err != nil {
			return nil, err
		}
		if v.version < 0 || uint64(v.version) < floor {
			return nil, storage.ErrPermissionDenied
		}
	}
	g, err := securitystate.ReadEffectiveGrants(ctx, tx, h, id)
	if err != nil {
		return nil, err
	}
	directory, err := identity.DirectorySubjectFingerprint(ctx, tx, h, id)
	if err != nil {
		return nil, err
	}
	return &subject{id: id, grants: g.Entries, fingerprint: digest([]any{"execution-participant/v1", id, sv, pv, g.Entries, directory})}, nil
}
func (s *Service) actor(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, a Actor, write bool) (*subject, error) {
	if a.Origin != s.origin || a.TokenHash == "" || h.RecordedAt.IsZero() {
		return nil, storage.ErrPermissionDenied
	}
	if err := securitystate.CheckManagementSession(ctx, tx, h, a.TokenHash, s.current); err != nil {
		return nil, err
	}
	id, mfa, err := s.session(ctx, tx, h, a, write)
	if err != nil {
		return nil, err
	}
	p, err := s.subject(ctx, tx, h, id)
	if err != nil {
		return nil, err
	}
	p.mfa = mfa
	return p, nil
}
func (s *Service) session(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, a Actor, write bool) (string, time.Time, error) {
	var id string
	var mfa time.Time
	now := h.RecordedAt.UTC()
	q := `SELECT s.user_id,s.mfa_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>? AND s.last_seen_at>=? AND s.last_seen_at<=? AND s.audience='management' AND s.audience_origin=? AND s.authority_epoch=? AND s.security_version=u.security_version AND u.blocked_at IS NULL AND u.lifecycle_state='active' AND s.mfa_at IS NOT NULL AND s.mfa_at<=? AND (s.source_session_id='' OR EXISTS(SELECT 1 FROM sessions source WHERE source.id=s.source_session_id AND source.user_id=s.user_id AND source.revoked_at IS NULL AND source.authority_epoch=s.authority_epoch AND source.security_version=u.security_version AND source.expires_at>? AND source.last_seen_at>=? AND source.last_seen_at<=?))`
	args := []any{a.TokenHash, now, now.Add(-30 * time.Minute), now, s.origin, int64(h.Epoch), now, now, now.Add(-30 * time.Minute), now}
	if write {
		q += ` AND s.mfa_at>=?`
		args = append(args, now.Add(-5*time.Minute))
	}
	err := securitystate.One(ctx, tx, q, args, func(r storage.IdentityRows) error { return r.Scan(&id, &mfa) })
	if err == storage.ErrNotFound {
		return "", mfa, storage.ErrPermissionDenied
	}
	return id, mfa, err
}

// Resource grants never cover a shared full-node bundle. Coverage is a union
// of exact installation-owned nodes/groups, not a flattened permission list.
func covers(grants []securitystate.EffectiveGrant, permission string, targets []TargetSnapshot) bool {
	for _, t := range targets {
		allowed := false
		for _, g := range grants {
			if g.Permission != permission && !(permission == "config.read" && g.Permission == "config.edit") {
				continue
			}
			switch g.ScopeType {
			case "global":
				allowed = true
			case "site":
				allowed = g.ScopeID == t.Installation.SiteID
			case "node":
				allowed = g.ScopeID == t.Installation.NodeID
			case "node_group":
				for _, id := range t.NodeGroupIDs {
					if id == g.ScopeID {
						allowed = true
						break
					}
				}
			}
			if allowed {
				break
			}
		}
		if !allowed {
			return false
		}
	}
	return len(targets) > 0
}

type requirement struct {
	id, permission string
	targets        []TargetSnapshot
}
type sessionBinding struct {
	actor Actor
	id    string
	mfa   time.Time
}
type operation struct {
	s            *Service
	ctx          context.Context
	tx           storage.IdentityTx
	head         securityjournal.Head
	actor        *subject
	credentials  *Actor
	write        bool
	witnesses    map[string]*subject
	requirements []requirement
	targets      map[string]TargetSnapshot
	expiries     []time.Time
	peer         *tls.ConnectionState
	peerNode     string
	sessions     []sessionBinding
}

func newOperation(s *Service, ctx context.Context, tx storage.IdentityTx, h securityjournal.Head) *operation {
	return &operation{s: s, ctx: ctx, tx: tx, head: h, witnesses: map[string]*subject{}, targets: map[string]TargetSnapshot{}}
}
func (o *operation) person(id string) (*subject, error) {
	if p := o.witnesses[id]; p != nil {
		return p, nil
	}
	p, err := o.s.subject(o.ctx, o.tx, o.head, id)
	if err != nil {
		return nil, err
	}
	o.witnesses[id] = p
	return p, nil
}
func (o *operation) need(id, permission string, targets []TargetSnapshot) error {
	p, err := o.person(id)
	if err != nil {
		return err
	}
	if !covers(p.grants, permission, targets) {
		return storage.ErrPermissionDenied
	}
	o.requirements = append(o.requirements, requirement{id, permission, targets})
	return nil
}
func (o *operation) target(t TargetSnapshot) error {
	i := t.Installation
	key, err := base64.RawURLEncoding.DecodeString(t.ReceiptPublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(key) != t.ReceiptPublicKey || !configmodel.ValidID(t.ReceiptKeyID) || t.ReceiptKeyID == o.s.keys.PermitKeyID || t.ReceiptKeyID == o.s.keys.ControlKeyID || bytes.Equal(key, o.s.keys.PermitKey.Public().(ed25519.PublicKey)) || bytes.Equal(key, o.s.keys.ControlKey.Public().(ed25519.PublicKey)) {
		return ErrUnavailable
	}
	if i.AuthorityID != o.head.AuthorityID || i.AuthorityEpoch != o.head.Epoch || i.WriterEpoch == 0 || i.MinimumDenySequence > o.head.Sequence {
		return ErrStale
	}
	if err := checkNode(o.ctx, o.tx, i.NodeID); err != nil {
		return err
	}
	if err := o.s.sources.Recheck(o.ctx, o.tx, o.head, t); err != nil {
		return err
	}
	o.targets[i.NodeID] = t
	return nil
}
func (o *operation) times(now time.Time) error {
	for _, expiry := range o.expiries {
		if expiry.IsZero() || !now.Before(expiry) {
			return ErrStale
		}
	}
	for _, p := range o.witnesses {
		for _, g := range p.grants {
			if g.ExpiresAt != nil && !now.Before(*g.ExpiresAt) {
				return storage.ErrPermissionDenied
			}
		}
	}
	if o.actor != nil && o.write && (o.actor.mfa.After(now) || o.actor.mfa.Before(now.Add(-5*time.Minute))) {
		return storage.ErrPermissionDenied
	}
	return nil
}
func (o *operation) finish() error {
	h, err := o.s.current.Head(o.ctx)
	if err != nil || !o.head.SameState(h) || h.RecordedAt.Before(o.head.RecordedAt) {
		return ErrUnavailable
	}
	if o.actor != nil {
		p, err := o.s.actor(o.ctx, o.tx, h, *o.credentials, o.write)
		if err != nil {
			return err
		}
		if p.fingerprint != o.actor.fingerprint || !p.mfa.Equal(o.actor.mfa) {
			return storage.ErrPermissionDenied
		}
	}
	for id, p := range o.witnesses {
		fresh, err := o.s.subject(o.ctx, o.tx, h, id)
		if err != nil {
			return err
		}
		if fresh.fingerprint != p.fingerprint {
			return storage.ErrPermissionDenied
		}
	}
	for _, r := range o.requirements {
		if !covers(o.witnesses[r.id].grants, r.permission, r.targets) {
			return storage.ErrPermissionDenied
		}
	}
	for _, t := range o.targets {
		if err := checkNode(o.ctx, o.tx, t.Installation.NodeID); err != nil {
			return err
		}
		if err := o.s.sources.Recheck(o.ctx, o.tx, h, t); err != nil {
			return err
		}
	}
	if o.peer != nil {
		node, err := o.s.agents(o.ctx, o.tx, h, o.peer)
		if err != nil {
			return err
		}
		if node != o.peerNode {
			return storage.ErrPermissionDenied
		}
	}
	last, err := o.s.current.Head(o.ctx)
	if err != nil || !h.SameState(last) || last.RecordedAt.Before(h.RecordedAt) {
		return ErrUnavailable
	}
	if err = o.times(last.RecordedAt); err != nil {
		return err
	}
	if o.credentials != nil {
		if err = securitystate.CheckManagementSession(o.ctx, o.tx, last, o.credentials.TokenHash, o.s.current); err != nil {
			return err
		}
		if _, _, err = o.s.session(o.ctx, o.tx, last, *o.credentials, o.write); err != nil {
			return err
		}
	}
	for _, session := range o.sessions {
		if err = securitystate.CheckManagementSession(o.ctx, o.tx, last, session.actor.TokenHash, o.s.current); err != nil {
			return err
		}
		id, mfa, e := o.s.session(o.ctx, o.tx, last, session.actor, true)
		if e != nil {
			return e
		}
		if id != session.id || !mfa.Equal(session.mfa) {
			return storage.ErrPermissionDenied
		}
	}
	if o.peer != nil {
		node, err := o.s.agents(o.ctx, o.tx, last, o.peer)
		if err != nil {
			return err
		}
		if node != o.peerNode {
			return storage.ErrPermissionDenied
		}
	}
	now := time.Now().UTC()
	if last.RecordedAt.After(now) {
		now = last.RecordedAt
	}
	return o.times(now)
}
