package configuration

import (
	"context"
	"time"

	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// ScopeGrant remains the bootstrap wire DTO. Incarnation and expiry evidence
// belongs to the private server-side projection, never to caller input.
func (p *Principal) loadGrants(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head) error {
	grants, err := securitystate.ReadEffectiveGrants(ctx, tx, h, p.ID)
	if err != nil {
		return subjectFailure(tx, err)
	}
	p.grantEvidence = grants.Entries
	p.grants = make([]ScopeGrant, 0, len(grants.Entries))
	for _, entry := range grants.Entries {
		p.grants = append(p.grants, ScopeGrant{ID: entry.ID, PrincipalID: entry.PrincipalID, Permission: entry.Permission, ScopeType: entry.ScopeType, ScopeID: entry.ScopeID})
	}
	return nil
}

func readConfigurationActor(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, a Actor, write bool, current Current, origin string) (*Principal, error) {
	if h.Epoch == 0 || h.RecordedAt.IsZero() {
		return nil, ErrUnavailable
	}
	if err := securitystate.CheckManagementSession(ctx, tx, h, a.TokenHash, current); err != nil {
		return nil, err
	}
	now := h.RecordedAt.UTC()
	p := &Principal{Epoch: int64(h.Epoch), head: h}
	q := `SELECT s.user_id,u.is_admin,s.mfa_at,u.security_version FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>? AND s.last_seen_at>=? AND s.last_seen_at<=? AND s.audience='management' AND s.audience_origin=? AND s.authority_epoch=? AND s.security_version=u.security_version AND u.blocked_at IS NULL AND u.lifecycle_state='active' AND s.mfa_at IS NOT NULL AND s.mfa_at<=? AND (s.source_session_id='' OR EXISTS(SELECT 1 FROM sessions source WHERE source.id=s.source_session_id AND source.user_id=s.user_id AND source.revoked_at IS NULL AND source.authority_epoch=s.authority_epoch AND source.security_version=u.security_version AND source.expires_at>? AND source.last_seen_at>=? AND source.last_seen_at<=?))`
	args := []any{a.TokenHash, now, now.Add(-30 * time.Minute), now, origin, int64(h.Epoch), now, now, now.Add(-30 * time.Minute), now}
	if write {
		q += ` AND s.mfa_at>=?`
		args = append(args, now.Add(-5*time.Minute))
	}
	err := securitystate.One(ctx, tx, q, args, func(r storage.IdentityRows) error { return r.Scan(&p.ID, &p.Admin, &p.MFAAt, &p.SecurityVersion) })
	if err == storage.ErrNotFound {
		return nil, storage.ErrPermissionDenied
	}
	if err != nil {
		return nil, err
	}
	if err = p.loadGrants(ctx, tx, h); err != nil {
		return nil, err
	}
	return p, nil
}

func configurationActorFingerprint(p *Principal) string {
	return digest([]any{"configuration-actor-v2", p.ID, p.Admin, p.SecurityVersion, p.MFAAt, p.grantEvidence})
}

type configurationSubjectWitness struct {
	fingerprint string
	entries     []securitystate.EffectiveGrant
}

func identitySubjectFingerprint(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, id string) (string, error) {
	fingerprint, err := identity.DirectorySubjectFingerprint(ctx, tx, h, id)
	if err != nil {
		return "", subjectFailure(tx, err)
	}
	return fingerprint, nil
}

func configurationSubject(ctx context.Context, tx storage.IdentityTx, id string, h securityjournal.Head) (configurationSubjectWitness, error) {
	var out configurationSubjectWitness
	var admin bool
	var version, passwordVersion int64
	err := securitystate.One(ctx, tx, `SELECT is_admin,security_version,password_version FROM users WHERE id=? AND blocked_at IS NULL AND lifecycle_state='active'`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&admin, &version, &passwordVersion) })
	if err != nil {
		return out, err
	}
	grants, err := securitystate.ReadEffectiveGrants(ctx, tx, h, id)
	if err != nil {
		return out, err
	}
	directory, err := identitySubjectFingerprint(ctx, tx, h, id)
	if err != nil {
		return out, err
	}
	out.entries = grants.Entries
	out.fingerprint = digest([]any{"configuration-subject-v2", id, admin, version, passwordVersion, grants.Entries, directory})
	return out, nil
}

func grantsUnexpired(entries []securitystate.EffectiveGrant, now time.Time) bool {
	for _, entry := range entries {
		if entry.ExpiresAt != nil && !now.Before(*entry.ExpiresAt) {
			return false
		}
	}
	return true
}

// The callback executes once. A failed final check rolls back its writes and
// audit atomically; an old role incarnation cannot authorize a saved response.
func (s *Service) finishConfigurationEvidence(ctx context.Context, a Actor, write bool, p *Principal, evidence *subjectEvidenceTx, callbackErr error) error {
	if err := finalSubjectEvidence(evidence, callbackErr); err != nil {
		return err
	}
	final, err := s.current.Head(ctx)
	if err != nil || !p.head.SameState(final) || final.RecordedAt.IsZero() || final.RecordedAt.Before(p.head.RecordedAt) {
		return ErrUnavailable
	}
	actor, err := readConfigurationActor(ctx, evidence, final, a, write, s.current, s.origin)
	if err != nil {
		return err
	}
	if configurationActorFingerprint(actor) != configurationActorFingerprint(p) {
		return storage.ErrPermissionDenied
	}
	witnesses := make(map[string]configurationSubjectWitness, len(evidence.subjects))
	for id, previous := range evidence.subjects {
		current, e := configurationSubject(ctx, evidence, id, final)
		if e != nil {
			return e
		}
		if current.fingerprint != previous.fingerprint {
			return storage.ErrPermissionDenied
		}
		witnesses[id] = current
	}
	if err := p.revalidateResourceEvidence(ctx, evidence, final); err != nil {
		return err
	}
	if err := p.revalidateGatewayEvidence(ctx, evidence, final); err != nil {
		return err
	}
	// Projection may be expensive. Validate all immutable expiry witnesses at a
	// later independent time, then repeat only the live session/directory gates.
	last, err := s.current.Head(ctx)
	if err != nil || !final.SameState(last) || last.RecordedAt.IsZero() || last.RecordedAt.Before(final.RecordedAt) {
		return ErrUnavailable
	}
	if !grantsUnexpired(actor.grantEvidence, last.RecordedAt) {
		return storage.ErrPermissionDenied
	}
	for id, witness := range witnesses {
		if !grantsUnexpired(witness.entries, last.RecordedAt) {
			return storage.ErrPermissionDenied
		}
		if _, err := identitySubjectFingerprint(ctx, evidence, last, id); err != nil {
			return err
		}
	}
	if err = securitystate.CheckManagementSession(ctx, evidence, last, a.TokenHash, s.current); err != nil {
		return err
	}
	if write && (actor.MFAAt.After(last.RecordedAt) || actor.MFAAt.Before(last.RecordedAt.Add(-5*time.Minute))) {
		return storage.ErrPermissionDenied
	}
	// Session lifetimes are checked without reloading the role catalog a third
	// time. The writer TX keeps every row and incarnation stable until commit.
	var live string
	err = securitystate.One(ctx, evidence, `SELECT s.id FROM sessions s WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>? AND s.last_seen_at>=? AND s.last_seen_at<=? AND (s.source_session_id='' OR EXISTS(SELECT 1 FROM sessions source WHERE source.id=s.source_session_id AND source.user_id=s.user_id AND source.revoked_at IS NULL AND source.authority_epoch=s.authority_epoch AND source.security_version=s.security_version AND source.expires_at>? AND source.last_seen_at>=? AND source.last_seen_at<=?))`, []any{a.TokenHash, last.RecordedAt, last.RecordedAt.Add(-30 * time.Minute), last.RecordedAt, last.RecordedAt, last.RecordedAt.Add(-30 * time.Minute), last.RecordedAt}, func(r storage.IdentityRows) error { return r.Scan(&live) })
	if err == storage.ErrNotFound {
		return storage.ErrPermissionDenied
	}
	return err
}
