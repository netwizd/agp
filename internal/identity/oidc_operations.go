package identity

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type oidcOperationRecord struct {
	operation         OIDCSecurityOperation
	authorFingerprint string
}

func oidcOperationDigest(o OIDCSecurityOperation) (string, error) {
	if o.Family == "provider_security_change" && o.ProviderChange != nil && o.OIDCLinkChange == nil {
		return configmodel.Digest(o.ProviderChange)
	}
	if o.Family == "oidc_identity_link" && o.OIDCLinkChange != nil && o.ProviderChange == nil {
		return configmodel.Digest(o.OIDCLinkChange)
	}
	return "", ErrOIDCStale
}
func readOIDCOperation(ctx context.Context, tx storage.IdentityTx, id string) (*oidcOperationRecord, error) {
	if !configmodel.ValidID(id) {
		return nil, ErrOIDCInvalid
	}
	r := &oidcOperationRecord{}
	var raw, state, approval, family, provider, version, digest, author string
	e := securitystate.One(ctx, tx, `SELECT intent_json,author_fingerprint,state,approval_status,family,provider_id,version_id,request_digest,author_id FROM oidc_operations WHERE id=?`, []any{id}, func(rows storage.IdentityRows) error {
		return rows.Scan(&raw, &r.authorFingerprint, &state, &approval, &family, &provider, &version, &digest, &author)
	})
	if e != nil {
		return nil, e
	}
	if configmodel.StrictJSON(strings.NewReader(raw), &r.operation, 65536) != nil {
		return nil, ErrOIDCStale
	}
	o := &r.operation
	actual, e := oidcOperationDigest(*o)
	if e != nil || o.ID != id || o.Family != family || o.RequestDigest != digest || actual != digest || o.CreatedBy != author {
		return nil, ErrOIDCStale
	}
	if o.ProviderChange != nil && (o.ProviderChange.ProviderID != provider || o.ProviderChange.VersionID != version || o.SubjectID != provider || o.ProviderChange.ProviderType != "oidc") {
		return nil, ErrOIDCStale
	}
	if o.OIDCLinkChange != nil && (o.OIDCLinkChange.ProviderID != provider || o.OIDCLinkChange.VersionID != version || o.SubjectID != o.OIDCLinkChange.LinkID) {
		return nil, ErrOIDCStale
	}
	o.State = state
	o.ApprovalStatus = approval
	return r, nil
}
func oidcReplayRequest(ctx context.Context, tx storage.IdentityTx, actor, action, key, fp string) (string, error) {
	var prior, id string
	e := securitystate.One(ctx, tx, `SELECT fingerprint,operation_id FROM oidc_action_requests WHERE actor_id=? AND action=? AND request_key=?`, []any{actor, action, key}, func(r storage.IdentityRows) error { return r.Scan(&prior, &id) })
	if errors.Is(e, storage.ErrNotFound) {
		return "", nil
	}
	if e != nil {
		return "", e
	}
	if prior != fp {
		return "", storage.ErrConflict
	}
	return id, nil
}
func storeOIDCRequest(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, actor, action, key, fp, id string) error {
	if prior, e := oidcReplayRequest(ctx, tx, actor, action, key, fp); e != nil {
		return e
	} else if prior != "" {
		if prior != id {
			return storage.ErrConflict
		}
		return nil
	}
	_, e := tx.Exec(ctx, `INSERT INTO oidc_action_requests(actor_id,action,request_key,fingerprint,operation_id,created_at) VALUES(?,?,?,?,?,?)`, actor, action, key, fp, id, h.RecordedAt)
	return e
}
func storeOIDCOperation(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, p *directoryPrincipal, o *OIDCSecurityOperation, action, key, fp string) error {
	raw, e := configmodel.CanonicalJSON(o)
	if e != nil {
		return e
	}
	provider, version := "", ""
	if o.ProviderChange != nil {
		provider = o.ProviderChange.ProviderID
		version = o.ProviderChange.VersionID
	} else {
		provider = o.OIDCLinkChange.ProviderID
		version = o.OIDCLinkChange.VersionID
	}
	_, e = tx.Exec(ctx, `INSERT INTO oidc_operations(id,family,provider_id,version_id,request_digest,intent_json,author_id,author_fingerprint,state,approval_status,created_at) VALUES(?,?,?,?,?,?,?,?,'pending','pending',?)`, o.ID, o.Family, provider, version, o.RequestDigest, string(raw), p.id, p.fingerprint, h.RecordedAt)
	if e != nil {
		return e
	}
	if e = storeOIDCRequest(ctx, tx, h, p.id, action, key, fp, o.ID); e != nil {
		return e
	}
	return securitystate.Audit(ctx, tx, "identity.oidc.operation_planned", p.id, map[string]any{"operationId": o.ID, "requestDigest": o.RequestDigest, "family": o.Family})
}
func (s *OIDCService) peopleContext(ctx context.Context, a DirectoryActor, id string) (context.Context, error) {
	var subjects []string
	e := s.current(ctx, a, false, false, func(tx storage.IdentityTx, _ securityjournal.Head, _ *directoryPrincipal) error {
		r, e := readOIDCOperation(ctx, tx, id)
		if e != nil {
			return e
		}
		if r.operation.State != "pending" {
			return nil
		}
		subjects = append(subjects, r.operation.CreatedBy)
		if c := r.operation.ProviderChange; c != nil {
			ids, e := securitystate.Strings(ctx, tx, `SELECT author_id FROM oidc_provider_versions WHERE id=? AND provider_id=?`, c.VersionID, c.ProviderID)
			if e != nil {
				return e
			}
			subjects = append(subjects, ids...)
		}
		ids, e := securitystate.Strings(ctx, tx, `SELECT reviewer_id FROM oidc_approvals WHERE operation_id=?`, id)
		subjects = append(subjects, ids...)
		return e
	})
	if e != nil {
		return nil, e
	}
	return s.directory.withDirectoryPeople(ctx, subjects)
}
func (s *OIDCService) replayContext(ctx context.Context, a DirectoryActor, action, key string) (context.Context, error) {
	var id string
	e := s.current(ctx, a, true, false, func(tx storage.IdentityTx, _ securityjournal.Head, p *directoryPrincipal) error {
		e := securitystate.One(ctx, tx, `SELECT operation_id FROM oidc_action_requests WHERE actor_id=? AND action=? AND request_key=?`, []any{p.id, action, key}, func(r storage.IdentityRows) error { return r.Scan(&id) })
		if errors.Is(e, storage.ErrNotFound) {
			return nil
		}
		return e
	})
	if e != nil {
		return nil, e
	}
	if id != "" {
		return s.peopleContext(ctx, a, id)
	}
	return ctx, nil
}
func (s *OIDCService) PlanActivationAtRevision(ctx context.Context, a DirectoryActor, id, key string, expected securityjournal.UInt63, in DirectoryActivation) (out *OIDCSecurityOperation, err error) {
	if !configmodel.ValidID(id) || !configmodel.ValidID(in.VersionID) || expected == 0 || expected >= securityjournal.MaxUInt63 || !directoryReason(in.Reason) || !directoryRequestKey.MatchString(key) {
		return nil, ErrOIDCInvalid
	}
	ctx, err = s.replayContext(ctx, a, "provider_plan", key)
	if err != nil {
		return nil, err
	}
	var author string
	err = s.current(ctx, a, true, false, func(tx storage.IdentityTx, _ securityjournal.Head, _ *directoryPrincipal) error {
		return securitystate.One(ctx, tx, `SELECT author_id FROM oidc_provider_versions WHERE id=? AND provider_id=?`, []any{in.VersionID, id}, func(r storage.IdentityRows) error { return r.Scan(&author) })
	})
	if err != nil {
		return nil, err
	}
	ctx, err = s.directory.withDirectoryPeople(ctx, []string{author})
	if err != nil {
		return nil, err
	}
	fp, e := configmodel.Digest(struct {
		ID       string
		Expected securityjournal.UInt63
		Request  DirectoryActivation
	}{id, expected, in})
	if e != nil {
		return nil, e
	}
	err = s.current(ctx, a, true, false, func(tx storage.IdentityTx, h securityjournal.Head, p *directoryPrincipal) error {
		current, _, e := readOIDCProvider(ctx, tx, id)
		if e != nil {
			return e
		}
		if current.Revision != expected {
			return ErrOIDCStale
		}
		if replay, e := oidcReplayRequest(ctx, tx, p.id, "provider_plan", key, fp); e != nil {
			return e
		} else if replay != "" {
			r, e := readOIDCOperation(ctx, tx, replay)
			if e != nil {
				return e
			}
			if r.operation.State != "applied" {
				if e = s.currentOperation(ctx, tx, h, r, false, false); e != nil {
					return e
				}
			}
			out = &r.operation
			return nil
		}
		provider, g, e := readOIDCProvider(ctx, tx, id)
		if e != nil {
			return e
		}
		v, e := readOIDCVersion(ctx, tx, id, in.VersionID)
		if e != nil {
			return e
		}
		f, e := securitystate.Floor(ctx, tx, provider.SecurityGuardID, provider.SecurityGuardID)
		if e != nil {
			return e
		}
		m := v.Configuration.Metadata
		if provider.Revision != expected || uint64(m.SecurityGuardVersion) <= g || uint64(m.SecurityGuardVersion) <= f {
			return ErrOIDCStale
		}
		if _, e = oidcVersionAuthor(ctx, tx, h, in.VersionID); e != nil {
			return e
		}
		if in.Enabled {
			if e = oidcTestCurrent(ctx, tx, h, v); e != nil {
				return e
			}
		}
		c := &ProviderSecurityChange{ProviderType: "oidc", ProviderID: id, VersionID: in.VersionID, ContentDigest: v.ContentDigest, GuardID: provider.SecurityGuardID, PreviousGuardVersion: securityjournal.UInt63(g), NextGuardVersion: m.SecurityGuardVersion, ExpectedRowVersion: expected, ExpectedAuthorityEpoch: h.Epoch, Enabled: in.Enabled, ExpiresAt: h.RecordedAt.Add(5 * time.Minute).UTC().Truncate(time.Microsecond), Reason: in.Reason}
		digest, e := configmodel.Digest(c)
		if e != nil {
			return e
		}
		out = &OIDCSecurityOperation{ID: securitystate.ID("oidcop"), Family: "provider_security_change", RequestDigest: digest, State: "pending", ApprovalStatus: "pending", SubjectID: id, CreatedBy: p.id, CreatedAt: h.RecordedAt, ProviderChange: c}
		return storeOIDCOperation(ctx, tx, h, p, out, "provider_plan", key, fp)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func oidcVersionAuthor(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, version string) (string, error) {
	var id, fp string
	e := securitystate.One(ctx, tx, `SELECT author_id,author_fingerprint FROM oidc_provider_versions WHERE id=?`, []any{version}, func(r storage.IdentityRows) error { return r.Scan(&id, &fp) })
	if e != nil {
		return "", e
	}
	actual, e := directorySubject(ctx, tx, id, h, false)
	if e != nil {
		return "", e
	}
	if actual != fp {
		return "", ErrOIDCStale
	}
	return id, nil
}
func (s *OIDCService) currentOperation(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, r *oidcOperationRecord, approved, materializing bool) error {
	o := r.operation
	if o.State != "pending" {
		return ErrOIDCStale
	}
	var expires time.Time
	var epoch, old, next, row securityjournal.UInt63
	var guard, versionAuthor string
	if c := o.ProviderChange; c != nil {
		expires, epoch, old, next, row, guard = c.ExpiresAt, c.ExpectedAuthorityEpoch, c.PreviousGuardVersion, c.NextGuardVersion, c.ExpectedRowVersion, c.GuardID
		p, g, e := readOIDCProvider(ctx, tx, c.ProviderID)
		if e != nil {
			return e
		}
		v, e := readOIDCVersion(ctx, tx, c.ProviderID, c.VersionID)
		if e != nil {
			return e
		}
		if p.Revision != row || p.SecurityGuardID != guard || g != uint64(old) || v.ContentDigest != c.ContentDigest || v.Configuration.Metadata.SecurityGuardVersion != next {
			return ErrOIDCStale
		}
		versionAuthor, e = oidcVersionAuthor(ctx, tx, h, c.VersionID)
		if e != nil {
			return e
		}
		if c.Enabled && !materializing {
			if e = oidcTestCurrent(ctx, tx, h, v); e != nil {
				return e
			}
		}
	} else if c := o.OIDCLinkChange; c != nil {
		expires, epoch, old, next, row, guard = c.ExpiresAt, c.ExpectedAuthorityEpoch, c.PreviousGuardVersion, c.NextGuardVersion, c.ExpectedRowVersion, c.GuardID
		p, pg, e := readOIDCProvider(ctx, tx, c.ProviderID)
		if e != nil {
			return e
		}
		if p.Configuration == nil || p.Configuration.Metadata.VersionID != c.ProviderVersionID || pg != uint64(c.ProviderGuardVersion) {
			return ErrOIDCStale
		}
		if c.Enabled {
			if _, e = currentOIDCProvider(ctx, tx, c.ProviderID); e != nil {
				return e
			}
		}
		l, g, e := readOIDCLink(ctx, tx, c.ProviderID, c.LinkID)
		if e != nil {
			return e
		}
		v, e := readOIDCLinkVersion(ctx, tx, c.LinkID, c.VersionID)
		if e != nil {
			return e
		}
		if l.Revision != row || g != uint64(old) || l.SecurityGuardID != guard || l.Subject != c.Subject || v.ContentDigest != c.ContentDigest || v.DirectoryIdentityID != c.DirectoryIdentityID || v.PrincipalID != c.TargetPrincipalID || v.SecurityGuardVersion != next {
			return ErrOIDCStale
		}
		if !c.Enabled && (l.Configuration == nil || l.Configuration.DirectoryIdentityID != c.DirectoryIdentityID) {
			return ErrOIDCStale
		}
		if e = oidcTargetProof(ctx, tx, h, *c); e != nil {
			return e
		}
		if c.Enabled {
			var count int
			e = securitystate.One(ctx, tx, `SELECT COUNT(*) FROM oidc_links l JOIN oidc_link_versions v ON v.id=l.active_version_id LEFT JOIN authenticator_floors f ON f.principal_id=l.guard_id AND f.authenticator_id=l.guard_id WHERE l.provider_id=? AND l.id<>? AND l.enabled=TRUE AND l.guard_version>=COALESCE(f.minimum_version,0) AND v.principal_id=?`, []any{c.ProviderID, c.LinkID, c.TargetPrincipalID}, func(r storage.IdentityRows) error { return r.Scan(&count) })
			if e != nil {
				return e
			}
			if count >= 2 {
				return storage.ErrConflict
			}
		}
	} else {
		return ErrOIDCStale
	}
	if h.Epoch != epoch || h.RecordedAt.IsZero() || !h.RecordedAt.Before(expires) || next <= old {
		return ErrOIDCStale
	}
	f, e := securitystate.Floor(ctx, tx, guard, guard)
	if e != nil {
		return e
	}
	if (!materializing && uint64(next) <= f) || (materializing && uint64(next) != f) {
		return ErrOIDCStale
	}
	actual, e := directorySubject(ctx, tx, o.CreatedBy, h, false)
	if e != nil {
		return e
	}
	if actual != r.authorFingerprint {
		return ErrOIDCStale
	}
	if approved {
		var reviewer, fp string
		var mfa, primary time.Time
		e = securitystate.One(ctx, tx, `SELECT reviewer_id,reviewer_fingerprint,mfa_at,primary_at FROM oidc_approvals WHERE operation_id=? AND request_digest=?`, []any{o.ID, o.RequestDigest}, func(r storage.IdentityRows) error { return r.Scan(&reviewer, &fp, &mfa, &primary) })
		if errors.Is(e, storage.ErrNotFound) {
			return storage.ErrApprovalRequired
		}
		if e != nil {
			return e
		}
		if reviewer == o.CreatedBy || reviewer == versionAuthor || h.RecordedAt.Before(mfa) || h.RecordedAt.Sub(mfa) > 5*time.Minute || h.RecordedAt.Before(primary) || h.RecordedAt.Sub(primary) > 5*time.Minute {
			return ErrOIDCStale
		}
		if e = RequireDistinctPeople(ctx, tx, reviewer, o.CreatedBy); e != nil {
			return e
		}
		if versionAuthor != "" {
			if e = RequireDistinctPeople(ctx, tx, reviewer, versionAuthor); e != nil {
				return e
			}
		}
		actual, e := directorySubject(ctx, tx, reviewer, h, true)
		if e != nil {
			return e
		}
		if actual != fp {
			return ErrOIDCStale
		}
	}
	return nil
}
func (s *OIDCService) GetOperation(ctx context.Context, a DirectoryActor, id string) (out *OIDCSecurityOperation, err error) {
	ctx, err = s.peopleContext(ctx, a, id)
	if err != nil {
		return nil, err
	}
	var change *OIDCLinkChange
	err = s.current(ctx, a, false, false, func(tx storage.IdentityTx, _ securityjournal.Head, _ *directoryPrincipal) error {
		r, e := readOIDCOperation(ctx, tx, id)
		if e == nil && r.operation.State == "pending" {
			change = r.operation.OIDCLinkChange
		}
		return e
	})
	if err != nil {
		return nil, err
	}
	var targetErr error
	if change != nil {
		var checked context.Context
		checked, targetErr = s.withLiveTarget(ctx, *change)
		if targetErr == nil {
			ctx = checked
		} else if !directoryPermanentlyStale(targetErr) {
			return nil, targetErr
		}
	}
	err = s.current(ctx, a, false, false, func(tx storage.IdentityTx, h securityjournal.Head, _ *directoryPrincipal) error {
		r, e := readOIDCOperation(ctx, tx, id)
		if e != nil {
			return e
		}
		out = &r.operation
		if out.State == "pending" {
			if targetErr != nil {
				out.ApprovalStatus = "expired"
				return nil
			}
			e = s.currentOperation(ctx, tx, h, r, out.ApprovalStatus == "approved", false)
			if errors.Is(e, ErrDirectoryUnavailable) {
				return e
			}
			if e != nil {
				out.ApprovalStatus = "expired"
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *OIDCService) ApproveOperationRequest(ctx context.Context, a DirectoryActor, id, key, digest, reason string) (out *DirectoryApprovalView, err error) {
	if !directoryRequestKey.MatchString(key) || !directoryReason(reason) {
		return nil, ErrOIDCInvalid
	}
	ctx, err = s.peopleContext(ctx, a, id)
	if err != nil {
		return nil, err
	}
	var change *OIDCLinkChange
	err = s.current(ctx, a, true, true, func(tx storage.IdentityTx, _ securityjournal.Head, _ *directoryPrincipal) error {
		r, e := readOIDCOperation(ctx, tx, id)
		if e == nil {
			change = r.operation.OIDCLinkChange
		}
		return e
	})
	if err != nil {
		return nil, err
	}
	if change != nil {
		ctx, err = s.withLiveTarget(ctx, *change)
		if err != nil {
			return nil, err
		}
	}
	fp, e := configmodel.Digest(struct{ Digest, Reason string }{digest, reason})
	if e != nil {
		return nil, e
	}
	err = s.current(ctx, a, true, true, func(tx storage.IdentityTx, h securityjournal.Head, p *directoryPrincipal) error {
		r, e := readOIDCOperation(ctx, tx, id)
		if e != nil {
			return e
		}
		if r.operation.RequestDigest != digest {
			return ErrOIDCStale
		}
		if r.operation.CreatedBy == p.id {
			return storage.ErrPermissionDenied
		}
		if e = RequireDistinctPeople(ctx, tx, p.id, r.operation.CreatedBy); e != nil {
			return e
		}
		if c := r.operation.ProviderChange; c != nil {
			author, e := oidcVersionAuthor(ctx, tx, h, c.VersionID)
			if e != nil {
				return e
			}
			if author == p.id {
				return storage.ErrPermissionDenied
			}
			if e = RequireDistinctPeople(ctx, tx, p.id, author); e != nil {
				return e
			}
		}
		if e = s.currentOperation(ctx, tx, h, r, false, false); e != nil {
			return e
		}
		if e = storeOIDCRequest(ctx, tx, h, p.id, "approve:"+id, key, fp, id); e != nil {
			return e
		}
		var prior, priorReason, approvalID string
		e = securitystate.One(ctx, tx, `SELECT id,reviewer_id,reason FROM oidc_approvals WHERE operation_id=?`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&approvalID, &prior, &priorReason) })
		if e == nil {
			if prior != p.id || priorReason != reason {
				return storage.ErrConflict
			}
			if e = s.currentOperation(ctx, tx, h, r, true, false); e != nil {
				return e
			}
			out = &DirectoryApprovalView{ApprovalID: approvalID, OperationID: id, RequestDigest: digest, ApprovedBy: p.id}
			return nil
		}
		if !errors.Is(e, storage.ErrNotFound) {
			return e
		}
		var primary time.Time
		if e = securitystate.One(ctx, tx, `SELECT primary_at FROM sessions WHERE token_hash=?`, []any{a.TokenHash}, func(r storage.IdentityRows) error { return r.Scan(&primary) }); e != nil {
			return e
		}
		approvalID = securitystate.ID("approval")
		_, e = tx.Exec(ctx, `INSERT INTO oidc_approvals(id,operation_id,request_digest,reviewer_id,reviewer_fingerprint,mfa_at,primary_at,created_at,reason) VALUES(?,?,?,?,?,?,?,?,?)`, approvalID, id, digest, p.id, p.fingerprint, p.mfa, primary, h.RecordedAt, reason)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `UPDATE oidc_operations SET approval_status='approved' WHERE id=? AND state='pending'`, id)
		if e != nil {
			return e
		}
		out = &DirectoryApprovalView{ApprovalID: approvalID, OperationID: id, RequestDigest: digest, ApprovedBy: p.id}
		return securitystate.Audit(ctx, tx, "identity.oidc.operation_approved", p.id, map[string]any{"operationId": id, "requestDigest": digest})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

type oidcChangeIntent struct {
	OperationID, RequestDigest, ActorID, ActorFingerprint string
	ActorMFAAt, ActorPrimaryAt                            time.Time
}

func (s *OIDCService) ExecuteOperationRequest(ctx context.Context, a DirectoryActor, id, key, digest, reason string) (out *OIDCSecurityOperation, err error) {
	if !directoryRequestKey.MatchString(key) || !directoryReason(reason) {
		return nil, ErrOIDCInvalid
	}
	ctx, err = s.peopleContext(ctx, a, id)
	if err != nil {
		return nil, err
	}
	var r *oidcOperationRecord
	var h0 securityjournal.Head
	var version *OIDCVersionView
	err = s.current(ctx, a, true, false, func(tx storage.IdentityTx, h securityjournal.Head, _ *directoryPrincipal) error {
		var e error
		r, e = readOIDCOperation(ctx, tx, id)
		if e != nil {
			return e
		}
		if r.operation.RequestDigest != digest {
			return ErrOIDCStale
		}
		h0 = h
		if r.operation.ProviderChange != nil && r.operation.ProviderChange.Enabled {
			version, e = readOIDCVersion(ctx, tx, r.operation.ProviderChange.ProviderID, r.operation.ProviderChange.VersionID)
		}
		return e
	})
	if err != nil {
		return nil, err
	}
	if r.operation.State != "applied" {
		if version != nil {
			ctx, err = s.connectivity(ctx, version, h0)
			if err != nil {
				return nil, err
			}
		}
		if c := r.operation.OIDCLinkChange; c != nil {
			ctx, err = s.withLiveTarget(ctx, *c)
			if err != nil {
				return nil, err
			}
		}
	}
	fp, e := configmodel.Digest(struct{ Digest, Reason string }{digest, reason})
	if e != nil {
		return nil, e
	}
	var applied bool
	err = s.current(ctx, a, true, false, func(tx storage.IdentityTx, h securityjournal.Head, p *directoryPrincipal) error {
		r, e := readOIDCOperation(ctx, tx, id)
		if e != nil {
			return e
		}
		if r.operation.RequestDigest != digest {
			return ErrOIDCStale
		}
		if r.operation.State != "applied" {
			if e = s.currentOperation(ctx, tx, h, r, true, false); e != nil {
				return e
			}
		}
		if e = storeOIDCRequest(ctx, tx, h, p.id, "execute:"+id, key, fp, id); e != nil {
			return e
		}
		out = &r.operation
		applied = out.State == "applied"
		return nil
	})
	if err != nil {
		return nil, err
	}
	if applied {
		return out, nil
	}
	err = s.identity.Coordinator.ExecuteDynamic(ctx, "oidc_security_change", func(tx storage.IdentityTx, h securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error) {
		p, e := s.actor(ctx, tx, h, a, true, false)
		if e != nil {
			return nil, nil, e
		}
		if e = CheckOIDCSessionProjection(ctx, tx, h, a.TokenHash); e != nil {
			return nil, nil, e
		}
		r, e := readOIDCOperation(ctx, tx, id)
		if e != nil {
			return nil, nil, e
		}
		if r.operation.RequestDigest != digest {
			return nil, nil, ErrOIDCStale
		}
		if e = s.currentOperation(ctx, tx, h, r, true, false); e != nil {
			return nil, nil, e
		}
		guard := ""
		var next securityjournal.UInt63
		if c := r.operation.ProviderChange; c != nil {
			guard, next = c.GuardID, c.NextGuardVersion
		} else {
			guard, next = r.operation.OIDCLinkChange.GuardID, r.operation.OIDCLinkChange.NextGuardVersion
		}
		var primary time.Time
		if e = securitystate.One(ctx, tx, `SELECT primary_at FROM sessions WHERE token_hash=?`, []any{a.TokenHash}, func(r storage.IdentityRows) error { return r.Scan(&primary) }); e != nil {
			return nil, nil, e
		}
		raw, e := configmodel.CanonicalJSON(oidcChangeIntent{OperationID: id, RequestDigest: digest, ActorID: p.id, ActorFingerprint: p.fingerprint, ActorMFAAt: p.mfa, ActorPrimaryAt: primary})
		return raw, []securityjournal.AppendRequest{securitystate.FloorRequest(p.id, guard, guard, uint64(next))}, e
	})
	if err != nil {
		return nil, err
	}
	err = s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, _ securityjournal.Head) error {
		r, e := readOIDCOperation(ctx, tx, id)
		if e == nil {
			out = &r.operation
		}
		return e
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *OIDCService) materializeChange(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
	var intent oidcChangeIntent
	if json.Unmarshal(raw, &intent) != nil {
		return ErrOIDCStale
	}
	r, e := readOIDCOperation(ctx, tx, intent.OperationID)
	if e != nil {
		return e
	}
	if intent.RequestDigest != r.operation.RequestDigest {
		return ErrOIDCStale
	}
	if r.operation.State == "applied" {
		return nil
	}
	head, e := s.identity.Coordinator.Authority.Head(ctx)
	if e != nil {
		return ErrDirectoryUnavailable
	}
	current := s.currentOperation(ctx, tx, head, r, true, true)
	if head.RecordedAt.Before(intent.ActorMFAAt) || head.RecordedAt.Sub(intent.ActorMFAAt) > 5*time.Minute || head.RecordedAt.Before(intent.ActorPrimaryAt) || head.RecordedAt.Sub(intent.ActorPrimaryAt) > 5*time.Minute {
		current = ErrOIDCStale
	}
	if current == nil {
		fp, e := directorySubject(ctx, tx, intent.ActorID, head, false)
		if e != nil || fp != intent.ActorFingerprint {
			current = ErrOIDCStale
		}
	}
	if c := r.operation.ProviderChange; c != nil && c.Enabled && current == nil {
		proof, ok := ctx.Value(oidcConnectivityKey{}).(oidcConnectivity)
		if !ok || proof.digest != c.ContentDigest || proof.epoch != head.Epoch || head.RecordedAt.Before(proof.observedAt) || head.RecordedAt.Sub(proof.observedAt) > 10*time.Second {
			current = ErrDirectoryUnavailable
		}
	}
	if current != nil {
		_, e = tx.Exec(ctx, `UPDATE oidc_operations SET state='recovery_required' WHERE id=?`, r.operation.ID)
		return e
	}
	var n int64
	if c := r.operation.ProviderChange; c != nil {
		n, e = tx.Exec(ctx, `UPDATE oidc_providers SET enabled=?,active_version_id=?,guard_version=?,row_version=row_version+1 WHERE id=? AND row_version=? AND guard_id=? AND guard_version=?`, c.Enabled, c.VersionID, int64(c.NextGuardVersion), c.ProviderID, int64(c.ExpectedRowVersion), c.GuardID, int64(c.PreviousGuardVersion))
	} else {
		c := r.operation.OIDCLinkChange
		n, e = tx.Exec(ctx, `UPDATE oidc_links SET enabled=?,active_version_id=?,guard_version=?,row_version=row_version+1 WHERE id=? AND provider_id=? AND row_version=? AND guard_id=? AND guard_version=?`, c.Enabled, c.VersionID, int64(c.NextGuardVersion), c.LinkID, c.ProviderID, int64(c.ExpectedRowVersion), c.GuardID, int64(c.PreviousGuardVersion))
	}
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrOIDCStale
	}
	_, e = tx.Exec(ctx, `UPDATE oidc_operations SET state='applied' WHERE id=?`, r.operation.ID)
	if e != nil {
		return e
	}
	return securitystate.Audit(ctx, tx, "identity.oidc.operation_applied", intent.ActorID, map[string]any{"operationId": r.operation.ID, "requestDigest": intent.RequestDigest})
}
