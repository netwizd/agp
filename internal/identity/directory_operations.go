package identity

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type ProviderSecurityChange struct {
	ProviderType           string                 `json:"providerType"`
	ProviderID             string                 `json:"providerId"`
	VersionID              string                 `json:"versionId"`
	ContentDigest          string                 `json:"contentDigest"`
	GuardID                string                 `json:"guardId"`
	PreviousGuardVersion   securityjournal.UInt63 `json:"previousGuardVersion"`
	NextGuardVersion       securityjournal.UInt63 `json:"nextGuardVersion"`
	ExpectedRowVersion     securityjournal.UInt63 `json:"expectedRowVersion"`
	ExpectedAuthorityEpoch securityjournal.UInt63 `json:"expectedAuthorityEpoch"`
	Enabled                bool                   `json:"enabled"`
	ExpiresAt              time.Time              `json:"expiresAt"`
	Reason                 string                 `json:"reason"`
}
type ProviderSecurityOperation struct {
	ID             string                 `json:"id"`
	Family         string                 `json:"family"`
	RequestDigest  string                 `json:"requestDigest"`
	State          string                 `json:"state"`
	ApprovalStatus string                 `json:"approvalStatus"`
	SubjectID      string                 `json:"subjectId"`
	CreatedBy      string                 `json:"createdBy"`
	CreatedAt      time.Time              `json:"createdAt"`
	ProviderChange ProviderSecurityChange `json:"providerChange"`
}
type directoryOperationRecord struct {
	operation         ProviderSecurityOperation
	authorFingerprint string
}
type directoryChangeIntent struct {
	OperationID, RequestDigest string
	Change                     ProviderSecurityChange
	ActorID, ApproverID        string
}

var directoryRequestKey = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

func readDirectoryOperation(ctx context.Context, tx storage.IdentityTx, id string) (*directoryOperationRecord, error) {
	if !configmodel.ValidID(id) {
		return nil, ErrDirectoryInvalid
	}
	r := &directoryOperationRecord{}
	var raw string
	e := securitystate.One(ctx, tx, `SELECT intent_json,author_fingerprint,state,approval_status FROM directory_provider_operations WHERE id=?`, []any{id}, func(row storage.IdentityRows) error {
		return row.Scan(&raw, &r.authorFingerprint, &r.operation.State, &r.operation.ApprovalStatus)
	})
	if e != nil {
		return nil, e
	}
	state, approval := r.operation.State, r.operation.ApprovalStatus
	if json.Unmarshal([]byte(raw), &r.operation) != nil {
		return nil, ErrDirectoryStale
	}
	if r.operation.ID != id || r.operation.Family != "provider_security_change" || r.operation.ProviderChange.ProviderType != "directory" || r.operation.SubjectID != r.operation.ProviderChange.ProviderID {
		return nil, ErrDirectoryStale
	}
	digest, e := configmodel.Digest(r.operation.ProviderChange)
	if e != nil || digest != r.operation.RequestDigest {
		return nil, ErrDirectoryStale
	}
	canonical, e := configmodel.CanonicalJSON(r.operation)
	if e != nil || string(canonical) != raw {
		return nil, ErrDirectoryStale
	}
	r.operation.State = state
	r.operation.ApprovalStatus = approval
	return r, nil
}
func (s *DirectoryService) PlanActivation(ctx context.Context, a DirectoryActor, id, key string, in DirectoryActivation) (*ProviderSecurityOperation, error) {
	return s.planActivation(ctx, a, id, key, 0, in)
}

// PlanActivationAtRevision enforces HTTP If-Match in the same locked transaction
// as the frozen intent. Zero and wildcard row versions are never accepted.
func (s *DirectoryService) PlanActivationAtRevision(ctx context.Context, a DirectoryActor, id, key string, expected securityjournal.UInt63, in DirectoryActivation) (*ProviderSecurityOperation, error) {
	if expected == 0 || expected > securityjournal.MaxUInt63 {
		return nil, ErrDirectoryInvalid
	}
	return s.planActivation(ctx, a, id, key, expected, in)
}
func (s *DirectoryService) planActivation(ctx context.Context, a DirectoryActor, id, key string, expected securityjournal.UInt63, in DirectoryActivation) (out *ProviderSecurityOperation, err error) {
	if !configmodel.ValidID(id) || !configmodel.ValidID(in.VersionID) || !directoryReason(in.Reason) || !directoryRequestKey.MatchString(key) {
		return nil, ErrDirectoryInvalid
	}
	ctx, err = s.versionPeopleContext(ctx, a, id, in.VersionID)
	if err != nil {
		return nil, err
	}
	fp, e := configmodel.Digest(struct {
		ID      string
		Request DirectoryActivation
	}{id, in})
	if e != nil {
		return nil, e
	}
	err = s.current(ctx, a, true, false, func(tx storage.IdentityTx, h securityjournal.Head, p *directoryPrincipal) error {
		if expected != 0 {
			current, _, e := readDirectory(ctx, tx, id)
			if e != nil {
				return e
			}
			if current.Revision != expected {
				return ErrDirectoryStale
			}
		}
		var prior, opID string
		e := securitystate.One(ctx, tx, `SELECT fingerprint,operation_id FROM directory_provider_requests WHERE actor_id=? AND request_key=?`, []any{p.id, key}, func(r storage.IdentityRows) error { return r.Scan(&prior, &opID) })
		if e == nil {
			if prior != fp {
				return storage.ErrConflict
			}
			r, e := readDirectoryOperation(ctx, tx, opID)
			if e != nil {
				return e
			}
			if r.operation.State != "applied" {
				if e = s.currentDirectoryOperation(ctx, tx, h, r, false); e != nil {
					return e
				}
			}
			out = &r.operation
			return nil
		}
		if e != storage.ErrNotFound {
			return e
		}
		provider, guard, e := readDirectory(ctx, tx, id)
		if e != nil {
			return e
		}
		if provider.Revision == securityjournal.MaxUInt63 {
			return ErrDirectoryStale
		}
		v, e := readDirectoryVersion(ctx, tx, id, in.VersionID)
		if e != nil {
			return e
		}
		floor, e := securitystate.Floor(ctx, tx, provider.SecurityGuardID, provider.SecurityGuardID)
		if e != nil {
			return e
		}
		if uint64(v.Configuration.Metadata.SecurityGuardVersion) <= guard || uint64(v.Configuration.Metadata.SecurityGuardVersion) <= floor {
			return ErrDirectoryStale
		}
		if _, _, e = currentDirectoryVersionAuthor(ctx, tx, v.Configuration.Metadata.VersionID, h); e != nil {
			return e
		}
		if in.Enabled {
			if s.validator == nil {
				return ErrDirectoryUnavailable
			}
			if e = directoryTestCurrent(ctx, tx, h, v); e != nil {
				return e
			}
		}
		change := ProviderSecurityChange{ProviderType: "directory", ProviderID: id, VersionID: in.VersionID, ContentDigest: v.ContentDigest, GuardID: provider.SecurityGuardID, PreviousGuardVersion: securityjournal.UInt63(guard), NextGuardVersion: v.Configuration.Metadata.SecurityGuardVersion, ExpectedRowVersion: provider.Revision, ExpectedAuthorityEpoch: h.Epoch, Enabled: in.Enabled, ExpiresAt: h.RecordedAt.Add(5 * time.Minute).UTC().Truncate(time.Microsecond), Reason: in.Reason}
		requestDigest, e := configmodel.Digest(change)
		if e != nil {
			return e
		}
		out = &ProviderSecurityOperation{ID: securitystate.ID("securityop"), Family: "provider_security_change", RequestDigest: requestDigest, State: "pending", ApprovalStatus: "pending", SubjectID: id, CreatedBy: p.id, CreatedAt: h.RecordedAt.UTC().Truncate(time.Microsecond), ProviderChange: change}
		raw, e := configmodel.CanonicalJSON(out)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO directory_provider_operations(id,provider_id,version_id,request_digest,intent_json,author_id,author_fingerprint,state,approval_status,created_at) VALUES(?,?,?,?,?,?,?,'pending','pending',?)`, out.ID, id, in.VersionID, requestDigest, string(raw), p.id, p.fingerprint, out.CreatedAt)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO directory_provider_requests(actor_id,request_key,fingerprint,operation_id) VALUES(?,?,?,?)`, p.id, key, fp, out.ID)
		if e != nil {
			return e
		}
		return securitystate.Audit(ctx, tx, "identity.directory.activation_planned", p.id, map[string]any{"operationId": out.ID, "requestDigest": requestDigest, "enabled": in.Enabled})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *DirectoryService) currentDirectoryOperation(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, r *directoryOperationRecord, approval bool) error {
	o := r.operation
	c := o.ProviderChange
	if h.Epoch != c.ExpectedAuthorityEpoch || h.RecordedAt.Before(o.CreatedAt) || !h.RecordedAt.Before(c.ExpiresAt) || o.State != "pending" {
		return ErrDirectoryStale
	}
	provider, guard, e := readDirectory(ctx, tx, c.ProviderID)
	if e != nil {
		return e
	}
	if provider.Revision != c.ExpectedRowVersion || provider.SecurityGuardID != c.GuardID || guard != uint64(c.PreviousGuardVersion) {
		return ErrDirectoryStale
	}
	v, e := readDirectoryVersion(ctx, tx, c.ProviderID, c.VersionID)
	if e != nil {
		return e
	}
	if v.ContentDigest != c.ContentDigest || v.Configuration.Metadata.SecurityGuardID != c.GuardID || v.Configuration.Metadata.SecurityGuardVersion != c.NextGuardVersion || v.Configuration.Spec.ForestGUID != provider.ForestGUID {
		return ErrDirectoryStale
	}
	floor, e := securitystate.Floor(ctx, tx, c.GuardID, c.GuardID)
	if e != nil {
		return e
	}
	if c.NextGuardVersion <= c.PreviousGuardVersion || uint64(c.NextGuardVersion) <= floor {
		return ErrDirectoryStale
	}
	author, e := directorySubject(ctx, tx, o.CreatedBy, h, false)
	if e != nil {
		return e
	}
	if author != r.authorFingerprint {
		return ErrDirectoryStale
	}
	versionAuthor, _, e := currentDirectoryVersionAuthor(ctx, tx, c.VersionID, h)
	if e != nil {
		return e
	}
	if c.Enabled {
		if s.validator == nil {
			return ErrDirectoryUnavailable
		}
		if e = directoryTestCurrent(ctx, tx, h, v); e != nil {
			return e
		}
	}
	if approval {
		var approver, fp string
		var mfa time.Time
		e = securitystate.One(ctx, tx, `SELECT reviewer_id,reviewer_fingerprint,mfa_at FROM directory_provider_approvals WHERE operation_id=? AND request_digest=?`, []any{o.ID, o.RequestDigest}, func(r storage.IdentityRows) error { return r.Scan(&approver, &fp, &mfa) })
		if errors.Is(e, storage.ErrNotFound) {
			return storage.ErrApprovalRequired
		}
		if e != nil {
			return e
		}
		if approver == o.CreatedBy || approver == versionAuthor || h.RecordedAt.Before(mfa) || h.RecordedAt.Sub(mfa) > 5*time.Minute {
			return ErrDirectoryStale
		}
		if e = RequireDistinctPeople(ctx, tx, approver, o.CreatedBy); e != nil {
			return e
		}
		if e = RequireDistinctPeople(ctx, tx, approver, versionAuthor); e != nil {
			return e
		}
		current, e := directorySubject(ctx, tx, approver, h, true)
		if e != nil {
			return e
		}
		if current != fp {
			return ErrDirectoryStale
		}
	}
	return nil
}
func directoryPermanentlyStale(e error) bool {
	return errors.Is(e, ErrDirectoryStale) || errors.Is(e, ErrProof) || errors.Is(e, storage.ErrPermissionDenied) || errors.Is(e, storage.ErrNotFound)
}
func (s *DirectoryService) GetOperation(ctx context.Context, a DirectoryActor, id string) (out *ProviderSecurityOperation, err error) {
	checked, peopleErr := s.operationPeopleContext(ctx, a, id, false, false)
	if peopleErr != nil && !directoryPermanentlyStale(peopleErr) {
		return nil, peopleErr
	}
	if peopleErr == nil {
		ctx = checked
	}
	err = s.current(ctx, a, false, false, func(tx storage.IdentityTx, h securityjournal.Head, _ *directoryPrincipal) error {
		r, e := readDirectoryOperation(ctx, tx, id)
		if e != nil {
			return e
		}
		out = &r.operation
		if out.State == "pending" {
			if peopleErr != nil {
				out.ApprovalStatus = "expired"
				return nil
			}
			currentErr := s.currentDirectoryOperation(ctx, tx, h, r, out.ApprovalStatus == "approved")
			if directoryPermanentlyStale(currentErr) {
				out.ApprovalStatus = "expired"
			} else if currentErr != nil {
				return currentErr
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *DirectoryService) ApproveOperation(ctx context.Context, a DirectoryActor, id, requestDigest, reason string) (*ProviderSecurityOperation, error) {
	checked, e := s.operationPeopleContext(ctx, a, id, true, true)
	if e != nil {
		return nil, e
	}
	return s.approveOperation(checked, a, id, requestDigest, reason, "")
}
func (s *DirectoryService) approveOperation(ctx context.Context, a DirectoryActor, id, requestDigest, reason, key string) (out *ProviderSecurityOperation, err error) {
	if !directoryReason(reason) {
		return nil, ErrDirectoryInvalid
	}
	err = s.current(ctx, a, true, true, func(tx storage.IdentityTx, h securityjournal.Head, p *directoryPrincipal) error {
		r, e := readDirectoryOperation(ctx, tx, id)
		if e != nil {
			return e
		}
		versionAuthor, _, e := currentDirectoryVersionAuthor(ctx, tx, r.operation.ProviderChange.VersionID, h)
		if e != nil {
			return e
		}
		if r.operation.CreatedBy == p.id || versionAuthor == p.id {
			return storage.ErrPermissionDenied
		}
		if e = RequireDistinctPeople(ctx, tx, p.id, r.operation.CreatedBy); e != nil {
			return e
		}
		if e = RequireDistinctPeople(ctx, tx, p.id, versionAuthor); e != nil {
			return e
		}
		if requestDigest != r.operation.RequestDigest {
			return ErrDirectoryStale
		}
		if e = s.currentDirectoryOperation(ctx, tx, h, r, false); e != nil {
			return e
		}
		if key != "" {
			if e = directoryActionRequest(ctx, tx, h, p.id, "approve:"+id, key, requestDigest, reason); e != nil {
				return e
			}
		}
		var prior, priorReason string
		e = securitystate.One(ctx, tx, `SELECT reviewer_id,reason FROM directory_provider_approvals WHERE operation_id=?`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&prior, &priorReason) })
		if e == nil {
			if prior != p.id || priorReason != reason {
				return storage.ErrConflict
			}
			if e = s.currentDirectoryOperation(ctx, tx, h, r, true); e != nil {
				return e
			}
			out = &r.operation
			return nil
		}
		if e != storage.ErrNotFound {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO directory_provider_approvals(id,operation_id,request_digest,reviewer_id,reviewer_fingerprint,mfa_at,created_at,reason) VALUES(?,?,?,?,?,?,?,?)`, securitystate.ID("approval"), id, requestDigest, p.id, p.fingerprint, p.mfa, h.RecordedAt, reason)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE directory_provider_operations SET approval_status='approved' WHERE id=? AND state='pending'`, id); e != nil {
			return e
		}
		out = &r.operation
		out.ApprovalStatus = "approved"
		return securitystate.Audit(ctx, tx, "identity.directory.activation_approved", p.id, map[string]any{"operationId": id, "requestDigest": requestDigest})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *DirectoryService) ExecuteOperation(ctx context.Context, a DirectoryActor, id, requestDigest string) (out *ProviderSecurityOperation, err error) {
	ctx, err = s.operationPeopleContext(ctx, a, id, true, false)
	if err != nil {
		return nil, err
	}
	// Read and authorize before opening any network connection. A fresh real
	// connector test is mandatory for enable even if a previous test is in TTL.
	var version, provider string
	var enabled, applied bool
	err = s.current(ctx, a, true, false, func(tx storage.IdentityTx, h securityjournal.Head, _ *directoryPrincipal) error {
		r, e := readDirectoryOperation(ctx, tx, id)
		if e != nil {
			return e
		}
		if r.operation.RequestDigest != requestDigest {
			return ErrDirectoryStale
		}
		if r.operation.State == "applied" {
			out = &r.operation
			applied = true
			return nil
		}
		if e = s.currentDirectoryOperation(ctx, tx, h, r, true); e != nil {
			return e
		}
		version = r.operation.ProviderChange.VersionID
		provider = r.operation.SubjectID
		enabled = r.operation.ProviderChange.Enabled
		return nil
	})
	if err != nil {
		return nil, err
	}
	if applied {
		return out, nil
	}
	if enabled {
		test, e := s.TestProvider(ctx, a, provider, version)
		if e != nil {
			return nil, e
		}
		if test.State != "passed" {
			return nil, ErrDirectoryUnavailable
		}
	}
	err = s.coordinator.ExecuteDynamic(ctx, "directory_provider_change", func(tx storage.IdentityTx, h securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error) {
		actor, e := s.actor(ctx, tx, h, a, true, false)
		if e != nil {
			return nil, nil, e
		}
		r, e := readDirectoryOperation(ctx, tx, id)
		if e != nil {
			return nil, nil, e
		}
		if r.operation.RequestDigest != requestDigest {
			return nil, nil, ErrDirectoryStale
		}
		if e = s.currentDirectoryOperation(ctx, tx, h, r, true); e != nil {
			return nil, nil, e
		}
		var approver string
		e = securitystate.One(ctx, tx, `SELECT reviewer_id FROM directory_provider_approvals WHERE operation_id=?`, []any{id}, func(row storage.IdentityRows) error { return row.Scan(&approver) })
		if e != nil {
			return nil, nil, e
		}
		intent := directoryChangeIntent{OperationID: id, RequestDigest: requestDigest, Change: r.operation.ProviderChange, ActorID: actor.id, ApproverID: approver}
		raw, e := configmodel.CanonicalJSON(intent)
		if e != nil {
			return nil, nil, e
		}
		c := intent.Change
		return raw, []securityjournal.AppendRequest{securitystate.FloorRequest(actor.id, c.GuardID, c.GuardID, uint64(c.NextGuardVersion))}, nil
	})
	if err != nil {
		return nil, err
	}
	// A successful self-provider change invalidates the executor's old directory
	// session. Return only the exact operation already authorized above without
	// requiring that deliberately invalidated credential to authenticate again.
	err = s.coordinator.Current(ctx, func(tx storage.IdentityTx, _ securityjournal.Head) error {
		r, e := readDirectoryOperation(ctx, tx, id)
		if e != nil {
			return e
		}
		if r.operation.RequestDigest != requestDigest {
			return ErrDirectoryStale
		}
		out = &r.operation
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *DirectoryService) materializeDirectoryChange(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
	var in directoryChangeIntent
	if json.Unmarshal(raw, &in) != nil {
		return ErrDirectoryStale
	}
	r, e := readDirectoryOperation(ctx, tx, in.OperationID)
	if e != nil {
		return e
	}
	c := in.Change
	actual, e := configmodel.Digest(c)
	if e != nil || actual != in.RequestDigest || r.operation.RequestDigest != actual {
		return ErrDirectoryStale
	}
	if r.operation.State == "applied" {
		return nil
	}
	floor, e := securitystate.Floor(ctx, tx, c.GuardID, c.GuardID)
	if e != nil {
		return e
	}
	// Use the independently authenticated journal time during restart/recovery.
	// The control-plane wall clock is not an authority for approval freshness.
	if s.coordinator == nil || s.coordinator.Authority == nil {
		return ErrDirectoryUnavailable
	}
	head, e := s.coordinator.Authority.Head(ctx)
	if e != nil || head.Epoch != c.ExpectedAuthorityEpoch || head.RecordedAt.IsZero() {
		return ErrDirectoryUnavailable
	}
	now := head.RecordedAt.UTC()
	// Recovery rechecks both authors and the independent reviewer. The durable
	// floor closes the provider even when mutable positive grants have changed.
	peopleCurrent := true
	authorFP, e := directorySubjectAtTransition(ctx, tx, r.operation.CreatedBy, head, false, &c)
	if e != nil || authorFP != r.authorFingerprint {
		peopleCurrent = false
	}
	versionAuthor, _, e := directoryVersionAuthorAtTransition(ctx, tx, c.VersionID, head, &c)
	if e != nil {
		peopleCurrent = false
	}
	var reviewer, reviewerFP string
	var mfa time.Time
	e = securitystate.One(ctx, tx, `SELECT reviewer_id,reviewer_fingerprint,mfa_at FROM directory_provider_approvals WHERE operation_id=? AND request_digest=?`, []any{in.OperationID, in.RequestDigest}, func(row storage.IdentityRows) error { return row.Scan(&reviewer, &reviewerFP, &mfa) })
	if e != nil || reviewer != in.ApproverID || reviewer == r.operation.CreatedBy || reviewer == versionAuthor || now.Before(mfa) || now.Sub(mfa) > 5*time.Minute {
		peopleCurrent = false
	}
	if e = RequireDistinctPeople(ctx, tx, reviewer, r.operation.CreatedBy); e != nil {
		peopleCurrent = false
	}
	if e = RequireDistinctPeople(ctx, tx, reviewer, versionAuthor); e != nil {
		peopleCurrent = false
	}
	liveReviewerFP, e := directorySubjectAtTransition(ctx, tx, reviewer, head, true, &c)
	if e != nil || liveReviewerFP != reviewerFP {
		peopleCurrent = false
	}
	// A delayed positive materialization must not outlive its approval. The
	// durable restrictive floor remains effective; recovery needs a new successor.
	if !peopleCurrent || !now.Before(c.ExpiresAt) || floor != uint64(c.NextGuardVersion) {
		_, e = tx.Exec(ctx, `UPDATE directory_provider_operations SET state='recovery_required' WHERE id=?`, in.OperationID)
		return e
	}
	n, e := tx.Exec(ctx, `UPDATE directory_providers SET enabled=?,active_version_id=?,guard_version=?,row_version=row_version+1 WHERE id=? AND guard_id=? AND row_version=? AND guard_version=?`, c.Enabled, c.VersionID, int64(c.NextGuardVersion), c.ProviderID, c.GuardID, int64(c.ExpectedRowVersion), int64(c.PreviousGuardVersion))
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrDirectoryStale
	}
	_, e = tx.Exec(ctx, `UPDATE directory_provider_operations SET state='applied' WHERE id=?`, in.OperationID)
	if e != nil {
		return e
	}
	return securitystate.Audit(ctx, tx, "identity.directory.activation_applied", in.ActorID, map[string]any{"operationId": in.OperationID, "requestDigest": in.RequestDigest, "approverId": in.ApproverID, "enabled": c.Enabled})
}

// CurrentProvider is the authorization boundary used by the actual AD connector.
// Restoring a provider version below its independently replayed guard never
// enables login or any subsequent positive access decision.
func (s *DirectoryService) CurrentProvider(ctx context.Context, id string) (out *DirectoryProviderDocument, err error) {
	if s == nil || s.coordinator == nil {
		return nil, ErrDirectoryUnavailable
	}
	err = s.coordinator.Current(ctx, func(tx storage.IdentityTx, _ securityjournal.Head) error {
		p, guard, e := readDirectory(ctx, tx, id)
		if e != nil {
			return e
		}
		if !p.Enabled || p.Configuration == nil {
			return storage.ErrPermissionDenied
		}
		floor, e := securitystate.Floor(ctx, tx, p.SecurityGuardID, p.SecurityGuardID)
		if e != nil {
			return e
		}
		if guard < floor {
			return storage.ErrPermissionDenied
		}
		out = p.Configuration
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func currentDirectoryVersionAuthor(ctx context.Context, tx storage.IdentityTx, versionID string, h securityjournal.Head) (string, string, error) {
	return directoryVersionAuthorAtTransition(ctx, tx, versionID, h, nil)
}
func directoryVersionAuthorAtTransition(ctx context.Context, tx storage.IdentityTx, versionID string, h securityjournal.Head, transition *ProviderSecurityChange) (string, string, error) {
	var id, expected string
	e := securitystate.One(ctx, tx, `SELECT author_id,author_fingerprint FROM directory_provider_versions WHERE id=?`, []any{versionID}, func(r storage.IdentityRows) error { return r.Scan(&id, &expected) })
	if e != nil {
		return "", "", e
	}
	actual, e := directorySubjectAtTransition(ctx, tx, id, h, false, transition)
	if e != nil {
		return "", "", e
	}
	if actual != expected {
		return "", "", ErrDirectoryStale
	}
	return id, actual, nil
}
