package identity

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

var directoryChecks = []string{"tls", "service_bind", "account_lookup", "group_resolution", "domain_policy"}

func validDirectoryValidation(v DirectoryValidation, forest string) bool {
	if v.ForestGUID != forest || len(v.Checks) != len(directoryChecks) {
		return false
	}
	seen := map[string]bool{}
	for _, c := range v.Checks {
		found := false
		for _, name := range directoryChecks {
			if c.Name == name {
				found = true
			}
		}
		if !found || seen[c.Name] || c.State != "passed" || c.ReasonCode != "verified" {
			return false
		}
		seen[c.Name] = true
	}
	return true
}
func failedDirectoryChecks() []DirectoryTestCheck {
	out := make([]DirectoryTestCheck, 0, len(directoryChecks))
	for _, name := range directoryChecks {
		out = append(out, DirectoryTestCheck{Name: name, State: "failed", ReasonCode: "identity_provider_unavailable"})
	}
	return out
}

// TestProvider executes one bounded trusted connector test. Its stored result is
// immutable and digest/epoch bound. Neither callers nor a restored cache can
// provide checks. HTTP may return the already completed result with 202.
func (s *DirectoryService) TestProvider(ctx context.Context, a DirectoryActor, id, version string) (out *DirectoryTestResult, err error) {
	var v *DirectoryVersionView
	var epoch securityjournal.UInt63
	err = s.current(ctx, a, true, false, func(tx storage.IdentityTx, h securityjournal.Head, _ *directoryPrincipal) error {
		var e error
		v, e = readDirectoryVersion(ctx, tx, id, version)
		epoch = h.Epoch
		return e
	})
	if err != nil {
		return nil, err
	}
	if s.validator == nil {
		return nil, ErrDirectoryUnavailable
	}
	timeout := time.Duration(v.Configuration.Spec.OperationTimeoutSeconds) * time.Second
	operation, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-operation.Done():
		return nil, ErrDirectoryUnavailable
	}
	validation, validateErr := s.validator.Validate(operation, v.Configuration)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	passed := validateErr == nil && operation.Err() == nil && validDirectoryValidation(validation, v.Configuration.Spec.ForestGUID)
	out = &DirectoryTestResult{OperationID: securitystate.ID("dirtest"), State: "failed", Checks: failedDirectoryChecks()}
	if passed {
		out.State = "passed"
		out.Checks = append([]DirectoryTestCheck{}, validation.Checks...)
	}
	err = s.current(ctx, a, true, false, func(tx storage.IdentityTx, h securityjournal.Head, p *directoryPrincipal) error {
		if epoch != h.Epoch {
			return ErrDirectoryStale
		}
		current, e := readDirectoryVersion(ctx, tx, id, version)
		if e != nil {
			return e
		}
		if current.ContentDigest != v.ContentDigest {
			return ErrDirectoryStale
		}
		raw, e := configmodel.CanonicalJSON(out)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO directory_provider_tests(id,provider_id,version_id,content_digest,authority_epoch,state,result_json,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)`, out.OperationID, id, version, v.ContentDigest, int64(h.Epoch), out.State, string(raw), h.RecordedAt, h.RecordedAt.Add(5*time.Minute))
		if e != nil {
			return e
		}
		return securitystate.Audit(ctx, tx, "identity.directory.tested", p.id, map[string]any{"providerId": id, "versionId": version, "testId": out.OperationID, "state": out.State})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *DirectoryService) GetTest(ctx context.Context, a DirectoryActor, id, testID string) (out *DirectoryTestResult, err error) {
	if !configmodel.ValidID(id) || !configmodel.ValidID(testID) {
		return nil, ErrDirectoryInvalid
	}
	err = s.current(ctx, a, false, false, func(tx storage.IdentityTx, _ securityjournal.Head, _ *directoryPrincipal) error {
		var raw string
		e := securitystate.One(ctx, tx, `SELECT result_json FROM directory_provider_tests WHERE id=? AND provider_id=?`, []any{testID, id}, func(r storage.IdentityRows) error { return r.Scan(&raw) })
		if e != nil {
			return e
		}
		out = &DirectoryTestResult{}
		return json.Unmarshal([]byte(raw), out)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func directoryTestCurrent(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, v *DirectoryVersionView) error {
	var id string
	e := securitystate.One(ctx, tx, `SELECT id FROM directory_provider_tests WHERE provider_id=? AND version_id=? AND content_digest=? AND authority_epoch=? AND state='passed' AND created_at<=? AND expires_at>? ORDER BY created_at DESC,id DESC LIMIT 1`, []any{v.Configuration.Metadata.ID, v.Configuration.Metadata.VersionID, v.ContentDigest, int64(h.Epoch), h.RecordedAt, h.RecordedAt}, func(r storage.IdentityRows) error { return r.Scan(&id) })
	if errors.Is(e, storage.ErrNotFound) {
		return ErrDirectoryUnavailable
	}
	return e
}
