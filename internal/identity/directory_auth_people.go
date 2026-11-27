package identity

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type directoryPeopleProofKey struct{}
type directoryPeopleProofs map[string]*directoryObservation

func directorySubjectProof(ctx context.Context, pin *directoryPin, h securityjournal.Head) error {
	var observation *directoryObservation
	if proofs, ok := ctx.Value(directoryPeopleProofKey{}).(directoryPeopleProofs); ok {
		observation = proofs[pin.identity.PrincipalID]
	}
	if observation == nil {
		if request, ok := ctx.Value(directoryRequestProofKey{}).(*directoryRequestProof); ok && request != nil && request.principalID == pin.identity.PrincipalID {
			observation = request.observation
		}
	}
	if !directorySubjectProofMatches(pin, h, observation) {
		return ErrDirectoryUnavailable
	}
	return nil
}
func directorySubjectProofMatches(pin *directoryPin, h securityjournal.Head, o *directoryObservation) bool {
	return o != nil && o.account != nil && directoryPinProofMatches(pin, h, o.pin) && o.account.ForestGUID == pin.identity.ForestGUID && o.account.ObjectGUID == pin.identity.ObjectGUID
}
func directoryPinProofMatches(pin *directoryPin, h securityjournal.Head, observed *directoryPin) bool {
	return pin != nil && observed != nil && !h.RecordedAt.IsZero() && !observed.observedAt.IsZero() && !h.RecordedAt.Before(observed.observedAt) && h.RecordedAt.Sub(observed.observedAt) <= 10*time.Second && pin.epoch == observed.epoch && h.Epoch == observed.epoch && pin.digest == observed.digest && pin.identity == observed.identity && pin.context == observed.context
}
func (s *DirectoryService) withDirectoryPeople(ctx context.Context, subjects []string) (context.Context, error) {
	proofs := directoryPeopleProofs{}
	if previous, ok := ctx.Value(directoryPeopleProofKey{}).(directoryPeopleProofs); ok {
		for id, proof := range previous {
			proofs[id] = proof
		}
	}
	var needed []*directoryPin
	e := s.coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		seen := map[string]bool{}
		for _, id := range subjects {
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			pin, e := directoryAuthPin(ctx, tx, h, id)
			if e != nil {
				return e
			}
			if pin == nil {
				continue
			}
			if directorySubjectProofMatches(pin, h, proofs[id]) {
				continue
			}
			if request, ok := ctx.Value(directoryRequestProofKey{}).(*directoryRequestProof); ok && request != nil && request.principalID == id && directorySubjectProofMatches(pin, h, request.observation) {
				proofs[id] = request.observation
				continue
			}
			needed = append(needed, pin)
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	if len(needed) == 0 {
		return context.WithValue(ctx, directoryPeopleProofKey{}, proofs), nil
	}
	connector, ok := s.validator.(*ADConnector)
	if !ok || connector == nil {
		return nil, ErrDirectoryUnavailable
	}
	// At most four lifecycle participants: creator, reviewer, target and executor.
	// Existing provider/configuration operations use at most three. Independent DC reads
	// run concurrently under the connector's own bounded worker/deadline budget.
	if len(needed) > 4 {
		return nil, ErrProof
	}
	operation, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make([]*directoryObservation, len(needed))
	errs := make([]error, len(needed))
	var workers sync.WaitGroup
	for i, pin := range needed {
		workers.Add(1)
		go func() {
			defer workers.Done()
			account, e := connector.LiveCheck(operation, pin.document, pin.identity.ObjectGUID)
			if e != nil {
				errs[i] = e
				cancel()
				return
			}
			if account.ObjectGUID != pin.identity.ObjectGUID || account.ForestGUID != pin.identity.ForestGUID {
				errs[i] = ErrProof
				cancel()
				return
			}
			results[i] = &directoryObservation{pin: pin, account: account}
		}()
	}
	workers.Wait()
	for i, e := range errs {
		if e != nil {
			return nil, e
		}
		proofs[needed[i].identity.PrincipalID] = results[i]
	}
	return context.WithValue(ctx, directoryPeopleProofKey{}, proofs), nil
}
func (s *DirectoryService) operationPeopleContext(ctx context.Context, a DirectoryActor, id string, write, approve bool) (context.Context, error) {
	var subjects []string
	e := s.current(ctx, a, write, approve, func(tx storage.IdentityTx, _ securityjournal.Head, _ *directoryPrincipal) error {
		r, e := readDirectoryOperation(ctx, tx, id)
		if e != nil {
			return e
		}
		if r.operation.State != "pending" {
			return nil
		}
		subjects = append(subjects, r.operation.CreatedBy)
		var author string
		e = securitystate.One(ctx, tx, `SELECT author_id FROM directory_provider_versions WHERE id=? AND provider_id=?`, []any{r.operation.ProviderChange.VersionID, r.operation.SubjectID}, func(row storage.IdentityRows) error { return row.Scan(&author) })
		if e != nil {
			return e
		}
		subjects = append(subjects, author)
		reviewers, e := securitystate.Strings(ctx, tx, `SELECT reviewer_id FROM directory_provider_approvals WHERE operation_id=?`, id)
		if e != nil {
			return e
		}
		subjects = append(subjects, reviewers...)
		return nil
	})
	if e != nil {
		return nil, e
	}
	return s.withDirectoryPeople(ctx, subjects)
}
func (s *DirectoryService) versionPeopleContext(ctx context.Context, a DirectoryActor, provider, version string) (context.Context, error) {
	var author string
	e := s.current(ctx, a, true, false, func(tx storage.IdentityTx, _ securityjournal.Head, _ *directoryPrincipal) error {
		return securitystate.One(ctx, tx, `SELECT author_id FROM directory_provider_versions WHERE id=? AND provider_id=?`, []any{version, provider}, func(row storage.IdentityRows) error { return row.Scan(&author) })
	})
	if e != nil {
		return nil, e
	}
	return s.withDirectoryPeople(ctx, []string{author})
}

// WithCurrentSubjects reads the live state of exact server-selected historical
// authors/reviewers outside the writer transaction. The callback must recheck
// each subject with DirectorySubjectFingerprint inside its final fenced TX.
// The resulting context is private volatile evidence, never a persisted allow.
func (s *DirectoryService) WithCurrentSubjects(ctx context.Context, principals []string, fn func(context.Context) error) error {
	if s == nil || s.coordinator == nil || fn == nil || len(principals) > 3 {
		return ErrDirectoryInvalid
	}
	checked, e := s.withDirectoryPeople(ctx, principals)
	if e != nil {
		return e
	}
	return fn(checked)
}

// DirectorySubjectFingerprint supplements the caller's current local privilege
// fingerprint with the immutable directory identity/provider context. A local
// principal returns an empty string. A linked principal requires actual live
// evidence minted by WithCurrentSubjects or WithCurrentSession in this request.
func DirectorySubjectFingerprint(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, principal string) (string, error) {
	pin, e := directoryAuthPin(ctx, tx, h, principal)
	if e != nil || pin == nil {
		return "", e
	}
	if negatives, ok := ctx.Value(directoryHistoricalNegativeKey{}).(directoryHistoricalNegatives); ok && directoryPinProofMatches(pin, h, negatives[principal]) {
		return "", ErrProof
	}
	if e = directorySubjectProof(ctx, pin, h); e != nil {
		return "", e
	}
	return configmodel.Digest(struct {
		Identity       DirectoryIdentityView
		ProviderDigest string
		Context        directoryContext
	}{pin.identity, pin.digest, pin.context})
}

// Historical negative evidence is produced only by an actual authenticated DC
// account read returning ErrProof. Transport/TLS/timeout failures never create
// negative evidence and fail the complete operation as unavailable.
type directoryHistoricalNegativeKey struct{}
type directoryHistoricalNegatives map[string]*directoryPin

// WithCurrentHistoricalSubjects supports bounded candidate selection. Unlike
// WithCurrentSubjects it lets final callers skip a precisely pinned AD account
// which is authoritatively disabled/deleted. It never makes a failed candidate
// positive. Every final TX must call DirectorySubjectFingerprint again.
func (s *DirectoryService) WithCurrentHistoricalSubjects(ctx context.Context, principals []string, fn func(context.Context) error) error {
	if s == nil || s.coordinator == nil || fn == nil || len(principals) > 256 {
		return ErrDirectoryInvalid
	}
	operation, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	proofs := directoryPeopleProofs{}
	if prior, ok := ctx.Value(directoryPeopleProofKey{}).(directoryPeopleProofs); ok {
		for id, o := range prior {
			proofs[id] = o
		}
	}
	negatives := directoryHistoricalNegatives{}
	if prior, ok := ctx.Value(directoryHistoricalNegativeKey{}).(directoryHistoricalNegatives); ok {
		for id, pin := range prior {
			negatives[id] = pin
		}
	}
	var pins, needed []*directoryPin
	e := s.coordinator.Current(operation, func(tx storage.IdentityTx, h securityjournal.Head) error {
		seen := map[string]bool{}
		for _, id := range principals {
			if id == "" || !configmodel.ValidID(id) {
				return ErrDirectoryInvalid
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			pin, e := directoryAuthPin(operation, tx, h, id)
			if errors.Is(e, ErrProof) || errors.Is(e, storage.ErrNotFound) {
				continue
			}
			if e != nil {
				return e
			}
			if pin == nil {
				continue
			}
			pins = append(pins, pin)
			if directoryPinProofMatches(pin, h, negatives[id]) {
				continue
			}
			if directorySubjectProofMatches(pin, h, proofs[id]) {
				continue
			}
			if request, ok := ctx.Value(directoryRequestProofKey{}).(*directoryRequestProof); ok && request != nil && request.principalID == id && directorySubjectProofMatches(pin, h, request.observation) {
				proofs[id] = request.observation
				continue
			}
			needed = append(needed, pin)
		}
		return nil
	})
	if e != nil {
		return e
	}
	if len(needed) > 0 {
		connector, ok := s.validator.(*ADConnector)
		if !ok || connector == nil {
			return ErrDirectoryUnavailable
		}
		results := make([]*directoryObservation, len(needed))
		denied := make([]bool, len(needed))
		errs := make([]error, len(needed))
		jobs := make(chan int)
		var workers sync.WaitGroup
		for range min(3, len(needed)) {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for i := range jobs {
					if operation.Err() != nil {
						return
					}
					pin := needed[i]
					account, e := connector.LiveCheck(operation, pin.document, pin.identity.ObjectGUID)
					if errors.Is(e, ErrProof) {
						denied[i] = true
						continue
					}
					if e != nil {
						errs[i] = e
						cancel()
						return
					}
					if account == nil || account.ObjectGUID != pin.identity.ObjectGUID || account.ForestGUID != pin.identity.ForestGUID {
						errs[i] = ErrDirectoryUnavailable
						cancel()
						return
					}
					results[i] = &directoryObservation{pin: pin, account: account}
				}
			}()
		}
	send:
		for i := range needed {
			select {
			case jobs <- i:
			case <-operation.Done():
				break send
			}
		}
		close(jobs)
		workers.Wait()
		if operation.Err() != nil {
			return ErrDirectoryUnavailable
		}
		for i, pin := range needed {
			if errs[i] != nil {
				return ErrDirectoryUnavailable
			}
			id := pin.identity.PrincipalID
			if denied[i] {
				negatives[id] = pin
				delete(proofs, id)
			} else if results[i] != nil {
				proofs[id] = results[i]
				delete(negatives, id)
			} else {
				return ErrDirectoryUnavailable
			}
		}
	}
	checked := context.WithValue(ctx, directoryPeopleProofKey{}, proofs)
	checked = context.WithValue(checked, directoryHistoricalNegativeKey{}, negatives)
	// Validate the complete batch against a fresh independently authenticated head
	// before entering the caller's own final fenced operation. Waiting for a pool
	// slot consumes the original ten-second freshness budget too.
	e = s.coordinator.Current(operation, func(tx storage.IdentityTx, h securityjournal.Head) error {
		for _, observed := range pins {
			pin, e := directoryAuthPin(operation, tx, h, observed.identity.PrincipalID)
			if errors.Is(e, ErrProof) || errors.Is(e, storage.ErrNotFound) {
				continue
			}
			if e != nil {
				return e
			}
			if !directoryPinProofMatches(pin, h, observed) {
				return ErrDirectoryUnavailable
			}
			id := observed.identity.PrincipalID
			if !directoryPinProofMatches(pin, h, negatives[id]) && !directorySubjectProofMatches(pin, h, proofs[id]) {
				return ErrDirectoryUnavailable
			}
		}
		return nil
	})
	if e != nil {
		return e
	}
	if operation.Err() != nil {
		return ErrDirectoryUnavailable
	}
	return fn(checked)
}
