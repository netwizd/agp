package configuration

import (
	"context"
	"errors"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/storage"
)

// The selection phase reads only exact server-owned artifact dependencies under
// the actor's current scope. Network observations finish outside the writer;
// the operation's callback executes once, with its own final fenced checks.
func (s *Service) directorySubjectContext(ctx context.Context, a Actor, write bool, selection directorySubjectSelection) (context.Context, error) {
	if s == nil {
		return nil, storage.ErrPermissionDenied
	}
	if s.directorySubjects == nil {
		return ctx, nil
	}
	var subjects []string
	err := s.transactScoped(ctx, a, write, func(tx storage.IdentityTx, p *Principal) error {
		var err error
		subjects, err = collectDirectorySubjects(ctx, tx, p, &selection)
		return err
	})
	if err != nil {
		return nil, err
	}
	if len(subjects) == 0 {
		return ctx, nil
	}
	var checked context.Context
	err = s.directorySubjects.WithCurrentHistoricalSubjects(ctx, subjects, func(fresh context.Context) error { checked = fresh; return nil })
	if err != nil {
		return nil, err
	}
	if checked == nil {
		return nil, identity.ErrDirectoryUnavailable
	}
	return checked, nil
}

// A swallowed infrastructure error must never become "stale" or allow another
// approval candidate to conceal an unavailable source. This wrapper does not
// retry callbacks, and all intermediate writes roll back with the error.
type subjectEvidenceTx struct {
	storage.IdentityTx
	unavailable  error
	proofContext context.Context
	subjects     map[string]configurationSubjectWitness
}

func subjectFailure(tx storage.IdentityTx, err error) error {
	if errors.Is(err, identity.ErrProof) {
		return storage.ErrPermissionDenied
	}
	// Historical proposal metadata remains readable after inventory goes stale
	// or its identity is revoked. These typed results never authorize replay;
	// dependency outages and unknown failures still abort the transaction.
	if errors.Is(err, inventory.ErrNotFresh) || errors.Is(err, inventory.ErrIdentity) {
		return err
	}
	if err != nil && !errors.Is(err, storage.ErrPermissionDenied) && !errors.Is(err, storage.ErrNotFound) && !errors.Is(err, storage.ErrConflict) && !errors.Is(err, ErrRevisionMismatch) {
		if evidence, ok := tx.(*subjectEvidenceTx); ok && evidence.unavailable == nil {
			evidence.unavailable = err
		}
	}
	return err
}

func distinctReviewPeople(ctx context.Context, tx storage.IdentityTx, reviewer string, authors ...string) error {
	seen := map[string]bool{}
	for _, author := range authors {
		if seen[author] {
			continue
		}
		seen[author] = true
		if err := identity.RequireDistinctPeople(ctx, tx, reviewer, author); err != nil {
			return subjectFailure(tx, err)
		}
	}
	return nil
}

func currentReviewPeople(ctx context.Context, tx storage.IdentityTx, reviewer string, authors ...string) error {
	err := distinctReviewPeople(ctx, tx, reviewer, authors...)
	if errors.Is(err, storage.ErrPermissionDenied) {
		return storage.ErrConflict
	}
	return err
}
func finalSubjectEvidence(tx *subjectEvidenceTx, err error) error {
	if tx.unavailable != nil {
		return tx.unavailable
	}
	return err
}

func replacementIDs(in []configmodel.ReplacementAssignment) []string {
	ids := make([]string, 0, len(in))
	for _, replacement := range in {
		ids = append(ids, replacement.ZoneRevisionID)
	}
	return ids
}
