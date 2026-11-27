package identity

import (
	"context"
	"time"

	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

// DirectorySubjectProofDeadline bounds an external side effect by the actual
// private live observation used in this transaction. The returned timestamp is
// never reusable authorization: callers must still recheck the subject/session
// and every local grant. A local subject has no directory deadline (zero, nil).
func DirectorySubjectProofDeadline(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, principal string) (time.Time, error) {
	fingerprint, err := DirectorySubjectFingerprint(ctx, tx, h, principal)
	if err != nil || fingerprint == "" {
		return time.Time{}, err
	}
	var observation *directoryObservation
	if proofs, ok := ctx.Value(directoryPeopleProofKey{}).(directoryPeopleProofs); ok {
		observation = proofs[principal]
	}
	if observation == nil {
		if request, ok := ctx.Value(directoryRequestProofKey{}).(*directoryRequestProof); ok && request != nil && request.principalID == principal {
			observation = request.observation
		}
	}
	if observation == nil || observation.pin == nil {
		return time.Time{}, ErrDirectoryUnavailable
	}
	deadline := observation.pin.observedAt.Add(10 * time.Second).UTC()
	if !h.RecordedAt.Before(deadline) {
		return time.Time{}, ErrDirectoryUnavailable
	}
	return deadline, nil
}
