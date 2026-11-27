package identity

import (
	"context"
	"strings"

	"github.com/netwizd/agp/internal/storage"
)

// RequireDistinctPeople checks an already authenticated quorum's stable person
// identities. Provider aliases of one AD object are the same person. Local
// accounts are compared only by principal ID, never by name or email.
// This check does not replace current permissions, floors or live AD evidence.
func RequireDistinctPeople(ctx context.Context, tx storage.IdentityTx, left, right string) error {
	if left == "" || right == "" || left == right {
		return storage.ErrPermissionDenied
	}
	first, err := readDirectoryIdentity(ctx, tx, left)
	if err != nil {
		return err
	}
	second, err := readDirectoryIdentity(ctx, tx, right)
	if err != nil {
		return err
	}
	if first != nil && second != nil && strings.EqualFold(first.ForestGUID, second.ForestGUID) && strings.EqualFold(first.ObjectGUID, second.ObjectGUID) {
		return storage.ErrPermissionDenied
	}
	return nil
}
