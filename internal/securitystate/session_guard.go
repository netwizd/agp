package securitystate

import (
	"context"

	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

type ManagementSessionGuard func(context.Context, storage.IdentityTx, securityjournal.Head, string) error

// RegisterSessionGuard is startup-only. The identity service installs a guard
// which validates its private live-directory proof and current provider/link
// pins; the coordinator never imports the identity/network implementation.
func (c *Coordinator) RegisterSessionGuard(guard ManagementSessionGuard) { c.sessionGuard = guard }

func (c *Coordinator) CheckManagementSession(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, hash string) error {
	if err := CheckManagementSessionFloors(ctx, tx, hash); err != nil {
		return err
	}
	if c != nil && c.sessionGuard != nil {
		return c.sessionGuard(ctx, tx, h, hash)
	}
	return localManagementSession(ctx, tx, hash)
}

// CheckManagementSession also closes direct service/CLI callers: linked AD
// sessions need the configured guard, even when an HTTP middleware was absent.
// Local-only test Current implementations remain usable without a connector.
func CheckManagementSession(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, hash string, current any) error {
	if c, ok := current.(interface {
		CheckManagementSession(context.Context, storage.IdentityTx, securityjournal.Head, string) error
	}); ok {
		return c.CheckManagementSession(ctx, tx, h, hash)
	}
	if err := CheckManagementSessionFloors(ctx, tx, hash); err != nil {
		return err
	}
	return localManagementSession(ctx, tx, hash)
}

// CheckManagementSessionFloors rejects restored credential/session rows below
// independently replayed deny floors in the final writer transaction.
func CheckManagementSessionFloors(ctx context.Context, tx storage.IdentityTx, hash string) error {
	var id string
	var sv, pv, sessionVersion int64
	err := One(ctx, tx, `SELECT s.user_id,u.security_version,u.password_version,s.security_version FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?`, []any{hash}, func(r storage.IdentityRows) error { return r.Scan(&id, &sv, &pv, &sessionVersion) })
	if err != nil {
		return err
	}
	if sv < 0 || pv < 0 || sessionVersion != sv {
		return storage.ErrPermissionDenied
	}
	for _, v := range []struct {
		key     string
		version int64
	}{{"principal_" + id, sv}, {"password_" + id, pv}} {
		floor, err := Floor(ctx, tx, id, v.key)
		if err != nil {
			return err
		}
		if uint64(v.version) < floor {
			return storage.ErrPermissionDenied
		}
	}
	return nil
}

func localManagementSession(ctx context.Context, tx storage.IdentityTx, hash string) error {
	var kind string
	err := One(ctx, tx, `SELECT u.identity_kind FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?`, []any{hash}, func(row storage.IdentityRows) error { return row.Scan(&kind) })
	if err != nil {
		return err
	}
	if kind != "local" {
		return ErrUnavailable
	}
	return nil
}

// ManagementSessionResolver refreshes live evidence outside the writer. The
// callback receives only volatile request context; the final TX guard remains
// mandatory. Registration is startup-only, like RegisterSessionGuard.
type ManagementSessionResolver func(context.Context, string, func(context.Context) error) error

func (c *Coordinator) RegisterSessionResolver(resolve ManagementSessionResolver) {
	c.sessionResolver = resolve
}
func (c *Coordinator) WithManagementSession(ctx context.Context, hash string, fn func(context.Context) error) error {
	if c != nil && c.sessionResolver != nil {
		return c.sessionResolver(ctx, hash, fn)
	}
	return fn(ctx)
}
func WithManagementSession(ctx context.Context, hash string, current any, fn func(context.Context) error) error {
	if source, ok := current.(interface {
		WithManagementSession(context.Context, string, func(context.Context) error) error
	}); ok {
		return source.WithManagementSession(ctx, hash, fn)
	}
	return fn(ctx)
}
