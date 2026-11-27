package identity

import (
	"context"
	"time"

	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

func cancelOIDCPredecessors(ctx context.Context, tx storage.IdentityTx, flowID string) error {
	_, e := tx.Exec(ctx, `UPDATE oidc_authorizations SET state='cancelled',key_id='',nonce='',ciphertext='' WHERE flow_id=? AND state IN ('pending','exchanging')`, flowID)
	return e
}

// CancelOIDCAuthorizations runs inside the existing fenced flow cancellation.
func CancelOIDCAuthorizations(ctx context.Context, tx storage.IdentityTx, flowID string) error {
	return cancelOIDCPredecessors(ctx, tx, flowID)
}

// CleanupOIDCAuthorizations only removes expired/terminal ephemeral proofs. It
// must run before deleting expired parent flows in the same transaction.
func CleanupOIDCAuthorizations(ctx context.Context, tx storage.IdentityTx, now time.Time) error {
	for _, q := range []string{
		`UPDATE identity_flows SET state='cancelled',next_step='none' WHERE state='pending_primary' AND id IN (SELECT flow_id FROM oidc_authorizations WHERE (state='pending' AND expires_at<=?) OR (state='exchanging' AND exchange_started_at<=?))`,
		`UPDATE oidc_authorizations SET state='failed',key_id='',nonce='',ciphertext='' WHERE (state='pending' AND expires_at<=?) OR (state='exchanging' AND exchange_started_at<=?)`,
	} {
		if _, e := tx.Exec(ctx, q, now, now.Add(-10*time.Second)); e != nil {
			return e
		}
	}
	_, e := tx.Exec(ctx, `DELETE FROM oidc_authorizations WHERE state IN ('failed','completed','cancelled') AND expires_at<=?`, now.Add(-24*time.Hour))
	return e
}

// RecoverAuthorizations closes process uncertainty before listeners start. An
// exchanging request is never requeued; an old-epoch request never survives DR.
func (s *OIDCService) RecoverAuthorizations(ctx context.Context) error {
	return s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		if _, e := tx.Exec(ctx, `UPDATE identity_flows SET state='cancelled',next_step='none' WHERE state='pending_primary' AND id IN (SELECT flow_id FROM oidc_authorizations WHERE state='exchanging' OR (state='pending' AND authority_epoch<>?))`, int64(h.Epoch)); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `UPDATE oidc_authorizations SET state='failed',key_id='',nonce='',ciphertext='' WHERE state='exchanging' OR (state='pending' AND authority_epoch<>?)`, int64(h.Epoch)); e != nil {
			return e
		}
		return CleanupOIDCAuthorizations(ctx, tx, h.RecordedAt)
	})
}
func (s *OIDCService) Cleanup(ctx context.Context) error {
	return s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		return CleanupOIDCAuthorizations(ctx, tx, h.RecordedAt)
	})
}

// RunCleanup is synchronous. The runtime owns its goroutine, cancellation and
// join, and should run RecoverAuthorizations before launching this worker.
func (s *OIDCService) RunCleanup(ctx context.Context) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if e := s.Cleanup(ctx); e != nil && ctx.Err() != nil {
				return ctx.Err()
			}
		}
	}
}
