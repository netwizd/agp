package identity

import (
	"context"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func (s *Service) directoryRedeemObservation(ctx context.Context, node, peer string, in domain.HandoffRedeemRequest) (*directoryObservation, error) {
	return s.directoryObserve(ctx, func(tx storage.IdentityTx, h securityjournal.Head) (string, string, string, error) {
		if peer != in.GatewayID {
			return "", "", "", ErrProof
		}
		var principal, source string
		e := securitystate.One(ctx, tx, `SELECT principal_id,source_session_id FROM handoffs WHERE code_hash=? AND gateway_id=? AND node_id=? AND redirect_uri=? AND consumed_at IS NULL AND expires_at>? AND epoch=?`, []any{auth.TokenHash(in.Code), in.GatewayID, node, in.RedirectURI, s.Now(), int64(h.Epoch)}, func(r storage.IdentityRows) error { return r.Scan(&principal, &source) })
		return principal, "sessions", source, e
	})
}
