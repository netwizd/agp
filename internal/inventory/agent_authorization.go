package inventory

import (
	"context"
	"crypto/tls"

	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

// AuthenticateAgent is the shared certificate boundary for execution traffic on
// the dedicated mTLS listener. The caller supplies its fenced Current transaction
// and must repeat this check before committing a new authorization. Browser
// sessions, headers and a previously resolved node ID are not agent evidence.
func (s *Service) AuthenticateAgent(ctx context.Context, tx storage.IdentityTx, head securityjournal.Head, peer *tls.ConnectionState) (string, error) {
	if s == nil || ctx == nil || tx == nil || head.Epoch == 0 || head.RecordedAt.IsZero() {
		return "", ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	node, err := s.admitted(ctx, tx, peer, head)
	if err != nil {
		return "", err
	}
	if err := s.registrationUnchanged(ctx, node, head); err != nil {
		return "", err
	}
	return node.NodeID, nil
}
