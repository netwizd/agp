package inventory

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

func TestExecutionAgentIdentitySQLite(t *testing.T)   { testExecutionAgentIdentity(t, false) }
func TestExecutionAgentIdentityPostgres(t *testing.T) { testExecutionAgentIdentity(t, true) }

func testExecutionAgentIdentity(t *testing.T, pg bool) {
	ctx := context.Background()
	f := fixture(t, pg)
	check := func(peer *tls.ConnectionState, allowed bool) {
		t.Helper()
		err := f.current.Current(ctx, func(tx storage.IdentityTx, head securityjournal.Head) error {
			id, err := f.service.AuthenticateAgent(ctx, tx, head, peer)
			if allowed {
				if err != nil || id != f.registry.Nodes[0].NodeID {
					t.Fatalf("registered certificate rejected: id=%q err=%v", id, err)
				}
			} else if !errors.Is(err, ErrIdentity) || id != "" {
				t.Fatalf("invalid agent acquired execution identity: id=%q err=%v", id, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	check(f.peer, true)
	check(nil, false)
	unverified := *f.peer
	unverified.VerifiedChains = nil
	check(&unverified, false)
	legacy := *f.peer
	legacy.Version = tls.VersionTLS12
	check(&legacy, false)

	// Reusing the same TLS connection must not retain authority after the
	// installation registry revokes its exact credential.
	f.registry.Nodes[0].Revoked = true
	f.writeRegistry()
	check(f.peer, false)
	f.registry.Nodes[0].Revoked = false
	f.writeRegistry()
	check(f.peer, true)
	f.authority.advance(25 * time.Hour)
	check(f.peer, false)
}
