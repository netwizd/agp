package rolescope

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/storage"
)

func TestGatewayRecipientsFleetSQLite(t *testing.T)   { testGatewayRecipientsFleet(t, false) }
func TestGatewayRecipientsFleetPostgres(t *testing.T) { testGatewayRecipientsFleet(t, true) }

// The authority caller consumes an already bounded fleet snapshot. Its private
// Gateway validation must not reimpose the standalone pilot byte limit.
func testGatewayRecipientsFleet(t *testing.T, pg bool) {
	f := newGraphFixture(t, pg)
	base := f.configuration.Gateways[0]
	large := base
	large.Spec.Routes = make([]configmodel.Route, 200)
	groups := make([]string, 100)
	for i := range groups {
		groups[i] = fmt.Sprintf("group_%03d_%s", i, strings.Repeat("x", 116))
	}
	for i := range large.Spec.Routes {
		route := base.Spec.Routes[0]
		route.ID, route.Path = fmt.Sprintf("route_large_%03d", i), fmt.Sprintf("/large/%d", i)
		route.Access.GroupIDs = append([]string(nil), groups...)
		large.Spec.Routes[i] = route
	}
	raw, err := json.Marshal(large)
	if err != nil || len(raw) <= configmodel.Pilot.MaxBytes || len(raw) > configmodel.Fleet.MaxBytes {
		t.Fatalf("invalid fleet boundary fixture: bytes=%d err=%v", len(raw), err)
	}
	err = f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		before, err := ResolveGatewayRecipients(f.ctx, tx, f.head, base)
		if err != nil {
			return err
		}
		after, err := ResolveGatewayRecipients(f.ctx, tx, f.head, large)
		if err == nil && (after.Digest != before.Digest || len(after.Nodes) == 0) {
			t.Fatal("fleet route payload altered the receiving authority")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}
