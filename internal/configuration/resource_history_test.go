package configuration

import (
	"context"
	"errors"
	"testing"

	"github.com/netwizd/agp/internal/storage"
)

func TestResourceScopedHistorySQLite(t *testing.T)   { testResourceScopedHistory(t, false) }
func TestResourceScopedHistoryPostgres(t *testing.T) { testResourceScopedHistory(t, true) }

func testResourceScopedHistory(t *testing.T, pg bool) {
	ctx := context.Background()
	actor := Actor{TokenHash: "editor_token", Origin: "https://management.test"}
	for _, path := range []string{"/legacy/", "/_agp_legacy"} {
		t.Run(path, func(t *testing.T) {
			f := resourceScopedFixture(t, pg)
			configurationReaderBinding(t, f, "resource_history", "editor", "config.edit", "resource", "resource_owned", nil)
			cfg := resourceConfiguration(t)
			cfg.Gateways[1].Spec.Routes[0].Path = path
			base := gatewayBase(t, f, cfg)
			view, err := f.service.ResourceRevision(ctx, actor, base.ID, "resource_owned", "gw_second", "route_placement")
			if err != nil || view == nil || view.ResourceView == nil || view.ResourceView.Route.Path != path {
				t.Fatalf("previously accepted historical placement became unreadable: %#v %v", view, err)
			}
			if _, err := f.service.GatewayRevision(ctx, f.actor, base.ID, "gw_second"); err != nil {
				t.Fatalf("historical Gateway projection became unreadable: %v", err)
			}
			page, err := f.service.ListResources(ctx, actor, base.ID, 50, "")
			if err != nil || len(page.Items) != 2 {
				t.Fatalf("historical route broke authorized listing: %#v %v", page, err)
			}
			// An unsupported old route must never become a supported narrow
			// routing proof, even when its replacement would have a valid path.
			route := cfg.Gateways[1].Spec.Routes[0]
			route.Path = "/repaired"
			command := resourceCommand(t, base, route)
			command.ResourceChange.GatewayID = "gw_second"
			command.ResourceChange.RouteID = "route_placement"
			if out, err := f.service.ChangeResource(ctx, actor, "resource_legacy_boundary_01", command); !errors.Is(err, storage.ErrConflict) || out != nil {
				t.Fatalf("unsupported historical prefix acquired narrow routing proof: %#v %v", out, err)
			}
			// The same historical route on a different Gateway must not block
			// an independently authorized, supported resource edit.
			next := cfg.Gateways[0].Spec.Routes[0]
			next.Name = "Independent supported route"
			changed, err := f.service.ChangeResource(ctx, actor, "resource_other_history_01", resourceCommand(t, base, next))
			if err != nil {
				t.Fatal(err)
			}
			preserved, err := f.service.ResourceRevision(ctx, actor, changed.ID, "resource_owned", "gw_second", "route_placement")
			if err != nil || preserved == nil || preserved.ResourceView == nil || preserved.ResourceView.Route.Path != path || scalar(t, f, `SELECT COUNT(*) FROM config_revisions`) != 2 {
				t.Fatalf("independent edit rewrote historical placement or failed atomicity: %#v %v", preserved, err)
			}
		})
	}
}
