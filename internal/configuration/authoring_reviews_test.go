package configuration

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func TestAuthoringReviewsSQLite(t *testing.T)   { testAuthoringReviews(t, false) }
func TestAuthoringReviewsPostgres(t *testing.T) { testAuthoringReviews(t, true) }
func testAuthoringReviews(t *testing.T, pg bool) {
	ctx := context.Background()
	f := scopedFixture(t, pg)
	editor := Actor{"editor_token", f.actor.Origin}
	reviewer := Actor{"reviewer_token", f.actor.Origin}
	if e := f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		_, e := tx.Exec(ctx, `INSERT INTO groups(id,name) VALUES('grp_AbCdEf123','Review fixture')`)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile("../../docs/v2/examples/catalog-authoring-pilot.json")
	if e != nil {
		t.Fatal(e)
	}
	catalog, e := f.service.ImportCatalog(ctx, f.actor, "test_review_catalog_01", raw, configmodel.JSON)
	if e != nil {
		t.Fatal(e)
	}
	base, e := f.service.CreateRevision(ctx, f.actor, "test_review_base_0001", CreateRevision{Content: example(t)})
	if e != nil {
		t.Fatal(e)
	}
	body := zoneBody("zone_review", configmodel.ZoneMembership{GatewayIDs: []string{"gw_portal"}})
	body.Metadata.OwnerID = "editor"
	zone, e := f.service.CreateZoneRevision(ctx, editor, "test_review_zone_0001", ZoneCreate{Content: mustJSON(t, body)})
	if e != nil {
		t.Fatal(e)
	}
	preview, e := f.service.PreviewZone(ctx, editor, zone.ID, "test_review_preview01", previewRequest(base, catalog))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.service.ReviewZonePreview(ctx, editor, preview.ID, "test_self_review_0001", preview.PreviewDigest, "I reviewed my own draft"); !errors.Is(e, storage.ErrPermissionDenied) {
		t.Fatalf("self-review accepted %v", e)
	}
	mark, e := f.service.ReviewZonePreview(ctx, reviewer, preview.ID, "test_other_review_01", preview.PreviewDigest, "Independent exact draft review")
	if e != nil {
		t.Fatal(e)
	}
	if mark.Purpose != "draft_review" || mark.AuthorID != "editor" || mark.ReviewerID != "reviewer" || !mark.ExpiresAt.Equal(preview.ExpiresAt) || mark.Status != "current" {
		t.Fatalf("bad review %#v", mark)
	}
	again, e := f.service.ReviewZonePreview(ctx, reviewer, preview.ID, "test_other_review_01", preview.PreviewDigest, "Independent exact draft review")
	if e != nil || again.ID != mark.ID {
		t.Fatalf("review replay %v %#v", e, again)
	}
	oldCompiler := f.service.compiler
	f.service.compiler.BuildDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	stale, e := f.service.ZoneReviews(ctx, f.actor, preview.ID)
	if e != nil || len(stale) != 1 || stale[0].Status != "stale" {
		t.Fatalf("old-build review retained %#v %v", stale, e)
	}
	if _, e = f.service.ReviewZonePreview(ctx, reviewer, preview.ID, "test_old_build_review01", preview.PreviewDigest, "Old binary preview must be stale"); !errors.Is(e, storage.ErrConflict) {
		t.Fatalf("old binary review accepted %v", e)
	}
	f.service.compiler = oldCompiler
	marks, e := f.service.ZoneReviews(ctx, f.actor, preview.ID)
	if e != nil || len(marks) != 1 || marks[0].Status != "current" {
		t.Fatalf("review not current %v %#v", e, marks)
	}
	// A newly added co-zone must invalidate a previous exact membership review.
	second := zoneBody("zone_new_candidate", configmodel.ZoneMembership{GatewayIDs: []string{"gw_portal"}})
	createZone(t, f, "test_new_cozone_0001", "", second)
	marks, e = f.service.ZoneReviews(ctx, f.actor, preview.ID)
	if e != nil || marks[0].Status != "stale" {
		t.Fatalf("changed Site closure retained review %v %#v", e, marks)
	}
	if _, e = f.service.ReviewZonePreview(ctx, reviewer, preview.ID, "test_review_stale_01", preview.PreviewDigest, "Review old membership after new zone"); !errors.Is(e, storage.ErrConflict) {
		t.Fatalf("stale review accepted %v", e)
	}
	if e = f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		return securitystate.MaterializeEvent(ctx, tx, securityjournal.Event{Request: securityjournal.AppendRequest{Kind: "revoke_role_binding", Payload: securityjournal.Payload{GrantID: "cgrant_reviewer"}}, RecordedAt: time.Now()})
	}); e != nil {
		t.Fatal(e)
	}
	if _, e = f.service.ZoneReviews(ctx, reviewer, preview.ID); !errors.Is(e, storage.ErrNotFound) {
		t.Fatalf("revoked reviewer still reads %v", e)
	}
	for _, q := range []string{`UPDATE config_authoring_reviews SET review_json='{}' WHERE id=?`, `DELETE FROM config_authoring_reviews WHERE id=?`} {
		if e = f.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error { _, e := tx.Exec(ctx, q, mark.ID); return e }); e == nil {
			t.Fatal("mutable review accepted")
		}
	}
}
