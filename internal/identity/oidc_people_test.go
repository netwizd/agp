package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func TestOIDCHistoricalPeopleSQLite(t *testing.T)   { testOIDCHistoricalPeople(t, false) }
func TestOIDCHistoricalPeoplePostgres(t *testing.T) { testOIDCHistoricalPeople(t, true) }
func testOIDCHistoricalPeople(t *testing.T, pg bool) {
	for _, role := range []string{"version_author", "reviewer"} {
		for _, denial := range []string{"disabled", "revoked"} {
			t.Run(role+"_"+denial, func(t *testing.T) {
				f := newOIDCFixture(t, pg)
				link, adActor := f.managementDirectory(t)
				proposeActor := f.author
				if role == "version_author" {
					proposeActor = adActor
				}
				propose := func(ctx context.Context) error {
					_, e := f.oidc.ProposeVersion(ctx, proposeActor, f.p.ID, f.p.Revision, f.documentOIDC)
					return e
				}
				var e error
				if role == "version_author" {
					e = f.s.WithCurrentSession(f.ctx, adActor.TokenHash, "management", adActor.Origin, func(ctx context.Context, _ *domain.SessionContext) error { return propose(ctx) })
				} else {
					e = propose(f.ctx)
				}
				if e != nil {
					t.Fatal(e)
				}
				f.p.Revision++
				if tested, e := f.oidc.TestProvider(f.ctx, f.author, f.p.ID, f.documentOIDC.Metadata.VersionID); e != nil || tested.State != "passed" {
					t.Fatal("test", tested, e)
				}
				op, e := f.oidc.PlanActivationAtRevision(f.ctx, f.author, f.p.ID, securitystate.ID("req"), f.p.Revision, DirectoryActivation{VersionID: f.documentOIDC.Metadata.VersionID, Enabled: true, Reason: "current independent people remain required"})
				if e != nil {
					t.Fatal(e)
				}
				if role == "reviewer" {
					e = f.s.WithCurrentSession(f.ctx, adActor.TokenHash, "management", adActor.Origin, func(ctx context.Context, _ *domain.SessionContext) error {
						_, e := f.oidc.ApproveOperationRequest(ctx, adActor, op.ID, securitystate.ID("req"), op.RequestDigest, "AD reviewer current rights and live proof")
						return e
					})
					if e != nil {
						t.Fatal(e)
					}
				} else {
					f.approveOIDC(t, op)
				}
				if denial == "disabled" {
					f.wire.disabled.Store(true)
				} else {
					if e = f.directory.RevokeIdentity(f.ctx, f.author, f.provider.ID, link.ID, "immediate local revoke of historical participant"); e != nil {
						t.Fatal(e)
					}
				}
				before := len(f.j.events)
				if _, e = f.oidc.ExecuteOperationRequest(f.ctx, f.author, op.ID, securitystate.ID("req"), op.RequestDigest, "stale participant must prevent activation"); !errors.Is(e, ErrProof) && !errors.Is(e, storage.ErrPermissionDenied) {
					t.Fatal("historical participant accepted", e)
				}
				if len(f.j.events) != before {
					t.Fatal("stale historical participant appended new positive operation")
				}
				p, e := f.oidc.GetProvider(f.ctx, f.author, f.p.ID)
				if e != nil || p.Enabled {
					t.Fatal("provider activated after participant denial", e)
				}
			})
		}
	}
}
