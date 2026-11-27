package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type providerPersonFixture struct {
	id    string
	actor DirectoryActor
	wire  *adWireFixture
}

// Synthetic already-authenticated MG sessions retain actual, independently
// pinned TLS LDAP peers. Equal names and emails do not identify a person.
// Provider aliases intentionally share the same trusted forest/object pair.
func providerPeopleFixture(t *testing.T, f *directoryAuthFixture, aliases bool) []providerPersonFixture {
	t.Helper()
	people := make([]providerPersonFixture, 2)
	ca := append([]byte{}, f.wire.connector.secrets.(adFixtureSecrets).ca...)
	for i := range people {
		wire := newADWireFixture(t, "ldaps")
		forest := i + 700
		if aliases {
			forest = 700
		}
		wire.config.Spec.ForestGUID = fmt.Sprintf("00000000-0000-0000-0000-%012d", forest)
		ca = append(ca, wire.connector.secrets.(adFixtureSecrets).ca...)
		doc := f.document
		doc.Spec.Endpoints = wire.config.Spec.Endpoints
		doc.Spec.ForestGUID = wire.config.Spec.ForestGUID
		person := providerPersonFixture{id: historicalFixturePrincipalDocument(t, f, 700+i, doc), wire: wire}
		_, hash, e := auth.NewToken()
		if e != nil {
			t.Fatal(e)
		}
		person.actor = DirectoryActor{TokenHash: hash, Origin: f.s.Profile.ManagementOrigin}
		e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
			if _, e := tx.Exec(f.ctx, `INSERT INTO user_groups(user_id,group_id) VALUES(?,?)`, person.id, f.group.ID); e != nil {
				return e
			}
			id := securitystate.ID("session")
			if e := InsertSession(f.ctx, tx, domain.Session{ID: id, UserID: person.id, TokenHash: hash, CSRFHash: auth.TokenHash("provider-people-fixture"), Audience: "management", AudienceOrigin: person.actor.Origin, AuthorityEpoch: 1, SecurityVersion: 1, CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour), PrimaryAt: &f.now, MFAAt: &f.now, LastSeenAt: &f.now}); e != nil {
				return e
			}
			head, e := f.s.Coordinator.Authority.Head(f.ctx)
			if e != nil {
				return e
			}
			pin, e := directoryAuthPin(f.ctx, tx, head, person.id)
			if e != nil {
				return e
			}
			return writeDirectoryContext(f.ctx, tx, "sessions", id, pin.context)
		})
		if e != nil {
			t.Fatal(e)
		}
		people[i] = person
	}
	f.wire.connector.secrets = adFixtureSecrets{ca: ca}
	return people
}

func providerPersonRequest(f *directoryAuthFixture, actor DirectoryActor, fn func(context.Context) error) error {
	return f.s.WithCurrentSession(f.ctx, actor.TokenHash, "management", actor.Origin, func(ctx context.Context, _ *domain.SessionContext) error { return fn(ctx) })
}

func TestDirectoryIndependentPeopleSQLite(t *testing.T)   { directoryIndependentPeople(t, false) }
func TestDirectoryIndependentPeoplePostgres(t *testing.T) { directoryIndependentPeople(t, true) }
func directoryIndependentPeople(t *testing.T, pg bool) {
	for _, mode := range []string{"operation_author_alias", "version_author_alias", "distinct_AD_people"} {
		t.Run(mode, func(t *testing.T) {
			f := newDirectoryAuthFixture(t, pg, false)
			people := providerPeopleFixture(t, f, mode != "distinct_AD_people")
			versionActor, planActor := f.author, people[0].actor
			if mode != "operation_author_alias" {
				versionActor = people[0].actor
			}
			if mode == "version_author_alias" {
				planActor = f.author
			}
			f.provider.Revision++
			f.document.Metadata.VersionID = securitystate.ID("dirver")
			f.document.Metadata.SecurityGuardVersion = 2
			if e := providerPersonRequest(f, versionActor, func(ctx context.Context) error {
				_, e := f.directory.ProposeVersion(ctx, versionActor, f.provider.ID, f.provider.Revision, f.document)
				return e
			}); e != nil {
				t.Fatal("version author", e)
			}
			f.provider.Revision++
			f.test(t)
			var op *ProviderSecurityOperation
			if e := providerPersonRequest(f, planActor, func(ctx context.Context) error {
				var e error
				op, e = f.directory.PlanActivation(ctx, planActor, f.provider.ID, "provider_people_plan_request", DirectoryActivation{VersionID: f.document.Metadata.VersionID, Enabled: true, Reason: "independent people provider activation"})
				return e
			}); e != nil {
				t.Fatal("operation author", e)
			}
			e := providerPersonRequest(f, people[1].actor, func(ctx context.Context) error {
				_, e := f.directory.ApproveOperationRequest(ctx, people[1].actor, op.ID, "provider_people_approve_request", op.RequestDigest, "independent human provider review")
				return e
			})
			if mode == "distinct_AD_people" {
				if e != nil {
					t.Fatal("distinct AD reviewer", e)
				}
				if e = providerPersonRequest(f, planActor, func(ctx context.Context) error {
					applied, e := f.directory.ExecuteOperationRequest(ctx, planActor, op.ID, "provider_people_execute_request", op.RequestDigest, "author may execute independently reviewed change")
					if e == nil && applied.State != "applied" {
						t.Fatal("independent provider not applied")
					}
					return e
				}); e != nil {
					t.Fatal("legitimate author executor", e)
				}
				return
			}
			if !errors.Is(e, storage.ErrPermissionDenied) {
				t.Fatal("same AD person approved through provider alias", e)
			}
			assertProviderApprovalAbsent(t, f, "directory_provider_approvals", op.ID)

			// Model an approval legitimately persisted by the previous software.
			// Current public receipts and execution must reject that old metadata.
			e = providerPersonRequest(f, people[1].actor, func(ctx context.Context) error {
				return f.directory.current(ctx, people[1].actor, true, true, func(tx storage.IdentityTx, h securityjournal.Head, p *directoryPrincipal) error {
					if _, e := tx.Exec(ctx, `INSERT INTO directory_provider_approvals(id,operation_id,request_digest,reviewer_id,reviewer_fingerprint,mfa_at,created_at,reason) VALUES(?,?,?,?,?,?,?,?)`, securitystate.ID("approval"), op.ID, op.RequestDigest, p.id, p.fingerprint, p.mfa, h.RecordedAt, "trusted pre-fix approval fixture"); e != nil {
						return e
					}
					_, e := tx.Exec(ctx, `UPDATE directory_provider_operations SET approval_status='approved' WHERE id=?`, op.ID)
					return e
				})
			})
			if e != nil {
				t.Fatal("legacy approval fixture", e)
			}
			if view, e := f.directory.GetOperation(f.ctx, f.author, op.ID); e != nil || view.ApprovalStatus != "expired" {
				t.Fatal("current receipt accepted aliased old approval", view, e)
			}
			before := providerJournalEvents(f.fixture)
			if _, e = f.directory.ExecuteOperationRequest(f.ctx, f.author, op.ID, "provider_legacy_execute_request", op.RequestDigest, "old metadata cannot authorize execution"); !errors.Is(e, storage.ErrPermissionDenied) {
				t.Fatal("historical aliased reviewer executed", e)
			}
			if providerJournalEvents(f.fixture) != before {
				t.Fatal("rejected old approval appended journal event")
			}
			ctx, e := f.directory.operationPeopleContext(f.ctx, f.author, op.ID, true, false)
			if e != nil {
				t.Fatal(e)
			}
			// A trusted old pending receipt can replay its restrictive floor, but
			// final materialization must never activate the invalid positive state.
			e = f.s.Coordinator.ExecuteDynamic(ctx, "directory_provider_change", func(tx storage.IdentityTx, h securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error) {
				raw, e := configmodel.CanonicalJSON(directoryChangeIntent{OperationID: op.ID, RequestDigest: op.RequestDigest, Change: op.ProviderChange, ActorID: f.user.ID, ApproverID: people[1].id})
				return raw, []securityjournal.AppendRequest{securitystate.FloorRequest(f.user.ID, op.ProviderChange.GuardID, op.ProviderChange.GuardID, uint64(op.ProviderChange.NextGuardVersion))}, e
			})
			if e != nil {
				t.Fatal("old pending receipt", e)
			}
			if view, e := f.directory.GetOperation(f.ctx, f.author, op.ID); e != nil || view.State != "recovery_required" {
				t.Fatal("final receipt activated aliased quorum", view, e)
			}
			if _, e = f.directory.CurrentProvider(f.ctx, f.provider.ID); e == nil {
				t.Fatal("restrictive floor lost after aliased old receipt")
			}
			assertProviderPeopleObserved(t, people)
		})
	}
}

func providerJournalEvents(f *fixture) int {
	f.j.mu.Lock()
	defer f.j.mu.Unlock()
	return len(f.j.events)
}
func assertProviderApprovalAbsent(t *testing.T, f *directoryAuthFixture, table, id string) {
	t.Helper()
	if table != "directory_provider_approvals" && table != "oidc_approvals" {
		t.Fatal("invalid test table")
	}
	if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		var n int
		if e := securitystate.One(f.ctx, tx, `SELECT COUNT(*) FROM `+table+` WHERE operation_id=?`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&n) }); e != nil {
			return e
		}
		if n != 0 {
			t.Fatal("alias denial persisted approval")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
func assertProviderPeopleObserved(t *testing.T, people []providerPersonFixture) {
	t.Helper()
	for _, person := range people {
		if person.wire.serviceBinds.Load() == 0 {
			t.Fatal("missing actual current TLS LDAP observation", person.id)
		}
	}
}

func TestOIDCIndependentPeopleSQLite(t *testing.T)   { oidcIndependentPeople(t, false) }
func TestOIDCIndependentPeoplePostgres(t *testing.T) { oidcIndependentPeople(t, true) }
func oidcIndependentPeople(t *testing.T, pg bool) {
	for _, mode := range []string{"operation_author_alias", "version_author_alias", "link_author_alias", "distinct_AD_people", "distinct_AD_link_people"} {
		t.Run(mode, func(t *testing.T) {
			f := newOIDCFixture(t, pg)
			independent := mode == "distinct_AD_people" || mode == "distinct_AD_link_people"
			people := providerPeopleFixture(t, f.directoryAuthFixture, !independent)
			versionActor, planActor := f.author, people[0].actor
			if mode == "version_author_alias" || independent {
				versionActor = people[0].actor
			}
			if mode == "version_author_alias" {
				planActor = f.author
			}
			var op *OIDCSecurityOperation
			linkChange := mode == "link_author_alias" || mode == "distinct_AD_link_people"
			if linkChange {
				f.activateOIDC(t)
				f.directoryIdentity = f.provision(t)
				if e := providerPersonRequest(f.directoryAuthFixture, planActor, func(ctx context.Context) error {
					var e error
					op, e = f.oidc.PlanLink(ctx, planActor, f.p.ID, "oidc_people_link_plan_request", OIDCLinkCreate{Subject: "ProviderPeopleSubject", DirectoryIdentityID: f.directoryIdentity.ID, ExpiresAt: f.now.Add(4 * time.Minute), Reason: "independently reviewed external identity binding"})
					return e
				}); e != nil {
					t.Fatal("link plan", e)
				}
			} else {
				if e := providerPersonRequest(f.directoryAuthFixture, versionActor, func(ctx context.Context) error {
					_, e := f.oidc.ProposeVersion(ctx, versionActor, f.p.ID, f.p.Revision, f.documentOIDC)
					return e
				}); e != nil {
					t.Fatal("version author", e)
				}
				f.p.Revision++
				if result, e := f.oidc.TestProvider(f.ctx, f.author, f.p.ID, f.documentOIDC.Metadata.VersionID); e != nil || result.State != "passed" {
					t.Fatal("actual OIDC test", result, e)
				}
				if e := providerPersonRequest(f.directoryAuthFixture, planActor, func(ctx context.Context) error {
					var e error
					op, e = f.oidc.PlanActivationAtRevision(ctx, planActor, f.p.ID, "oidc_people_plan_request", f.p.Revision, DirectoryActivation{VersionID: f.documentOIDC.Metadata.VersionID, Enabled: true, Reason: "independently reviewed provider activation"})
					return e
				}); e != nil {
					t.Fatal("operation author", e)
				}
			}
			e := providerPersonRequest(f.directoryAuthFixture, people[1].actor, func(ctx context.Context) error {
				_, e := f.oidc.ApproveOperationRequest(ctx, people[1].actor, op.ID, "oidc_people_approve_request", op.RequestDigest, "independent human OIDC review")
				return e
			})
			if independent {
				if e != nil {
					t.Fatal("distinct AD reviewer", e)
				}
				if e = providerPersonRequest(f.directoryAuthFixture, planActor, func(ctx context.Context) error {
					applied, e := f.oidc.ExecuteOperationRequest(ctx, planActor, op.ID, "oidc_people_execute_request", op.RequestDigest, "author may execute independently reviewed OIDC change")
					if e == nil && applied.State != "applied" {
						t.Fatal("independent OIDC operation not applied")
					}
					return e
				}); e != nil {
					t.Fatal("legitimate author executor", e)
				}
				assertProviderPeopleObserved(t, people)
				return
			}
			if !errors.Is(e, storage.ErrPermissionDenied) {
				t.Fatal("same AD person approved OIDC through provider alias", e)
			}
			assertProviderApprovalAbsent(t, f.directoryAuthFixture, "oidc_approvals", op.ID)
			e = providerPersonRequest(f.directoryAuthFixture, people[1].actor, func(ctx context.Context) error {
				return f.oidc.current(ctx, people[1].actor, true, true, func(tx storage.IdentityTx, h securityjournal.Head, p *directoryPrincipal) error {
					if _, e := tx.Exec(ctx, `INSERT INTO oidc_approvals(id,operation_id,request_digest,reviewer_id,reviewer_fingerprint,mfa_at,primary_at,created_at,reason) VALUES(?,?,?,?,?,?,?,?,?)`, securitystate.ID("approval"), op.ID, op.RequestDigest, p.id, p.fingerprint, p.mfa, f.now, h.RecordedAt, "trusted pre-fix OIDC approval fixture"); e != nil {
						return e
					}
					_, e := tx.Exec(ctx, `UPDATE oidc_operations SET approval_status='approved' WHERE id=?`, op.ID)
					return e
				})
			})
			if e != nil {
				t.Fatal("legacy OIDC approval fixture", e)
			}
			if view, e := f.oidc.GetOperation(f.ctx, f.author, op.ID); e != nil || view.ApprovalStatus != "expired" {
				t.Fatal("OIDC current receipt accepted old alias approval", view, e)
			}
			before := providerJournalEvents(f.fixture)
			if _, e = f.oidc.ExecuteOperationRequest(f.ctx, f.author, op.ID, "oidc_legacy_execute_request", op.RequestDigest, "old metadata cannot authorize OIDC execution"); !errors.Is(e, storage.ErrPermissionDenied) {
				t.Fatal("historical aliased OIDC reviewer executed", e)
			}
			if providerJournalEvents(f.fixture) != before {
				t.Fatal("rejected old OIDC approval appended journal event")
			}
			ctx, e := f.oidc.peopleContext(f.ctx, f.author, op.ID)
			if e != nil {
				t.Fatal(e)
			}
			guard := ""
			var next securityjournal.UInt63
			if c := op.ProviderChange; c != nil {
				var version *OIDCVersionView
				var head securityjournal.Head
				if e = f.s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
					var e error
					head = h
					version, e = readOIDCVersion(ctx, tx, c.ProviderID, c.VersionID)
					return e
				}); e == nil {
					ctx, e = f.oidc.connectivity(ctx, version, head)
				}
				guard, next = c.GuardID, c.NextGuardVersion
			} else {
				c := op.OIDCLinkChange
				ctx, e = f.oidc.withLiveTarget(ctx, *c)
				guard, next = c.GuardID, c.NextGuardVersion
			}
			if e != nil {
				t.Fatal("fresh final receipt connectivity/target proof", e)
			}
			var intent oidcChangeIntent
			if e = f.oidc.current(ctx, f.author, true, false, func(tx storage.IdentityTx, _ securityjournal.Head, p *directoryPrincipal) error {
				intent = oidcChangeIntent{OperationID: op.ID, RequestDigest: op.RequestDigest, ActorID: p.id, ActorFingerprint: p.fingerprint, ActorMFAAt: p.mfa, ActorPrimaryAt: f.now}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			e = f.s.Coordinator.ExecuteDynamic(ctx, "oidc_security_change", func(tx storage.IdentityTx, h securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error) {
				raw, e := configmodel.CanonicalJSON(intent)
				return raw, []securityjournal.AppendRequest{securitystate.FloorRequest(f.user.ID, guard, guard, uint64(next))}, e
			})
			if e != nil {
				t.Fatal("old OIDC pending receipt", e)
			}
			if view, e := f.oidc.GetOperation(f.ctx, f.author, op.ID); e != nil || view.State != "recovery_required" {
				t.Fatal("final OIDC receipt applied aliased quorum", view, e)
			}
			if e = f.s.Coordinator.Current(f.ctx, func(tx storage.IdentityTx, _ securityjournal.Head) error {
				floor, e := securitystate.Floor(f.ctx, tx, guard, guard)
				if e == nil && floor != uint64(next) {
					t.Fatal("old receipt lost restrictive OIDC floor", floor, next)
				}
				return e
			}); e != nil {
				t.Fatal(e)
			}
			assertProviderPeopleObserved(t, people)
		})
	}
}
