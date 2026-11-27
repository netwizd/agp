package identity

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func TestRoleDirectoryWireSQLite(t *testing.T)   { roleDirectoryWire(t, false) }
func TestRoleDirectoryWirePostgres(t *testing.T) { roleDirectoryWire(t, true) }

// Four independently pinned provider/link fixtures have actual verified TLS
// LDAP peers. Account/session/role fixture bootstrap is trusted SQL, not a
// corporate AD DS setup or four completed browser logins. Every grant phase
// itself uses production private live-directory observations.
func roleDirectoryWire(t *testing.T, pg bool) {
	for _, mode := range []string{"all_four_live", "creator_disabled", "reviewer_disabled", "target_disabled", "executor_tls_outage", "historical_proof_expired", "final_positive_proof_expired", "reviewer_aliases_creator", "reviewer_aliases_target"} {
		t.Run(mode, func(t *testing.T) {
			f := newDirectoryAuthFixture(t, pg, false)
			wires := []*adWireFixture{f.wire, newADWireFixture(t, "ldaps"), newADWireFixture(t, "ldaps"), newADWireFixture(t, "ldaps")}
			var ca []byte
			ids := []string{}
			for i, wire := range wires {
				wire.config.Spec.ForestGUID = fmt.Sprintf("00000000-0000-0000-0000-%012d", i+100)
				if mode == "reviewer_aliases_creator" && i == 1 {
					wire.config.Spec.ForestGUID = wires[0].config.Spec.ForestGUID
				}
				if mode == "reviewer_aliases_target" && (i == 1 || i == 3) {
					wire.config.Spec.ForestGUID = "00000000-0000-0000-0000-000000000999"
				}
				ca = append(ca, wire.connector.secrets.(adFixtureSecrets).ca...)
				doc := f.document
				doc.Spec.Endpoints = wire.config.Spec.Endpoints
				doc.Spec.ForestGUID = wire.config.Spec.ForestGUID
				ids = append(ids, historicalFixturePrincipalDocument(t, f, 50+i, doc))
			}
			f.wire.connector.secrets = adFixtureSecrets{ca: ca}
			actors := []LifecycleActor{}
			for i, id := range ids[:3] {
				_, hash, e := auth.NewToken()
				if e != nil {
					t.Fatal(e)
				}
				sessionID := securitystate.ID("session")
				e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
					if _, e := tx.Exec(f.ctx, `UPDATE users SET is_admin=TRUE WHERE id=?`, id); e != nil {
						return e
					}
					if _, e := tx.Exec(f.ctx, `INSERT INTO user_groups(user_id,group_id) VALUES(?,?)`, id, f.group.ID); e != nil {
						return e
					}
					if e := InsertSession(f.ctx, tx, domain.Session{ID: sessionID, UserID: id, TokenHash: hash, CSRFHash: auth.TokenHash("fixture role csrf"), Audience: "management", AudienceOrigin: f.s.Profile.ManagementOrigin, AuthorityEpoch: 1, SecurityVersion: 1, CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour), PrimaryAt: &f.now, MFAAt: &f.now, LastSeenAt: &f.now}); e != nil {
						return e
					}
					head, e := f.s.Coordinator.Authority.Head(f.ctx)
					if e != nil {
						return e
					}
					pin, e := directoryAuthPin(f.ctx, tx, head, id)
					if e != nil {
						return e
					}
					return writeDirectoryContext(f.ctx, tx, "sessions", sessionID, pin.context)
				})
				if e != nil {
					t.Fatal(i, e)
				}
				actors = append(actors, LifecycleActor{TokenHash: hash, Origin: f.s.Profile.ManagementOrigin})
			}
			r := f.s.RoleBindingService()
			op, e := r.Create(f.ctx, actors[0], "four_party_role_create", RoleBindingRequest{PrincipalID: ids[3], RoleID: "role_config_read", ScopeType: "global"})
			if e != nil {
				t.Fatal("live AD creator+target", e)
			}
			_, e = r.ApproveOperationRequest(f.ctx, actors[1], op.ID, "four_party_role_approve", op.RequestDigest, "independent live directory reviewer")
			if mode == "reviewer_aliases_creator" || mode == "reviewer_aliases_target" {
				if !errors.Is(e, storage.ErrPermissionDenied) {
					t.Fatal("same AD human through a second provider reviewed grant", e)
				}
				if _, e = r.ExecuteOperationRequest(f.ctx, actors[2], op.ID, "same_ad_alias_execute", op.RequestDigest, "no independent approval exists"); !errors.Is(e, storage.ErrApprovalRequired) {
					t.Fatal("alias rejection left usable approval", e)
				}
				for i, wire := range wires {
					if wire.serviceBinds.Load() == 0 {
						t.Fatal("alias denial lacked current live proof", i)
					}
				}
				if e = f.s.Coordinator.Ready(f.ctx); e != nil {
					t.Fatal("alias denial installed barrier", e)
				}
				return
			}
			if e != nil {
				t.Fatal("live AD reviewer", e)
			}
			switch mode {
			case "creator_disabled":
				wires[0].disabled.Store(true)
			case "reviewer_disabled":
				wires[1].disabled.Store(true)
			case "target_disabled":
				wires[3].disabled.Store(true)
			case "executor_tls_outage":
				wires[2].rejectTLS.Store(true)
			}
			if mode == "historical_proof_expired" {
				observed, e := r.people(f.ctx, actors[2], op.ID)
				if e != nil {
					t.Fatal(e)
				}
				f.clock(f.now.Add(11 * time.Second))
				e = r.current(observed, actors[2], "users.privileged.manage", true, false, func(c context.Context, tx storage.IdentityTx, h securityjournal.Head, _ *lifecyclePrincipal) error {
					rec, e := readRoleOperation(c, tx, op.ID)
					if e != nil {
						return e
					}
					return r.operationCurrent(c, tx, h, rec, true)
				})
				if e == nil {
					t.Fatal("expired historical private proof accepted")
				}
				// Public execution refreshes all observations rather than trusting this
				// expired context. It must still complete with current evidence.
			}

			if mode == "final_positive_proof_expired" {
				observed, e := r.people(f.ctx, actors[2], op.ID)
				if e != nil {
					t.Fatal(e)
				}
				e = r.current(observed, actors[2], "users.privileged.manage", true, false, func(c context.Context, tx storage.IdentityTx, h securityjournal.Head, p *lifecyclePrincipal) error {
					rec, e := readRoleOperation(c, tx, op.ID)
					if e != nil {
						return e
					}
					if e = r.operationCurrent(c, tx, h, rec, true); e != nil {
						return e
					}
					if e = r.checkGrantAuthority(c, tx, h, p, rec); e != nil {
						return e
					}
					f.clock(f.now.Add(11 * time.Second))
					_, e = r.finalGrantHead(c, tx, h, rec, actors[2], p)
					return e
				})
				if e == nil {
					t.Fatal("elapsed final positive proof accepted")
				}
			}
			out, e := r.ExecuteOperationRequest(f.ctx, actors[2], op.ID, "four_party_role_execute", op.RequestDigest, "execute with all current directory people")
			if mode == "all_four_live" || mode == "historical_proof_expired" || mode == "final_positive_proof_expired" {
				if e != nil || out.State != "applied" {
					t.Fatal("four party execution", e)
				}
				for i, w := range wires {
					if w.serviceBinds.Load() == 0 {
						t.Fatal("missing actual LDAP party", i)
					}
				}
			} else if e == nil {
				t.Fatal("missing live authority published role")
			}
			var count int
			if e := f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
				return securitystate.One(f.ctx, tx, `SELECT COUNT(*) FROM role_bindings`, nil, func(row storage.IdentityRows) error { return row.Scan(&count) })
			}); e != nil {
				t.Fatal(e)
			}
			want := 0
			if mode == "all_four_live" || mode == "historical_proof_expired" || mode == "final_positive_proof_expired" {
				want = 1
			}
			if count != want {
				t.Fatal("positive publication after directory failure", count)
			}
			if e := f.s.Coordinator.Ready(f.ctx); e != nil {
				t.Fatal("failed positive operation installed global barrier", e)
			}
		})
	}
}
