package rolloutexecution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/netwizd/agp/internal/deploymentplan"
	"github.com/netwizd/agp/internal/helper"
	"github.com/netwizd/agp/internal/rolescope"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
	"github.com/netwizd/agp/internal/storage/postgres"
	"github.com/netwizd/agp/internal/storage/sqlite"
)

type fixtureAuthority struct{}

func (fixtureAuthority) Head(context.Context) (securityjournal.Head, error) {
	return securityjournal.Head{AuthorityID: "execution_test", Epoch: 1, Sequence: 0, Digest: "", RecordedAt: time.Now().UTC()}, nil
}
func (fixtureAuthority) Append(context.Context, securityjournal.AppendRequest) (securityjournal.Event, error) {
	return securityjournal.Event{}, errors.New("unexpected append")
}
func (fixtureAuthority) Operation(context.Context, string) (securityjournal.Event, error) {
	return securityjournal.Event{}, storage.ErrNotFound
}
func (fixtureAuthority) Events(context.Context, securityjournal.UInt63, int) ([]securityjournal.Event, error) {
	return nil, nil
}

// This is an installation-source double for CP transaction tests. Its fixture
// signatures and SQL facts are NOT native qualification or capture evidence.
type fixtureSources struct {
	installation  helper.Installation
	receiptKey    ed25519.PrivateKey
	failAfterTask atomic.Bool
	unavailable   atomic.Bool
}

func (s *fixtureSources) baseline(ctx context.Context, tx storage.IdentityTx) (helper.ExecutionGeneration, error) {
	return s.baselineFor(ctx, tx, "node_one")
}
func (s *fixtureSources) baselineFor(ctx context.Context, tx storage.IdentityTx, node string) (helper.ExecutionGeneration, error) {
	var raw string
	var base helper.ExecutionGeneration
	err := securitystate.One(ctx, tx, `SELECT generation_json FROM execution_fixture_baseline WHERE node_id=?`, []any{node}, func(r storage.IdentityRows) error { return r.Scan(&raw) })
	if err == nil {
		err = json.Unmarshal([]byte(raw), &base)
	}
	return base, err
}
func (s *fixtureSources) Resolve(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, in Selection) (*Snapshot, error) {
	if s.unavailable.Load() {
		return nil, ErrUnavailable
	}
	out := &Snapshot{CompilerVersion: "execution-fixture-1", ResolvedInputs: []deploymentplan.ResolvedInput{{Kind: "component_profile", ID: "profile_one", Digest: s.installation.ComponentProfileDigest}}, Authors: []string{"author"}, Targets: []TargetSnapshot{}}
	for _, node := range in.NodeIDs {
		base, err := s.baselineFor(ctx, tx, node)
		if err != nil {
			return nil, err
		}
		accepted := int64(base.Baseline.NodeDeploymentSequence)
		err = securitystate.One(ctx, tx, `SELECT accepted_sequence FROM execution_node_counters WHERE node_id=?`, []any{node}, func(r storage.IdentityRows) error { return r.Scan(&accepted) })
		if err != nil && err != storage.ErrNotFound {
			return nil, err
		}
		installation := s.installation
		installation.NodeID = node
		target := TargetSnapshot{Installation: installation, Baseline: base, AcceptedSequence: securityjournal.UInt63(accepted), NodeGroupIDs: []string{"group_one"}, BundleDigest: digest("bundle_" + in.RevisionID), TargetTreeDigest: digest("tree_" + in.RevisionID), DeploymentGeneration: "generation_" + in.RevisionID, SecretVersionIDs: []string{}, SourceDigest: digest([]any{"fixture_only", base, accepted}), ReceiptKeyID: "receipt_key", ReceiptPublicKey: base64.RawURLEncoding.EncodeToString(s.receiptKey.Public().(ed25519.PublicKey))}
		out.Targets = append(out.Targets, target)
	}
	return out, nil
}
func (s *fixtureSources) Recheck(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, t TargetSnapshot) error {
	if s.unavailable.Load() {
		return ErrUnavailable
	}
	if s.failAfterTask.Load() {
		var n int64
		if err := securitystate.One(ctx, tx, `SELECT COUNT(*) FROM execution_tasks`, nil, func(r storage.IdentityRows) error { return r.Scan(&n) }); err != nil {
			return err
		}
		if n > 0 {
			return ErrUnavailable
		}
	}
	base, err := s.baselineFor(ctx, tx, t.Installation.NodeID)
	if err != nil {
		return err
	}
	if base != t.Baseline {
		return ErrStale
	}
	return nil
}
func (s *fixtureSources) Record(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, t TargetSnapshot, r helper.ExecutionReceipt) error {
	if err := helper.VerifyExecutionReceipt(r, "receipt_key", s.receiptKey.Public().(ed25519.PublicKey)); err != nil {
		return err
	}
	if r.State == "recovery_required" {
		return nil
	}
	raw, err := canonical(r.Active)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE execution_fixture_baseline SET generation_json=? WHERE node_id=?`, string(raw), r.NodeID)
	return err
}

type executionFixture struct {
	store      storage.Store
	service    *Service
	sources    *fixtureSources
	peer       *tls.ConnectionState
	peerTwo    *tls.ConnectionState
	ctx        context.Context
	journalKey ed25519.PrivateKey
	trust      helper.Trust
}

func newExecutionFixture(t *testing.T, pg bool) *executionFixture {
	t.Helper()
	ctx := context.Background()
	var store storage.Store
	var err error
	if pg {
		dsn := os.Getenv("AGP_TEST_EXECUTION_DSN")
		if dsn == "" {
			dsn = os.Getenv("AGP_TEST_CONFIGURATION_DSN")
		}
		if dsn == "" {
			dsn = os.Getenv("AGP_TEST_POSTGRES_DSN")
		}
		if dsn == "" {
			t.Skip("PostgreSQL execution DSN is not set")
		}
		admin, e := pgxpool.New(ctx, dsn)
		if e != nil {
			t.Fatal(e)
		}
		schema := strings.ToLower(securitystate.ID("execution"))
		quoted := pgx.Identifier{schema}.Sanitize()
		if _, e = admin.Exec(ctx, `CREATE SCHEMA `+quoted); e != nil {
			admin.Close()
			t.Fatal(e)
		}
		t.Cleanup(func() { _, _ = admin.Exec(ctx, `DROP SCHEMA `+quoted+` CASCADE`); admin.Close() })
		if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
			u, e := url.Parse(dsn)
			if e != nil {
				t.Fatal(e)
			}
			q := u.Query()
			q.Set("search_path", schema)
			u.RawQuery = q.Encode()
			dsn = u.String()
		} else {
			dsn += " search_path=" + schema
		}
		store, err = postgres.Open(ctx, dsn)
	} else {
		store, err = sqlite.Open(t.TempDir() + "/execution.db")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err = store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if pg {
		release, e := store.(interface {
			AcquireIdentityLease(context.Context) (func(), error)
		}).AcquireIdentityLease(ctx)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(release)
	}
	_, permit, _ := ed25519.GenerateKey(rand.Reader)
	_, control, _ := ed25519.GenerateKey(rand.Reader)
	_, receipt, _ := ed25519.GenerateKey(rand.Reader)
	_, journal, _ := ed25519.GenerateKey(rand.Reader)
	trust := helper.Trust{PermitKeyID: "permit_key", PermitKey: permit.Public().(ed25519.PublicKey), ControlKeyID: "control_key", ControlKey: control.Public().(ed25519.PublicKey), JournalKeyID: "journal_key", JournalKey: journal.Public().(ed25519.PublicKey)}
	trustDigest, e := helper.TrustDigest(trust)
	if e != nil {
		t.Fatal(e)
	}
	i := helper.Installation{APIVersion: helper.InstallationVersion, NodeID: "node_one", SiteID: "site_one", IdentityDigest: digest("identity"), OwnershipDigest: digest("ownership"), CapabilityDigest: digest("capability"), ComponentProfileDigest: digest("profile"), ReleaseManifestDigest: digest("release"), TupleDigest: digest("tuple"), CompilerDigest: digest("compiler"), TrustDigest: trustDigest, AuthorityID: "execution_test", AuthorityEpoch: 1, WriterEpoch: 1, Baseline: helper.Baseline{RevisionID: "revision_base", BundleDigest: digest("bundle_revision_base"), NodeDeploymentSequence: 7}}
	base := helper.ExecutionGeneration{Baseline: i.Baseline, GenerationID: "generation_revision_base", TreeDigest: digest("tree_revision_base")}
	now := time.Now().UTC()
	err = store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		if _, e := tx.Exec(ctx, `CREATE TABLE execution_fixture_baseline(id INTEGER PRIMARY KEY,node_id TEXT NOT NULL UNIQUE,generation_json TEXT NOT NULL)`); e != nil {
			return e
		}
		raw, _ := canonical(base)
		if _, e := tx.Exec(ctx, `INSERT INTO execution_fixture_baseline(id,node_id,generation_json) VALUES(1,'node_one',?),(2,'node_two',?)`, string(raw), string(raw)); e != nil {
			return e
		}
		for _, id := range []string{"author", "approver", "deployer", "admin"} {
			if _, e := tx.Exec(ctx, `INSERT INTO users(id,username,password_hash,is_admin) VALUES(?,?,?,?)`, id, id, "hash", id == "admin"); e != nil {
				return e
			}
			if _, e := tx.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,csrf_hash,ip,user_agent,expires_at,created_at,audience,audience_origin,authority_epoch,security_version,mfa_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?,'management','https://management.test',1,1,?,?)`, id, id, id+"_token", "csrf", "", "", now.Add(time.Hour), now, now, now); e != nil {
				return e
			}
		}
		graph := rolescope.Manifest{APIVersion: "agp.role-scopes/v1alpha1", ID: "execution_graph", Sites: []rolescope.Site{{ID: "site_one"}}, NodeGroups: []rolescope.NodeGroup{{ID: "group_one", SiteID: "site_one"}}, Nodes: []rolescope.Node{{ID: "node_one", SiteID: "site_one", GroupIDs: []string{"group_one"}}, {ID: "node_two", SiteID: "site_one", GroupIDs: []string{"group_one"}}}, Resources: []rolescope.Resource{}, ResourceRoutes: []rolescope.ResourceRoute{}}
		if err := rolescope.BootstrapTx(ctx, tx, 1, graph); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO security_state(id,authority_id,epoch,sequence,digest,enabled) VALUES(1,'execution_test',1,0,?,TRUE)`, ""); err != nil {
			return err
		}
		if err := securitystate.EnsureBuiltinRolesTx(ctx, tx); err != nil {
			return err
		}
		head := securityjournal.Head{AuthorityID: "execution_test", Epoch: 1, Sequence: 0, Digest: "", RecordedAt: now}
		for _, grant := range []struct{ id, user, permission, scope, scopeID string }{{"author_edit", "author", "config.edit", "site", "site_one"}, {"author_approve", "author", "config.approve", "site", "site_one"}, {"approver_read", "approver", "config.read", "site", "site_one"}, {"approver_approve", "approver", "config.approve", "site", "site_one"}, {"deployer_read", "deployer", "config.read", "site", "site_one"}, {"deployer_create", "deployer", "rollouts.create", "node_group", "group_one"}, {"deployer_cancel", "deployer", "rollouts.cancel", "site", "site_one"}, {"deployer_rollback", "deployer", "rollouts.rollback", "node", "node_one"}, {"admin_read", "admin", "config.read", "global", ""}} {
			role, err := securitystate.ReadRoleDefinitionTx(ctx, tx, "role_"+strings.ReplaceAll(grant.permission, ".", "_"))
			if err != nil {
				return err
			}
			binding := securitystate.RoleBinding{ID: "rbinding_" + grant.id, PrincipalID: grant.user, RoleID: role.ID, RoleVersion: role.Version, RoleDigest: role.Digest, ScopeType: grant.scope, ScopeID: grant.scopeID, Revision: 1, AuthorityEpoch: 1, CreatedAt: now}
			if err = securitystate.PublishRoleBindingTx(ctx, tx, head, binding); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sources := &fixtureSources{installation: i, receiptKey: receipt}
	coordinator := securitystate.New(store, fixtureAuthority{})
	svc, err := New(coordinator, sources, Keys{PermitKeyID: "permit_key", PermitKey: permit, ControlKeyID: "control_key", ControlKey: control}, "https://management.test")
	if err != nil {
		t.Fatal(err)
	}
	peer := &tls.ConnectionState{Version: tls.VersionTLS13}
	peerTwo := &tls.ConnectionState{Version: tls.VersionTLS13}
	svc.WithAgentAuthenticator(func(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, actual *tls.ConnectionState) (string, error) {
		if actual != peer && actual != peerTwo {
			return "", storage.ErrPermissionDenied
		}
		node := "node_one"
		if actual == peerTwo {
			node = "node_two"
		}
		if err := checkNode(ctx, tx, node); err != nil {
			return "", err
		}
		return node, nil
	})
	return &executionFixture{store: store, service: svc, sources: sources, peer: peer, peerTwo: peerTwo, ctx: ctx, journalKey: journal, trust: trust}
}
func actor(id string) Actor {
	return Actor{TokenHash: id + "_token", Origin: "https://management.test"}
}
func (f *executionFixture) create(t *testing.T, key string) *ExecutionPlan {
	t.Helper()
	p, e := f.service.Create(f.ctx, actor("author"), key, Create{SiteID: "site_one", RevisionID: "revision_target", NodeIDs: []string{"node_one"}, Policy: deploymentplan.RolloutPolicy{CanaryNodeIDs: []string{"node_one"}, MaxParallel: 1, MaxUnavailable: 1, ObservationSeconds: 30, FailureAction: "pause"}, Reason: "Reviewed actual execution fixture only", ExpiresAt: time.Now().UTC().Add(10 * time.Minute)})
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func (f *executionFixture) approved(t *testing.T, key string) *ExecutionPlan {
	t.Helper()
	p := f.create(t, key)
	if _, e := f.service.Approve(f.ctx, actor("approver"), p.Plan.ID, "approval_key_00000001", p.Plan.PlanDigest); e != nil {
		t.Fatal(e)
	}
	return p
}
func (f *executionFixture) dispatched(t *testing.T, p *ExecutionPlan) helper.Request {
	t.Helper()
	tasks, e := f.service.Dispatch(f.ctx, actor("deployer"), p.Plan.ID, "dispatch_key_00000001")
	if e != nil || len(tasks) != 1 {
		t.Fatalf("dispatch: %#v %v", tasks, e)
	}
	return tasks[0]
}
func (f *executionFixture) count(t *testing.T, query string, args ...any) int64 {
	t.Helper()
	var n int64
	e := f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		return securitystate.One(f.ctx, tx, query, args, func(r storage.IdentityRows) error { return r.Scan(&n) })
	})
	if e != nil {
		t.Fatal(e)
	}
	return n
}
func (f *executionFixture) receipt(t *testing.T, request helper.Request, state string) helper.ExecutionReceipt {
	t.Helper()
	active := helper.ExecutionGeneration{Baseline: f.sources.installation.Baseline, GenerationID: "generation_revision_base", TreeDigest: digest("tree_revision_base")}
	if state == "succeeded" {
		active = helper.ExecutionGeneration{Baseline: helper.Baseline{RevisionID: request.Task.Payload.TargetRevisionID, BundleDigest: request.Task.Payload.BundleDigest, NodeDeploymentSequence: request.Task.NodeDeploymentSequence}, GenerationID: request.Task.Payload.DeploymentGeneration, TreeDigest: digest("tree_" + request.Task.Payload.TargetRevisionID)}
	}
	r := helper.ExecutionReceipt{APIVersion: helper.ExecutionReceiptVersion, Purpose: "local_execution_outcome", ReceiptID: securitystate.ID("receipt"), ReceiptSequence: 1, NodeID: request.Task.NodeID, TaskID: request.Task.ID, RequestDigest: digest(request), NodeDeploymentSequence: request.Task.NodeDeploymentSequence, Active: active, State: state, RecoveryRequired: state == "recovery_required", RecordedAt: utc(time.Now()), KeyID: "receipt_key"}
	r.Signature = sign(r, "AGP-HELPER-EXECUTION-RECEIPT-v1", f.sources.receiptKey)
	return r
}
func (f *executionFixture) query(request helper.Request) helper.StartQuery {
	h, _ := (fixtureAuthority{}).Head(f.ctx)
	return helper.StartQuery{APIVersion: helper.StartVersion, Challenge: "fresh_challenge_0000001", RequestDigest: digest(request), InstallationDigest: request.Permit.InstallationDigest, Head: helper.HeadPin{AuthorityID: h.AuthorityID, Epoch: h.Epoch, Sequence: h.Sequence, Digest: h.Digest}}
}

func TestExecutionLifecycleSQLite(t *testing.T)   { testExecutionLifecycle(t, false) }
func TestExecutionLifecyclePostgres(t *testing.T) { testExecutionLifecycle(t, true) }
func testExecutionLifecycle(t *testing.T, pg bool) {
	t.Run("completed_canary_keeps_remaining_target_current", func(t *testing.T) {
		f := newExecutionFixture(t, pg)
		p, e := f.service.Create(f.ctx, actor("author"), "two_nodes_create_0001", Create{SiteID: "site_one", RevisionID: "revision_target", NodeIDs: []string{"node_one", "node_two"}, Policy: deploymentplan.RolloutPolicy{CanaryNodeIDs: []string{"node_one"}, MaxParallel: 1, MaxUnavailable: 1, ObservationSeconds: 30, FailureAction: "pause"}, Reason: "Canary before the next independently frozen node", ExpiresAt: time.Now().Add(10 * time.Minute)})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.service.Approve(f.ctx, actor("approver"), p.Plan.ID, "two_nodes_approval_01", p.Plan.PlanDigest); e != nil {
			t.Fatal(e)
		}
		first := f.dispatched(t, p)
		if first.Task.NodeID != "node_one" {
			t.Fatal("noncanary dispatched first")
		}
		if e = f.service.RecordReceiptPeer(f.ctx, f.peer, f.receipt(t, first, "succeeded")); e != nil {
			t.Fatal(e)
		}
		f.service.current = fixtureClock{underlying: f.service.current, advance: 31 * time.Second}
		view, e := f.service.Get(f.ctx, actor("deployer"), p.Plan.ID)
		if e != nil || !view.Current || view.Access == nil || !view.Access.Dispatch {
			t.Fatalf("own completed baseline invalidated remaining wave: %#v %v", view, e)
		}
		next, e := f.service.Dispatch(f.ctx, actor("deployer"), p.Plan.ID, "two_nodes_dispatch_02")
		if e != nil || len(next) != 1 || next[0].Task.NodeID != "node_two" {
			t.Fatalf("second frozen node not dispatched: %#v %v", next, e)
		}
	})
	t.Run("independent_exact_approval_explicit_dispatch_and_signed_receipt", func(t *testing.T) {
		f := newExecutionFixture(t, pg)
		p := f.create(t, "create_key_0000000001")
		if _, e := f.service.Approve(f.ctx, actor("author"), p.Plan.ID, "self_approval_0000001", p.Plan.PlanDigest); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatalf("self approval: %v", e)
		}
		if _, e := f.service.Approve(f.ctx, actor("approver"), p.Plan.ID, "wrong_digest_00000001", digest("other")); !errors.Is(e, ErrConflict) {
			t.Fatalf("wrong digest: %v", e)
		}
		if _, e := f.service.Approve(f.ctx, actor("approver"), p.Plan.ID, "approval_key_00000001", p.Plan.PlanDigest); e != nil {
			t.Fatal(e)
		}
		for _, id := range []string{"author", "admin"} {
			if _, e := f.service.Dispatch(f.ctx, actor(id), p.Plan.ID, "denied_dispatch_00001"); !errors.Is(e, storage.ErrPermissionDenied) {
				t.Fatalf("%s dispatch broadened: %v", id, e)
			}
		}
		request := f.dispatched(t, p)
		if request.Task.NodeDeploymentSequence != 8 || request.Task.Preconditions.ExpectedNodeDeploymentSequence != 7 || request.Permit.InstallationDigest != digest(f.sources.installation) {
			t.Fatal("wrong sequence or immutable installation pin")
		}
		if e := deploymentplan.Verify(*request.SignedPlan, f.service.keys.PermitKeyID, f.service.keys.PermitKey.Public().(ed25519.PublicKey), time.Now()); e != nil {
			t.Fatal(e)
		}
		replay, e := f.service.Dispatch(f.ctx, actor("deployer"), p.Plan.ID, "dispatch_key_00000001")
		if e != nil || len(replay) != 1 || digest(replay[0]) != digest(request) {
			t.Fatalf("dispatch replay: %v", e)
		}
		pending, e := f.service.PendingForPeer(f.ctx, f.peer)
		if e != nil || len(pending) != 1 || digest(pending[0]) != digest(request) {
			t.Fatalf("delivery: %v", e)
		}
		proof, e := f.service.AuthorizeStartPeer(f.ctx, f.peer, f.query(request))
		if e != nil || proof.WriterEpoch != 1 || proof.Query.RequestDigest != digest(request) {
			t.Fatalf("current start: %v", e)
		}
		r := f.receipt(t, request, "succeeded")
		forged := r
		forged.Signature = sign(forged, "AGP-HELPER-EXECUTION-RECEIPT-v1", f.service.keys.ControlKey)
		if e = f.service.RecordReceiptPeer(f.ctx, f.peer, forged); e == nil {
			t.Fatal("relay/control signature updated verified baseline")
		}
		if f.count(t, `SELECT COUNT(*) FROM execution_receipts`) != 0 {
			t.Fatal("forged receipt persisted")
		}
		if e = f.service.RecordReceiptPeer(f.ctx, f.peer, r); e != nil {
			t.Fatal(e)
		}
		if e = f.service.RecordReceiptPeer(f.ctx, f.peer, r); e != nil {
			t.Fatalf("exact durable receipt retry: %v", e)
		}
		if f.count(t, `SELECT accepted_sequence FROM execution_node_counters WHERE node_id='node_one'`) != 8 || f.count(t, `SELECT COUNT(*) FROM execution_receipts`) != 1 || f.count(t, `SELECT COUNT(*) FROM execution_plans WHERE state='succeeded'`) != 1 {
			t.Fatal("terminal result was not atomically projected")
		}
		r.State = "failed"
		r.Signature = ""
		r.Signature = sign(r, "AGP-HELPER-EXECUTION-RECEIPT-v1", f.sources.receiptKey)
		if e = f.service.RecordReceiptPeer(f.ctx, f.peer, r); e == nil {
			t.Fatal("contradicting terminal receipt replaced history")
		}
	})
	t.Run("concurrent_exact_dispatch_allocates_once", func(t *testing.T) {
		f := newExecutionFixture(t, pg)
		p := f.approved(t, "concurrent_create_0001")
		var wg sync.WaitGroup
		results := make([][]helper.Request, 2)
		errs := make([]error, 2)
		for i := range 2 {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				results[i], errs[i] = f.service.Dispatch(f.ctx, actor("deployer"), p.Plan.ID, "concurrent_dispatch_01")
			}(i)
		}
		wg.Wait()
		if errs[0] != nil || errs[1] != nil || len(results[0]) != 1 || len(results[1]) != 1 || digest(results[0][0]) != digest(results[1][0]) {
			t.Fatalf("concurrent dispatch lost durable replay: %v", errs)
		}
		if f.count(t, `SELECT COUNT(*) FROM execution_tasks`) != 1 || f.count(t, `SELECT allocated_sequence FROM execution_node_counters WHERE node_id='node_one'`) != 8 {
			t.Fatal("sequence allocated more than once")
		}
	})
	t.Run("cancel_stops_delivery_and_start_but_preserves_real_outcome", func(t *testing.T) {
		f := newExecutionFixture(t, pg)
		p := f.approved(t, "cancel_create_0000001")
		request := f.dispatched(t, p)
		if e := f.service.Cancel(f.ctx, actor("author"), p.Plan.ID, "denied_cancel_0000001"); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatalf("editor cancelled: %v", e)
		}
		if e := f.service.Cancel(f.ctx, actor("deployer"), p.Plan.ID, "cancel_key_000000001"); e != nil {
			t.Fatal(e)
		}
		if pending, e := f.service.PendingForPeer(f.ctx, f.peer); e != nil || len(pending) != 0 {
			t.Fatalf("cancelled new delivery: %v", e)
		}
		if _, e := f.service.AuthorizeStartPeer(f.ctx, f.peer, f.query(request)); e == nil {
			t.Fatal("cancelled task got new start proof")
		}
		if f.count(t, `SELECT COUNT(*) FROM execution_tasks WHERE state='dispatched'`) != 1 {
			t.Fatal("cancel pretended to undo an active task")
		}
		if e := f.service.RecordReceiptPeer(f.ctx, f.peer, f.receipt(t, request, "succeeded")); e != nil {
			t.Fatal(e)
		}
		if f.count(t, `SELECT COUNT(*) FROM execution_plans WHERE state='cancelled'`) != 1 {
			t.Fatal("late outcome erased cancellation history")
		}
	})
	t.Run("failed_highwater_is_distinct_from_applied_baseline_and_rollback_is_new_plan", func(t *testing.T) {
		f := newExecutionFixture(t, pg)
		p := f.approved(t, "failed_create_0000001")
		request := f.dispatched(t, p)
		if e := f.service.RecordReceiptPeer(f.ctx, f.peer, f.receipt(t, request, "failed")); e != nil {
			t.Fatal(e)
		}
		rollback, e := f.service.Rollback(f.ctx, actor("deployer"), "rollback_create_00001", p.Plan.ID, Create{SiteID: "site_one", RevisionID: "revision_base", NodeIDs: []string{"node_one"}, Policy: p.Plan.RolloutPolicy, Reason: "Explicit independently approved rollback", ExpiresAt: time.Now().Add(10 * time.Minute)})
		if e != nil {
			t.Fatal(e)
		}
		if rollback.Plan.ID == p.Plan.ID || rollback.Plan.Kind != "rollback_config" || rollback.Plan.Targets[0].ExpectedNodeDeploymentSequence != 8 || rollback.Plan.Targets[0].BaseRevisionID != "revision_base" {
			t.Fatal("rollback reused task/sequence or confused highwater with active baseline")
		}
		if _, e = f.service.Dispatch(f.ctx, actor("deployer"), rollback.Plan.ID, "rollback_unapproved_01"); e == nil {
			t.Fatal("rollback bypassed independent approval")
		}
		if _, e = f.service.Approve(f.ctx, actor("approver"), rollback.Plan.ID, "rollback_approval_001", rollback.Plan.PlanDigest); e != nil {
			t.Fatal(e)
		}
		tasks, e := f.service.Dispatch(f.ctx, actor("deployer"), rollback.Plan.ID, "rollback_dispatch_001")
		if e != nil || len(tasks) != 1 || tasks[0].Task.NodeDeploymentSequence != 9 || tasks[0].Task.ID == request.Task.ID || tasks[0].Permit.InstallationDigest != request.Permit.InstallationDigest {
			t.Fatalf("rollback allocation/pin: %#v %v", tasks, e)
		}
	})
	for _, mode := range []string{"grant_revoke", "session_revoke", "node_revoke", "source_outage"} {
		t.Run("start_rechecks_"+mode, func(t *testing.T) {
			f := newExecutionFixture(t, pg)
			p := f.approved(t, "recheck_create_000001")
			request := f.dispatched(t, p)
			err := f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
				var e error
				switch mode {
				case "grant_revoke":
					e = securitystate.MaterializeEvent(f.ctx, tx, securityjournal.Event{ID: "fixture_revoke_deployer", Epoch: 1, Request: securityjournal.AppendRequest{Kind: "revoke_role_binding", TargetType: "grant", TargetID: "rbinding_deployer_create", Payload: securityjournal.Payload{GrantID: "rbinding_deployer_create"}}, RecordedAt: time.Now().UTC()})
				case "session_revoke":
					_, e = tx.Exec(f.ctx, `UPDATE sessions SET revoked_at=? WHERE id='deployer'`, time.Now())
				case "node_revoke":
					_, e = tx.Exec(f.ctx, `INSERT INTO security_node_revocations(node_id,event_id) VALUES('node_one','revoke_fixture')`)
				case "source_outage":
					f.sources.unavailable.Store(true)
				}
				return e
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, e := f.service.AuthorizeStartPeer(f.ctx, f.peer, f.query(request)); e == nil {
				t.Fatal("saved permit bypassed current authority")
			}
			if f.count(t, `SELECT COUNT(*) FROM execution_tasks`) != 1 {
				t.Fatal("start authorization allocated another task")
			}
		})
	}
	t.Run("late_source_failure_rolls_back_sequence_task_audit_and_replay_handle", func(t *testing.T) {
		f := newExecutionFixture(t, pg)
		p := f.approved(t, "atomic_create_0000001")
		f.sources.failAfterTask.Store(true)
		if _, e := f.service.Dispatch(f.ctx, actor("deployer"), p.Plan.ID, "atomic_dispatch_00001"); !errors.Is(e, ErrUnavailable) {
			t.Fatalf("late source failure: %v", e)
		}
		for _, query := range []string{`SELECT COUNT(*) FROM execution_tasks`, `SELECT COUNT(*) FROM execution_node_counters`, `SELECT COUNT(*) FROM execution_rollouts`, `SELECT COUNT(*) FROM execution_requests WHERE operation='dispatch'`, `SELECT COUNT(*) FROM audit_events WHERE event_type='execution.task.dispatched'`} {
			if f.count(t, query) != 0 {
				t.Fatalf("partial execution transaction: %s", query)
			}
		}
		if f.count(t, `SELECT COUNT(*) FROM execution_plans WHERE state='approved'`) != 1 {
			t.Fatal("failed callback advanced plan state")
		}
	})
}

type fixtureClock struct {
	underlying Current
	advance    time.Duration
}

func (c fixtureClock) Head(ctx context.Context) (securityjournal.Head, error) {
	h, e := c.underlying.Head(ctx)
	h.RecordedAt = h.RecordedAt.Add(c.advance)
	return h, e
}
func (c fixtureClock) Current(ctx context.Context, fn func(storage.IdentityTx, securityjournal.Head) error) error {
	return c.underlying.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		h.RecordedAt = h.RecordedAt.Add(c.advance)
		return fn(tx, h)
	})
}
