package agentvalidation

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/repository"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
	"github.com/netwizd/agp/internal/storage/postgres"
	"github.com/netwizd/agp/internal/storage/sqlite"
)

func testRequest() Request {
	d := repository.Hash([]byte("test pins"))
	return Request{APIVersion: RequestVersion, RequestID: "request_one", AuthorityEpoch: 1, CapabilityDigest: d, Pins: Pins{d, d, d, d, d}, Mode: "blocking", Policy: configmodel.WafPolicy{APIVersion: "agp.waf/v1alpha1", Kind: "WafPolicy", Metadata: configmodel.WafPolicyMetadata{ID: "policy_one", Name: "Closed typed probe", SiteID: "site_one"}, Spec: configmodel.WafPolicySpec{Engine: "modsecurity", RulesetVersionID: "crs_one", ParanoiaLevel: 1, InboundAnomalyThreshold: 5, OutboundAnomalyThreshold: 4, Exceptions: []configmodel.WafException{}}}}
}

type testAgents struct {
	store  storage.Store
	mu     sync.Mutex
	node   inventory.Node
	head   securityjournal.Head
	denied bool
}

func (a *testAgents) Current(ctx context.Context, fn func(storage.IdentityTx, securityjournal.Head) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error { return fn(tx, a.head) })
}
func (a *testAgents) WithFreshAgent(ctx context.Context, peer *tls.ConnectionState, fn func(storage.IdentityTx, securityjournal.Head, inventory.Node) error) error {
	return a.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		if peer == nil || a.denied {
			return inventory.ErrIdentity
		}
		return fn(tx, h, a.node)
	})
}

type testNative struct {
	q     *qualified
	calls int
	err   error
	after func()
}

func (n *testNative) current(context.Context, Pins) (*qualified, error) { return n.q, nil }
func (n *testNative) Check(context.Context, Request) error {
	n.calls++
	if n.after != nil {
		n.after()
	}
	return n.err
}
func fixture(t *testing.T, supplied ...storage.Store) (*Service, *testAgents, *testNative, Request) {
	t.Helper()
	var store storage.Store
	var e error
	if len(supplied) > 0 {
		store = supplied[0]
	} else {
		store, e = sqlite.Open(filepath.Join(t.TempDir(), "validation.db"))
		if e != nil {
			t.Fatal(e)
		}
	}
	t.Cleanup(func() { store.Close() })
	if e = store.Migrate(context.Background()); e != nil {
		t.Fatal(e)
	}
	in := testRequest()
	d := in.CapabilityDigest
	p := repository.ComponentProfile{Platform: repository.Platform{OS: "ubuntu", OSVersion: "24.04", Arch: "amd64"}, Files: []repository.ProfileFile{{Path: "bin/nginx", Digest: d}}}
	q := &qualified{profile: &repository.QualifiedProfile{Profile: p, ProfileDigest: d, Evidence: repository.QualificationEvidence{HostKernel: "kernel"}}}
	a := &testAgents{store: store, head: securityjournal.Head{AuthorityID: "test_authority", Epoch: 1, RecordedAt: time.Now().UTC().Truncate(time.Microsecond)}, node: inventory.Node{ID: "node_one", SiteID: "site_one", IdentityDigest: d, CapabilityDigest: d, Capabilities: inventory.Capabilities{ProtocolVersion: inventory.ProtocolVersion, OS: inventory.OS{ID: "ubuntu", VersionID: "24.04", Architecture: "amd64", Kernel: "kernel"}, Component: &inventory.Component{ProfileDigest: d, Files: []inventory.File{{Path: "bin/nginx", Digest: d}}}}}}
	n := &testNative{q: q}
	return &Service{current: a, agents: a, native: n}, a, n, in
}

func TestAgentLocalValidationPostgres(t *testing.T) {
	dsn := os.Getenv("AGP_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires native PostgreSQL lab")
	}
	ctx := context.Background()
	admin, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close()
	schema := "agent_validation_" + strings.ToLower(stringsWithoutPrefix(repository.Hash([]byte(time.Now().String())))[:20])
	q := pgx.Identifier{schema}.Sanitize()
	if _, e = admin.Exec(ctx, `CREATE SCHEMA `+q); e != nil {
		t.Fatal(e)
	}
	defer admin.Exec(ctx, `DROP SCHEMA `+q+` CASCADE`)
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, e := url.Parse(dsn)
		if e != nil {
			t.Fatal(e)
		}
		query := u.Query()
		query.Set("search_path", schema)
		u.RawQuery = query.Encode()
		dsn = u.String()
	} else {
		dsn += " search_path=" + schema
	}
	store, e := postgres.Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	s, a, n, in := fixture(t, store)
	if lease, e := store.AcquireIdentityLease(ctx); e != nil {
		t.Fatal(e)
	} else {
		defer lease()
	}
	out, e := s.Validate(ctx, &tls.ConnectionState{}, in)
	if e != nil || out.State != "validated" {
		t.Fatalf("out=%+v err=%v", out, e)
	}
	retry, e := s.Validate(ctx, &tls.ConnectionState{}, in)
	if e != nil || !reflect.DeepEqual(out, retry) || n.calls != 1 {
		t.Fatalf("PG exact replay failed: %+v %v", retry, e)
	}
	if e = a.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		_, e := tx.Exec(ctx, `DELETE FROM agent_local_validation_results WHERE id=?`, out.ID)
		return e
	}); e == nil {
		t.Fatal("Postgres result mutable")
	}
}

func TestServiceImmutableExactReplayAndRoleFence(t *testing.T) {
	s, a, n, in := fixture(t)
	ctx := context.Background()
	peer := &tls.ConnectionState{}
	if _, e := s.Validate(ctx, nil, in); !errors.Is(e, inventory.ErrIdentity) {
		t.Fatalf("fake agent admitted: %v", e)
	}
	out, e := s.Validate(ctx, peer, in)
	if e != nil || out.State != "validated" || out.NodeDeploymentSequence != 0 || !out.NativeSyntaxOnly || out.ExecutionLocation != "control_plane" {
		t.Fatalf("result=%+v err=%v", out, e)
	}
	retry, e := s.Validate(ctx, peer, in)
	if e != nil || !reflect.DeepEqual(out, retry) || n.calls != 1 {
		t.Fatalf("retry reran job: %v calls=%d", e, n.calls)
	}
	in.Mode = "detection"
	if _, e = s.Validate(ctx, peer, in); !errors.Is(e, ErrConflict) {
		t.Fatalf("changed replay accepted: %v", e)
	}
	if e = a.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		_, e := tx.Exec(ctx, `UPDATE agent_local_validation_results SET result_json='{}' WHERE id=?`, out.ID)
		return e
	}); e == nil {
		t.Fatal("result mutable")
	}
	if e = a.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		_, e := tx.Exec(ctx, `DELETE FROM agent_local_validation_requests WHERE id=?`, out.ID)
		return e
	}); e == nil {
		t.Fatal("intent deletable")
	}
	a.mu.Lock()
	a.denied = true
	a.mu.Unlock()
	if _, e = s.Get(ctx, peer, out.ID); !errors.Is(e, inventory.ErrIdentity) {
		t.Fatalf("revoked identity read result: %v", e)
	}
}

func TestServicePostExecutionFencesAndNoRetryExecution(t *testing.T) {
	for _, name := range []string{"epoch", "capability", "identity", "expiry", "revoked"} {
		t.Run(name, func(t *testing.T) {
			s, a, n, in := fixture(t)
			n.after = func() {
				a.mu.Lock()
				defer a.mu.Unlock()
				switch name {
				case "epoch":
					a.head.Epoch++
				case "capability":
					a.node.CapabilityDigest = repository.Hash([]byte("new capability"))
				case "identity":
					a.node.IdentityDigest = repository.Hash([]byte("renewed identity"))
				case "expiry":
					a.head.RecordedAt = a.head.RecordedAt.Add(RequestTTL)
				case "revoked":
					a.denied = true
				}
			}
			if _, e := s.Validate(context.Background(), &tls.ConnectionState{}, in); e == nil {
				t.Fatal("post-execution change issued proof")
			}
			// Restore identity/current time only to test uncertain intent behavior.
			a.mu.Lock()
			a.head.Epoch = 1
			a.node.CapabilityDigest = in.CapabilityDigest
			a.node.IdentityDigest = in.CapabilityDigest
			a.denied = false
			a.mu.Unlock()
			if _, e := s.Validate(context.Background(), &tls.ConnectionState{}, in); !errors.Is(e, ErrPending) {
				t.Fatalf("uncertain intent retried: %v", e)
			}
			if n.calls != 1 {
				t.Fatal("uncertain intent reran native")
			}
		})
	}
}

func TestServiceNativeFailureIsBoundedImmutableFact(t *testing.T) {
	s, _, n, in := fixture(t)
	n.err = ErrNativeRejected
	out, e := s.Validate(context.Background(), &tls.ConnectionState{}, in)
	if e != nil || out.State != "rejected" || out.ErrorCode != "native_syntax_rejected" {
		t.Fatalf("out=%+v err=%v", out, e)
	}
	b, _ := json.Marshal(out)
	if len(b) > MaxResultBytes || bytes.Contains(b, []byte("activeRevision")) || bytes.Contains(b, []byte("healthy")) {
		t.Fatal("result became an apply receipt")
	}
}

func TestDecodeClosedSyntaxVocabulary(t *testing.T) {
	b, _ := json.Marshal(testRequest())
	if _, e := Decode(bytes.NewReader(b)); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{strings.Replace(string(b), `"mode":"blocking"`, `"mode":"blocking","argv":["sh"]`, 1), strings.Replace(string(b), `"nodeDeploymentSequence":"0"`, `"nodeDeploymentSequence":"1"`, 1), strings.Replace(string(b), `"mode":"blocking"`, `"mode":"blocking","mode":"detection"`, 1), string(b) + " {}", strings.Repeat(" ", MaxRequestBytes+1), strings.Replace(string(b), `"paranoiaLevel":1`, `"paranoiaLevel":9`, 1)} {
		if _, e := Decode(strings.NewReader(bad)); e == nil {
			t.Fatal("unsafe request accepted")
		}
	}
}

func TestPrivateLocalStateRejectsLinksAndUnsafeParents(t *testing.T) {
	dir, e := os.MkdirTemp("/tmp", "agp-local-state-test-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	if e = privateState(dir); e != nil {
		t.Fatal(e)
	}
	if e = durableLocal(dir, "intent.json", map[string]string{"fact": "one"}); e != nil {
		t.Fatal(e)
	}
	if e = durableLocal(dir, "intent.json", map[string]string{"fact": "two"}); e == nil {
		t.Fatal("immutable fact overwritten")
	}
	if e = os.Link(filepath.Join(dir, "intent.json"), filepath.Join(dir, "hard.json")); e != nil {
		t.Fatal(e)
	}
	if _, e = readLocal(dir, "hard.json", 1024); e == nil {
		t.Fatal("hardlinked state accepted")
	}
	if e = os.Symlink("intent.json", filepath.Join(dir, "link.json")); e != nil {
		t.Fatal(e)
	}
	if _, e = readLocal(dir, "link.json", 1024); e == nil {
		t.Fatal("symlink accepted")
	}
	if e = os.Chmod(dir, 0770); e != nil {
		t.Fatal(e)
	}
	if e = privateState(dir); e == nil {
		t.Fatal("unsafe directory accepted")
	}
}
