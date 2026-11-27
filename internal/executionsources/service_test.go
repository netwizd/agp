package executionsources

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/configuration"
	"github.com/netwizd/agp/internal/helper"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/nativeactivation"
	"github.com/netwizd/agp/internal/repository"
	"github.com/netwizd/agp/internal/repository/repotest"
	"github.com/netwizd/agp/internal/rolescope"
	"github.com/netwizd/agp/internal/rolloutexecution"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
	"github.com/netwizd/agp/internal/storage/postgres"
	"github.com/netwizd/agp/internal/storage/sqlite"
)

// Synthetic files and signed test repositories exercise the verification and
// SQL lifecycle. They make no native Nginx/root qualification claim.
type fixture struct {
	t                  *testing.T
	store              storage.Store
	now                time.Time
	service            *Service
	current            *fixtureCurrent
	registry           *fixtureRegistry
	peer               *tls.ConnectionState
	cfg                Config
	rootKey, qualifier ed25519.PrivateKey
	baseline           helper.ExecutionGeneration
	profile            *repository.QualifiedProfile
	release            *repository.VerifiedRelease
	observation        inventory.Observation
}
type fixtureCurrent struct {
	store storage.Store
	head  securityjournal.Head
}

func (c *fixtureCurrent) Head(context.Context) (securityjournal.Head, error) { return c.head, nil }
func (c *fixtureCurrent) Current(ctx context.Context, fn func(storage.IdentityTx, securityjournal.Head) error) error {
	return c.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error { return fn(tx, c.head) })
}

type fixtureRegistry struct{ value inventory.Registry }

func (r *fixtureRegistry) Registry(context.Context, securityjournal.Head) (inventory.Registry, error) {
	return r.value, nil
}
func (r *fixtureRegistry) DeclaredNodes(_ context.Context, _ storage.IdentityTx, _ securityjournal.Head, site string) ([]inventory.DeclaredNode, error) {
	out := []inventory.DeclaredNode{}
	for _, n := range r.value.Nodes {
		if n.SiteID == site {
			out = append(out, inventory.DeclaredNode{NodeID: n.NodeID, SiteID: n.SiteID, Name: n.Name, Labels: n.Labels, GroupIDs: n.GroupIDs})
		}
	}
	return out, nil
}

func newFixture(t *testing.T, pg bool) *fixture {
	t.Helper()
	ctx := context.Background()
	f := &fixture{t: t, now: time.Now().UTC().Truncate(time.Second)}
	var err error
	if pg {
		dsn := os.Getenv("AGP_TEST_EXECUTION_SOURCES_DSN")
		if dsn == "" {
			t.Skip("AGP_TEST_EXECUTION_SOURCES_DSN is not set")
		}
		admin, e := pgxpool.New(ctx, dsn)
		if e != nil {
			t.Fatal(e)
		}
		schema := strings.ToLower(securitystate.ID("execution_sources"))
		quoted := pgx.Identifier{schema}.Sanitize()
		if _, e = admin.Exec(ctx, "CREATE SCHEMA "+quoted); e != nil {
			admin.Close()
			t.Fatal(e)
		}
		t.Cleanup(func() { _, _ = admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE"); admin.Close() })
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
		f.store, err = postgres.Open(ctx, dsn)
	} else {
		f.store, err = sqlite.Open(filepath.Join(t.TempDir(), "sources.db"))
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.store.Close() })
	if err = f.store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if pg {
		release, e := f.store.(interface {
			AcquireIdentityLease(context.Context) (func(), error)
		}).AcquireIdentityLease(ctx)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(release)
	}
	f.current = &fixtureCurrent{f.store, securityjournal.Head{AuthorityID: "source_authority", Epoch: 1, RecordedAt: f.now}}
	rf := repotest.New(f.now)
	p := repository.ComponentProfile{APIVersion: "agp.component-profile/v1alpha1", ID: "profile", Platform: rf.Anchor.Platform, RulesetVersionID: "ruleset", Tuple: repository.ComponentTuple{Nginx: "1.30.8", Connector: "1.0.4", LibModSecurity: "3.0.17", CRS: "4.30.0", BuildFlags: []string{"--with-compat"}, ABIDigest: hash("test ABI")}, LoaderPath: "lib/loader", NginxPath: "bin/nginx", ModulePath: "modules/waf.so", UnicodePath: "share/unicode", RulesPath: "share/crs/rules"}
	files := map[string][]byte{}
	for _, path := range []string{p.LoaderPath, p.NginxPath, p.ModulePath, p.UnicodePath, "share/crs/rules/test.conf"} {
		files[path] = []byte("synthetic file " + path)
	}
	checks := []repository.QualificationCheck{}
	for _, id := range repository.RequiredNativeChecks {
		checks = append(checks, repository.QualificationCheck{ID: id, Passed: true})
	}
	rf.SetProfile(p, files, checks, []byte("test corpus"), []byte("test harness"))
	in := rf.Build(1)
	bundleDir := t.TempDir()
	anchor, e := rf.Write(bundleDir, in)
	if e != nil {
		t.Fatal(e)
	}
	repo := repository.Store{Dir: t.TempDir(), AnchorPath: anchor}
	if e = os.Chmod(repo.Dir, 0700); e != nil {
		t.Fatal(e)
	}
	f.release, e = repo.Import(ctx, bundleDir, f.now)
	if e != nil {
		t.Fatal(e)
	}
	f.profile, e = f.release.QualifiedProfile(f.now)
	if e != nil {
		t.Fatal(e)
	}
	_, f.rootKey, _ = ed25519.GenerateKey(rand.Reader)
	qp, qkey, _ := ed25519.GenerateKey(rand.Reader)
	f.qualifier = qkey
	caPub, caKey, _ := ed25519.GenerateKey(rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, e := x509.ParseCertificate(caDER)
	if e != nil {
		t.Fatal(e)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	uri, _ := url.Parse("spiffe://agp/agent/node_one")
	leafDER, e := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}, ca, pub, caKey)
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := x509.ParseCertificate(leafDER)
	if e != nil {
		t.Fatal(e)
	}
	reg := inventory.Registration{NodeID: "node_one", SiteID: "site_one", Name: "Test node", Labels: map[string]string{"env": "test"}, GroupIDs: []string{"node_group"}, CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})), CertificateDigest: configmodel.DigestBytes(leaf.Raw), PublicKeyDigest: configmodel.DigestBytes(leaf.RawSubjectPublicKeyInfo), IssuerDigest: configmodel.DigestBytes(ca.Raw), Serial: "2", IssuanceEpoch: 1}
	f.registry = &fixtureRegistry{inventory.Registry{APIVersion: "agp.agent-registry/v1alpha1", AuthorityID: "source_authority", Nodes: []inventory.Registration{reg}}}
	f.peer = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, ca}}}
	agents, e := inventory.NewWithRegistry(f.current, f.current, f.registry)
	if e != nil {
		t.Fatal(e)
	}
	f.observation = inventory.Observation{BootID: "00000000-1111-2222-3333-444444444444", FreeBytes: 1 << 30, Capabilities: inventory.Capabilities{AgentVersion: "test", ProtocolVersion: inventory.ProtocolVersion, OS: inventory.OS{ID: "ubuntu", VersionID: "24.04", Kernel: "test-only", Architecture: "amd64"}, Component: &inventory.Component{ProfileDigest: f.profile.ProfileDigest, Files: []inventory.File{}}}}
	for _, x := range f.profile.Profile.Files {
		f.observation.Capabilities.Component.Files = append(f.observation.Capabilities.Component.Files, inventory.File{Path: x.Path, Digest: x.Digest})
	}
	ch, e := agents.Challenge(ctx, f.peer)
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := agents.Submit(ctx, f.peer, inventory.Submission{RequestID: "inventory_request_00001", ChallengeID: ch.ID, Challenge: ch.Challenge, Observation: f.observation})
	if e != nil {
		t.Fatal(e)
	}
	native := nativeactivation.Config{NodeID: "node_one", SiteID: "site_one", RootDir: "/var/lib/agp/native", QualificationDigest: f.profile.EvidenceDigest, ReleaseManifestDigest: f.release.ManifestDigest}
	native.LayoutDigest, _ = nativeactivation.LayoutDigest(native)
	i := helper.Installation{APIVersion: helper.InstallationVersion, NodeID: "node_one", SiteID: "site_one", IdentityDigest: hash(reg), CapabilityDigest: receipt.CapabilityDigest, OwnershipDigest: native.LayoutDigest, ComponentProfileDigest: f.profile.ProfileDigest, ReleaseManifestDigest: f.release.ManifestDigest, TupleDigest: f.profile.TupleDigest, CompilerDigest: hash("test compiler"), TrustDigest: hash("test trust"), AuthorityID: "source_authority", AuthorityEpoch: 1, WriterEpoch: 1, Baseline: helper.Baseline{RevisionID: "revision_base", BundleDigest: hash("baseline bundle"), NodeDeploymentSequence: 1}}
	a := helper.ExecutionAnchor{APIVersion: helper.ExecutionAnchorVersion, Installation: i, LayoutDigest: native.LayoutDigest, ReceiptKeyID: "root_receipt", ReceiptPublicKey: base64.RawURLEncoding.EncodeToString(f.rootKey.Public().(ed25519.PublicKey))}
	f.cfg = Config{APIVersion: CatalogVersion, WriterEpoch: 1, Bindings: []Binding{{Anchor: a, Native: native}}, QualificationKeys: map[string]string{"qualifier": base64.RawURLEncoding.EncodeToString(qp)}, Materials: []Materialization{}, SecretVersions: []SecretVersion{{ID: "certificate_one", SiteID: "site_one", Digest: hash("certificate bytes"), AuthorityEpoch: 1}}}
	f.baseline = helper.ExecutionGeneration{Baseline: i.Baseline, GenerationID: "baseline_generation", TreeDigest: hash("baseline tree")}
	f.service, e = New(f.current, agents, repo, func(context.Context) (Config, error) { return f.cfg, nil }, func(context.Context) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	f.seedConfig()
	return f
}

func (f *fixture) tx(fn func(storage.IdentityTx) error) error {
	return f.current.Current(context.Background(), func(tx storage.IdentityTx, _ securityjournal.Head) error { return fn(tx) })
}
func (f *fixture) mustTx(fn func(storage.IdentityTx) error) {
	f.t.Helper()
	if e := f.tx(fn); e != nil {
		f.t.Fatal(e)
	}
}
func (f *fixture) seedConfig() {
	f.t.Helper()
	f.mustTx(func(tx storage.IdentityTx) error {
		ctx := context.Background()
		exec := func(q string, args ...any) error { _, e := tx.Exec(ctx, q, args...); return e }
		if e := exec(`INSERT INTO groups(id,name) VALUES('access_group','Access')`); e != nil {
			return e
		}
		if e := exec(`INSERT INTO config_gateway_ownership(gateway_id,site_id) VALUES('gateway_one','site_one')`); e != nil {
			return e
		}
		manifest := rolescope.Manifest{APIVersion: "agp.role-scopes/v1alpha1", ID: "graph_one", Sites: []rolescope.Site{{ID: "site_one"}}, NodeGroups: []rolescope.NodeGroup{{ID: "node_group", SiteID: "site_one"}}, Nodes: []rolescope.Node{{ID: "node_one", SiteID: "site_one", GroupIDs: []string{"node_group"}}}, Resources: []rolescope.Resource{}, ResourceRoutes: []rolescope.ResourceRoute{}}
		if e := rolescope.BootstrapTx(ctx, tx, 1, manifest); e != nil {
			return e
		}
		node, _ := json.Marshal(map[string]any{"id": "node_one", "siteId": "site_one", "name": "Test node", "labels": map[string]string{"env": "test"}, "groupIds": []string{"node_group"}, "createdAt": f.now})
		if e := exec(`INSERT INTO managed_nodes(id,site_id,node_json,authority_epoch,created_at) VALUES('node_one','site_one',?,1,?)`, string(node), f.now); e != nil {
			return e
		}
		policy := configmodel.WafPolicy{APIVersion: "agp.waf/v1alpha1", Kind: "WafPolicy", Metadata: configmodel.WafPolicyMetadata{ID: "policy_one", Name: "Test policy", SiteID: "site_one"}, Spec: configmodel.WafPolicySpec{Engine: "modsecurity", RulesetVersionID: f.profile.Profile.RulesetVersionID, ParanoiaLevel: 1, InboundAnomalyThreshold: 5, OutboundAnomalyThreshold: 4, Exceptions: []configmodel.WafException{}}}
		praw, _ := configmodel.CanonicalJSON(policy)
		pd := hash(policy)
		if e := exec(`INSERT INTO config_waf_policy_revisions(id,policy_id,site_id,revision_number,content_digest,canonical_json,created_by,created_at) VALUES('policy_revision','policy_one','site_one',1,?,?,'policy_author',?)`, pd, string(praw), f.now); e != nil {
			return e
		}
		if e := exec(`INSERT INTO config_waf_policy_heads(policy_id,site_id,revision_id,row_version) VALUES('policy_one','site_one','policy_revision',1)`); e != nil {
			return e
		}
		q := configuration.WAFQualification{ContentDigest: pd, RulesetVersionID: f.profile.Profile.RulesetVersionID, RulesetDigest: f.profile.RulesetDigest, ProfileID: f.profile.Profile.ID, ProfileDigest: f.profile.ProfileDigest, TupleDigest: f.profile.TupleDigest, EvidenceDigest: f.profile.EvidenceDigest, ManifestDigest: f.release.ManifestDigest, ReleaseSequence: f.release.Manifest.Signed.Sequence, CompilerDigest: f.cfg.Bindings[0].Anchor.Installation.CompilerDigest, ExpiresAt: f.now.Add(time.Hour)}
		q.ID = "wafq_" + strings.TrimPrefix(ordinaryHash(q), "sha256:")
		validation := configuration.WafPolicyValidation{ID: "validation_one", PolicyRevisionID: "policy_revision", ContentDigest: pd, Qualification: &q, QualificationDigest: ordinaryHash(q), Valid: true, Issues: []configmodel.Issue{}, CreatedAt: f.now, ExpiresAt: q.ExpiresAt}
		vraw, _ := json.Marshal(validation)
		if e := exec(`INSERT INTO config_waf_policy_validations(id,policy_revision_id,authority_epoch,author_fingerprint,qualification_digest,report_json,created_by,created_at,expires_at) VALUES('validation_one','policy_revision',1,'fingerprint',?,?,'policy_author',?,?)`, ordinaryHash(q), string(vraw), f.now, q.ExpiresAt); e != nil {
			return e
		}
		if e := exec(`INSERT INTO config_waf_policy_approvals(id,policy_revision_id,validation_id,content_digest,qualification_digest,author_id,approver_id,authority_epoch,author_fingerprint,approver_fingerprint,created_at,expires_at,mfa_at,reason) VALUES('approval_one','policy_revision','validation_one',?,?,'policy_author','policy_reviewer',1,'author_fp','reviewer_fp',?,?,?,'test independent approval')`, pd, ordinaryHash(q), f.now, q.ExpiresAt, f.now); e != nil {
			return e
		}
		if e := exec(`INSERT INTO config_waf_policy_publications(id,policy_revision_id,approval_id,authority_epoch,content_digest,qualification_digest,published_by,created_at,mfa_at) VALUES('publication_one','policy_revision','approval_one',1,?,?,'publisher',?,?)`, pd, ordinaryHash(q), f.now, f.now); e != nil {
			return e
		}
		c := configmodel.Configuration{APIVersion: "agp.config/v1alpha1", Kind: "Configuration", Metadata: configmodel.Metadata{ID: "configuration", Name: "Test configuration"}, ProfileAssignments: []configmodel.ProfileAssignment{}, Gateways: []configmodel.Gateway{{APIVersion: "agp.config/v1alpha1", Kind: "Gateway", Metadata: configmodel.GatewayMetadata{ID: "gateway_one", Name: "Test gateway", SiteID: "site_one", Labels: configmodel.Labels{}}, Spec: configmodel.GatewaySpec{Ownership: "managed", NodeSelector: configmodel.NodeSelector{NodeIDs: []string{"node_one"}}, ComponentProfileRef: configmodel.Reference{ID: f.profile.Profile.ID, Digest: f.profile.ProfileDigest}, TLS: configmodel.GatewayTLS{CertificateVersionID: "certificate_one"}, Authorization: configmodel.Authorization{Mode: "central", FailureMode: "closed"}, WAF: configmodel.WAFBinding{Engine: "modsecurity", PolicyRevisionID: "policy_revision", Mode: "blocking"}, Routes: []configmodel.Route{{ID: "route_one", Name: "Route", Hostname: "example.test", Path: "/", Upstream: configmodel.Upstream{URL: "https://backend.test", ConnectTimeoutSeconds: 5, ReadTimeoutSeconds: 30, TLS: configmodel.UpstreamTLS{Verify: true}}, Access: configmodel.Access{GroupIDs: []string{"access_group"}, AllowCIDRs: []string{}}, WAFExceptionIDs: []string{}}}}}}}
		doc, e := configmodel.Canonicalize(c)
		if e != nil {
			return e
		}
		if e = exec(`INSERT INTO config_revisions(id,revision_number,schema_version,capacity_profile,canonical_size_bytes,content_digest,canonical_json,created_by,created_at) VALUES('revision_target',1,'agp.config/v1alpha1','pilot-500',?,?,?,'config_author',?)`, len(doc.Canonical), doc.Digest, string(doc.Canonical), f.now); e != nil {
			return e
		}
		if e = exec(`INSERT INTO config_revision_seals(revision_id,created_at) VALUES('revision_target',?)`, f.now); e != nil {
			return e
		}
		return exec(`UPDATE config_head SET revision_id='revision_target',row_version=1 WHERE id=1`)
	})
}

func (f *fixture) capture(active helper.ExecutionGeneration, high, receipt helper.UInt63) (helper.BaselineCapture, error) {
	f.t.Helper()
	ctx := context.Background()
	q, e := f.service.ChallengePeer(ctx, f.peer)
	if e != nil {
		return helper.BaselineCapture{}, e
	}
	c := helper.BaselineCapture{APIVersion: helper.BaselineCaptureVersion, Purpose: "verified_baseline_capture", Query: *q, Active: active, HighWater: high, ReceiptSequence: receipt, AuthorityEpoch: 1, WriterEpoch: 1, Head: helper.HeadPin{AuthorityID: "source_authority", Epoch: 1}, BootDigest: configmodel.DigestBytes([]byte(f.observation.BootID)), RecordedAt: utc(f.current.head.RecordedAt), KeyID: "root_receipt"}
	c.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.rootKey, []byte("AGP-HELPER-BASELINE-CAPTURE-v1\n"+hash(c))))
	return c, f.service.CapturePeer(ctx, f.peer, c)
}

func (f *fixture) qualify() {
	f.t.Helper()
	ctx := context.Background()
	var sourceDigest string
	f.mustTx(func(tx storage.IdentityTx) error {
		inputs, e := f.service.MaterializationInputs(ctx, tx, f.current.head, "revision_target", "site_one")
		if e == nil {
			sourceDigest = inputs["node_one"]
		}
		return e
	})
	if sourceDigest == "" {
		f.t.Fatal("missing source projection")
	}
	b := nativeactivation.Bundle{APIVersion: nativeactivation.BundleVersion, NodeID: "node_one", RevisionID: "revision_target", GenerationID: "target_generation", BundleDigest: hash("qualified target bundle"), QualificationDigest: f.profile.EvidenceDigest, ReleaseManifestDigest: f.release.ManifestDigest, Files: []nativeactivation.File{{Path: "nginx.conf", Content: "synthetic qualified native tree", Digest: configmodel.DigestBytes([]byte("synthetic qualified native tree"))}}, Probes: []nativeactivation.Probe{{Kind: "route", Path: "/route", Host: "example.test", Status: 200, BodyDigest: hash("routed")}, {Kind: "auth-deny", Path: "/auth", Host: "example.test", Status: 401, BodyDigest: hash("denied")}, {Kind: "waf-deny", Path: "/waf", Host: "example.test", Status: 403, BodyDigest: hash("blocked")}}}
	g, e := nativeactivation.ProjectedGeneration(f.cfg.Bindings[0].Native, b, 1)
	if e != nil {
		f.t.Fatal(e)
	}
	var configDigest string
	f.mustTx(func(tx storage.IdentityTx) error {
		return securitystate.One(ctx, tx, `SELECT content_digest FROM config_revisions WHERE id='revision_target'`, nil, func(r storage.IdentityRows) error { return r.Scan(&configDigest) })
	})
	a := Attestation{APIVersion: MaterializationVersion, Purpose: "qualified_native_materialization", ID: "materialization_one", NodeID: "node_one", SiteID: "site_one", RevisionID: "revision_target", ConfigurationDigest: configDigest, ResolvedSourceDigest: sourceDigest, BundleDigest: b.BundleDigest, BundleFileDigest: hash(b), GenerationID: b.GenerationID, TargetTreeDigest: g.TreeDigest, CompilerVersion: "test compiler/1", CompilerDigest: f.cfg.Bindings[0].Anchor.Installation.CompilerDigest, RendererDigest: f.profile.Evidence.RendererDigest, ProfileDigest: f.profile.ProfileDigest, ReleaseManifestDigest: f.release.ManifestDigest, TupleDigest: f.profile.TupleDigest, EvidenceDigest: f.profile.EvidenceDigest, NativeReportDigest: f.profile.Evidence.NativeReportDigest, HarnessDigest: f.profile.Evidence.HarnessDigest, SecretVersionIDs: []string{"certificate_one"}, IssuedAt: utc(f.now), ExpiresAt: utc(f.now.Add(time.Hour)), KeyID: "qualifier"}
	a.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.qualifier, []byte(MaterializationDomain+"\n"+hash(a))))
	f.cfg.Materials = []Materialization{{Attestation: a, Bundle: b}}
}

func (f *fixture) resolve() (out *rolloutexecution.Snapshot, err error) {
	err = f.tx(func(tx storage.IdentityTx) error {
		out, err = f.service.Resolve(context.Background(), tx, f.current.head, rolloutexecution.Selection{Kind: "apply_config", SiteID: "site_one", RevisionID: "revision_target", NodeIDs: []string{"node_one"}})
		return err
	})
	return
}

func TestSourcesSQLite(t *testing.T)   { testSources(t, false) }
func TestSourcesPostgres(t *testing.T) { testSources(t, true) }
func testSources(t *testing.T, pg bool) {
	f := newFixture(t, pg)
	ctx := context.Background()
	if _, e := f.resolve(); e == nil {
		t.Fatal("missing capture/materialization admitted")
	}
	c, e := f.capture(f.baseline, 1, 0)
	if e != nil {
		t.Fatal("initial root capture", e)
	}
	if e = f.service.CapturePeer(ctx, f.peer, c); e != nil {
		t.Fatal("exact capture replay", e)
	}
	f.qualify()
	snapshot, e := f.resolve()
	if e != nil {
		t.Fatal("qualified resolve", e)
	}
	target := snapshot.Targets[0]
	if hash(snapshot.Authors) != hash([]string{"config_author", "policy_author"}) {
		t.Fatal("authors were not read from SQL", snapshot.Authors)
	}
	if e = f.tx(func(tx storage.IdentityTx) error { return f.service.Recheck(ctx, tx, f.current.head, target) }); e != nil {
		t.Fatal("recheck", e)
	}
	t.Run("untrusted_agent_cannot_replace_root_signature", func(t *testing.T) {
		bad := c
		bad.Active.TreeDigest = hash("forged")
		if e := f.service.CapturePeer(ctx, f.peer, bad); !errors.Is(e, storage.ErrPermissionDenied) {
			t.Fatal(e)
		}
	})
	t.Run("full_bytes_are_bound", func(t *testing.T) {
		old := f.cfg.Materials[0].Bundle.Files[0]
		f.cfg.Materials[0].Bundle.Files[0].Content = "tampered"
		if _, e := f.resolve(); e == nil {
			t.Fatal("tampered native bytes admitted")
		}
		f.cfg.Materials[0].Bundle.Files[0] = old
	})
	t.Run("qualification_key_revocation", func(t *testing.T) {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		old := f.cfg.QualificationKeys["qualifier"]
		f.cfg.QualificationKeys["qualifier"] = base64.RawURLEncoding.EncodeToString(pub)
		if _, e := f.resolve(); e == nil {
			t.Fatal("revoked signer admitted")
		}
		f.cfg.QualificationKeys["qualifier"] = old
	})
	t.Run("secret_revocation", func(t *testing.T) {
		f.cfg.SecretVersions[0].Revoked = true
		if _, e := f.resolve(); e == nil {
			t.Fatal("revoked secret admitted")
		}
		f.cfg.SecretVersions[0].Revoked = false
	})
	t.Run("heartbeat_refresh_does_not_change_stable_projection", func(t *testing.T) {
		ch, e := f.service.inventory.Challenge(ctx, f.peer)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.service.inventory.Submit(ctx, f.peer, inventory.Submission{RequestID: "inventory_request_00002", ChallengeID: ch.ID, Challenge: ch.Challenge, Observation: f.observation}); e != nil {
			t.Fatal(e)
		}
		if e = f.tx(func(tx storage.IdentityTx) error { return f.service.Recheck(ctx, tx, f.current.head, target) }); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("catalog_replacement_is_fenced", func(t *testing.T) {
		f.registry.value.Nodes[0].Revoked = true
		if _, e := f.resolve(); e == nil {
			t.Fatal("revoked agent admitted")
		}
		f.registry.value.Nodes[0].Revoked = false
	})
	t.Run("baseline_freshness", func(t *testing.T) {
		f.current.head.RecordedAt = f.now.Add(BaselineFreshness + time.Second)
		if _, e := f.resolve(); e == nil {
			t.Fatal("expired current evidence admitted")
		}
		f.current.head.RecordedAt = f.now
	})
	t.Run("single_writer_required", func(t *testing.T) {
		old := f.service.witness
		f.service.witness = func(context.Context) error { return errors.New("lost lock") }
		if _, e := f.resolve(); e == nil {
			t.Fatal("lost writer admitted")
		}
		f.service.witness = old
	})
	t.Run("unknown_root_tree_freezes_without_adopting_it", func(t *testing.T) {
		unknown := f.baseline
		unknown.TreeDigest = hash("unknown tree")
		if _, e := f.capture(unknown, 1, 0); !errors.Is(e, ErrCapture) {
			t.Fatal(e)
		}
		if _, e := f.capture(f.baseline, 1, 0); !errors.Is(e, ErrCapture) {
			t.Fatal("unknown runtime was silently cleared", e)
		}
	})
	for _, q := range []string{`DELETE FROM execution_baseline_captures`, `UPDATE execution_baseline_captures SET capture_digest='x'`, `DELETE FROM execution_source_freezes`, `UPDATE execution_verified_baselines SET accepted_sequence=0,row_version=row_version+1`, `UPDATE execution_verified_baselines SET frozen=FALSE,row_version=row_version+1`} {
		if e = f.tx(func(tx storage.IdentityTx) error { _, e := tx.Exec(ctx, q); return e }); e == nil {
			t.Fatal("SQL monotonic/immutable guard missing", q)
		}
	}
}

func TestAttestationPurposeAndCompleteProjection(t *testing.T) {
	f := newFixture(t, false)
	f.qualify()
	a := f.cfg.Materials[0].Attestation
	pub := f.qualifier.Public().(ed25519.PublicKey)
	if VerifyAttestation(a, pub) != nil {
		t.Fatal("valid independent attestation rejected")
	}
	for _, mutate := range []func(*Attestation){func(a *Attestation) { a.Purpose = "planning_review" }, func(a *Attestation) { a.ConfigurationDigest = hash("other config") }, func(a *Attestation) { a.BundleFileDigest = hash("other bytes") }, func(a *Attestation) { a.ResolvedSourceDigest = hash("operator declaration") }, func(a *Attestation) { a.NativeReportDigest = hash("other report") }, func(a *Attestation) { a.SecretVersionIDs = []string{} }, func(a *Attestation) { a.NodeID = "other_node" }} {
		b := a
		mutate(&b)
		if VerifyAttestation(b, pub) == nil {
			t.Fatal("altered materialization admitted")
		}
	}
	b := a
	b.Signature = ""
	b.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.rootKey, []byte(MaterializationDomain+"\n"+hash(b))))
	if VerifyAttestation(b, pub) == nil {
		t.Fatal("root receipt key substituted for independent qualifier")
	}
}
