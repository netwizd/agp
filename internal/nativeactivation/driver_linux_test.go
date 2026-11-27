//go:build linux

package nativeactivation

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/helper"
)

type testRuntime struct {
	generation                   string
	root                         string
	reloads, validations, probes int
	failReload                   bool
	failVerifyMarker             string
	onVerify                     func()
}

func (r *testRuntime) validate(context.Context, string) error { r.validations++; return nil }
func (r *testRuntime) contain(context.Context) error          { r.generation = "contained"; return nil }
func (r *testRuntime) reload(context.Context) error {
	r.reloads++
	if r.failReload {
		return ErrRuntime
	}
	target, e := os.Readlink(filepath.Join(r.root, "active"))
	if e != nil {
		return e
	}
	bytes, e := os.ReadFile(filepath.Join(r.root, "generations", strings.Split(target, "/")[1], "generation.json"))
	if e != nil {
		return e
	}
	var manifest generationManifest
	if e = json.Unmarshal(bytes, &manifest); e != nil {
		return e
	}
	r.generation = manifest.Generation.GenerationID
	return nil
}
func (r *testRuntime) verify(_ context.Context, g helper.ExecutionGeneration, _ []Probe) error {
	r.probes++
	if r.onVerify != nil {
		r.onVerify()
	}
	if r.generation != g.GenerationID {
		return ErrRuntime
	}
	if g.GenerationID == r.failVerifyMarker {
		return ErrRuntime
	}
	return nil
}

type fixture struct {
	cfg     Config
	repo    *Repository
	driver  *Driver
	runtime *testRuntime
	base    helper.ExecutionGeneration
	next    Bundle
	owner   uint32
}

func testBundle(id, revision string) Bundle {
	b := Bundle{APIVersion: BundleVersion, NodeID: "node-a", RevisionID: revision, GenerationID: id, BundleDigest: configmodel.DigestBytes([]byte("qualified:" + id)), QualificationDigest: configmodel.DigestBytes([]byte("qualification")), ReleaseManifestDigest: configmodel.DigestBytes([]byte("release")), Files: []File{{Path: "nginx.conf", Content: "qualified native " + id}, {Path: "tls/certificate.pem", Content: "cert"}}}
	for i := range b.Files {
		b.Files[i].Digest = configmodel.DigestBytes([]byte(b.Files[i].Content))
	}
	for _, p := range []struct {
		kind, path, body string
		status           int
	}{{"route", "/route", "routed", 200}, {"auth-deny", "/auth", "unauthorized", 401}, {"waf-deny", "/waf", "blocked", 403}} {
		b.Probes = append(b.Probes, Probe{Kind: p.kind, Path: p.path, Host: "example.test", Status: p.status, BodyDigest: configmodel.DigestBytes([]byte(p.body))})
	}
	return b
}
func makeFixture(t *testing.T) *fixture {
	return makeFixtureWithSequence(t, 1)
}
func makeFixtureWithSequence(t *testing.T, sequence helper.UInt63) *fixture {
	t.Helper()
	temp, e := os.MkdirTemp("/tmp", "agp-nativeactivation-test-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		filepath.Walk(temp, func(p string, info os.FileInfo, e error) error {
			if e == nil && info.IsDir() {
				os.Chmod(p, 0700)
			}
			return nil
		})
		os.RemoveAll(temp)
	})
	repoDir := filepath.Join(temp, "repository")
	root := filepath.Join(temp, "installation")
	for _, p := range []string{repoDir, root} {
		if e = os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	b1, b2 := testBundle("generation-a", "revision-a"), testBundle("generation-b", "revision-b")
	manifest := RepositoryManifest{APIVersion: RepositoryVersion}
	for _, b := range []Bundle{b1, b2} {
		bytes, _ := configmodel.CanonicalJSON(b)
		if e = os.WriteFile(filepath.Join(repoDir, strings.TrimPrefix(b.BundleDigest, "sha256:")+".json"), bytes, 0400); e != nil {
			t.Fatal(e)
		}
		manifest.Bundles = append(manifest.Bundles, BundlePin{BundleDigest: b.BundleDigest, ManifestDigest: configmodel.DigestBytes(bytes)})
	}
	sort.Slice(manifest.Bundles, func(i, j int) bool { return manifest.Bundles[i].BundleDigest < manifest.Bundles[j].BundleDigest })
	bytes, _ := configmodel.CanonicalJSON(manifest)
	os.WriteFile(filepath.Join(repoDir, "repository.json"), bytes, 0400)
	owner := uint32(os.Geteuid())
	repo, e := openRepository(repoDir, configmodel.DigestBytes(bytes), owner)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { repo.Close() })
	cfg := Config{RootDir: root, NodeID: b1.NodeID, SiteID: "site-a", QualificationDigest: b1.QualificationDigest, ReleaseManifestDigest: b1.ReleaseManifestDigest}
	cfg.LayoutDigest, _ = LayoutDigest(cfg)
	m, e := makeManifest(cfg, b1, helper.Baseline{RevisionID: b1.RevisionID, BundleDigest: b1.BundleDigest, NodeDeploymentSequence: sequence}, owner)
	if e != nil {
		t.Fatal(e)
	}
	if e = initialize(cfg, repo, m.Generation, owner); e != nil {
		t.Fatal(e)
	}
	runtime := &testRuntime{generation: b1.GenerationID, root: root}
	driver, e := openDriver(cfg, repo, runtime, owner)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { driver.Close() })
	return &fixture{cfg: cfg, repo: repo, driver: driver, runtime: runtime, base: m.Generation, next: b2, owner: owner}
}
func (f *fixture) request() helper.Request {
	return helper.Request{Task: helper.Task{NodeID: f.cfg.NodeID, NodeDeploymentSequence: 2, Preconditions: helper.Preconditions{BaseRevisionID: f.base.Baseline.RevisionID, ExpectedNodeDeploymentSequence: 1}, Payload: helper.Payload{TargetRevisionID: f.next.RevisionID, BundleDigest: f.next.BundleDigest, DeploymentGeneration: f.next.GenerationID, RecoveryBaseBundleDigest: f.base.Baseline.BundleDigest}}, Permit: helper.Permit{Recovery: helper.Recovery{BaseRevisionID: f.base.Baseline.RevisionID, BaseBundleDigest: f.base.Baseline.BundleDigest}}}
}
func (f *fixture) prepare(t *testing.T) helper.ExecutionGeneration {
	t.Helper()
	g, e := f.driver.Prepare(context.Background(), f.request(), f.base)
	if e != nil {
		t.Fatal(e)
	}
	return g
}

func TestApplyAndExactRecoveryFilesystemAndRuntime(t *testing.T) {
	f := makeFixture(t)
	ctx := context.Background()
	if got, e := f.driver.Snapshot(ctx); e != nil || got != f.base {
		t.Fatalf("base snapshot: %v", e)
	}
	target := f.prepare(t)
	if f.runtime.reloads != 0 {
		t.Fatal("prepare reloaded")
	}
	if e := f.driver.Validate(ctx, target); e != nil {
		t.Fatal(e)
	}
	if e := f.driver.Activate(ctx, f.base, target); e != nil {
		t.Fatal(e)
	}
	if _, e := f.driver.Snapshot(ctx); !errors.Is(e, ErrRuntime) {
		t.Fatalf("filesystem switch must not assert runtime healthy: %v", e)
	}
	if e := f.driver.Reload(ctx, target); e != nil {
		t.Fatal(e)
	}
	if e := f.driver.Verify(ctx, target); e != nil {
		t.Fatal(e)
	}
	if e := f.driver.Activate(ctx, f.base, target); !errors.Is(e, ErrStale) {
		t.Fatalf("stale CAS: %v", e)
	}
	wrong := f.base
	wrong.Baseline.BundleDigest = configmodel.DigestBytes([]byte("other"))
	if e := f.driver.Recover(ctx, target, wrong); !errors.Is(e, ErrStale) {
		t.Fatalf("arbitrary recovery: %v", e)
	}
	if e := f.driver.Recover(ctx, target, f.base); e != nil {
		t.Fatal(e)
	}
	got, e := f.driver.Snapshot(ctx)
	if e != nil || got != f.base || f.runtime.reloads != 2 || f.runtime.validations != 2 {
		t.Fatalf("recovery did not restore exact live generation: %+v %v", got, e)
	}
	if _, e = os.Stat(filepath.Join(f.cfg.RootDir, "recovery", storageSlot(target)+".json")); e != nil {
		t.Fatal("durable recovery evidence lost")
	}
}
func TestMissingOrUnqualifiedBundleFailsBeforeTargetCreation(t *testing.T) {
	f := makeFixture(t)
	r := f.request()
	r.Task.Payload.BundleDigest = configmodel.DigestBytes([]byte("unqualified"))
	if _, e := f.driver.Prepare(context.Background(), r, f.base); !errors.Is(e, ErrBundle) {
		t.Fatalf("unknown qualified input: %v", e)
	}
	target, _ := makeManifest(f.cfg, f.next, helper.Baseline{RevisionID: f.next.RevisionID, BundleDigest: f.next.BundleDigest, NodeDeploymentSequence: 2}, f.owner)
	if _, e := os.Stat(filepath.Join(f.cfg.RootDir, "generations", storageSlot(target.Generation))); !os.IsNotExist(e) {
		t.Fatal("created unqualified target")
	}
}
func TestPreparePersistsBaseBeforeTargetAndCanResumeAfterReopen(t *testing.T) {
	f := makeFixture(t)
	f.driver.fault = func(point string) error {
		if point == "base_durable" {
			return errors.New("power loss")
		}
		return nil
	}
	if _, e := f.driver.Prepare(context.Background(), f.request(), f.base); !errors.Is(e, ErrTree) {
		t.Fatal(e)
	}
	expected, _ := makeManifest(f.cfg, f.next, helper.Baseline{RevisionID: f.next.RevisionID, BundleDigest: f.next.BundleDigest, NodeDeploymentSequence: 2}, f.owner)
	if _, e := os.Stat(filepath.Join(f.cfg.RootDir, "recovery", storageSlot(expected.Generation)+".json")); e != nil {
		t.Fatal("base record not durable first")
	}
	if _, e := os.Stat(filepath.Join(f.cfg.RootDir, "generations", storageSlot(expected.Generation))); !os.IsNotExist(e) {
		t.Fatal("target created before base")
	}
	f.driver.Close()
	d, e := openDriver(f.cfg, f.repo, f.runtime, f.owner)
	if e != nil {
		t.Fatal(e)
	}
	f.driver = d
	t.Cleanup(func() { d.Close() })
	target := f.prepare(t)
	if e = d.Recover(context.Background(), target, f.base); e != nil {
		t.Fatal(e)
	}
}
func TestPointerDurabilityFailureRequiresReopenAndExactRecovery(t *testing.T) {
	f := makeFixture(t)
	target := f.prepare(t)
	f.driver.fault = func(point string) error {
		if point == "pointer_durability" {
			return errors.New("fsync failed")
		}
		return nil
	}
	if e := f.driver.Activate(context.Background(), f.base, target); !errors.Is(e, ErrTree) {
		t.Fatal(e)
	}
	if e := f.driver.Verify(context.Background(), target); !errors.Is(e, ErrTree) {
		t.Fatal("poisoned handle reused")
	}
	f.driver.Close()
	d, e := openDriver(f.cfg, f.repo, f.runtime, f.owner)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { d.Close() })
	if e = d.Recover(context.Background(), target, f.base); e != nil {
		t.Fatal(e)
	}
	if g, e := d.Snapshot(context.Background()); e != nil || g != f.base {
		t.Fatalf("reopened crash recovery: %v", e)
	}
}
func TestCompleteTreeRejectsMutationUnexpectedFileLinkAndManifestRewrite(t *testing.T) {
	for _, kind := range []string{"bytes", "extra", "symlink", "hardlink", "manifest"} {
		t.Run(kind, func(t *testing.T) {
			f := makeFixture(t)
			target := f.prepare(t)
			tree := f.driver.treePath(target)
			os.Chmod(tree, 0700)
			switch kind {
			case "bytes":
				os.Chmod(filepath.Join(tree, "nginx.conf"), 0600)
				os.WriteFile(filepath.Join(tree, "nginx.conf"), []byte("different"), 0400)
			case "extra":
				os.WriteFile(filepath.Join(tree, "unexpected.conf"), []byte("extra"), 0400)
			case "symlink":
				os.Remove(filepath.Join(tree, "nginx.conf"))
				os.Symlink("/etc/passwd", filepath.Join(tree, "nginx.conf"))
			case "hardlink":
				os.Link(filepath.Join(tree, "nginx.conf"), filepath.Join(tree, "alias.conf"))
			case "manifest":
				parent := filepath.Dir(tree)
				os.Chmod(parent, 0700)
				p := filepath.Join(parent, "generation.json")
				os.Chmod(p, 0600)
				b, _ := os.ReadFile(p)
				b = append(b, '\n')
				os.WriteFile(p, b, 0400)
				os.Chmod(parent, 0500)
			}
			os.Chmod(tree, 0500)
			if e := f.driver.Validate(context.Background(), target); e == nil {
				t.Fatal("drift accepted")
			}
			if f.runtime.validations != 0 {
				t.Fatal("ran native syntax on drifted bytes")
			}
		})
	}
}
func TestExclusiveLayoutLockAndPointerAncestryDrift(t *testing.T) {
	f := makeFixture(t)
	if d, e := openDriver(f.cfg, f.repo, f.runtime, f.owner); !errors.Is(e, helper.ErrBusy) {
		if d != nil {
			d.Close()
		}
		t.Fatalf("second writer acquired: %v", e)
	}
	old := f.cfg.RootDir + "-old"
	if e := os.Rename(f.cfg.RootDir, old); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(f.cfg.RootDir); os.Rename(old, f.cfg.RootDir) })
	if e := os.Mkdir(f.cfg.RootDir, 0700); e != nil {
		t.Fatal(e)
	}
	if _, e := f.driver.Snapshot(context.Background()); !errors.Is(e, ErrTree) {
		t.Fatalf("replaced ancestry accepted: %v", e)
	}
}
func TestQualifiedBundleRejectsPartialTreeAndProbePolicy(t *testing.T) {
	for _, change := range []func(*Bundle){func(b *Bundle) { b.Files = b.Files[1:] }, func(b *Bundle) { b.Files[0].Path = "../nginx.conf" }, func(b *Bundle) { b.Files[0].Content = "changed" }, func(b *Bundle) { b.Probes = b.Probes[:2] }, func(b *Bundle) { b.Probes[1].Status = 200 }, func(b *Bundle) { b.Probes[0].Path = "http://evil.test" }} {
		b := testBundle("g", "r")
		change(&b)
		if validateBundle(b) == nil {
			t.Fatal("unqualified native input accepted")
		}
	}
}

func TestRecoveredServingSequenceDoesNotReplaceAcceptedHighWater(t *testing.T) {
	f := makeFixtureWithSequence(t, 7)
	request := f.request()
	request.Task.Preconditions.ExpectedNodeDeploymentSequence = 8
	request.Task.NodeDeploymentSequence = 9
	ctx := context.Background()
	target, e := f.driver.Prepare(ctx, request, f.base)
	if e != nil {
		t.Fatal(e)
	}
	if target.Baseline.NodeDeploymentSequence != 9 {
		t.Fatal("target sequence changed")
	}
	for _, step := range []func() error{func() error { return f.driver.Validate(ctx, target) }, func() error { return f.driver.Activate(ctx, f.base, target) }, func() error { return f.driver.Reload(ctx, target) }, func() error { return f.driver.Verify(ctx, target) }, func() error { return f.driver.Recover(ctx, target, f.base) }} {
		if e = step(); e != nil {
			t.Fatal(e)
		}
	}
	if actual, e := f.driver.Snapshot(ctx); e != nil || actual != f.base {
		t.Fatalf("rollback did not restore serving sequence7: %v", e)
	}
}

type crashFixture struct {
	Config           Config
	RepoPath, Digest string
	Base, Target     helper.ExecutionGeneration
}

func TestNativePointerCrashChild(t *testing.T) {
	configPath := os.Getenv("AGP_NATIVE_POINTER_CRASH_FIXTURE")
	if configPath == "" {
		return
	}
	bytes, e := os.ReadFile(configPath)
	if e != nil {
		t.Fatal(e)
	}
	var fixture crashFixture
	if e = json.Unmarshal(bytes, &fixture); e != nil {
		t.Fatal(e)
	}
	owner := uint32(os.Geteuid())
	repo, e := openRepository(fixture.RepoPath, fixture.Digest, owner)
	if e != nil {
		t.Fatal(e)
	}
	defer repo.Close()
	runtime := &testRuntime{generation: fixture.Base.GenerationID, root: fixture.Config.RootDir}
	driver, e := openDriver(fixture.Config, repo, runtime, owner)
	if e != nil {
		t.Fatal(e)
	}
	defer driver.Close()
	driver.fault = func(point string) error {
		if point == "pointer_durability" {
			os.Exit(77)
		}
		return nil
	}
	if e = driver.Activate(context.Background(), fixture.Base, fixture.Target); e != nil {
		t.Fatal(e)
	}
	t.Fatal("child did not crash")
}
func TestActualProcessCrashReconcilesOnlyProvedPendingPointer(t *testing.T) {
	testActualProcessCrashReconcile(t, 0)
}
func TestActualProcessCrashReconcilesAfterMoreThan256ExecutionRecords(t *testing.T) {
	testActualProcessCrashReconcile(t, 257)
}
func testActualProcessCrashReconcile(t *testing.T, extraRecords int) {
	f := makeFixture(t)
	request := f.request()
	if extraRecords > 0 {
		request.Task.Preconditions.ExpectedNodeDeploymentSequence = helper.UInt63(extraRecords + 2)
		request.Task.NodeDeploymentSequence = request.Task.Preconditions.ExpectedNodeDeploymentSequence + 1
	}
	target, e := f.driver.Prepare(context.Background(), request, f.base)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < extraRecords; i++ {
		base := target.Baseline
		base.NodeDeploymentSequence = helper.UInt63(i + 2)
		historical, e := makeManifest(f.cfg, f.next, base, f.owner)
		if e != nil {
			t.Fatal(e)
		}
		record := recoveryRecord{APIVersion: Version, Base: f.base, Target: historical.Generation}
		bytes, _ := configmodel.CanonicalJSON(record)
		if e := os.WriteFile(filepath.Join(f.cfg.RootDir, "recovery", storageSlot(historical.Generation)+".json"), bytes, 0400); e != nil {
			t.Fatal(e)
		}
	}
	info := crashFixture{Config: f.cfg, RepoPath: filepath.Join(filepath.Dir(f.cfg.RootDir), "repository"), Digest: f.repo.digest, Base: f.base, Target: target}
	bytes, _ := json.Marshal(info)
	path := filepath.Join(filepath.Dir(f.cfg.RootDir), "crash-fixture.json")
	if e := os.WriteFile(path, bytes, 0600); e != nil {
		t.Fatal(e)
	}
	f.driver.Close()
	command := exec.Command(os.Args[0], "-test.run=^TestNativePointerCrashChild$")
	command.Env = append(os.Environ(), "AGP_NATIVE_POINTER_CRASH_FIXTURE="+path)
	output, e := command.CombinedOutput()
	exit, ok := e.(*exec.ExitError)
	if !ok || exit.ExitCode() != 77 {
		t.Fatalf("child did not terminate at actual exchange: %v %s", e, output)
	}
	all, e := os.ReadDir(f.cfg.RootDir)
	if e != nil {
		t.Fatal(e)
	}
	pending := 0
	for _, entry := range all {
		if strings.HasPrefix(entry.Name(), ".active-") {
			pending++
		}
	}
	if pending != 1 {
		t.Fatalf("crash evidence absent: pending %d", pending)
	}
	driver, e := openDriver(f.cfg, f.repo, f.runtime, f.owner)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { driver.Close() })
	if e = driver.Recover(context.Background(), target, f.base); e != nil {
		t.Fatal(e)
	}
	if got, e := driver.Snapshot(context.Background()); e != nil || got != f.base {
		t.Fatalf("crash recovery: %v", e)
	}
	all, _ = os.ReadDir(f.cfg.RootDir)
	if len(all) != 4 {
		t.Fatal("proved temporary pointer not reconciled")
	}
}
func TestUnknownPendingPointerIsPreservedAndRejected(t *testing.T) {
	f := makeFixture(t)
	f.prepare(t)
	f.driver.Close()
	name := ".active-00000000000000000000000000000000"
	path := filepath.Join(f.cfg.RootDir, name)
	if e := os.Symlink("generations/"+storageSlot(f.base)+"/tree", path); e != nil {
		t.Fatal(e)
	}
	if d, e := openDriver(f.cfg, f.repo, f.runtime, f.owner); e == nil {
		d.Close()
		t.Fatal("unproved pending pointer accepted")
	}
	if _, e := os.Lstat(path); e != nil {
		t.Fatal("unknown pointer was removed")
	}
}
