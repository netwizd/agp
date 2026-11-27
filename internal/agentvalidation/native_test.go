package agentvalidation

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/repository"
	"github.com/netwizd/agp/internal/repository/repotest"
)

func TestFixedCommandBoundsAndCleanEnvironment(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, e := runFixed(ctx, "/usr/bin/sleep", []string{"30"}, "/tmp", nil, false); e == nil || time.Since(started) > 3*time.Second {
		t.Fatalf("timeout did not terminate process: %v", e)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, e := runFixed(ctx, "/usr/bin/yes", nil, "/tmp", nil, false); e == nil {
		t.Fatal("unlimited output accepted")
	}
	t.Setenv("AGP_TEST_SECRET", "must-not-leak")
	out, e := runFixed(context.Background(), "/usr/bin/env", nil, "/tmp", nil, false)
	if e != nil || strings.Contains(string(out), "must-not-leak") || strings.Contains(string(out), "PATH=") {
		t.Fatalf("child inherited environment: %q %v", out, e)
	}
	if os.Geteuid() == 0 {
		out, e = runFixed(context.Background(), "/usr/bin/id", []string{"-u"}, "/tmp", &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}, false)
		if e != nil || strings.TrimSpace(string(out)) != "65534" {
			t.Fatalf("child did not drop root: %q %v", out, e)
		}
	}
}

func TestNativeRequiresExplicitPrivilegeAndResourceBounds(t *testing.T) {
	n := &Native{}
	if os.Geteuid() == 0 {
		if _, e := n.identity(); e == nil {
			t.Fatal("root inherited by validator")
		}
		n.ExecutionUID = 65534
		if _, e := n.identity(); e == nil {
			t.Fatal("root group inherited by validator")
		}
	}
	if e := UnsupportedRemoteBundle(); !errors.Is(e, ErrUnsupported) {
		t.Fatal("remote bundle accidentally supported")
	}
}

func TestNativeFailureCodesRedactOSAndRequestData(t *testing.T) {
	for _, tc := range []struct {
		cause  error
		suffix string
	}{{syscall.EDQUOT, "quota"}, {syscall.EMFILE, "descriptors"}, {syscall.ENFILE, "descriptors"}, {syscall.EIO, "io"}, {syscall.ENOMEM, "memory"}, {syscall.EROFS, "readonly"}} {
		e := nativeFailure("renderer_stage_failed", &os.PathError{Op: "write", Path: "/identity/private-secret.pem", Err: tc.cause})
		if safeError(e) != "renderer_stage_failed_"+tc.suffix || strings.Contains(safeError(e), "errno") || !errors.Is(e, ErrUnavailable) {
			t.Fatalf("unsafe filesystem failure classification: %v", e)
		}
	}
	e := nativeFailure("runtime_stage_failed", &os.PathError{Op: "open", Path: "/identity/private-secret.pem", Err: syscall.EACCES})
	if !errors.Is(e, ErrUnavailable) || safeError(e) != "runtime_stage_failed_permission" || strings.Contains(e.Error(), "identity") || strings.Contains(e.Error(), "secret") {
		t.Fatalf("unsafe diagnostic: %v", e)
	}
	if resultState(e) != "failed" {
		t.Fatal("diagnostic changed native failure into success")
	}
	n := &Native{Clock: func(context.Context) (time.Time, error) {
		return time.Time{}, errors.New("transport /identity/private-journal.pem refused")
	}}
	_, e = n.current(context.Background(), testRequest().Pins)
	if !errors.Is(e, ErrUnavailable) || safeError(e) != "journal_head_unavailable" || strings.Contains(e.Error(), "identity") || strings.Contains(e.Error(), "transport") {
		t.Fatalf("journal clock details leaked: %v", e)
	}
}

// Run explicitly in the mandatory native harness. Its isolated test subprocess
// owns the one-shot resource limits; it never changes go test's parent limits.
func TestActualSignedNativeSyntax(t *testing.T) {
	if os.Getenv("AGP_TEST_WAF") != "1" {
		t.Skip("requires prepared actual signed WAF artifacts")
	}
	if os.Getenv("AGP_LOCAL_SYNTAX_TEST_WORKER") != "1" {
		exe, e := os.Executable()
		if e != nil {
			t.Fatal(e)
		}
		cmd := exec.Command(exe, "-test.run=^TestActualSignedNativeSyntax$", "-test.v")
		cmd.Env = append(os.Environ(), "AGP_LOCAL_SYNTAX_TEST_WORKER=1")
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("isolated native worker: %v\n%s", e, out)
		}
		t.Log(string(out))
		return
	}
	if e := ApplyLocalProcessLimits(); e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	root, e := filepath.Abs("../..")
	if e != nil {
		t.Fatal(e)
	}
	f, e := repotest.Native(ctx, repotest.NativeInput{BundlePath: os.Getenv("AGP_TEST_WAF_BUNDLE"), EvidencePath: os.Getenv("AGP_TEST_WAF_EVIDENCE"), RendererPath: os.Getenv("AGP_TEST_WAF_RENDERER"), HarnessPath: filepath.Join(root, "tests/native-waf/qualification.py"), CorpusPath: filepath.Join(root, "tests/native-waf/corpus.json")})
	if e != nil {
		t.Fatal(e)
	}
	bundle := t.TempDir()
	anchor, e := f.Write(bundle, f.Build(1))
	if e != nil {
		t.Fatal(e)
	}
	storeDir := t.TempDir()
	if e = os.Chmod(storeDir, 0700); e != nil {
		t.Fatal(e)
	}
	store := repository.Store{Dir: storeDir, AnchorPath: anchor}
	v, e := store.Import(ctx, bundle, f.Now)
	if e != nil {
		t.Fatal(e)
	}
	p, e := v.QualifiedProfile(f.Now)
	if e != nil {
		t.Fatal(e)
	}
	n := &Native{Store: store, Clock: func(context.Context) (time.Time, error) { return f.Now, nil }}
	if os.Geteuid() == 0 {
		n.ExecutionUID = 65534
		n.ExecutionGID = 65534
	}
	in := testRequest()
	in.Pins = Pins{v.ManifestDigest, p.ProfileDigest, p.TupleDigest, p.EvidenceDigest, p.Evidence.RendererDigest}
	in.Policy.Spec.RulesetVersionID = p.Profile.RulesetVersionID
	if e = n.Check(ctx, in); e != nil {
		t.Fatal(e)
	}
	// Different mode still runs only the same fixed typed probe; no live server.
	in.Mode = "detection"
	if e = n.Check(ctx, in); e != nil {
		t.Fatal(e)
	}
	in.Pins.RendererDigest = repository.Hash([]byte("foreign renderer"))
	if e = n.Check(ctx, in); !errors.Is(e, ErrStale) {
		t.Fatalf("foreign signed-artifact pin accepted: %v", e)
	}
	in.Pins.RendererDigest = p.Evidence.RendererDigest
	// Clock freshness must be repeated after native execution.
	calls := 0
	n.Clock = func(context.Context) (time.Time, error) {
		calls++
		if calls > 1 {
			return time.Time{}, errors.New("journal unavailable")
		}
		return f.Now, nil
	}
	if e = n.Check(ctx, in); !errors.Is(e, ErrUnavailable) || calls != 2 {
		t.Fatalf("post-validation journal outage issued proof: %v calls=%d", e, calls)
	}
}
