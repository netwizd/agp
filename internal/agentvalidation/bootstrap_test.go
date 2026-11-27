//go:build linux

package agentvalidation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/nativesandbox"
	"github.com/netwizd/agp/internal/ownedtree"
	"github.com/netwizd/agp/internal/repository"
	"github.com/netwizd/agp/internal/repository/repotest"
	"github.com/netwizd/agp/internal/securityjournal"
)

func bootstrapTree(t *testing.T, content []byte, extra bool) *ownedtree.Tree {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "agp-bootstrap-tree-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	root := filepath.Join(base, "generation-1")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nginx.conf"), content, 0600); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	m := ownedtree.Manifest{APIVersion: ownedtree.Version, NodeID: "node-1", SiteID: "site-1", Root: root, Entries: []ownedtree.Entry{
		{Path: ".", Kind: "directory", UID: uid, GID: gid, Mode: "0700"},
		{Path: "nginx.conf", Kind: "file", UID: uid, GID: gid, Mode: "0600", Size: ownedtree.UInt63(len(content)), Digest: configmodel.DigestBytes(content)},
	}}
	if extra {
		if err := os.WriteFile(filepath.Join(root, "extra.conf"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		m.Entries = append(m.Entries, ownedtree.Entry{Path: "extra.conf", Kind: "file", UID: uid, GID: gid, Mode: "0600", Digest: configmodel.DigestBytes(nil)})
	}
	digest, err := ownedtree.Digest(m)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := ownedtree.Open(m, digest)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tree.Close() })
	return tree
}

func TestBootstrapClosedProfileDoesNotAdoptArbitrarySyntax(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content []byte
		extra   bool
		pass    bool
	}{
		{"generated", ManagedBootstrapConfig(), false, true},
		{"wildcard-silently-empty", []byte("events {}\nhttp { include conf.d/*.conf; }\n"), false, false},
		{"absolute-include", []byte("include /etc/nginx/nginx.conf;\n"), false, false},
		{"valid-but-unapproved", []byte("events {}\nhttp {}\n"), false, false},
		{"extra-approved-file", ManagedBootstrapConfig(), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, view, err := bootstrapSnapshot(context.Background(), bootstrapTree(t, tc.content, tc.extra))
			if !tc.pass {
				if err == nil || s != nil || view != nil {
					t.Fatal("unsupported tree gained syntax eligibility")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if view.RuntimeValidated || !view.NoExecution {
				t.Fatal("filesystem observation gained runtime authority")
			}
		})
	}
}

func TestBootstrapMissingDependenciesNeverEmitCandidate(t *testing.T) {
	for _, v := range []*BootstrapValidator{nil, {}, {Tree: bootstrapTree(t, ManagedBootstrapConfig(), false)}} {
		if out, err := v.Validate(context.Background()); !errors.Is(err, ErrBootstrap) || out != nil {
			t.Fatal("incomplete validator issued candidate")
		}
	}
}

type bootstrapTestAuthority struct {
	head  securityjournal.Head
	calls int
	after func()
}

func (a *bootstrapTestAuthority) Head(context.Context) (securityjournal.Head, error) {
	a.calls++
	if a.calls > 1 && a.after != nil {
		a.after()
	}
	return a.head, nil
}

// This mandatory acceptance test executes the retained, signed real Nginx/WAF
// tuple in the kernel sandbox. The isolated worker owns all process limits.
func TestActualSignedBootstrapCandidate(t *testing.T) {
	if os.Getenv("AGP_TEST_WAF") != "1" {
		t.Skip("requires actual signed WAF inputs and kernel namespaces")
	}
	if os.Getenv("AGP_BOOTSTRAP_TEST_WORKER") != "1" {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(exe, "-test.run=^TestActualSignedBootstrapCandidate$", "-test.v")
		cmd.Env = append(os.Environ(), "AGP_BOOTSTRAP_TEST_WORKER=1", "GOMEMLIMIT=512MiB")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated bootstrap worker: %v\n%s", err, out)
		}
		t.Log(string(out))
		return
	}
	if err := nativesandbox.ApplyLocalProcessLimits(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	f, err := repotest.Native(ctx, repotest.NativeInput{BundlePath: os.Getenv("AGP_TEST_WAF_BUNDLE"), EvidencePath: os.Getenv("AGP_TEST_WAF_EVIDENCE"), RendererPath: os.Getenv("AGP_TEST_WAF_RENDERER"), HarnessPath: filepath.Join(root, "tests/native-waf/qualification.py"), CorpusPath: filepath.Join(root, "tests/native-waf/corpus.json")})
	if err != nil {
		t.Fatal(err)
	}
	bundle := t.TempDir()
	anchor, err := f.Write(bundle, f.Build(1))
	if err != nil {
		t.Fatal(err)
	}
	storeDir := t.TempDir()
	if err := os.Chmod(storeDir, 0700); err != nil {
		t.Fatal(err)
	}
	store := repository.Store{Dir: storeDir, AnchorPath: anchor}
	if _, err = store.Import(ctx, bundle, f.Now); err != nil {
		t.Fatal(err)
	}
	runner, err := nativesandbox.New(nativesandbox.Tool{Path: "/usr/bin/bwrap", Digest: "sha256:523da3e7399044be5163aee6f57a77a6bef7454376e28f0a0627920bae1b76b6"})
	if err != nil {
		t.Fatal(err)
	}
	authority := &bootstrapTestAuthority{head: securityjournal.Head{AuthorityID: "bootstrap_test", Epoch: 1, Sequence: 7, RecordedAt: f.Now}}
	v := &BootstrapValidator{Repository: store, Tree: bootstrapTree(t, ManagedBootstrapConfig(), false), Sandbox: runner, Authority: authority}
	got, err := v.Validate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !got.SyntaxValidated || got.ActiveConfigurationVerified || got.BaselineVerified || got.Deployable || !got.NoApply || got.Provenance != "managed_bootstrap" || got.Purpose != "baseline_candidate" {
		t.Fatal("syntax gained active/baseline/apply authority")
	}
	if got.NodeID != "node-1" || got.SiteID != "site-1" || got.SandboxToolDigest != runner.Binding().ToolDigest || got.SandboxProfileDigest != runner.Binding().ProfileDigest || authority.calls != 2 || !got.CheckedAt.Equal(f.Now) || got.ExpiresAt.After(f.Now.Add(5*time.Minute)) {
		t.Fatal("candidate lost exact bindings or time bound")
	}
	copy := *got
	copy.CandidateDigest = ""
	digest, err := configmodel.Digest(copy)
	if err != nil || digest != got.CandidateDigest {
		t.Fatal("candidate digest does not cover evidence")
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseBootstrapCandidate(bytes.NewReader(raw)); err != nil || parsed.CandidateDigest != got.CandidateDigest {
		t.Fatal("candidate closed wire roundtrip failed", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"baselineVerified", "activeConfigurationVerified", "deployable", "unknownAuthority"} {
		wire[key] = true
		altered, _ := json.Marshal(wire)
		if parsed, err := ParseBootstrapCandidate(bytes.NewReader(altered)); err == nil || parsed != nil {
			t.Fatal("wire accepted promotion or unknown property", key)
		}
		delete(wire, key)
		if key != "unknownAuthority" {
			wire[key] = false
		}
	}
	if got.ExecutionHost.ID == "" || got.ExecutionHost.Kernel == "" || !configmodel.ValidDigest(got.ExecutionBootDigest) {
		t.Fatal("actual execution host omitted")
	}
	// A concurrent independent journal change must suppress the whole result,
	// even after a real, successful nginx -t. No stale positive evidence returns.
	authority.calls = 0
	authority.after = func() { authority.head.Sequence++ }
	if out, err := v.Validate(ctx); err == nil || out != nil || authority.calls != 2 {
		t.Fatal("journal drift issued stale positive evidence")
	}
}
