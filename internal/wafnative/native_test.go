package wafnative

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/repository"
	"github.com/netwizd/agp/internal/repository/repotest"
)

// This integration test executes the actual Ubuntu24 Nginx/module/CRS and the
// exact renderer artifact qualified by the real 25-case functional corpus.
func TestNativeWAFProvider(t *testing.T) {
	if os.Getenv("AGP_TEST_WAF") != "1" {
		t.Skip("requires prepared real native WAF lab")
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
	if err = os.Chmod(storeDir, 0700); err != nil {
		t.Fatal(err)
	}
	store := repository.Store{Dir: storeDir, AnchorPath: anchor}
	v, err := store.Import(ctx, bundle, f.Now)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := v.QualifiedProfile(f.Now)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	p := &Provider{Store: store, CompilerDigest: repository.Hash([]byte("native integration compiler")), TempDir: t.TempDir(), Clock: func(context.Context) (time.Time, error) { calls++; return f.Now, nil }}
	policy := configmodel.WafPolicy{APIVersion: "agp.waf/v1alpha1", Kind: "WafPolicy", Metadata: configmodel.WafPolicyMetadata{ID: "policy_native", Name: "Actual native policy", SiteID: "site_native"}, Spec: configmodel.WafPolicySpec{Engine: "modsecurity", RulesetVersionID: profile.Profile.RulesetVersionID, ParanoiaLevel: 2, InboundAnomalyThreshold: 5, OutboundAnomalyThreshold: 4, Exceptions: []configmodel.WafException{}}}
	q, err := p.ValidatePolicy(ctx, policy)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || q.ManifestDigest != v.ManifestDigest || q.EvidenceDigest != profile.EvidenceDigest || q.ReleaseSequence != "1" {
		t.Fatalf("fresh pre/post clock and exact qualification required: calls=%d proof=%+v", calls, q)
	}
	if err = p.Current(ctx, q); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(p.TempDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("private native scratch not cleaned: %v %v", entries, err)
	}

	// Syntax validation must execute the qualified artifact, never silently fall
	// back to the currently embedded Render implementation.
	work := t.TempDir()
	if err = materialize(v, profile.Profile, work); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(work, "qualified-renderer"), []byte("invalid ELF: must never fall back to embedded renderer"), 0500); err != nil {
		t.Fatal(err)
	}
	if err = checkPolicy(ctx, policy, "blocking", work); err == nil {
		t.Fatal("native validation ignored the qualified renderer artifact")
	}

	calls = 0
	p.Clock = func(context.Context) (time.Time, error) {
		calls++
		if calls > 1 {
			return time.Time{}, errors.New("journal unavailable after native work")
		}
		return f.Now, nil
	}
	if proof, err := p.ValidatePolicy(ctx, policy); err == nil || proof != nil || calls != 2 {
		t.Fatalf("post-validation journal outage issued proof: calls=%d proof=%v err=%v", calls, proof, err)
	}
}
