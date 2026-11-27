package wafnative

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/configuration"
	"github.com/netwizd/agp/internal/repository"
	"github.com/netwizd/agp/internal/repository/repotest"
)

func unitProvider(t *testing.T) (*Provider, *configuration.WAFQualification, *repotest.Fixture, string) {
	t.Helper()
	f := repotest.New(time.Now())
	p := repository.ComponentProfile{APIVersion: "agp.component-profile/v1alpha1", ID: "profile_native", Platform: f.Anchor.Platform, RulesetVersionID: "crs_native", Tuple: repository.ComponentTuple{Nginx: "1.30.8", Connector: "1.0.4", LibModSecurity: "3.0.17", CRS: "4.30.0", BuildFlags: []string{"--with-compat"}, ABIDigest: repository.Hash([]byte("unit ABI"))}, LoaderPath: "lib/ld-linux-x86-64.so.2", NginxPath: "bin/nginx", ModulePath: "modules/ngx_http_modsecurity_module.so", UnicodePath: "share/modsecurity/unicode.mapping", RulesPath: "share/crs/rules"}
	files := map[string][]byte{}
	for _, name := range []string{p.LoaderPath, p.NginxPath, p.ModulePath, p.UnicodePath, "share/crs/rules/unit.conf"} {
		files[name] = []byte("UNIT TEST NOT EXECUTABLE " + name)
	}
	checks := []repository.QualificationCheck{}
	for _, id := range repository.RequiredNativeChecks {
		checks = append(checks, repository.QualificationCheck{ID: id, Passed: true})
	}
	f.SetProfile(p, files, checks, []byte("unit corpus"), []byte("unit harness"))
	in := f.Build(1)
	bundle := t.TempDir()
	anchor, e := f.Write(bundle, in)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	store := repository.Store{Dir: dir, AnchorPath: anchor}
	v, e := store.Import(context.Background(), bundle, f.Now)
	if e != nil {
		t.Fatal(e)
	}
	profile, e := v.QualifiedProfile(f.Now)
	if e != nil {
		t.Fatal(e)
	}
	provider := &Provider{Store: store, CompilerDigest: repository.Hash([]byte("unit compiler")), Clock: func(context.Context) (time.Time, error) { return f.Now, nil }}
	q := &configuration.WAFQualification{ContentDigest: repository.Hash([]byte("unit policy")), ManifestDigest: v.ManifestDigest, ReleaseSequence: "1", RulesetVersionID: p.RulesetVersionID, RulesetDigest: profile.RulesetDigest, ProfileID: p.ID, ProfileDigest: profile.ProfileDigest, TupleDigest: profile.TupleDigest, EvidenceDigest: profile.EvidenceDigest, CompilerDigest: provider.CompilerDigest, ExpiresAt: f.Now.Add(30 * time.Minute)}
	q.ID = proofID(*q)
	return provider, q, f, bundle
}
func TestCurrentRequiresIndependentClockAndExactRelease(t *testing.T) {
	ctx := context.Background()
	p, q, f, bundle := unitProvider(t)
	if e := p.Current(ctx, q); e != nil {
		t.Fatal(e)
	}
	p.Clock = nil
	if e := p.Current(ctx, q); e == nil {
		t.Fatal("missing independent clock fell back to local time")
	}
	p.Clock = func(context.Context) (time.Time, error) { return time.Time{}, errors.New("journal unavailable") }
	if e := p.Current(ctx, q); e == nil {
		t.Fatal("journal outage used cached time")
	}
	// CP wall time is still before expiry; the independent authority has passed it.
	p.Clock = func(context.Context) (time.Time, error) { return f.Now.Add(31 * time.Minute), nil }
	if e := p.Current(ctx, q); e == nil {
		t.Fatal("local wall clock revived expired proof")
	}
	p.Clock = func(context.Context) (time.Time, error) { return f.Now, nil }
	copy := *q
	copy.ProfileDigest = repository.Hash([]byte("wrong profile"))
	copy.ID = proofID(copy)
	if e := p.Current(ctx, &copy); e == nil {
		t.Fatal("mutated profile pin accepted")
	}
	copy = *q
	copy.CompilerDigest = repository.Hash([]byte("different compiler"))
	copy.ID = proofID(copy)
	if e := p.Current(ctx, &copy); e == nil {
		t.Fatal("other compiler accepted")
	}
	// Even identical runtime bytes must not keep a proof across a new release floor.
	f.Manifest.Sequence = "2"
	f.Manifest.SecurityFloor = "2"
	in := f.Build(2)
	if _, e := f.Write(bundle, in); e != nil {
		t.Fatal(e)
	}
	if _, e := p.Store.Import(ctx, bundle, f.Now); e != nil {
		t.Fatal(e)
	}
	if e := p.Current(ctx, q); e == nil {
		t.Fatal("old release proof survived independent floor advance")
	}
}
func TestRenderClosedTypedPolicy(t *testing.T) {
	p := configmodel.WafPolicy{APIVersion: "agp.waf/v1alpha1", Kind: "WafPolicy", Metadata: configmodel.WafPolicyMetadata{ID: "policy_test", Name: "Policy", SiteID: "site_test"}, Spec: configmodel.WafPolicySpec{Engine: "modsecurity", RulesetVersionID: "crs_native", ParanoiaLevel: 1, InboundAnomalyThreshold: 5, OutboundAnomalyThreshold: 4, Exceptions: []configmodel.WafException{}}}
	for _, mode := range []string{"off", "detection", "blocking"} {
		if _, e := Render(p, mode, "/tmp/bundle", "/tmp/scratch"); e != nil {
			t.Fatal(mode, e)
		}
	}
	if _, e := Render(p, "blocking", "/tmp/bundle;include", "/tmp/scratch"); e == nil {
		t.Fatal("native path injection accepted")
	}
	p.Spec.ParanoiaLevel = 5
	if _, e := Render(p, "blocking", "/tmp/bundle", "/tmp/scratch"); e == nil {
		t.Fatal("out of range policy accepted")
	}
}
