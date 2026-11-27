package repository_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/repository"
	"github.com/netwizd/agp/internal/repository/repotest"
)

func largeFixture() *repotest.Fixture {
	f := repotest.New(time.Now())
	p := repository.ComponentProfile{APIVersion: "agp.component-profile/v1alpha1", ID: "profile_large", Platform: f.Anchor.Platform, RulesetVersionID: "crs_large", Tuple: repository.ComponentTuple{Nginx: "1.30.8", Connector: "1.0.4", LibModSecurity: "3.0.17", CRS: "4.30.0", BuildFlags: []string{"--with-compat"}, ABIDigest: repository.Hash([]byte("synthetic unit ABI"))}, LoaderPath: "lib/loader", NginxPath: "bin/nginx", ModulePath: "modules/modsecurity.so", UnicodePath: "share/unicode.mapping", RulesPath: "share/crs/rules"}
	files := map[string][]byte{}
	for _, name := range []string{p.LoaderPath, p.NginxPath, p.ModulePath, p.UnicodePath} {
		files[name] = []byte("synthetic unit runtime " + name)
	}
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf("share/crs/rules/unit_%03d.conf", i)
		files[name] = []byte("synthetic unit rule " + name)
	}
	checks := []repository.QualificationCheck{}
	for _, id := range repository.RequiredNativeChecks {
		checks = append(checks, repository.QualificationCheck{ID: id, Passed: true})
	}
	f.SetProfile(p, files, checks, []byte(`{"syntheticUnitCorpus":true}`), []byte("synthetic unit harness"))
	return f
}

func TestLargeSignedRuntimeInventory(t *testing.T) {
	f := largeFixture()
	in := f.Build(1)
	verified, e := repository.Verify(context.Background(), f.Anchor, nil, in, f.Now)
	if e != nil {
		t.Fatal(e)
	}
	p, e := verified.QualifiedProfile(f.Now)
	if e != nil || len(p.Profile.Files) != 104 {
		t.Fatalf("large signed runtime inventory %#v %v", p, e)
	}
	dir := t.TempDir()
	anchorPath, e := f.Write(dir, in)
	if e != nil {
		t.Fatal(e)
	}
	anchor, e := repository.ReadAnchor(anchorPath)
	if e != nil {
		t.Fatal(e)
	}
	fromDisk, e := repository.ReadBundle(dir)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = repository.Verify(context.Background(), anchor, nil, fromDisk, f.Now); e != nil {
		t.Fatal(e)
	}
	in.Targets = bytes.Replace(in.Targets, []byte(`"signed":`), []byte(`"signed":{},"signed":`), 1)
	if _, e = repository.Verify(context.Background(), f.Anchor, nil, in, f.Now); e == nil {
		t.Fatal("duplicate signed key accepted in large TUF metadata")
	}
}

func TestRepositoryMetadataJSONBudgets(t *testing.T) {
	inventory := map[string]any{}
	for i := 0; i < 1000; i++ {
		inventory[fmt.Sprintf("objects/%064x", i)] = map[string]any{"length": 123, "sha256": strings.Repeat("a", 64)}
	}
	raw, _ := json.Marshal(inventory)
	if e := repository.ValidateMetadataJSON(raw); e != nil {
		t.Fatal("valid large map rejected", e)
	}
	invalid := map[string][]byte{
		"duplicate":         []byte(`{"a":1,"a":2}`),
		"escaped_duplicate": []byte(`{"a":1,"\u0061":2}`),
		"invalid_utf8":      {'{', '"', 'a', '"', ':', '"', 0xff, '"', '}'},
		"high_surrogate":    []byte(`{"a":"\ud800"}`),
		"low_surrogate":     []byte(`{"a":"\udc00"}`),
		"trailing":          []byte(`{} {}`),
		"unfinished":        []byte(`{"a":{`),
		"non_object":        []byte(`[]`),
		"depth":             []byte(`{"a":` + strings.Repeat("[", 33) + `0` + strings.Repeat("]", 33) + `}`),
		"bytes":             []byte(`{"a":"` + strings.Repeat("a", repository.MaxMetadataBytes) + `"}`),
	}
	for name, data := range invalid {
		t.Run(name, func(t *testing.T) {
			if e := repository.ValidateMetadataJSON(data); e == nil {
				t.Fatal("unsafe metadata accepted")
			}
		})
	}
}

func TestRepositoryProfileFieldsRemainClosed(t *testing.T) {
	f := largeFixture()
	var profile map[string]any
	if e := json.Unmarshal(f.Objects[f.Manifest.CompatibilityProfile.Digest], &profile); e != nil {
		t.Fatal(e)
	}
	profile["ID"] = profile["id"]
	delete(profile, "id")
	f.Manifest.CompatibilityProfile.Digest = f.Add(repotest.Canonical(profile), "application/vnd.agp.component-profile+json")
	v, e := repository.Verify(context.Background(), f.Anchor, nil, f.Build(1), f.Now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = v.QualifiedProfile(f.Now); e == nil || !strings.Contains(e.Error(), "unknown metadata field") {
		t.Fatalf("case-insensitive profile field accepted or wrong rejection: %v", e)
	}
}
