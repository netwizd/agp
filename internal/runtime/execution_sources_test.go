//go:build linux

package runtime

import (
	"context"
	"strings"
	"testing"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/executionsources"
	"github.com/netwizd/agp/internal/nativeactivation"
)

func TestExecutionFilesKeepPublicPinsSeparateFromNativeSecrets(t *testing.T) {
	c := executionsources.Config{APIVersion: executionsources.CatalogVersion, WriterEpoch: 1, Bindings: []executionsources.Binding{{Native: nativeactivation.Config{NodeID: "node_one", SiteID: "site_one"}}}, QualificationKeys: map[string]string{}, Materials: []executionsources.Materialization{}, SecretVersions: []executionsources.SecretVersion{}}
	materials := []executionsources.Materialization{{Bundle: nativeactivation.Bundle{Files: []nativeactivation.File{{Content: strings.Repeat("native_private_content", 1024)}}}}}
	public, e := configmodel.CanonicalJSON(c)
	if e != nil {
		t.Fatal(e)
	}
	private, e := configmodel.CanonicalJSON(materials)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := decodeExecutionFiles(public, private)
	if e != nil || parsed.Bindings[0].Native.NodeID != "node_one" || parsed.Materials[0].Bundle.Files[0].Content != materials[0].Bundle.Files[0].Content {
		t.Fatal("persisted native format or full bytes rejected by HTTP limits", e)
	}
	// Parsing does not confer qualification; constructor admission separately
	// requires installed pins, witness, signed materials and source closure.
	c.Materials = materials
	inline, _ := configmodel.CanonicalJSON(c)
	if _, e = decodeExecutionFiles(inline, private); e == nil {
		t.Fatal("secret-bearing bundle admitted from public trust file")
	}
	for _, bad := range []string{`null`, `{}`, `[{"unknown":true}]`, string(private) + ` []`} {
		if _, e = decodeExecutionFiles(public, []byte(bad)); e == nil {
			t.Fatal("noncanonical/unknown private payload accepted")
		}
	}
}
func TestExecutionRuntimeIsExplicitAndRequiresSecureDependencies(t *testing.T) {
	t.Setenv("AGP_EXECUTION_CONFIG", "")
	if r, e := OpenExecutionRuntime(context.Background(), nil, nil, "https://management.test"); e != nil || r != nil {
		t.Fatal("absent execution config enabled runtime")
	}
	t.Setenv("AGP_EXECUTION_CONFIG", "/tmp/not-an-installed-execution-config")
	if _, e := OpenExecutionRuntime(context.Background(), nil, nil, "https://management.test"); e != ErrExecutionRuntime {
		t.Fatal("partial execution configuration silently accepted")
	}
}
