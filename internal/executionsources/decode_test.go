package executionsources

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/netwizd/agp/internal/configmodel"
)

func TestCatalogDecoderPreservesNativeLayoutContract(t *testing.T) {
	f := newFixture(t, false)
	raw, e := configmodel.CanonicalJSON(f.cfg)
	if e != nil {
		t.Fatal(e)
	}
	c, e := DecodeConfig(raw)
	if e != nil || hash(c) != hash(f.cfg) {
		t.Fatal("native layout/public catalog roundtrip", e)
	}
	pretty, _ := json.MarshalIndent(f.cfg, "", "  ")
	if _, e = DecodeConfig(pretty); e != nil {
		t.Fatal("formatted protected catalog rejected", e)
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"apiVersion":`), []byte(`"APIVersion":`), 1),
		bytes.Replace(raw, []byte(`"writerEpoch":"1"`), []byte(`"writerEpoch":"1","writerEpoch":"2"`), 1),
		bytes.Replace(raw, []byte(`"materials":[]`), []byte(`"materials":[],"unexpected":true`), 1),
		bytes.Replace(raw, []byte(`"apivalue"`), []byte(`"\ud800"`), 1),
		append(append([]byte{}, raw...), []byte(` {}`)...),
	} {
		if bytes.Equal(bad, raw) {
			continue
		}
		if _, e = DecodeConfig(bad); e == nil {
			t.Fatal("ambiguous or open catalog accepted")
		}
	}
	// Real materialized files exceed the restricted configuration DTO parser's
	// scalar budget. Decoding allows their bounded exact bytes; authentication
	// and native file-size checks still happen separately before Resolve.
	f.qualify()
	f.cfg.Materials[0].Bundle.Files[0].Content = strings.Repeat("synthetic native input\n", 1000)
	materialRaw, _ := configmodel.CanonicalJSON(f.cfg.Materials)
	materials, e := DecodeMaterials(materialRaw)
	if e != nil || len(materials) != 1 || materials[0].Bundle.Files[0].Content != f.cfg.Materials[0].Bundle.Files[0].Content {
		t.Fatal("bounded complete native file rejected", e)
	}
	bad := bytes.Replace(materialRaw, []byte(`"nodeId":"node_one"`), []byte(`"nodeId":"\ud800"`), 1)
	if _, e = DecodeMaterials(bad); e == nil {
		t.Fatal("unpaired Unicode surrogate accepted")
	}
}
