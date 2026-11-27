//go:build linux

package nativeactivation

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/helper"
)

func TestProjectedGenerationHasContentIdentityIndependentOfDispatchSequence(t *testing.T) {
	b := testBundle("generation-a", "revision-a")
	c := Config{NodeID: b.NodeID, SiteID: "site-a", QualificationDigest: b.QualificationDigest, ReleaseManifestDigest: b.ReleaseManifestDigest}
	c.LayoutDigest, _ = LayoutDigest(c)
	first, err := ProjectedGeneration(c, b, 1)
	if err != nil {
		t.Fatal(err)
	}
	again, err := ProjectedGeneration(c, b, 3)
	if err != nil || first.TreeDigest != again.TreeDigest || first.GenerationID != again.GenerationID || first.Baseline.RevisionID != again.Baseline.RevisionID || first.Baseline.BundleDigest != again.Baseline.BundleDigest || first.Baseline.NodeDeploymentSequence == again.Baseline.NodeDeploymentSequence || storageSlot(first) == storageSlot(again) {
		t.Fatalf("content/attempt identities conflated: %+v %+v %v", first, again, err)
	}
	changed := b
	changed.Files = append([]File(nil), b.Files...)
	changed.Files[0].Content += " changed"
	changed.Files[0].Digest = configmodel.DigestBytes([]byte(changed.Files[0].Content))
	other, err := ProjectedGeneration(c, changed, 1)
	if err != nil || other.TreeDigest == first.TreeDigest {
		t.Fatal("materialized bytes escaped content identity", err)
	}
	changed = b
	changed.Probes = append([]Probe(nil), b.Probes...)
	changed.Probes[0].BodyDigest = configmodel.DigestBytes([]byte("other response"))
	other, err = ProjectedGeneration(c, changed, 1)
	if err != nil || other.TreeDigest == first.TreeDigest {
		t.Fatal("functional probe pins escaped content identity", err)
	}
	if _, err = ProjectedGeneration(c, b, 0); err == nil {
		t.Fatal("zero execution sequence accepted")
	}
	if _, err = ProjectedGeneration(c, b, helper.UInt63(1)<<63); err == nil {
		t.Fatal("overflow execution sequence accepted")
	}
	c.LayoutDigest = configmodel.DigestBytes([]byte("wrong installation"))
	if _, err = ProjectedGeneration(c, b, 1); err == nil {
		t.Fatal("unbound layout accepted")
	}
}

func TestGenerationManifestRejectsSequenceRewriteAtPreviousStorageSlot(t *testing.T) {
	f := makeFixture(t)
	target := f.prepare(t)
	slot := storageSlot(target)
	m, err := f.driver.readManifest(context.Background(), slot)
	if err != nil {
		t.Fatal(err)
	}
	m.Generation.Baseline.NodeDeploymentSequence++
	digest, err := generationTreeDigest(m)
	if err != nil || digest != target.TreeDigest {
		t.Fatal("sequence unexpectedly changed content digest", err)
	}
	path := filepath.Join(f.cfg.RootDir, "generations", slot, "generation.json")
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	raw, _ := configmodel.CanonicalJSON(m)
	if err = os.WriteFile(path, raw, 0400); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err = f.driver.readManifest(context.Background(), slot); err == nil {
		t.Fatal("sequence rewrite reused old storage slot")
	}
}

func TestOldGenerationManifestVersionCannotBeReinterpreted(t *testing.T) {
	f := makeFixture(t)
	target := f.prepare(t)
	m, err := f.driver.readManifest(context.Background(), storageSlot(target))
	if err != nil {
		t.Fatal(err)
	}
	m.APIVersion = "agp.native-generation/v1alpha1"
	m.Generation.TreeDigest, _ = generationTreeDigest(m)
	path := filepath.Join(f.cfg.RootDir, "generations", storageSlot(target), "generation.json")
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	raw, _ := configmodel.CanonicalJSON(m)
	if err = os.WriteFile(path, raw, 0400); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err = f.driver.readManifest(context.Background(), storageSlot(target)); err == nil {
		t.Fatal("old prototype manifest reinterpreted with new content digest")
	}
}
