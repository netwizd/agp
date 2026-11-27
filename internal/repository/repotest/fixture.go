// Package repotest creates ephemeral signed repositories for isolated tests.
// Private keys exist only in memory and are never production trust material.
package repotest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/netwizd/agp/internal/repository"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

type Fixture struct {
	Now        time.Time
	Anchor     repository.Anchor
	Root       *metadata.Metadata[metadata.RootType]
	RoleKeys   map[string]ed25519.PrivateKey
	ReleaseKey ed25519.PrivateKey
	Objects    map[string][]byte
	MediaTypes map[string]string
	Manifest   repository.ManifestBody
}

func Canonical(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	b, e = jsoncanonicalizer.Transform(b)
	if e != nil {
		panic(e)
	}
	return b
}
func New(now time.Time) *Fixture {
	f := &Fixture{Now: now.UTC().Truncate(time.Second), RoleKeys: map[string]ed25519.PrivateKey{}, Objects: map[string][]byte{}, MediaTypes: map[string]string{}}
	f.Root = metadata.Root(f.Now.Add(48 * time.Hour))
	for _, role := range []string{metadata.ROOT, metadata.TIMESTAMP, metadata.SNAPSHOT, metadata.TARGETS} {
		pub, priv, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			panic(e)
		}
		key, e := metadata.KeyFromPublicKey(pub)
		if e != nil {
			panic(e)
		}
		if e = f.Root.Signed.AddKey(key, role); e != nil {
			panic(e)
		}
		f.RoleKeys[role] = priv
	}
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		panic(e)
	}
	f.ReleaseKey = priv
	f.signRoot()
	f.Anchor = repository.Anchor{Root: mustBytes(f.Root.ToBytes(false)), ReleaseKeys: map[string]ed25519.PublicKey{"test_release": pub}, ReleaseThreshold: 1, Platform: repository.Platform{OS: "ubuntu", OSVersion: "24.04", Arch: "amd64"}}
	f.Manifest = repository.ManifestBody{APIVersion: "agp.release/v1alpha1", ReleaseID: "release_test", Sequence: "1", CreatedAt: f.Now, ExpiresAt: f.Now.Add(24 * time.Hour), Platform: f.Anchor.Platform, CompatibilityProfile: repository.ProfileRef{ID: "profile_test"}, MinimumAgentProtocol: "agp.task/v1alpha1", SecurityFloor: "1"}
	return f
}
func mustBytes(b []byte, e error) []byte {
	if e != nil {
		panic(e)
	}
	return b
}
func (f *Fixture) signRoot() {
	f.Root.ClearSignatures()
	signer, _ := signature.LoadED25519Signer(f.RoleKeys[metadata.ROOT])
	if _, e := f.Root.Sign(signer); e != nil {
		panic(e)
	}
}
func (f *Fixture) Add(raw []byte, mediaType string) string {
	digest := repository.Hash(raw)
	f.Objects[digest] = append([]byte(nil), raw...)
	f.MediaTypes[digest] = mediaType
	return digest
}

// SetProfile uses actual native files when supplied by the native acceptance;
// unit tests can supply synthetic bytes without claiming runtime qualification.
func (f *Fixture) SetProfile(p repository.ComponentProfile, files map[string][]byte, checks []repository.QualificationCheck, corpus, harness []byte) {
	p.Files = []repository.ProfileFile{}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	sbom := repository.SBOM{APIVersion: "agp.sbom/v1alpha1", Files: []repository.SBOMFile{}}
	for _, name := range names {
		d := f.Add(files[name], "application/octet-stream")
		p.Files = append(p.Files, repository.ProfileFile{Path: name, Digest: d})
		sbom.Files = append(sbom.Files, repository.SBOMFile{Path: name, Digest: d, License: "TEST-ONLY"})
	}
	f.Manifest.CompatibilityProfile = repository.ProfileRef{ID: p.ID, Digest: f.Add(Canonical(p), "application/vnd.agp.component-profile+json")}
	evidence := repository.QualificationEvidence{APIVersion: "agp.waf-qualification/v1alpha1", ProfileDigest: f.Manifest.CompatibilityProfile.Digest, TupleDigest: repository.Hash(Canonical(p.Tuple)), CorpusDigest: f.Add(corpus, "application/vnd.agp.native-corpus+json"), HarnessDigest: f.Add(harness, "text/plain"), RendererDigest: f.Add([]byte("synthetic unit renderer"), "application/octet-stream"), NativeReportDigest: f.Add([]byte(`{"syntheticUnitFixture":true}`), "application/json"), Platform: p.Platform, HostKernel: "test-only", StartedAt: f.Now.Add(-time.Minute), CompletedAt: f.Now, Checks: checks}
	f.Add(Canonical(evidence), "application/vnd.agp.waf-qualification+json")
	f.Manifest.SBOMDigest = f.Add(Canonical(sbom), "application/vnd.agp.sbom+json")
}
func (f *Fixture) Build(version int64) repository.Input {
	// Rebuild the closure after a test has deliberately modified a signed input.
	for d, media := range f.MediaTypes {
		if media == "application/vnd.agp.dependency-closure+json" {
			delete(f.Objects, d)
			delete(f.MediaTypes, d)
		}
	}
	closure := repository.DependencyClosure{APIVersion: "agp.dependency-closure/v1alpha1", Artifacts: []repository.ClosureEntry{}}
	digests := []string{}
	for d := range f.Objects {
		digests = append(digests, d)
	}
	sort.Strings(digests)
	for _, d := range digests {
		closure.Artifacts = append(closure.Artifacts, repository.ClosureEntry{Path: "objects/" + strings.TrimPrefix(d, "sha256:"), Length: strconv.Itoa(len(f.Objects[d])), SHA256: strings.TrimPrefix(d, "sha256:")})
	}
	f.Manifest.DependencyClosureDigest = f.Add(Canonical(closure), "application/vnd.agp.dependency-closure+json")
	f.Manifest.Artifacts = []repository.Artifact{}
	digests = append(digests, f.Manifest.DependencyClosureDigest)
	sort.Strings(digests)
	for _, d := range digests {
		f.Manifest.Artifacts = append(f.Manifest.Artifacts, repository.Artifact{Path: "objects/" + strings.TrimPrefix(d, "sha256:"), Length: strconv.Itoa(len(f.Objects[d])), SHA256: strings.TrimPrefix(d, "sha256:"), MediaType: f.MediaTypes[d]})
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(f.ReleaseKey, Canonical(f.Manifest)))
	manifest := Canonical(repository.Manifest{Signed: f.Manifest, Signatures: []repository.Signature{{KeyID: "test_release", Algorithm: "ed25519", Signature: sig}}})
	manifestPath := "releases/" + f.Manifest.ReleaseID + ".json"
	targets := metadata.Targets(f.Now.Add(12 * time.Hour))
	targets.Signed.Version = version
	for _, a := range f.Manifest.Artifacts {
		d := "sha256:" + a.SHA256
		targets.Signed.Targets[a.Path], _ = metadata.TargetFile().FromBytes(a.Path, f.Objects[d], "sha256")
	}
	targets.Signed.Targets[manifestPath], _ = metadata.TargetFile().FromBytes(manifestPath, manifest, "sha256")
	signer, _ := signature.LoadED25519Signer(f.RoleKeys[metadata.TARGETS])
	if _, e := targets.Sign(signer); e != nil {
		panic(e)
	}
	targetsBytes := mustBytes(targets.ToBytes(false))
	snapshot := metadata.Snapshot(f.Now.Add(12 * time.Hour))
	snapshot.Signed.Version = version
	snapshot.Signed.Meta["targets.json"] = metaFile(version, targetsBytes)
	signer, _ = signature.LoadED25519Signer(f.RoleKeys[metadata.SNAPSHOT])
	if _, e := snapshot.Sign(signer); e != nil {
		panic(e)
	}
	snapshotBytes := mustBytes(snapshot.ToBytes(false))
	stamp := metadata.Timestamp(f.Now.Add(6 * time.Hour))
	stamp.Signed.Version = version
	stamp.Signed.Meta["snapshot.json"] = metaFile(version, snapshotBytes)
	signer, _ = signature.LoadED25519Signer(f.RoleKeys[metadata.TIMESTAMP])
	if _, e := stamp.Sign(signer); e != nil {
		panic(e)
	}
	return repository.Input{Timestamp: mustBytes(stamp.ToBytes(false)), Snapshot: snapshotBytes, Targets: targetsBytes, ManifestPath: manifestPath, Manifest: manifest, ReadObject: func(p string, n int64) ([]byte, error) {
		b, ok := f.Objects["sha256:"+strings.TrimPrefix(p, "objects/")]
		if !ok {
			return nil, os.ErrNotExist
		}
		if int64(len(b)) != n {
			return nil, fmt.Errorf("test object length")
		}
		return append([]byte(nil), b...), nil
	}}
}
func metaFile(version int64, b []byte) *metadata.MetaFiles {
	t, _ := metadata.TargetFile().FromBytes("metadata", b, "sha256")
	m := metadata.MetaFile(version)
	m.Length = int64(len(b))
	m.Hashes = t.Hashes
	return m
}
func (f *Fixture) Write(dir string, in repository.Input) (string, error) {
	for _, sub := range []string{"metadata", "objects", "releases"} {
		if e := os.MkdirAll(filepath.Join(dir, sub), 0700); e != nil {
			return "", e
		}
	}
	files := map[string][]byte{"metadata/timestamp.json": in.Timestamp, "metadata/snapshot.json": in.Snapshot, "metadata/targets.json": in.Targets, in.ManifestPath: in.Manifest, "bundle.json": Canonical(map[string]any{"manifestPath": in.ManifestPath, "rootVersions": []int64{}})}
	for _, a := range f.Manifest.Artifacts {
		files[a.Path] = f.Objects["sha256:"+a.SHA256]
	}
	for name, raw := range files {
		if e := os.WriteFile(filepath.Join(dir, name), raw, 0600); e != nil {
			return "", e
		}
	}
	keys := map[string]string{}
	for id, key := range f.Anchor.ReleaseKeys {
		keys[id] = base64.StdEncoding.EncodeToString(key)
	}
	anchor := Canonical(map[string]any{"root": json.RawMessage(f.Anchor.Root), "releaseKeys": keys, "releaseThreshold": f.Anchor.ReleaseThreshold, "platform": f.Anchor.Platform, "minimumSequence": strconv.FormatUint(f.Anchor.MinimumSequence, 10), "securityFloor": strconv.FormatUint(f.Anchor.SecurityFloor, 10)})
	anchorPath := filepath.Join(dir, "test-anchor.json")
	return anchorPath, os.WriteFile(anchorPath, anchor, 0600)
}
