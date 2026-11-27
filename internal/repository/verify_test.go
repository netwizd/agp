package repository_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/repository"
	"github.com/netwizd/agp/internal/repository/repotest"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func fixture() *repotest.Fixture {
	f := repotest.New(time.Now())
	p := repository.ComponentProfile{APIVersion: "agp.component-profile/v1alpha1", ID: "profile_test", Platform: f.Anchor.Platform, RulesetVersionID: "crs_test", Tuple: repository.ComponentTuple{Nginx: "1.30.8", Connector: "1.0.4", LibModSecurity: "3.0.17", CRS: "4.30.0", BuildFlags: []string{"--with-compat"}, ABIDigest: repository.Hash([]byte("test ABI"))}, LoaderPath: "lib/loader", NginxPath: "bin/nginx", ModulePath: "modules/modsecurity.so", UnicodePath: "share/unicode.mapping", RulesPath: "share/crs/rules"}
	files := map[string][]byte{}
	for _, name := range []string{p.LoaderPath, p.NginxPath, p.ModulePath, p.UnicodePath, "share/crs/rules/test.conf"} {
		files[name] = []byte("synthetic unit fixture " + name)
	}
	checks := []repository.QualificationCheck{}
	for _, id := range repository.RequiredNativeChecks {
		checks = append(checks, repository.QualificationCheck{ID: id, Passed: true})
	}
	f.SetProfile(p, files, checks, []byte(`{"synthetic":true}`), []byte("synthetic unit harness"))
	return f
}
func TestVerifiedReleaseAndProfile(t *testing.T) {
	f := fixture()
	in := f.Build(1)
	v, e := repository.Verify(context.Background(), f.Anchor, nil, in, f.Now)
	if e != nil {
		t.Fatal(e)
	}
	p, e := v.QualifiedProfile(f.Now)
	if e != nil || p.Profile.ID != "profile_test" {
		t.Fatalf("profile: %#v %v", p, e)
	}
	if v.ExpiresAt.Sub(f.Now) != 6*time.Hour {
		t.Fatal("TUF expiry not intersected")
	}
	if _, e = repository.Verify(context.Background(), f.Anchor, &v.Next, in, f.Now.Add(time.Second)); e != nil {
		t.Fatal("exact current repository rejected", e)
	}
	b, ok := v.Object(v.Manifest.Signed.CompatibilityProfile.Digest)
	if !ok {
		t.Fatal("missing profile")
	}
	b[0] = 'x'
	if _, e = v.QualifiedProfile(f.Now); e != nil {
		t.Fatal("caller mutated verified bytes", e)
	}
}
func TestUntrustedReleaseNegatives(t *testing.T) {
	for _, name := range []string{"wrong_release_signer", "reused_tuf_key", "threshold", "tampered_object", "expired", "wrong_platform", "missing_sbom", "bad_closure", "duplicate_json", "unqualified_evidence", "clock_rollback", "metadata_rollback", "release_rollback", "equivocation"} {
		t.Run(name, func(t *testing.T) {
			f := fixture()
			in := f.Build(2)
			now := f.Now
			v, e := repository.Verify(context.Background(), f.Anchor, nil, in, now)
			if e != nil {
				t.Fatal(e)
			}
			var previous *repository.State
			switch name {
			case "wrong_release_signer":
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				f.Anchor.ReleaseKeys["test_release"] = pub
			case "reused_tuf_key":
				f.Anchor.ReleaseKeys["test_release"] = f.RoleKeys["root"].Public().(ed25519.PublicKey)
			case "threshold":
				f.Anchor.ReleaseThreshold = 2
			case "tampered_object":
				old := in.ReadObject
				in.ReadObject = func(p string, n int64) ([]byte, error) {
					b, e := old(p, n)
					if len(b) > 0 {
						b[0] ^= 1
					}
					return b, e
				}
			case "expired":
				now = now.Add(7 * time.Hour)
			case "wrong_platform":
				f.Manifest.Platform.OSVersion = "26.04"
				in = f.Build(3)
			case "missing_sbom":
				f.Manifest.SBOMDigest = repository.Hash([]byte("missing"))
				in = f.Build(3)
			case "bad_closure":
				in.ReadObject = func(string, int64) ([]byte, error) { return []byte("{}"), nil }
			case "duplicate_json":
				in.Timestamp = []byte(`{"signed":{},"signed":{},"signatures":[]}`)
			case "unqualified_evidence":
				for d, media := range f.MediaTypes {
					if media == "application/vnd.agp.waf-qualification+json" {
						var ev repository.QualificationEvidence
						json.Unmarshal(f.Objects[d], &ev)
						ev.Checks = ev.Checks[1:]
						delete(f.Objects, d)
						delete(f.MediaTypes, d)
						f.Add(repotest.Canonical(ev), media)
					}
				}
				in = f.Build(3)
			case "clock_rollback":
				previous = &v.Next
				now = now.Add(-time.Second)
			case "metadata_rollback":
				previous = &v.Next
				in = f.Build(1)
			case "release_rollback":
				previous = &v.Next
				f.Manifest.Sequence = "0"
				in = f.Build(3)
			case "equivocation":
				previous = &v.Next
				f.Manifest.ReleaseID = "other_release"
				in = f.Build(3)
			}
			got, e := repository.Verify(context.Background(), f.Anchor, previous, in, now)
			if e == nil && got != nil {
				_, e = got.QualifiedProfile(now)
			}
			if !errors.Is(e, repository.ErrUntrusted) {
				t.Fatalf("accepted invalid %s: %v", name, e)
			}
		})
	}
}
func TestIndependentStoreDurableFloorAndSymlinks(t *testing.T) {
	ctx := context.Background()
	f := fixture()
	in := f.Build(2)
	bundle := t.TempDir()
	anchor, e := f.Write(bundle, in)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	store := repository.Store{Dir: dir, AnchorPath: anchor}
	if _, e = store.Import(ctx, bundle, f.Now); e != nil {
		t.Fatal(e)
	}
	if _, e = store.Current(ctx, f.Now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	// Restart/CP database restore has no influence on this independent highwater.
	reopened := repository.Store{Dir: dir, AnchorPath: anchor}
	older := f.Build(1)
	if _, e = f.Write(bundle, older); e != nil {
		t.Fatal(e)
	}
	if _, e = reopened.Import(ctx, bundle, f.Now.Add(time.Second)); !errors.Is(e, repository.ErrUntrusted) {
		t.Fatal("rollback after restart accepted", e)
	}
	for _, a := range f.Manifest.Artifacts {
		file := filepath.Join(dir, a.Path)
		if e = os.Remove(file); e != nil {
			t.Fatal(e)
		}
		if e = os.Symlink(filepath.Join(bundle, a.Path), file); e != nil {
			t.Fatal(e)
		}
		break
	}
	if _, e = reopened.Current(ctx, f.Now.Add(time.Second)); e == nil {
		t.Fatal("symlink CAS accepted")
	}
	read := repository.DirectoryReader(bundle)
	if _, e = read("../test-anchor.json", 4096); e == nil {
		t.Fatal("traversal accepted")
	}
	if _, e = read(strings.Repeat("x", 257), 4096); e == nil {
		t.Fatal("unbounded path accepted")
	}
}

func TestTUFRoleSeparationAndRootRotation(t *testing.T) {
	for _, roles := range [][2]string{{metadata.TIMESTAMP, metadata.TARGETS}, {metadata.ROOT, metadata.SNAPSHOT}} {
		f := fixture()
		f.Root.Signed.Roles[roles[0]].KeyIDs = append([]string(nil), f.Root.Signed.Roles[roles[1]].KeyIDs...)
		f.RoleKeys[roles[0]] = f.RoleKeys[roles[1]]
		f.Root.ClearSignatures()
		signer, _ := signature.LoadED25519Signer(f.RoleKeys[metadata.ROOT])
		f.Root.Sign(signer)
		f.Anchor.Root, _ = f.Root.ToBytes(false)
		if _, e := repository.Verify(context.Background(), f.Anchor, nil, f.Build(1), f.Now); !errors.Is(e, repository.ErrUntrusted) {
			t.Fatal("shared role key accepted", roles, e)
		}
	}
	f := fixture()
	in := f.Build(1)
	rotated, e := metadata.Root().FromBytes(f.Anchor.Root)
	if e != nil {
		t.Fatal(e)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := metadata.KeyFromPublicKey(pub)
	oldIDs := append([]string(nil), rotated.Signed.Roles[metadata.ROOT].KeyIDs...)
	if e = rotated.Signed.AddKey(key, metadata.ROOT); e != nil {
		t.Fatal(e)
	}
	allIDs := rotated.Signed.Roles[metadata.ROOT].KeyIDs
	rotated.Signed.Roles[metadata.ROOT].KeyIDs = allIDs[len(allIDs)-1:]
	for _, id := range oldIDs {
		delete(rotated.Signed.Keys, id)
	}
	rotated.Signed.Version = 2
	rotated.ClearSignatures()
	oldSigner, _ := signature.LoadED25519Signer(f.RoleKeys[metadata.ROOT])
	newSigner, _ := signature.LoadED25519Signer(priv)
	rotated.Sign(oldSigner)
	rotated.Sign(newSigner)
	rootBytes, e := rotated.ToBytes(false)
	if e != nil {
		t.Fatal(e)
	}
	in.RootUpdates = [][]byte{rootBytes}
	v, e := repository.Verify(context.Background(), f.Anchor, nil, in, f.Now)
	if e != nil || v.Next.RootVersion != 2 {
		t.Fatal("valid dual-authorized root rotation rejected", e)
	}
	rotated.ClearSignatures()
	rotated.Sign(newSigner)
	bad, _ := rotated.ToBytes(false)
	in.RootUpdates = [][]byte{bad}
	if _, e = repository.Verify(context.Background(), f.Anchor, nil, in, f.Now); !errors.Is(e, repository.ErrUntrusted) {
		t.Fatal("root without prior authorization accepted", e)
	}
}
