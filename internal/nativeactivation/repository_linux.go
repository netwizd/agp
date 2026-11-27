//go:build linux

package nativeactivation

import (
	"context"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/helper"
	"github.com/netwizd/agp/internal/ownedtree"
)

// Repository loads complete native inputs from an installer-pinned, canonical
// repository. Preview artifacts cannot enter this API without separately
// producing and qualifying a complete Bundle and a trusted repository pin.
type Repository struct {
	mu       sync.Mutex
	dir      *protectedDir
	manifest RepositoryManifest
	digest   string
	pins     map[string]string
	closed   bool
}

func OpenRepository(dir, manifestDigest string) (*Repository, error) {
	if os.Geteuid() != 0 || os.Getuid() != 0 {
		return nil, ErrInstallation
	}
	return openRepository(dir, manifestDigest, 0)
}
func openRepository(dir, digest string, owner uint32) (_ *Repository, err error) {
	if !configmodel.ValidDigest(digest) {
		return nil, ErrInstallation
	}
	d, e := openDir(dir, owner)
	if e != nil {
		return nil, e
	}
	r := &Repository{dir: d, digest: digest, pins: map[string]string{}}
	defer func() {
		if err != nil {
			d.close()
		}
	}()
	b, e := canonicalRead(d.file(), "repository.json", maxMetadata, owner, &r.manifest)
	if e != nil || configmodel.DigestBytes(b) != digest || r.manifest.APIVersion != RepositoryVersion || len(r.manifest.Bundles) < 1 || len(r.manifest.Bundles) > maxBundles {
		return nil, ErrBundle
	}
	want := []string{"repository.json"}
	last := ""
	for _, p := range r.manifest.Bundles {
		if !configmodel.ValidDigest(p.BundleDigest) || !configmodel.ValidDigest(p.ManifestDigest) || p.BundleDigest <= last {
			return nil, ErrBundle
		}
		last = p.BundleDigest
		r.pins[p.BundleDigest] = p.ManifestDigest
		want = append(want, strings.TrimPrefix(p.BundleDigest, "sha256:")+".json")
	}
	if exactNames(d.file(), want) != nil || d.check() != nil {
		return nil, ErrBundle
	}
	return r, nil
}
func (r *Repository) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		r.dir.close()
	}
	return nil
}
func (r *Repository) load(ctx context.Context, digest string) (Bundle, error) {
	var b Bundle
	if r == nil || ctx == nil {
		return b, ErrBundle
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.dir.check() != nil {
		return b, ErrBundle
	}
	if e := ctx.Err(); e != nil {
		return b, e
	}
	var current RepositoryManifest
	metadata, e := canonicalRead(r.dir.file(), "repository.json", maxMetadata, r.dir.owner, &current)
	if e != nil || configmodel.DigestBytes(metadata) != r.digest {
		return b, ErrBundle
	}
	want := []string{"repository.json"}
	for _, p := range r.manifest.Bundles {
		want = append(want, strings.TrimPrefix(p.BundleDigest, "sha256:")+".json")
	}
	if exactNames(r.dir.file(), want) != nil {
		return b, ErrBundle
	}
	pin, ok := r.pins[digest]
	if !ok {
		return b, ErrBundle
	}
	bytes, e := canonicalRead(r.dir.file(), strings.TrimPrefix(digest, "sha256:")+".json", maxBundleBytes, r.dir.owner, &b)
	if e != nil || configmodel.DigestBytes(bytes) != pin || b.BundleDigest != digest || validateBundle(b) != nil || r.dir.check() != nil {
		return Bundle{}, ErrBundle
	}
	return b, nil
}

// InitialGeneration projects only a bundle authenticated by this pinned root
// repository. It does not stage files or establish runtime health.
func (r *Repository) InitialGeneration(ctx context.Context, c Config, base helper.Baseline) (helper.ExecutionGeneration, error) {
	b, err := r.load(ctx, base.BundleDigest)
	if err != nil {
		return helper.ExecutionGeneration{}, err
	}
	return InitialGeneration(c, b, base)
}
func validateBundle(b Bundle) error {
	if b.APIVersion != BundleVersion || !configmodel.ValidID(b.NodeID) || !configmodel.ValidID(b.RevisionID) || !configmodel.ValidID(b.GenerationID) || !configmodel.ValidDigest(b.BundleDigest) || !configmodel.ValidDigest(b.QualificationDigest) || !configmodel.ValidDigest(b.ReleaseManifestDigest) || len(b.Files) < 1 || len(b.Files) > ownedtree.MaxEntries-2 || len(b.Probes) < 3 || len(b.Probes) > 32 {
		return ErrBundle
	}
	last := ""
	total := 0
	nginx := false
	for _, f := range b.Files {
		if !validRelative(f.Path) || f.Path <= last || len(f.Content) > ownedtree.MaxFileBytes || f.Digest != configmodel.DigestBytes([]byte(f.Content)) {
			return ErrBundle
		}
		last = f.Path
		total += len(f.Content)
		if total > ownedtree.MaxTotalBytes {
			return ErrBundle
		}
		if f.Path == "nginx.conf" {
			nginx = true
		}
	}
	if !nginx {
		return ErrBundle
	}
	kinds := map[string]bool{}
	for _, p := range b.Probes {
		u, e := url.ParseRequestURI(p.Path)
		if e != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(p.Path, "/") || strings.HasPrefix(p.Path, "//") || len(p.Path) > 2048 || strings.ContainsAny(p.Path, "\x00\r\n") || len(p.Host) > 253 || p.Host == "" || strings.ContainsAny(p.Host, "\x00\r\n /\\") || !configmodel.ValidDigest(p.BodyDigest) || p.Status < 200 || p.Status > 599 {
			return ErrBundle
		}
		switch p.Kind {
		case "route":
			if p.Status < 200 || p.Status >= 300 {
				return ErrBundle
			}
		case "auth-deny", "waf-deny":
			if p.Status != 401 && p.Status != 403 {
				return ErrBundle
			}
		default:
			return ErrBundle
		}
		kinds[p.Kind] = true
	}
	if !kinds["route"] || !kinds["auth-deny"] || !kinds["waf-deny"] {
		return ErrBundle
	}
	return nil
}
func validRelative(s string) bool {
	return s != "" && s != "." && !strings.HasPrefix(s, "/") && path.Clean(s) == s && !strings.HasPrefix(s, "../") && !strings.ContainsAny(s, "\x00\r\n\\") && len(s) <= ownedtree.MaxPathBytes && strings.Count(s, "/") < ownedtree.MaxDepth
}
func sortFiles(files []File) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
}
