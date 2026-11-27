//go:build linux

package nativeactivation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/helper"
	"github.com/netwizd/agp/internal/ownedtree"
	"golang.org/x/sys/unix"
)

type runtimeAdapter interface {
	validate(context.Context, string) error
	reload(context.Context) error
	verify(context.Context, helper.ExecutionGeneration, []Probe) error
	contain(context.Context) error
}

func (d *Driver) Contain(ctx context.Context) error {
	// Containment remains available after a poisoned activation handle: it does
	// not trust mutable generation state, switch files, or accept task input.
	if d == nil || ctx == nil {
		return ErrRuntime
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return ErrRuntime
	}
	return d.runtime.contain(ctx)
}

// Driver holds an exclusive installation lock. Closing it never deletes
// generations or recovery evidence. A durability failure poisons the handle;
// reopening observes disk state and never assumes a failed write had no effect.
type Driver struct {
	mu                          sync.Mutex
	cfg                         Config
	repository                  *Repository
	root                        *protectedDir
	generations, recovery, lock *os.File
	lockPin                     unix.Stat_t
	runtime                     runtimeAdapter
	owner                       uint32
	closed, poisoned            bool
	fault                       func(string) error // internal crash/failure injection only
}

var _ helper.ExecutionDriver = (*Driver)(nil)

// LayoutDigest binds stable installation policy separately from generation
// content. It is computed and approved by the installer, not supplied in tasks.
func LayoutDigest(c Config) (string, error) {
	c.LayoutDigest = ""
	return configmodel.Digest(struct {
		Version string
		Config  Config
	}{"agp.native-layout/v1alpha1", c})
}

func Open(c Config, r *Repository) (*Driver, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, ErrInstallation
	}
	rt, e := newNativeRuntime(c)
	if e != nil {
		return nil, e
	}
	return openDriver(c, r, rt, 0)
}
func openDriver(c Config, r *Repository, rt runtimeAdapter, owner uint32) (_ *Driver, err error) {
	digest, e := LayoutDigest(c)
	if e != nil || digest != c.LayoutDigest || !configmodel.ValidDigest(c.LayoutDigest) || !configmodel.ValidID(c.NodeID) || !configmodel.ValidID(c.SiteID) || !configmodel.ValidDigest(c.QualificationDigest) || !configmodel.ValidDigest(c.ReleaseManifestDigest) || r == nil || rt == nil {
		return nil, ErrInstallation
	}
	root, e := openDir(c.RootDir, owner)
	if e != nil {
		return nil, e
	}
	d := &Driver{cfg: c, repository: r, root: root, runtime: rt, owner: owner}
	defer func() {
		if err != nil {
			d.close()
		}
	}()
	if _, e := names(root.file(), 20); e != nil {
		return nil, ErrInstallation
	}
	d.generations, e = openChild(root.file(), "generations", true, owner)
	if e != nil {
		return nil, e
	}
	d.recovery, e = openChild(root.file(), "recovery", true, owner)
	if e != nil {
		return nil, e
	}
	d.lock, e = openChild(root.file(), "native.lock", false, owner)
	if e != nil {
		return nil, e
	}
	if unix.Fstat(int(d.lock.Fd()), &d.lockPin) != nil || d.lockPin.Mode != unix.S_IFREG|0600 || d.lockPin.Size != 0 {
		return nil, ErrInstallation
	}
	if e = unix.Flock(int(d.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return nil, helper.ErrBusy
	}
	if e = d.reconcilePointers(context.Background()); e != nil {
		return nil, e
	}
	if d.check() != nil {
		return nil, ErrInstallation
	}
	if _, e = d.active(context.Background()); e != nil {
		return nil, e
	}
	return d, nil
}

// Initialize is an explicit installer operation on an existing empty private
// directory. It does not run Nginx, qualify an artifact, or establish runtime
// health. Open/Snapshot subsequently require actual runtime evidence.
func Initialize(c Config, r *Repository, initial helper.ExecutionGeneration) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return ErrInstallation
	}
	return initialize(c, r, initial, 0)
}
func initialize(c Config, r *Repository, initial helper.ExecutionGeneration, owner uint32) error {
	digest, e := LayoutDigest(c)
	if e != nil || digest != c.LayoutDigest || r == nil {
		return ErrInstallation
	}
	root, e := openDir(c.RootDir, owner)
	if e != nil {
		return e
	}
	defer root.close()
	if exactNames(root.file(), nil) != nil {
		return ErrInstallation
	}
	b, e := r.load(context.Background(), initial.Baseline.BundleDigest)
	if e != nil {
		return e
	}
	m, e := makeManifest(c, b, initial.Baseline, owner)
	if e != nil || m.Generation != initial {
		return ErrBundle
	}
	if unix.Mkdirat(int(root.file().Fd()), "generations", 0700) != nil || unix.Mkdirat(int(root.file().Fd()), "recovery", 0700) != nil || writeExclusive(root.file(), "native.lock", nil, 0600) != nil {
		return ErrTree
	}
	gens, e := openChild(root.file(), "generations", true, owner)
	if e != nil {
		return e
	}
	defer gens.Close()
	d := &Driver{cfg: c, root: root, generations: gens, owner: owner}
	if e = d.stage(context.Background(), m, b); e != nil {
		return e
	}
	if unix.Symlinkat("generations/"+storageSlot(initial)+"/tree", int(root.file().Fd()), "active") != nil || root.file().Sync() != nil {
		return ErrTree
	}
	return root.check()
}

// InitialGeneration calculates the expected immutable identity before the
// installer writes a qualified initial bundle. It proves no runtime health.
func InitialGeneration(c Config, b Bundle, base helper.Baseline) (helper.ExecutionGeneration, error) {
	m, e := makeManifest(c, b, base, 0)
	return m.Generation, e
}

// ProjectedGeneration calculates root-owned content identity without accessing
// the filesystem or claiming artifact qualification or runtime health. A trusted
// source must authenticate the complete bundle and installation separately.
// Its content digest is stable before Dispatch assigns an execution sequence;
// that sequence remains bound by the generation manifest and durable slot.
func ProjectedGeneration(c Config, b Bundle, sequence helper.UInt63) (helper.ExecutionGeneration, error) {
	digest, err := LayoutDigest(c)
	if err != nil || digest != c.LayoutDigest || !configmodel.ValidDigest(c.LayoutDigest) || !configmodel.ValidID(c.NodeID) || !configmodel.ValidID(c.SiteID) || sequence == 0 || sequence > 1<<63-1 {
		return helper.ExecutionGeneration{}, ErrInstallation
	}
	return InitialGeneration(c, b, helper.Baseline{RevisionID: b.RevisionID, BundleDigest: b.BundleDigest, NodeDeploymentSequence: sequence})
}

func (d *Driver) Close() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.close()
	return nil
}
func (d *Driver) close() {
	if d == nil || d.closed {
		return
	}
	d.closed = true
	for _, f := range []*os.File{d.lock, d.generations, d.recovery} {
		if f != nil {
			f.Close()
		}
	}
	if d.root != nil {
		d.root.close()
	}
}
func (d *Driver) check() error {
	if d.closed || d.poisoned || d.root.check() != nil {
		return ErrTree
	}
	var st unix.Stat_t
	if unix.Fstatat(int(d.root.file().Fd()), "native.lock", &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !fullSame(d.lockPin, st) {
		return ErrTree
	}
	for _, v := range []struct {
		name string
		f    *os.File
	}{{"generations", d.generations}, {"recovery", d.recovery}} {
		var a, b unix.Stat_t
		if v.f == nil || unix.Fstat(int(v.f.Fd()), &a) != nil || unix.Fstatat(int(d.root.file().Fd()), v.name, &b, unix.AT_SYMLINK_NOFOLLOW) != nil || !same(a, b) || a.Nlink == 0 {
			return ErrTree
		}
		fdMount, fe := mountID(int(v.f.Fd()))
		nameMount, ne := namedMountID(d.root.file(), v.name)
		rootMount, re := mountID(int(d.root.file().Fd()))
		if fe != nil || ne != nil || re != nil || fdMount != nameMount || fdMount != rootMount {
			return ErrTree
		}
	}
	return exactNames(d.root.file(), []string{"active", "generations", "native.lock", "recovery"})
}
func (d *Driver) checkpoint(name string) error {
	if d.fault != nil && d.fault(name) != nil {
		d.poisoned = true
		return ErrTree
	}
	return nil
}
func (d *Driver) with(ctx context.Context, fn func() error) error {
	if d == nil || ctx == nil {
		return ErrTree
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if e := ctx.Err(); e != nil {
		return e
	}
	if d.check() != nil {
		return ErrTree
	}
	return fn()
}
func (d *Driver) Snapshot(ctx context.Context) (out helper.ExecutionGeneration, err error) {
	err = d.with(ctx, func() error {
		m, e := d.active(ctx)
		if e != nil {
			return e
		}
		if e = d.runtime.verify(ctx, m.Generation, m.Probes); e != nil {
			return e
		}
		if _, e = d.load(ctx, m.Generation); e != nil {
			return e
		}
		out = m.Generation
		return d.check()
	})
	return
}
func (d *Driver) Prepare(ctx context.Context, r helper.Request, base helper.ExecutionGeneration) (out helper.ExecutionGeneration, err error) {
	err = d.with(ctx, func() error {
		current, e := d.active(ctx)
		if e != nil {
			return e
		}
		if current.Generation != base {
			return ErrStale
		}
		if e = d.runtime.verify(ctx, base, current.Probes); e != nil {
			return e
		}
		// ExpectedNodeDeploymentSequence belongs to the accepted-task ledger,
		// which may have advanced after recovery of an earlier serving base.
		if r.Task.NodeID != d.cfg.NodeID || r.Task.Preconditions.BaseRevisionID != base.Baseline.RevisionID || r.Task.NodeDeploymentSequence <= base.Baseline.NodeDeploymentSequence || r.Permit.Recovery.BaseRevisionID != base.Baseline.RevisionID || r.Permit.Recovery.BaseBundleDigest != base.Baseline.BundleDigest || r.Task.Payload.RecoveryBaseBundleDigest != base.Baseline.BundleDigest {
			return ErrStale
		}
		b, e := d.repository.load(ctx, r.Task.Payload.BundleDigest)
		if e != nil {
			return e
		}
		targetBase := helper.Baseline{RevisionID: r.Task.Payload.TargetRevisionID, BundleDigest: r.Task.Payload.BundleDigest, NodeDeploymentSequence: r.Task.NodeDeploymentSequence}
		m, e := makeManifest(d.cfg, b, targetBase, d.owner)
		if e != nil || m.Generation.GenerationID != r.Task.Payload.DeploymentGeneration || m.Generation == base {
			return ErrBundle
		}
		// The exact immutable base is rehashed, fsynced and pinned in an exclusive
		// durable record BEFORE any target directory can be created.
		if e = d.syncGeneration(ctx, base); e != nil {
			return e
		}
		record := recoveryRecord{APIVersion: Version, Base: base, Target: m.Generation}
		rb, _ := configmodel.CanonicalJSON(record)
		name := storageSlot(m.Generation) + ".json"
		var old recoveryRecord
		if _, e = canonicalRead(d.recovery, name, maxMetadata, d.owner, &old); e == nil {
			if old != record {
				return ErrStale
			}
		} else {
			var st unix.Stat_t
			if e = unix.Fstatat(int(d.recovery.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(e, unix.ENOENT) {
				return ErrTree
			}
			if e = writeExclusive(d.recovery, name, rb, 0400); e != nil {
				return e
			}
		}
		if e = d.checkpoint("base_durable"); e != nil {
			return e
		}
		if e = d.stage(ctx, m, b); e != nil {
			return e
		}
		if _, e = d.load(ctx, m.Generation); e != nil {
			return e
		}
		out = m.Generation
		return d.check()
	})
	return
}
func (d *Driver) Validate(ctx context.Context, target helper.ExecutionGeneration) error {
	return d.with(ctx, func() error {
		if _, e := d.load(ctx, target); e != nil {
			return e
		}
		if e := d.runtime.validate(ctx, d.treePath(target)); e != nil {
			return e
		}
		_, e := d.load(ctx, target)
		return e
	})
}
func (d *Driver) Activate(ctx context.Context, base, target helper.ExecutionGeneration) error {
	return d.with(ctx, func() error {
		if e := d.recoveryPair(base, target); e != nil {
			return e
		}
		return d.switchActive(ctx, base, target)
	})
}
func (d *Driver) Reload(ctx context.Context, target helper.ExecutionGeneration) error {
	return d.with(ctx, func() error {
		m, e := d.active(ctx)
		if e != nil {
			return e
		}
		if m.Generation != target {
			return ErrStale
		}
		return d.runtime.reload(ctx)
	})
}
func (d *Driver) Verify(ctx context.Context, target helper.ExecutionGeneration) error {
	return d.with(ctx, func() error {
		m, e := d.active(ctx)
		if e != nil {
			return e
		}
		if m.Generation != target {
			return ErrStale
		}
		if e = d.runtime.verify(ctx, target, m.Probes); e != nil {
			return e
		}
		m, e = d.active(ctx)
		if e != nil || m.Generation != target {
			return ErrTree
		}
		return nil
	})
}
func (d *Driver) Recover(ctx context.Context, target, base helper.ExecutionGeneration) error {
	return d.with(ctx, func() error {
		if e := d.recoveryPair(base, target); e != nil {
			return e
		}
		m, e := d.active(ctx)
		if e != nil {
			return e
		}
		if m.Generation != base && m.Generation != target {
			return ErrStale
		}
		if _, e = d.load(ctx, base); e != nil {
			return e
		}
		if e = d.runtime.validate(ctx, d.treePath(base)); e != nil {
			return e
		}
		if m.Generation == target {
			if e = d.switchActive(ctx, target, base); e != nil {
				return e
			}
		}
		if e = d.runtime.reload(ctx); e != nil {
			return e
		}
		bm, e := d.load(ctx, base)
		if e != nil {
			return e
		}
		if e = d.runtime.verify(ctx, base, bm.Probes); e != nil {
			return e
		}
		am, e := d.active(ctx)
		if e != nil || am.Generation != base {
			return ErrTree
		}
		return nil
	})
}
func (d *Driver) recoveryPair(base, target helper.ExecutionGeneration) error {
	var r recoveryRecord
	if _, e := canonicalRead(d.recovery, storageSlot(target)+".json", maxMetadata, d.owner, &r); e != nil || r.APIVersion != Version || r.Base != base || r.Target != target {
		return ErrStale
	}
	return nil
}

// A qualified content marker is immutable and may be deployed repeatedly. Its
// execution sequence selects a distinct durable slot without rewriting bytes.
func storageSlot(g helper.ExecutionGeneration) string {
	digest, _ := configmodel.Digest(struct {
		Marker   string        `json:"marker"`
		Sequence helper.UInt63 `json:"sequence"`
	}{g.GenerationID, g.Baseline.NodeDeploymentSequence})
	return "generation-" + strings.TrimPrefix(digest, "sha256:")
}
func (d *Driver) treePath(g helper.ExecutionGeneration) string {
	return filepath.Join(d.cfg.RootDir, "generations", storageSlot(g), "tree")
}
func (d *Driver) active(ctx context.Context) (generationManifest, error) {
	var zero generationManifest
	var st unix.Stat_t
	if unix.Fstatat(int(d.root.file().Fd()), "active", &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFLNK || st.Uid != d.owner {
		return zero, ErrTree
	}
	b := make([]byte, 256)
	n, e := unix.Readlinkat(int(d.root.file().Fd()), "active", b)
	if e != nil || n == len(b) {
		return zero, ErrTree
	}
	s := string(b[:n])
	parts := strings.Split(s, "/")
	if len(parts) != 3 || parts[0] != "generations" || parts[2] != "tree" || !configmodel.ValidID(parts[1]) {
		return zero, ErrTree
	}
	m, e := d.readManifest(ctx, parts[1])
	if e != nil {
		return zero, e
	}
	if _, e = d.load(ctx, m.Generation); e != nil {
		return zero, e
	}
	var after unix.Stat_t
	if unix.Fstatat(int(d.root.file().Fd()), "active", &after, unix.AT_SYMLINK_NOFOLLOW) != nil || !fullSame(st, after) {
		return zero, ErrTree
	}
	return m, nil
}
func (d *Driver) readManifest(ctx context.Context, id string) (generationManifest, error) {
	var m generationManifest
	if !configmodel.ValidID(id) {
		return m, ErrTree
	}
	if e := ctx.Err(); e != nil {
		return m, e
	}
	g, e := openChild(d.generations, id, true, d.owner)
	if e != nil {
		return m, e
	}
	defer g.Close()
	if exactNames(g, []string{"generation.json", "tree"}) != nil {
		return m, ErrTree
	}
	if _, e = canonicalRead(g, "generation.json", maxMetadata, d.owner, &m); e != nil {
		return m, e
	}
	expected := m.Generation.TreeDigest
	dg, e := generationTreeDigest(m)
	if e != nil || dg != expected || m.APIVersion != Version || !configmodel.ValidID(m.Generation.GenerationID) || m.Generation.Baseline.NodeDeploymentSequence == 0 || storageSlot(m.Generation) != id {
		return m, ErrTree
	}
	return m, nil
}
func (d *Driver) load(ctx context.Context, expected helper.ExecutionGeneration) (generationManifest, error) {
	m, e := d.readManifest(ctx, storageSlot(expected))
	if e != nil {
		return m, e
	}
	if m.Generation != expected {
		return m, ErrStale
	}
	entries := make([]ownedtree.Entry, len(m.Entries))
	for i, e := range m.Entries {
		if e.UID < 0 || e.GID < 0 || uint64(e.UID) > 1<<32-1 || uint64(e.GID) > 1<<32-1 {
			return m, ErrTree
		}
		entries[i] = ownedtree.Entry{Path: e.Path, Kind: e.Kind, UID: uint32(e.UID), GID: uint32(e.GID), Mode: e.Mode, Size: e.Size, Digest: e.Digest}
	}
	manifest := ownedtree.Manifest{APIVersion: ownedtree.Version, NodeID: d.cfg.NodeID, SiteID: d.cfg.SiteID, Root: d.treePath(expected), Entries: entries}
	dg, e := ownedtree.Digest(manifest)
	if e != nil {
		return m, ErrTree
	}
	tree, e := ownedtree.Open(manifest, dg)
	if e != nil {
		return m, ErrTree
	}
	defer tree.Close()
	if _, e = tree.Verify(ctx); e != nil {
		return m, ErrTree
	}
	return m, nil
}
func makeManifest(c Config, b Bundle, base helper.Baseline, owner uint32) (generationManifest, error) {
	m := generationManifest{}
	if validateBundle(b) != nil || b.NodeID != c.NodeID || b.RevisionID != base.RevisionID || b.BundleDigest != base.BundleDigest || b.QualificationDigest != c.QualificationDigest || b.ReleaseManifestDigest != c.ReleaseManifestDigest || base.NodeDeploymentSequence == 0 {
		return m, ErrBundle
	}
	entries := map[string]generationEntry{".": {Path: ".", Kind: "directory", UID: int(owner), GID: int(owner), Mode: "0500"}}
	for _, f := range b.Files {
		for p := filepath.Dir(f.Path); p != "."; p = filepath.Dir(p) {
			if existing, ok := entries[p]; ok && existing.Kind != "directory" {
				return m, ErrBundle
			}
			entries[p] = generationEntry{Path: p, Kind: "directory", UID: int(owner), GID: int(owner), Mode: "0500"}
		}
		if _, ok := entries[f.Path]; ok {
			return m, ErrBundle
		}
		entries[f.Path] = generationEntry{Path: f.Path, Kind: "file", UID: int(owner), GID: int(owner), Mode: "0400", Size: ownedtree.UInt63(len(f.Content)), Digest: f.Digest}
	}
	m = generationManifest{APIVersion: Version, Generation: helper.ExecutionGeneration{Baseline: base, GenerationID: b.GenerationID}, Probes: append([]Probe(nil), b.Probes...)}
	for _, e := range entries {
		m.Entries = append(m.Entries, e)
	}
	sort.Slice(m.Entries, func(i, j int) bool { return m.Entries[i].Path < m.Entries[j].Path })
	dg, e := generationTreeDigest(m)
	if e != nil {
		return m, ErrBundle
	}
	m.Generation.TreeDigest = dg
	return m, nil
}

// TreeDigest commits to exact content, ownership, probes, revision, bundle and
// runtime marker. Sequence is a property of the attempt, not materialized bytes.
// readManifest additionally derives its storage slot from the manifest sequence.
func generationTreeDigest(m generationManifest) (string, error) {
	m.Generation.TreeDigest = ""
	m.Generation.Baseline.NodeDeploymentSequence = 0
	return configmodel.Digest(m)
}
func (d *Driver) stage(ctx context.Context, m generationManifest, b Bundle) error {
	var st unix.Stat_t
	if e := unix.Fstatat(int(d.generations.Fd()), storageSlot(m.Generation), &st, unix.AT_SYMLINK_NOFOLLOW); e == nil {
		_, e = d.load(ctx, m.Generation)
		return e
	} else if !errors.Is(e, unix.ENOENT) {
		return ErrTree
	}
	name, e := randomName(".stage-")
	if e != nil {
		return e
	}
	if unix.Mkdirat(int(d.generations.Fd()), name, 0700) != nil {
		return ErrTree
	}
	stage, e := openChild(d.generations, name, true, d.owner)
	if e != nil {
		return e
	}
	defer stage.Close()
	if unix.Mkdirat(int(stage.Fd()), "tree", 0700) != nil {
		return ErrTree
	}
	root, e := openChild(stage, "tree", true, d.owner)
	if e != nil {
		return e
	}
	defer root.Close()
	dirs := map[string]*os.File{".": root}
	defer func() {
		for p, f := range dirs {
			if p != "." {
				f.Close()
			}
		}
	}()
	for _, entry := range m.Entries {
		if entry.Path == "." || entry.Kind != "directory" {
			continue
		}
		parent := dirs[filepath.Dir(entry.Path)]
		if parent == nil || unix.Mkdirat(int(parent.Fd()), filepath.Base(entry.Path), 0700) != nil {
			return ErrTree
		}
		f, e := openChild(parent, filepath.Base(entry.Path), true, d.owner)
		if e != nil {
			return e
		}
		dirs[entry.Path] = f
	}
	for _, f := range b.Files {
		if e = ctx.Err(); e != nil {
			return e
		}
		if e = writeExclusive(dirs[filepath.Dir(f.Path)], filepath.Base(f.Path), []byte(f.Content), 0400); e != nil {
			return e
		}
	}
	for _, entry := range m.Entries {
		if entry.Kind == "directory" {
			f := dirs[entry.Path]
			if unix.Fchmod(int(f.Fd()), 0500) != nil || f.Sync() != nil {
				return ErrTree
			}
		}
	}
	meta, _ := configmodel.CanonicalJSON(m)
	if e = writeExclusive(stage, "generation.json", meta, 0400); e != nil {
		return e
	}
	if unix.Fchmod(int(stage.Fd()), 0500) != nil || stage.Sync() != nil {
		return ErrTree
	}
	if e = d.checkpoint("target_durable"); e != nil {
		return e
	}
	if unix.Renameat2(int(d.generations.Fd()), name, int(d.generations.Fd()), storageSlot(m.Generation), unix.RENAME_NOREPLACE) != nil {
		return ErrTree
	}
	if e = d.checkpoint("generation_rename"); e != nil {
		return e
	}
	if d.generations.Sync() != nil {
		d.poisoned = true
		return ErrTree
	}
	return nil
}
func (d *Driver) syncGeneration(ctx context.Context, g helper.ExecutionGeneration) error {
	m, e := d.load(ctx, g)
	if e != nil {
		return e
	}
	root, e := openChild(d.generations, storageSlot(g), true, d.owner)
	if e != nil {
		return e
	}
	defer root.Close()
	tree, e := openChild(root, "tree", true, d.owner)
	if e != nil {
		return e
	}
	defer tree.Close()
	for _, entry := range m.Entries {
		if e = ctx.Err(); e != nil {
			return e
		}
		if entry.Path == "." {
			continue
		}
		parts := strings.Split(entry.Path, "/")
		current := tree
		var opened []*os.File
		for i, p := range parts {
			f, oe := openChild(current, p, i < len(parts)-1 || entry.Kind == "directory", d.owner)
			if oe != nil {
				for _, f := range opened {
					f.Close()
				}
				return oe
			}
			opened = append(opened, f)
			current = f
		}
		e = current.Sync()
		for _, f := range opened {
			f.Close()
		}
		if e != nil {
			return ErrTree
		}
	}
	if tree.Sync() != nil || root.Sync() != nil || d.generations.Sync() != nil {
		return ErrTree
	}
	_, e = d.load(ctx, g)
	return e
}
func (d *Driver) switchActive(ctx context.Context, expected, target helper.ExecutionGeneration) error {
	before, e := d.active(ctx)
	if e != nil {
		return e
	}
	if before.Generation != expected {
		return ErrStale
	}
	if _, e = d.load(ctx, target); e != nil {
		return e
	}
	var pin unix.Stat_t
	if unix.Fstatat(int(d.root.file().Fd()), "active", &pin, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return ErrTree
	}
	tmp, e := randomName(".active-")
	if e != nil {
		return e
	}
	if unix.Symlinkat("generations/"+storageSlot(target)+"/tree", int(d.root.file().Fd()), tmp) != nil {
		return ErrTree
	}
	defer unix.Unlinkat(int(d.root.file().Fd()), tmp, 0)
	if e = d.checkpoint("pointer_exchange"); e != nil {
		return e
	}
	var latest unix.Stat_t
	if unix.Fstatat(int(d.root.file().Fd()), "active", &latest, unix.AT_SYMLINK_NOFOLLOW) != nil || !fullSame(pin, latest) {
		return ErrStale
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if unix.Renameat2(int(d.root.file().Fd()), tmp, int(d.root.file().Fd()), "active", unix.RENAME_EXCHANGE) != nil {
		return ErrTree
	}
	var exchanged unix.Stat_t
	// rename changes the symlink ctime. Its inode, owner, type, mode, link
	// count and length must still identify the exact compared pointer.
	if unix.Fstatat(int(d.root.file().Fd()), tmp, &exchanged, unix.AT_SYMLINK_NOFOLLOW) != nil || !same(pin, exchanged) || pin.Nlink != exchanged.Nlink || pin.Size != exchanged.Size {
		d.poisoned = true
		return ErrTree
	}
	if e = d.checkpoint("pointer_durability"); e != nil {
		return e
	}
	if d.root.file().Sync() != nil {
		d.poisoned = true
		return ErrTree
	}
	if unix.Unlinkat(int(d.root.file().Fd()), tmp, 0) != nil || d.root.file().Sync() != nil {
		d.poisoned = true
		return ErrTree
	}
	after, e := d.active(ctx)
	if e != nil || after.Generation != target {
		return fmt.Errorf("%w", ErrTree)
	}
	return nil
}
