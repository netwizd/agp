//go:build linux

package ownedtree

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"golang.org/x/sys/unix"
)

type fixture struct {
	base, root string
	m          Manifest
	digest     string
}

func treeFixture(t *testing.T) fixture {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "agp-ownedtree-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "version-initial")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "conf.d"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "conf.d"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nginx.conf"), []byte("http {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "conf.d", "site.conf"), []byte("server {}\n"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "conf.d", "site.conf"), 0640); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	m := Manifest{APIVersion: Version, NodeID: "node-1", SiteID: "site-1", Root: root, Entries: []Entry{
		{Path: ".", Kind: "directory", UID: uid, GID: gid, Mode: "0700"},
		{Path: "conf.d", Kind: "directory", UID: uid, GID: gid, Mode: "0750"},
		{Path: "conf.d/site.conf", Kind: "file", UID: uid, GID: gid, Mode: "0640", Size: 10, Digest: configmodel.DigestBytes([]byte("server {}\n"))},
		{Path: "nginx.conf", Kind: "file", UID: uid, GID: gid, Mode: "0600", Size: 8, Digest: configmodel.DigestBytes([]byte("http {}\n"))},
	}}
	d, err := Digest(m)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{base, root, m, d}
}
func mustOpen(t *testing.T, f fixture) *Tree {
	t.Helper()
	tr, err := Open(f.m, f.digest)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}
func mustReject(t *testing.T, tr *Tree) {
	t.Helper()
	o, err := tr.Verify(context.Background())
	if err == nil || o != nil {
		t.Fatal("drift accepted")
	}
	tr.checkpoint = nil
	if o, err = tr.Verify(context.Background()); err == nil || o != nil {
		t.Fatal("poisoned handle accepted")
	}
}

func TestOwnedTreeObservationAndDetachedMetadata(t *testing.T) {
	f := treeFixture(t)
	tr := mustOpen(t, f)
	f.m.Entries[0].Mode = "0777"
	f.m.Root = "/other"
	f.m.NodeID = "wrong"
	o, err := tr.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if o.APIVersion != ObservationVersion || o.Purpose != "filesystem_observation" || !o.NoExecution || o.RuntimeValidated || o.NodeID != "node-1" || o.Root != f.root || o.ManifestDigest != f.digest || len(o.Entries) != 4 || !configmodel.ValidDigest(o.TreeDigest) || o.ObservedAt.Location() != time.UTC {
		t.Fatal("bad observation")
	}
	firstDigest := o.TreeDigest
	o.Entries[0].Mode = "0777"
	o.NodeID = "changed"
	o, err = tr.Verify(context.Background())
	if err != nil || o.TreeDigest != firstDigest || o.NodeID != "node-1" || o.Entries[0].Mode != "0700" {
		t.Fatal("observation aliased internal state")
	}
	bind := tr.Binding()
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	if tr.Binding() != bind {
		t.Fatal("close changed binding")
	}
	if o, err = tr.Verify(context.Background()); !errors.Is(err, ErrClosed) || o != nil {
		t.Fatal("closed accepted")
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOwnedTreeOpenRejectsUnsafeFilesAndManifestMismatch(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "directory", "group-write", "executable", "uid", "gid", "size", "hash", "hidden-extra", "missing", "root-mode", "parent-mode", "parent-symlink", "digest"} {
		t.Run(kind, func(t *testing.T) {
			f := treeFixture(t)
			target := filepath.Join(f.root, "nginx.conf")
			switch kind {
			case "symlink":
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(f.root, "conf.d/site.conf"), target); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(target, filepath.Join(f.base, "second")); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(target, 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				_ = os.Remove(target)
				if err := os.Mkdir(target, 0600); err != nil {
					t.Fatal(err)
				}
			case "group-write":
				if err := os.Chmod(target, 0620); err != nil {
					t.Fatal(err)
				}
			case "executable":
				if err := os.Chmod(target, 0700); err != nil {
					t.Fatal(err)
				}
			case "uid":
				f.m.Entries[3].UID++
			case "gid":
				f.m.Entries[3].GID++
			case "size":
				f.m.Entries[3].Size++
			case "hash":
				f.m.Entries[3].Digest = configmodel.DigestBytes([]byte("other"))
			case "hidden-extra":
				if err := os.WriteFile(filepath.Join(f.root, ".extra"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				}
			case "root-mode":
				if err := os.Chmod(f.root, 0770); err != nil {
					t.Fatal(err)
				}
			case "parent-mode":
				if err := os.Chmod(f.base, 0770); err != nil {
					t.Fatal(err)
				}
			case "parent-symlink":
				renamed := f.base + "-renamed"
				if err := os.Rename(f.base, renamed); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Remove(f.base); _ = os.Rename(renamed, f.base) })
				if err := os.Symlink(renamed, f.base); err != nil {
					t.Fatal(err)
				}
			case "digest":
				f.digest = configmodel.DigestBytes([]byte("wrong"))
			}
			if kind != "digest" {
				f.digest, _ = Digest(f.m)
			}
			tr, err := Open(f.m, f.digest)
			if err == nil {
				defer tr.Close()
				if kind != "hash" {
					t.Fatal("unsafe open accepted")
				}
				if o, e := tr.Verify(context.Background()); e == nil || o != nil {
					t.Fatal("wrong content accepted")
				}
			}
		})
	}
}

func TestOwnedTreeDetectsPinnedTreeDrift(t *testing.T) {
	for _, kind := range []string{"same-size-write", "identical-replacement", "remove", "addition", "hidden-addition", "directory-replacement", "root-replacement", "parent-replacement", "hardlink", "permissions"} {
		t.Run(kind, func(t *testing.T) {
			f := treeFixture(t)
			tr := mustOpen(t, f)
			fired := false
			tr.checkpoint = func(step string) {
				if fired || step != "final" {
					return
				}
				fired = true
				target := filepath.Join(f.root, "nginx.conf")
				switch kind {
				case "same-size-write":
					if err := os.WriteFile(target, []byte("http{ }\n"), 0600); err != nil {
						t.Fatal(err)
					}
				case "identical-replacement":
					if err := os.Rename(target, target+".old"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(target, []byte("http {}\n"), 0600); err != nil {
						t.Fatal(err)
					}
					_ = os.Remove(target + ".old")
				case "remove":
					if err := os.Remove(target); err != nil {
						t.Fatal(err)
					}
				case "addition", "hidden-addition":
					name := "extra"
					if kind == "hidden-addition" {
						name = ".extra"
					}
					if err := os.WriteFile(filepath.Join(f.root, name), nil, 0600); err != nil {
						t.Fatal(err)
					}
				case "directory-replacement":
					dir := filepath.Join(f.root, "conf.d")
					if err := os.Rename(dir, dir+".old"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(dir, 0750); err != nil {
						t.Fatal(err)
					}
				case "root-replacement":
					if err := os.Rename(f.root, f.root+".old"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(f.root, 0700); err != nil {
						t.Fatal(err)
					}
				case "parent-replacement":
					old := f.base + "-old"
					if err := os.Rename(f.base, old); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(f.base, 0700); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = os.RemoveAll(f.base); _ = os.Rename(old, f.base) })
				case "hardlink":
					if err := os.Link(target, filepath.Join(f.base, "hardlink")); err != nil {
						t.Fatal(err)
					}
				case "permissions":
					if err := os.Chmod(target, 0644); err != nil {
						t.Fatal(err)
					}
				}
			}
			mustReject(t, tr)
			if !fired {
				t.Fatal("checkpoint not reached")
			}
		})
	}
}

func TestOwnedTreeMountIdentityProof(t *testing.T) {
	f := treeFixture(t)
	// Deterministic statx fault injection checks fail-closed behavior. This is
	// not a privileged real bind-mount or mount-namespace qualification.
	if tr, err := open(f.m, f.digest, func(int) (uint64, error) { return 0, ErrUnsupported }); !errors.Is(err, ErrUnsupported) || tr != nil {
		t.Fatal("unsupported mount proof accepted")
	}
	// The device and inode remain real and unchanged; only the mounted view's
	// identity differs, as with a same-device bind mount inside the owned root.
	if tr, err := open(f.m, f.digest, func(fd int) (uint64, error) {
		m, err := mountID(fd)
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil {
			return 0, ErrTree
		}
		if st.Mode&unix.S_IFMT == unix.S_IFREG {
			m++
		}
		return m, err
	}); err == nil || tr != nil {
		if tr != nil {
			_ = tr.Close()
		}
		t.Fatal("inside-root cross mount accepted")
	}
	tr := mustOpen(t, f)
	real := tr.mount
	fileFD := int(tr.entries[3].file.Fd())
	tr.mount = func(fd int) (uint64, error) {
		m, e := real(fd)
		if fd == fileFD {
			m++
		}
		return m, e
	}
	mustReject(t, tr)
}

func TestOwnedTreeRootCanSortAfterEntry(t *testing.T) {
	f := treeFixture(t)
	if err := os.WriteFile(filepath.Join(f.root, "!first"), nil, 0400); err != nil {
		t.Fatal(err)
	}
	f.m.Entries = append(f.m.Entries, Entry{Path: "!first", Kind: "file", UID: uint32(os.Geteuid()), GID: uint32(os.Getegid()), Mode: "0400", Digest: configmodel.DigestBytes(nil)})
	f.digest, _ = Digest(f.m)
	tr := mustOpen(t, f)
	o, err := tr.Verify(context.Background())
	if err != nil || o.Entries[0].Path != "!first" || o.Entries[1].Path != "." {
		t.Fatal("lexicographic root placement failed", err)
	}
}

func TestOwnedTreeCancellationAndConcurrentClose(t *testing.T) {
	f := treeFixture(t)
	tr := mustOpen(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if o, err := tr.Verify(ctx); !errors.Is(err, context.Canceled) || o != nil {
		t.Fatal("cancellation accepted")
	}
	if _, err := tr.Verify(context.Background()); err != nil {
		t.Fatal("cancellation poisoned handle")
	}
	fired := false
	ctx, cancel = context.WithCancel(context.Background())
	tr.checkpoint = func(string) {
		if !fired {
			fired = true
			cancel()
		}
	}
	if o, err := tr.Verify(ctx); !errors.Is(err, context.Canceled) || o != nil {
		t.Fatal("mid-scan cancellation accepted")
	}
	tr.checkpoint = nil
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o, e := tr.Verify(context.Background())
			if e == nil && o == nil {
				t.Error("nil success")
			}
			if e != nil && !errors.Is(e, ErrClosed) {
				t.Errorf("unexpected: %v", e)
			}
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); _ = tr.Close() }()
	wg.Wait()
}

func TestOwnedTreeProtectedManifestLoader(t *testing.T) {
	for _, kind := range []string{"valid", "symlink", "hardlink", "fifo", "writable", "executable", "oversized", "wrong-digest"} {
		t.Run(kind, func(t *testing.T) {
			f := treeFixture(t)
			manifestPath := filepath.Join(f.base, "owned.json")
			raw, _ := json.Marshal(f.m)
			if err := os.WriteFile(manifestPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				_ = os.Rename(manifestPath, manifestPath+".real")
				if err := os.Symlink(manifestPath+".real", manifestPath); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(manifestPath, manifestPath+".link"); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				_ = os.Remove(manifestPath)
				if err := unix.Mkfifo(manifestPath, 0600); err != nil {
					t.Fatal(err)
				}
			case "writable":
				_ = os.Chmod(manifestPath, 0620)
			case "executable":
				_ = os.Chmod(manifestPath, 0700)
			case "oversized":
				if err := os.WriteFile(manifestPath, []byte(strings.Repeat("x", MaxManifestBytes+1)), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-digest":
				f.digest = configmodel.DigestBytes(nil)
			}
			tr, err := Load(manifestPath, f.digest)
			if kind == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				defer tr.Close()
				if _, err = tr.Verify(context.Background()); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || tr != nil {
				if tr != nil {
					_ = tr.Close()
				}
				t.Fatal("unsafe manifest accepted")
			}
		})
	}
}
