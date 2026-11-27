//go:build linux

package ownedtree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"golang.org/x/sys/unix"
)

type pin struct {
	file   *os.File
	name   string
	parent int
	stat   unix.Stat_t
	mount  uint64
}

// Tree pins the complete ancestry and every manifest entry until Close.
// Verify and Close are serialized. A filesystem inconsistency permanently
// poisons this handle; context cancellation alone does not. Reopening requires
// the separately trusted manifest digest again. No active-runtime claim follows.
type Tree struct {
	mu        sync.Mutex
	manifest  Manifest
	binding   Binding
	ancestors []pin
	entries   []pin
	rootIndex int
	children  map[string][]string
	closed    bool
	poisoned  bool
	mount     func(int) (uint64, error)
	// Private test checkpoints never alter the production contract.
	checkpoint func(string)
}

func Open(m Manifest, expectedDigest string) (*Tree, error) { return open(m, expectedDigest, mountID) }

func open(m Manifest, expectedDigest string, mount func(int) (uint64, error)) (*Tree, error) {
	n, err := Normalize(m)
	if err != nil || !configmodel.ValidDigest(expectedDigest) {
		return nil, ErrManifest
	}
	d, err := Digest(*n)
	if err != nil || d != expectedDigest {
		return nil, ErrManifest
	}
	t := &Tree{manifest: *n, binding: Binding{NodeID: n.NodeID, SiteID: n.SiteID, ManifestDigest: d}, mount: mount, children: make(map[string][]string)}
	ok := false
	defer func() {
		if !ok {
			_ = t.Close()
		}
	}()
	t.ancestors, err = openAncestry(n.Root, mount)
	if err != nil {
		return nil, err
	}
	root := t.ancestors[len(t.ancestors)-1]
	root.parent = -1
	t.entries = make([]pin, len(n.Entries))
	for i, e := range n.Entries {
		if e.Path == "." {
			t.rootIndex = i
			t.entries[i] = root
			break
		}
	}
	byPath := map[string]int{".": t.rootIndex}
	for i, e := range n.Entries {
		if e.Path == "." {
			if !matches(e, root.stat) {
				return nil, ErrTree
			}
			continue
		}
		parent := byPath[path.Dir(e.Path)]
		p := &t.entries[parent]
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if e.Kind == "directory" {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(int(p.file.Fd()), path.Base(e.Path), flags, 0)
		if err != nil {
			return nil, ErrTree
		}
		v, err := makePin(fd, path.Base(e.Path), parent, mount)
		if err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
		t.entries[i] = v
		if v.mount != root.mount || !matches(e, v.stat) {
			return nil, ErrTree
		}
		byPath[e.Path] = i
		t.children[path.Dir(e.Path)] = append(t.children[path.Dir(e.Path)], path.Base(e.Path))
	}
	for p := range t.children {
		sort.Strings(t.children[p])
	}
	if err = t.checkAll(); err != nil {
		return nil, err
	}
	ok = true
	return t, nil
}

func (t *Tree) Binding() Binding {
	if t == nil {
		return Binding{}
	}
	// The binding is immutable for the full lifetime, including after Close.
	return t.binding
}

func (t *Tree) Close() error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	var result error
	// The root entry is closed with the ancestry exactly once.
	for i := len(t.entries) - 1; i >= 0; i-- {
		if i != t.rootIndex && t.entries[i].file != nil && t.entries[i].file.Close() != nil {
			result = ErrTree
		}
	}
	for i := len(t.ancestors) - 1; i >= 0; i-- {
		if t.ancestors[i].file.Close() != nil {
			result = ErrTree
		}
	}
	return result
}

func (t *Tree) Verify(ctx context.Context) (observation *Observation, err error) {
	return t.inspect(ctx, nil)
}

func (t *Tree) inspect(ctx context.Context, files map[string][]byte) (observation *Observation, err error) {
	if t == nil || ctx == nil {
		return nil, ErrTree
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, ErrClosed
	}
	if t.poisoned {
		return nil, ErrTree
	}
	defer func() {
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			t.poisoned = true
		}
		if err != nil {
			observation = nil
			for _, data := range files {
				clear(data)
			}
			clear(files)
		}
	}()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = t.checkAll(); err != nil {
		return nil, err
	}
	entries := make([]ObservedEntry, len(t.entries))
	for i, p := range t.entries {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		e := t.manifest.Entries[i]
		if e.Kind == "file" {
			var content bytes.Buffer
			var target io.Writer
			if files != nil {
				content.Grow(int(e.Size))
				target = &content
			}
			if err = t.readFile(ctx, p, e, target); err != nil {
				clear(content.Bytes())
				return nil, err
			}
			if files != nil {
				files[e.Path] = content.Bytes()
			}
		}
		if t.checkpoint != nil {
			t.checkpoint("entry:" + e.Path)
		}
		if err = t.checkEntry(i); err != nil {
			return nil, err
		}
		if uint64(p.stat.Dev) > uint64(securityjournal.MaxUInt63) || p.stat.Ino > uint64(securityjournal.MaxUInt63) || p.mount > uint64(securityjournal.MaxUInt63) || uint64(p.stat.Nlink) > uint64(securityjournal.MaxUInt63) {
			return nil, ErrTree
		}
		entries[i] = ObservedEntry{Entry: e, Device: UInt63(p.stat.Dev), Inode: UInt63(p.stat.Ino), MountID: UInt63(p.mount), Links: UInt63(p.stat.Nlink), ModifiedAt: timestamp(p.stat.Mtim), ChangedAt: timestamp(p.stat.Ctim)}
	}
	if t.checkpoint != nil {
		t.checkpoint("final")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = t.checkAll(); err != nil {
		return nil, err
	}
	treeDigest, err := configmodel.Digest(struct {
		APIVersion string          `json:"apiVersion"`
		Root       string          `json:"root"`
		Entries    []ObservedEntry `json:"entries"`
	}{"agp.owned-tree-digest/v1alpha1", t.manifest.Root, entries})
	if err != nil {
		return nil, ErrTree
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return &Observation{APIVersion: ObservationVersion, Purpose: "filesystem_observation", NoExecution: true, RuntimeValidated: false, NodeID: t.binding.NodeID, SiteID: t.binding.SiteID, ManifestDigest: t.binding.ManifestDigest, TreeDigest: treeDigest, Root: t.manifest.Root, ObservedAt: time.Now().UTC(), Entries: entries}, nil
}

func (t *Tree) hashFile(ctx context.Context, p pin, e Entry) error {
	return t.readFile(ctx, p, e, nil)
}

func (t *Tree) readFile(ctx context.Context, p pin, e Entry, target io.Writer) error {
	if _, err := p.file.Seek(0, io.SeekStart); err != nil {
		return ErrTree
	}
	h := sha256.New()
	buf := make([]byte, 32<<10)
	defer clear(buf)
	var total uint64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := p.file.Read(buf)
		if n > 0 {
			total += uint64(n)
			if total > uint64(e.Size) || total > MaxFileBytes {
				return ErrTree
			}
			_, _ = h.Write(buf[:n])
			if target != nil {
				if written, writeErr := target.Write(buf[:n]); writeErr != nil || written != n {
					return ErrTree
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return ErrTree
		}
		if n == 0 {
			return ErrTree
		}
	}
	if total != uint64(e.Size) || "sha256:"+hex.EncodeToString(h.Sum(nil)) != e.Digest {
		return ErrTree
	}
	return nil
}

func (t *Tree) checkAll() error {
	if err := checkAncestry(t.ancestors, t.mount); err != nil {
		return err
	}
	for i := range t.entries {
		if err := t.checkEntry(i); err != nil {
			return err
		}
		if t.manifest.Entries[i].Kind == "directory" {
			if err := directoryNames(t.entries[i].file, t.children[t.manifest.Entries[i].Path]); err != nil {
				return err
			}
			// Enumeration itself is bracketed by the full metadata comparison.
			if err := t.checkEntry(i); err != nil {
				return err
			}
		}
	}
	return checkAncestry(t.ancestors, t.mount)
}

func (t *Tree) checkEntry(i int) error {
	p := t.entries[i]
	var st unix.Stat_t
	if unix.Fstat(int(p.file.Fd()), &st) != nil || !sameFull(p.stat, st) {
		return ErrTree
	}
	m, err := t.mount(int(p.file.Fd()))
	if err != nil {
		return err
	}
	if m != p.mount {
		return ErrTree
	}
	if i == t.rootIndex {
		last := len(t.ancestors) - 1
		if last > 0 {
			return checkName(t.ancestors[last-1], p, true)
		}
		return ErrTree
	}
	return checkName(t.entries[p.parent], p, true)
}

func matches(e Entry, st unix.Stat_t) bool {
	mode, err := entryMode(e.Mode)
	if err != nil || st.Uid != e.UID || st.Gid != e.GID || !trustedUID(st.Uid) || st.Mode&07777 != mode {
		return false
	}
	if e.Kind == "directory" {
		return st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Nlink > 0
	}
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Nlink == 1 && st.Size >= 0 && UInt63(st.Size) == e.Size
}

func directoryNames(f *os.File, want []string) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return ErrTree
	}
	names, err := f.Readdirnames(len(want) + 1)
	if err != nil && err != io.EOF {
		return ErrTree
	}
	if len(names) != len(want) {
		return ErrTree
	}
	sort.Strings(names)
	for i := range names {
		if names[i] != want[i] {
			return ErrTree
		}
	}
	return nil
}

func makePin(fd int, name string, parent int, mount func(int) (uint64, error)) (pin, error) {
	p := pin{name: name, parent: parent}
	if unix.Fstat(fd, &p.stat) != nil {
		return pin{}, ErrTree
	}
	m, err := mount(fd)
	if err != nil {
		return pin{}, err
	}
	p.mount = m
	p.file = os.NewFile(uintptr(fd), "owned-tree")
	return p, nil
}

func mountID(fd int) (uint64, error) {
	var st unix.Statx_t
	if unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &st) != nil || st.Mask&unix.STATX_MNT_ID == 0 || st.Mnt_id == 0 {
		return 0, ErrUnsupported
	}
	return st.Mnt_id, nil
}

func openAncestry(dir string, mount func(int) (uint64, error)) (pins []pin, err error) {
	defer func() {
		if err != nil {
			for i := len(pins) - 1; i >= 0; i-- {
				_ = pins[i].file.Close()
			}
			pins = nil
		}
	}()
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrTree
	}
	p, e := makePin(fd, "", -1, mount)
	if e != nil {
		_ = unix.Close(fd)
		return nil, e
	}
	pins = append(pins, p)
	parts := strings.Split(strings.TrimPrefix(dir, "/"), "/")
	current := "/"
	privateChild := false
	for i := 0; i <= len(parts); i++ {
		p := &pins[len(pins)-1]
		if p.stat.Mode&unix.S_IFMT != unix.S_IFDIR || !trustedUID(p.stat.Uid) {
			return pins, ErrTree
		}
		if privateChild && (p.stat.Uid != uint32(os.Geteuid()) || p.stat.Mode != unix.S_IFDIR|0700) {
			return pins, ErrTree
		}
		privateChild = false
		if p.stat.Mode&07000 != 0 || p.stat.Mode&0022 != 0 {
			if current != "/tmp" || p.stat.Uid != 0 || p.stat.Mode&unix.S_ISVTX == 0 || p.stat.Mode&(unix.S_ISUID|unix.S_ISGID) != 0 || i == len(parts) {
				return pins, ErrTree
			}
			privateChild = true
		}
		if i == len(parts) {
			break
		}
		fd, e := unix.Openat(int(p.file.Fd()), parts[i], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if e != nil {
			return pins, ErrTree
		}
		next, e := makePin(fd, parts[i], len(pins)-1, mount)
		if e != nil {
			_ = unix.Close(fd)
			return pins, e
		}
		pins = append(pins, next)
		current = path.Join(current, parts[i])
	}
	if err = checkAncestry(pins, mount); err != nil {
		return pins, err
	}
	return pins, nil
}

func trustedUID(uid uint32) bool { return uid == 0 || uid == uint32(os.Geteuid()) }
func sameStructural(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode
}
func sameFull(a, b unix.Stat_t) bool {
	return sameStructural(a, b) && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func checkAncestry(pins []pin, mount func(int) (uint64, error)) error {
	for i, p := range pins {
		var st unix.Stat_t
		if unix.Fstat(int(p.file.Fd()), &st) != nil || !sameStructural(p.stat, st) {
			return ErrTree
		}
		m, err := mount(int(p.file.Fd()))
		if err != nil {
			return err
		}
		if m != p.mount {
			return ErrTree
		}
		if i > 0 {
			if err := checkName(pins[i-1], p, false); err != nil {
				return err
			}
		}
	}
	return nil
}
func checkName(parent, child pin, full bool) error {
	var st unix.Stat_t
	if unix.Fstatat(int(parent.file.Fd()), child.name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return ErrTree
	}
	if full && !sameFull(child.stat, st) || !full && !sameStructural(child.stat, st) {
		return ErrTree
	}
	var sx unix.Statx_t
	if unix.Statx(int(parent.file.Fd()), child.name, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT, unix.STATX_MNT_ID, &sx) != nil || sx.Mask&unix.STATX_MNT_ID == 0 || sx.Mnt_id == 0 {
		return ErrUnsupported
	}
	if sx.Mnt_id != child.mount {
		return ErrTree
	}
	return nil
}
func timestamp(v unix.Timespec) string {
	return time.Unix(v.Sec, v.Nsec).UTC().Format(time.RFC3339Nano)
}
