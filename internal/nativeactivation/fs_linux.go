//go:build linux

package nativeactivation

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/netwizd/agp/internal/configmodel"
	"golang.org/x/sys/unix"
)

type anchor struct {
	f     *os.File
	name  string
	st    unix.Stat_t
	mount uint64
}
type protectedDir struct {
	pins  []anchor
	owner uint32
}

func mountID(fd int) (uint64, error) {
	var s unix.Statx_t
	if unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &s) != nil || s.Mask&unix.STATX_MNT_ID == 0 || s.Mnt_id == 0 {
		return 0, ErrInstallation
	}
	return s.Mnt_id, nil
}
func namedMountID(dir *os.File, name string) (uint64, error) {
	var s unix.Statx_t
	if unix.Statx(int(dir.Fd()), name, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &s) != nil || s.Mask&unix.STATX_MNT_ID == 0 || s.Mnt_id == 0 {
		return 0, ErrTree
	}
	return s.Mnt_id, nil
}
func same(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid
}
func fullSame(a, b unix.Stat_t) bool {
	return same(a, b) && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

// Every ancestor stays pinned. The only writable-ancestor exception is the
// kernel's root-owned sticky /tmp followed immediately by a private child.
func openDir(path string, owner uint32) (_ *protectedDir, err error) {
	return openDirPolicy(path, owner, true)
}
func openDirPolicy(path string, owner uint32, requirePrivate bool) (_ *protectedDir, err error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsAny(path, "\x00\r\n") {
		return nil, ErrInstallation
	}
	d := &protectedDir{owner: owner}
	defer func() {
		if err != nil {
			d.close()
		}
	}()
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrInstallation
	}
	d.pins = append(d.pins, anchor{f: os.NewFile(uintptr(fd), "/")})
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	current := "/"
	private := false
	for i := 0; i <= len(parts); i++ {
		p := &d.pins[len(d.pins)-1]
		if unix.Fstat(int(p.f.Fd()), &p.st) != nil || p.st.Mode&unix.S_IFMT != unix.S_IFDIR || (p.st.Uid != 0 && p.st.Uid != owner) {
			return nil, ErrInstallation
		}
		p.mount, e = mountID(int(p.f.Fd()))
		if e != nil {
			return nil, e
		}
		if private && (p.st.Uid != owner || p.st.Mode != unix.S_IFDIR|0700) {
			return nil, ErrInstallation
		}
		private = false
		if p.st.Mode&0022 != 0 || p.st.Mode&07000 != 0 {
			if current != "/tmp" || p.st.Uid != 0 || p.st.Mode&unix.S_ISVTX == 0 || p.st.Mode&(unix.S_ISUID|unix.S_ISGID) != 0 || i == len(parts) {
				return nil, ErrInstallation
			}
			private = true
		}
		if i == len(parts) {
			if p.st.Uid != owner || (requirePrivate && p.st.Mode&07777 != 0700) {
				return nil, ErrInstallation
			}
			break
		}
		next, e := unix.Openat(int(p.f.Fd()), parts[i], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, ErrInstallation
		}
		d.pins = append(d.pins, anchor{f: os.NewFile(uintptr(next), parts[i]), name: parts[i]})
		current = filepath.Join(current, parts[i])
	}
	return d, d.check()
}
func (d *protectedDir) file() *os.File { return d.pins[len(d.pins)-1].f }
func (d *protectedDir) close() {
	if d == nil {
		return
	}
	for i := len(d.pins) - 1; i >= 0; i-- {
		d.pins[i].f.Close()
	}
	d.pins = nil
}
func (d *protectedDir) check() error {
	for i, p := range d.pins {
		var s unix.Stat_t
		if unix.Fstat(int(p.f.Fd()), &s) != nil || !same(p.st, s) || s.Nlink == 0 {
			return ErrTree
		}
		m, e := mountID(int(p.f.Fd()))
		if e != nil || m != p.mount {
			return ErrTree
		}
		if i > 0 {
			if unix.Fstatat(int(d.pins[i-1].f.Fd()), p.name, &s, unix.AT_SYMLINK_NOFOLLOW) != nil || !same(p.st, s) {
				return ErrTree
			}
			named, e := namedMountID(d.pins[i-1].f, p.name)
			if e != nil || named != p.mount {
				return ErrTree
			}
		}
	}
	return nil
}
func openChild(dir *os.File, name string, directory bool, owner uint32) (*os.File, error) {
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, e := unix.Openat(int(dir.Fd()), name, flags, 0)
	if e != nil {
		return nil, ErrTree
	}
	f := os.NewFile(uintptr(fd), name)
	var st, ps unix.Stat_t
	m, me := mountID(fd)
	pm, pe := mountID(int(dir.Fd()))
	if unix.Fstat(fd, &st) != nil || unix.Fstat(int(dir.Fd()), &ps) != nil || st.Uid != owner || st.Dev != ps.Dev || me != nil || pe != nil || m != pm || st.Mode&0022 != 0 || st.Mode&07000 != 0 || (!directory && (st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1)) || (directory && st.Mode&unix.S_IFMT != unix.S_IFDIR) {
		f.Close()
		return nil, ErrTree
	}
	return f, nil
}
func readFile(dir *os.File, name string, max int, owner uint32) ([]byte, error) {
	f, e := openChild(dir, name, false, owner)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var before, after, named unix.Stat_t
	if unix.Fstat(int(f.Fd()), &before) != nil || before.Size < 1 || before.Size > int64(max) {
		return nil, ErrTree
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if e != nil || int64(len(b)) != before.Size || unix.Fstat(int(f.Fd()), &after) != nil || !fullSame(before, after) || unix.Fstatat(int(dir.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !fullSame(before, named) {
		return nil, ErrTree
	}
	fdMount, fe := mountID(int(f.Fd()))
	nameMount, ne := namedMountID(dir, name)
	if fe != nil || ne != nil || fdMount != nameMount {
		return nil, ErrTree
	}
	return b, nil
}
func names(dir *os.File, max int) ([]string, error) {
	fd, e := unix.Openat(int(dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrTree
	}
	f := os.NewFile(uintptr(fd), ".")
	defer f.Close()
	n, e := f.Readdirnames(max + 1)
	if (e != nil && e != io.EOF) || len(n) > max {
		return nil, ErrTree
	}
	sort.Strings(n)
	return n, nil
}
func exactNames(dir *os.File, want []string) error {
	n, e := names(dir, len(want))
	if e != nil || len(n) != len(want) {
		return ErrTree
	}
	want = append([]string(nil), want...)
	sort.Strings(want)
	for i := range n {
		if n[i] != want[i] {
			return ErrTree
		}
	}
	return nil
}
func canonicalRead(dir *os.File, name string, max int, owner uint32, out any) ([]byte, error) {
	b, e := readFile(dir, name, max, owner)
	if e != nil {
		return nil, e
	}
	if configmodel.StrictJSON(bytes.NewReader(b), out, max) != nil {
		return nil, ErrTree
	}
	c, e := configmodel.CanonicalJSON(out)
	if e != nil || !bytes.Equal(c, b) {
		return nil, ErrTree
	}
	return b, nil
}
func randomName(prefix string) (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", ErrTree
	}
	return prefix + hex.EncodeToString(b[:]), nil
}
func writeExclusive(dir *os.File, name string, b []byte, mode uint32) error {
	fd, e := unix.Openat(int(dir.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return ErrTree
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	if n, e := f.Write(b); e != nil || n != len(b) {
		return ErrTree
	}
	if unix.Fchmod(fd, mode) != nil || f.Sync() != nil || dir.Sync() != nil {
		return ErrTree
	}
	return nil
}
