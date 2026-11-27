//go:build linux

package nativesandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

type entry struct {
	name   string
	mode   uint32
	stat   unix.Stat_t
	digest string
	file   *os.File
}
type snapshot struct {
	root    *os.File
	pin     unix.Stat_t
	entries []entry
	source  string
	total   int64
	max     int64
	config  bool
}

func (s *snapshot) close() {
	if s == nil {
		return
	}
	if s.root != nil {
		s.root.Close()
	}
	for _, e := range s.entries {
		if e.file != nil {
			e.file.Close()
		}
	}
}
func openTree(name string) (*os.File, unix.Stat_t, error) {
	var z unix.Stat_t
	if !filepath.IsAbs(name) || filepath.Clean(name) != name || name == "/" || strings.ContainsAny(name, "\x00\r\n") {
		return nil, z, ErrInput
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, z, ErrInput
	}
	for _, p := range strings.Split(strings.TrimPrefix(name, "/"), "/") {
		next, e := unix.Openat(fd, p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return nil, z, ErrInput
		}
		fd = next
	}
	var st unix.Stat_t
	f := os.NewFile(uintptr(fd), "sandbox-source")
	if unix.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&07777 != 0700 && st.Mode&07777 != 0500 {
		f.Close()
		return nil, z, ErrInput
	}
	return f, st, nil
}
func capture(ctx context.Context, name string, config bool) (*snapshot, error) {
	root, pin, e := openTree(name)
	if e != nil {
		return nil, e
	}
	s := &snapshot{root: root, pin: pin, source: name, max: 256 << 20, config: config}
	if config {
		s.max = 64 << 20
	}
	if e = s.walk(ctx, root, "", 0, true); e != nil {
		s.close()
		return nil, e
	}
	return s, nil
}
func (s *snapshot) walk(ctx context.Context, dir *os.File, prefix string, depth int, seal bool) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if depth > 32 {
		return ErrInput
	}
	// Open a separate directory description: ReadDir offsets must not affect the
	// pinned root or the later verification pass.
	fd, e := unix.Openat(int(dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return ErrInput
	}
	listing := os.NewFile(uintptr(fd), "sandbox-list")
	remaining := 4096 - len(s.entries)
	names, e := listing.Readdirnames(remaining + 1)
	listing.Close()
	if e != nil && e != io.EOF || len(names) > remaining {
		return ErrInput
	}
	sort.Strings(names)
	for _, name := range names {
		if e = ctx.Err(); e != nil {
			return e
		}
		if name == "." || name == ".." || strings.ContainsAny(name, "\x00\r\n") || len(name) > 255 {
			return ErrInput
		}
		rel := path.Join(prefix, name)
		fd, e = unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if e != nil {
			return ErrInput
		}
		f := os.NewFile(uintptr(fd), "sandbox-input")
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
			f.Close()
			return ErrInput
		}
		if len(s.entries) >= 4096 {
			f.Close()
			return ErrInput
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			if st.Mode&07777 != 0700 && st.Mode&07777 != 0500 {
				f.Close()
				return ErrInput
			}
			s.entries = append(s.entries, entry{name: rel, mode: st.Mode, stat: st})
			e = s.walk(ctx, f, rel, depth+1, seal)
			f.Close()
			if e != nil {
				return e
			}
		case unix.S_IFREG:
			if st.Nlink != 1 || st.Mode&07777 != 0400 && st.Mode&07777 != 0500 || st.Size < 0 || st.Size > s.max || s.config && st.Size > 4<<20 {
				f.Close()
				return ErrInput
			}
			s.total += st.Size
			if s.total > s.max {
				f.Close()
				return ErrInput
			}
			h := sha256.New()
			var mem *os.File
			var w io.Writer = h
			if seal {
				m, e := unix.MemfdCreate("agp-syntax-input", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
				if e != nil {
					f.Close()
					return ErrUnavailable
				}
				mem = os.NewFile(uintptr(m), "sandbox-sealed-input")
				w = io.MultiWriter(h, mem)
			}
			n, err := io.Copy(w, &contextReader{ctx: ctx, r: io.LimitReader(f, st.Size+1)})
			var after unix.Stat_t
			ok := err == nil && n == st.Size && unix.Fstat(fd, &after) == nil && sameStat(st, after)
			f.Close()
			if !ok {
				if mem != nil {
					mem.Close()
				}
				return ErrInput
			}
			if mem != nil {
				if unix.Fchmod(int(mem.Fd()), st.Mode&0777) != nil {
					mem.Close()
					return ErrInput
				}
				_, err = unix.FcntlInt(mem.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL)
				if err != nil {
					mem.Close()
					return ErrUnavailable
				}
				if _, err = mem.Seek(0, 0); err != nil {
					mem.Close()
					return ErrInput
				}
			}
			s.entries = append(s.entries, entry{rel, st.Mode, st, hex.EncodeToString(h.Sum(nil)), mem})
		default:
			f.Close()
			return ErrInput
		}
	}
	return nil
}
func (s *snapshot) verify(ctx context.Context) error {
	f, p, e := openTree(s.source)
	if e != nil {
		return e
	}
	defer f.Close()
	if !sameStat(s.pin, p) {
		return ErrInput
	}
	q := &snapshot{root: f, max: s.max, config: s.config}
	if e = q.walk(ctx, f, "", 0, false); e != nil {
		return e
	}
	if len(q.entries) != len(s.entries) {
		return ErrInput
	}
	for i, a := range s.entries {
		b := q.entries[i]
		if a.name != b.name || a.digest != b.digest || !sameStat(a.stat, b.stat) {
			return ErrInput
		}
	}
	return nil
}

// Files are regular staged inputs; cancellation is checked between every bounded
// read rather than only between files. No live network/FUSE path is accepted by
// the installation adapter, which stages verified bytes in its private tree.
type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.r.Read(p)
}
