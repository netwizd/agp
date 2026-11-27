//go:build linux

package nativesandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type Runner struct {
	tool                       Tool
	pin                        unix.Stat_t
	callerUID                  uint32
	executionUID, executionGID uint32
	rootBridge                 bool
}

func New(t Tool) (*Runner, error) {
	r, e := newRunner(t)
	if e != nil {
		return nil, e
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if uid == 0 || gid == 0 || uid == ^uint32(0) || gid == ^uint32(0) || os.Getuid() != os.Geteuid() {
		return nil, ErrUnavailable
	}
	r.callerUID = uid
	r.executionUID = uid
	r.executionGID = gid
	return r, nil
}

// NewAsUser is the explicit root-supervisor bridge. Only a real/effective root
// caller may capture root-owned private trees; the sandbox child always drops
// to the chosen nonroot UID/GID with all supplementary groups removed.
func NewAsUser(t Tool, uid, gid uint32) (*Runner, error) {
	if os.Geteuid() != 0 || os.Getuid() != 0 || uid == 0 || gid == 0 || uid == ^uint32(0) || gid == ^uint32(0) {
		return nil, ErrUnavailable
	}
	r, e := newRunner(t)
	if e != nil {
		return nil, e
	}
	r.callerUID = 0
	r.executionUID = uid
	r.executionGID = gid
	r.rootBridge = true
	return r, nil
}

func newRunner(t Tool) (*Runner, error) {
	if len(t.Digest) != 71 || !strings.HasPrefix(t.Digest, "sha256:") {
		return nil, ErrTool
	}
	b, e := hex.DecodeString(t.Digest[7:])
	if e != nil || len(b) != 32 || hex.EncodeToString(b) != t.Digest[7:] {
		return nil, ErrTool
	}
	f, p, e := openTool(t)
	if e != nil {
		return nil, e
	}
	_ = f.Close()
	return &Runner{tool: t, pin: p}, nil
}
func (r *Runner) Binding() Binding {
	if r == nil {
		return Binding{}
	}
	return Binding{ToolDigest: r.tool.Digest, ProfileDigest: ExecutionProfileDigest(r.executionUID, r.executionGID), ExecutionUID: r.executionUID, ExecutionGID: r.executionGID}
}

func openTool(t Tool) (*os.File, unix.Stat_t, error) {
	var zero unix.Stat_t
	if !filepath.IsAbs(t.Path) || filepath.Clean(t.Path) != t.Path || strings.ContainsAny(t.Path, "\x00\n\r") {
		return nil, zero, ErrTool
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, zero, ErrTool
	}
	parts := strings.Split(strings.TrimPrefix(t.Path, "/"), "/")
	for i, part := range parts {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&0022 != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR {
			unix.Close(fd)
			return nil, zero, ErrTool
		}
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(fd, part, flags, 0)
		unix.Close(fd)
		if err != nil {
			return nil, zero, ErrTool
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), "sandbox-tool")
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode != unix.S_IFREG|0755 || st.Nlink != 1 || st.Size <= 0 || st.Size > 32<<20 {
		f.Close()
		return nil, zero, ErrTool
	}
	if _, e := unix.Fgetxattr(fd, "security.capability", nil); e != unix.ENODATA && e != unix.EOPNOTSUPP {
		f.Close()
		return nil, zero, ErrTool
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, (32<<20)+1))
	var after unix.Stat_t
	if e != nil || n != st.Size || unix.Fstat(fd, &after) != nil || !sameStat(st, after) || "sha256:"+hex.EncodeToString(h.Sum(nil)) != t.Digest {
		f.Close()
		return nil, zero, ErrTool
	}
	if _, e = f.Seek(0, 0); e != nil {
		f.Close()
		return nil, zero, ErrTool
	}
	return f, st, nil
}
func sameStat(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
