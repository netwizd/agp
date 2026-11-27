//go:build linux

package helpertransport

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// WriterLock is a lifetime lock in an installation-owned directory. The
// service may lock its pre-provisioned file but cannot replace its inode.
// It fences a single writer across database copies on this host; it is not an
// HA lease and cannot fence independent hosts.
type WriterLock struct {
	mu       sync.Mutex
	file     *os.File
	path     string
	identity os.FileInfo
}

func AcquireWriterLock(path string) (*WriterLock, error) {
	if writerParent(path) != nil {
		return nil, ErrTransport
	}
	f, err := os.OpenFile(path, os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrTransport
	}
	st, err := f.Stat()
	if err != nil || !writerFile(st) {
		f.Close()
		return nil, ErrTransport
	}
	if unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		f.Close()
		return nil, ErrTransport
	}
	l := &WriterLock{file: f, path: path, identity: st}
	if l.Witness(context.Background()) != nil {
		l.Close()
		return nil, ErrTransport
	}
	return l, nil
}

func writerParent(path string) error {
	if ancestry(path, 0) != nil {
		return ErrTransport
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || parent.Mode().Perm()&0022 != 0 {
		return ErrTransport
	}
	return nil
}

func writerFile(st os.FileInfo) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && st.Mode().IsRegular() && s.Uid == uint32(os.Geteuid()) && s.Nlink == 1 && st.Mode().Perm() == 0600
}

func (l *WriterLock) Witness(ctx context.Context) error {
	if l == nil || ctx == nil || ctx.Err() != nil {
		return ErrTransport
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil || writerParent(l.path) != nil {
		return ErrTransport
	}
	fd, err := l.file.Stat()
	path, pe := os.Lstat(l.path)
	if err != nil || pe != nil || !writerFile(fd) || !writerFile(path) || !os.SameFile(l.identity, fd) || !os.SameFile(fd, path) {
		return ErrTransport
	}
	return nil
}

func (l *WriterLock) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}
