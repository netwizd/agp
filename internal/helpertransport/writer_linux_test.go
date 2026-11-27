//go:build linux

package helpertransport

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestWriterLockRejectsReplaceableServicePaths(t *testing.T) {
	dir := transportDir(t)
	path := filepath.Join(dir, "writer.lock")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if l, err := AcquireWriterLock(path); l != nil || !errors.Is(err, ErrTransport) {
			t.Fatalf("service-owned parent admitted: %v %v", l, err)
		}
	}
	f, err := os.CreateTemp("/tmp", "agp-writer-test-")
	if err != nil {
		t.Fatal(err)
	}
	tmp := f.Name()
	_ = f.Close()
	defer os.Remove(tmp)
	if l, err := AcquireWriterLock(tmp); l != nil || !errors.Is(err, ErrTransport) {
		t.Fatalf("sticky /tmp lets service replace its inode: %v %v", l, err)
	}
	if l, err := AcquireWriterLock("writer.lock"); l != nil || !errors.Is(err, ErrTransport) {
		t.Fatalf("relative writer path admitted: %v %v", l, err)
	}
}

func TestWriterFileRequiresExactPrivateSingleLink(t *testing.T) {
	dir := transportDir(t)
	path := filepath.Join(dir, "writer.lock")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(path)
	if err != nil || !writerFile(st) {
		t.Fatalf("private file rejected: %v %v", st, err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	st, _ = os.Lstat(path)
	if writerFile(st) {
		t.Fatal("group-readable lock admitted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	st, _ = os.Lstat(path)
	if writerFile(st) {
		t.Fatal("multiply linked lock admitted")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	st, _ = os.Lstat(alias)
	if writerFile(st) {
		t.Fatal("symlink lock admitted")
	}
}

func TestWriterCloseReleasesActualKernelLock(t *testing.T) {
	path := filepath.Join(transportDir(t), "writer.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	other, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := unix.Flock(int(other.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
		t.Fatal("independent descriptor bypassed held lock")
	}
	l := &WriterLock{file: f, path: path}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(other.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("close did not release lock: %v", err)
	}
	if err := l.Witness(context.Background()); !errors.Is(err, ErrTransport) {
		t.Fatalf("closed writer witnessed: %v", err)
	}
	var absent *WriterLock
	if err := absent.Witness(context.Background()); !errors.Is(err, ErrTransport) {
		t.Fatalf("nil writer witnessed: %v", err)
	}
	if err := absent.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.Witness(ctx); !errors.Is(err, ErrTransport) {
		t.Fatalf("canceled witness succeeded: %v", err)
	}
}

func TestInstalledWriterLockLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("positive production writer-lock qualification requires an installer-owned root directory")
	}
	dir := transportDir(t)
	path := filepath.Join(dir, "writer.lock")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	first, err := AcquireWriterLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if err := first.Witness(context.Background()); err != nil {
		t.Fatal(err)
	}
	if second, err := AcquireWriterLock(path); second != nil || !errors.Is(err, ErrTransport) {
		t.Fatalf("second writer acquired: %v %v", second, err)
	}
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := first.Witness(context.Background()); !errors.Is(err, ErrTransport) {
		t.Fatalf("replaced inode witnessed: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := AcquireWriterLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
}
