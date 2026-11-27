//go:build linux

package helper

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"golang.org/x/sys/unix"
)

// ExecutionStore is a separate, versioned ledger. Its state is intentionally
// incompatible with the historical admission-only Store, although descriptor
// ancestry, locking and atomic fsync primitives are shared.
type ExecutionStore struct {
	*Store
	anchor ExecutionAnchor
	digest string
	mounts []uint64
}

func executionAnchorDigest(a ExecutionAnchor) (string, error) {
	if a.APIVersion != ExecutionAnchorVersion || !configmodel.ValidDigest(a.LayoutDigest) || a.LayoutDigest != a.Installation.OwnershipDigest {
		return "", ErrInvalid
	}
	if _, err := executionReceiptKey(a); err != nil {
		return "", err
	}
	if _, err := installationDigest(a.Installation); err != nil {
		return "", err
	}
	return configmodel.Digest(a)
}

func newExecutionStore(dir string, a ExecutionAnchor) (*ExecutionStore, error) {
	digest, err := executionAnchorDigest(a)
	if err != nil {
		return nil, err
	}
	base, err := newStore(dir, a.Installation)
	if err != nil {
		return nil, err
	}
	s := &ExecutionStore{Store: base, anchor: a, digest: digest}
	for _, anchor := range s.anchors {
		m, err := executionMount(int(anchor.file.Fd()), "")
		if err != nil {
			_ = s.Close()
			return nil, err
		}
		s.mounts = append(s.mounts, m)
	}
	return s, nil
}

// CreateExecutionStore captures a verified serving baseline. Neither a caller
// boolean nor an ownedtree/bootstrap observation can initialize this ledger.
func CreateExecutionStore(ctx context.Context, dir string, a ExecutionAnchor, d ExecutionDriver) (*ExecutionStore, error) {
	if ctx == nil || d == nil {
		return nil, ErrInvalid
	}
	s, err := newExecutionStore(dir, a)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = s.Close()
		}
	}()
	names, err := s.directoryNames()
	if err != nil || len(names) != 0 {
		return nil, ErrState
	}
	initial, err := d.Snapshot(ctx)
	if err != nil || validateGeneration(initial) != nil || initial.Baseline != a.Installation.Baseline {
		return nil, ErrOwnedTree
	}
	if d.Verify(ctx, initial) != nil {
		return nil, ErrOwnedTree
	}
	again, err := d.Snapshot(ctx)
	if err != nil || again != initial || ctx.Err() != nil {
		return nil, ErrOwnedTree
	}
	fd, err := unix.Openat(int(s.dir.Fd()), storeLockName, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, ErrState
	}
	s.lock = os.NewFile(uintptr(fd), storeLockName)
	if unix.Fstat(fd, &s.lockPin) != nil || !s.regular(s.lockPin) || s.lockPin.Size != 0 {
		return nil, ErrState
	}
	if err = s.acquire(); err != nil {
		return nil, err
	}
	if s.lock.Sync() != nil || s.dir.Sync() != nil {
		return nil, ErrState
	}
	state := ExecutionState{APIVersion: ExecutionStateVersion, AnchorDigest: s.digest, Active: initial, LastHealthy: initial, HighWater: initial.Baseline.NodeDeploymentSequence, AuthorityEpoch: a.Installation.AuthorityEpoch, WriterEpoch: a.Installation.WriterEpoch, MinimumDenySequence: a.Installation.MinimumDenySequence, Records: []ExecutionRecord{}}
	if err = s.writeSnapshot(state); err != nil {
		return nil, err
	}
	ok = true
	return s, nil
}

func OpenExecutionStore(dir string, a ExecutionAnchor) (*ExecutionStore, error) {
	s, err := newExecutionStore(dir, a)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = s.Close()
		}
	}()
	fd, err := unix.Openat(int(s.dir.Fd()), storeLockName, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrState
	}
	s.lock = os.NewFile(uintptr(fd), storeLockName)
	if unix.Fstat(fd, &s.lockPin) != nil || !s.regular(s.lockPin) || s.lockPin.Size != 0 {
		return nil, ErrState
	}
	if err = s.acquire(); err != nil {
		return nil, err
	}
	if unix.Fstatat(int(s.dir.Fd()), storeStateName, &s.statePin, unix.AT_SYMLINK_NOFOLLOW) != nil || !s.regular(s.statePin) {
		return nil, ErrState
	}
	s.hasState = true
	if _, err = s.readSnapshot(false); err != nil {
		return nil, err
	}
	if s.checkAnchors() != nil || s.checkEntries() != nil {
		return nil, ErrState
	}
	ok = true
	return s, nil
}

func executionMount(fd int, name string) (uint64, error) {
	flags := unix.AT_SYMLINK_NOFOLLOW | unix.AT_NO_AUTOMOUNT
	if name == "" {
		flags |= unix.AT_EMPTY_PATH
	}
	var sx unix.Statx_t
	if unix.Statx(fd, name, flags, unix.STATX_MNT_ID, &sx) != nil || sx.Mask&unix.STATX_MNT_ID == 0 || sx.Mnt_id == 0 {
		return 0, ErrState
	}
	return sx.Mnt_id, nil
}

func (s *ExecutionStore) checkAnchors() error {
	if s.Store.checkAnchors() != nil || len(s.mounts) != len(s.anchors) {
		return ErrState
	}
	for i, a := range s.anchors {
		m, err := executionMount(int(a.file.Fd()), "")
		if err != nil || m != s.mounts[i] {
			return ErrState
		}
		if i > 0 {
			m, err = executionMount(int(s.anchors[i-1].file.Fd()), a.name)
			if err != nil || m != s.mounts[i] {
				return ErrState
			}
		}
	}
	for _, name := range []string{storeLockName, storeStateName} {
		if name == storeLockName && s.lock == nil || name == storeStateName && !s.hasState {
			continue
		}
		m, err := executionMount(int(s.dir.Fd()), name)
		if err != nil || m != s.mounts[len(s.mounts)-1] {
			return ErrState
		}
	}
	return nil
}

func (s *ExecutionStore) checkEntries() error {
	names, err := s.directoryNames()
	if err != nil {
		return ErrState
	}
	for _, name := range names {
		if name == storeLockName || (name == storeStateName && s.hasState) {
			continue
		}
		if !tempName(name) {
			return ErrState
		}
		var st unix.Stat_t
		m, err := executionMount(int(s.dir.Fd()), name)
		if err != nil || m != s.mounts[len(s.mounts)-1] || unix.Fstatat(int(s.dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !s.regular(st) || st.Size < 0 || st.Size > MaxExecutionStateBytes {
			return ErrState
		}
	}
	return nil
}

// lockState serializes an entire attempt, including its durable checkpoints.
// The filesystem flock additionally excludes other processes and handles.
func (s *ExecutionStore) lockState(ctx context.Context) (ExecutionState, error) {
	if s == nil || s.Store == nil || ctx == nil {
		return ExecutionState{}, ErrState
	}
	if err := ctx.Err(); err != nil {
		return ExecutionState{}, err
	}
	if !s.mu.TryLock() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for !s.mu.TryLock() {
			select {
			case <-ctx.Done():
				return ExecutionState{}, ctx.Err()
			case <-ticker.C:
			}
		}
	}
	if err := ctx.Err(); err != nil {
		s.mu.Unlock()
		return ExecutionState{}, err
	}
	if s.closed || s.poisoned || s.checkAnchors() != nil || s.checkEntries() != nil {
		s.mu.Unlock()
		return ExecutionState{}, ErrState
	}
	state, err := s.readSnapshot(true)
	if err != nil {
		s.poisoned = true
		s.mu.Unlock()
		return ExecutionState{}, err
	}
	return state, nil
}

func (s *ExecutionStore) readSnapshot(checkHash bool) (ExecutionState, error) {
	var state ExecutionState
	fd, err := unix.Openat(int(s.dir.Fd()), storeStateName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return state, ErrState
	}
	f := os.NewFile(uintptr(fd), storeStateName)
	keep := false
	defer func() {
		if !keep {
			_ = f.Close()
		}
	}()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || !samePin(st, s.statePin) || !s.regular(st) || st.Size < 1 || st.Size > MaxExecutionStateBytes {
		return state, ErrState
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxExecutionStateBytes+1))
	if err != nil || len(b) > MaxExecutionStateBytes || int64(len(b)) != st.Size {
		return state, ErrState
	}
	if unix.Fstat(fd, &st) != nil || !samePin(st, s.statePin) || !s.regular(st) || st.Size != int64(len(b)) {
		return state, ErrState
	}
	if unix.Fstatat(int(s.dir.Fd()), storeStateName, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !samePin(st, s.statePin) || !s.regular(st) {
		return state, ErrState
	}
	hash := sha256.Sum256(b)
	if checkHash && hash != s.stateHash {
		return state, ErrState
	}
	if decodeClosed(b, &state, MaxExecutionStateBytes) != nil || validateExecutionState(state, s.anchor, s.digest) != nil {
		return state, ErrState
	}
	canonical, err := configmodel.CanonicalJSON(state)
	if err != nil || !bytes.Equal(canonical, b) {
		return state, ErrState
	}
	if !checkHash {
		s.stateHash = hash
		s.stateFile = f
		keep = true
	}
	return state, nil
}

func (s *ExecutionStore) writeSnapshot(state ExecutionState) (err error) {
	defer func() {
		if err != nil {
			s.poisoned = true
		}
	}()
	if validateExecutionState(state, s.anchor, s.digest) != nil {
		return ErrState
	}
	b, err := configmodel.CanonicalJSON(state)
	if err != nil || len(b) < 1 || len(b) > MaxExecutionStateBytes || s.checkAnchors() != nil || s.checkEntries() != nil {
		return ErrState
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return ErrState
	}
	name := storeTempPrefix + hex.EncodeToString(random[:]) + storeTempSuffix
	fd, err := unix.Openat(int(s.dir.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrState
	}
	f := os.NewFile(uintptr(fd), name)
	keep := false
	defer func() {
		if !keep {
			_ = f.Close()
		}
	}()
	var pin, st unix.Stat_t
	if unix.Fstat(fd, &pin) != nil || !s.regular(pin) {
		return ErrState
	}
	if s.checkpoint("write") != nil {
		return ErrState
	}
	if n, e := f.Write(b); e != nil || n != len(b) {
		return ErrState
	}
	if s.checkpoint("file_sync") != nil || f.Sync() != nil {
		return ErrState
	}
	if unix.Fstat(fd, &st) != nil || !samePin(st, pin) || !s.regular(st) || st.Size != int64(len(b)) {
		return ErrState
	}
	if s.checkAnchors() != nil || s.checkEntries() != nil || unix.Fstatat(int(s.dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !samePin(st, pin) || !s.regular(st) || st.Size != int64(len(b)) {
		return ErrState
	}
	if s.hasState {
		if _, e := s.readSnapshot(true); e != nil {
			return ErrState
		}
	} else if e := unix.Fstatat(int(s.dir.Fd()), storeStateName, &st, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(e, unix.ENOENT) {
		return ErrState
	}
	if s.checkpoint("rename") != nil || unix.Renameat(int(s.dir.Fd()), name, int(s.dir.Fd()), storeStateName) != nil {
		return ErrState
	}
	previous := s.stateFile
	s.stateFile = f
	keep = true
	s.statePin, s.stateHash, s.hasState = pin, sha256.Sum256(b), true
	if previous != nil && previous.Close() != nil {
		return ErrState
	}
	if s.checkpoint("directory_sync") != nil || s.dir.Sync() != nil || s.checkAnchors() != nil {
		return ErrState
	}
	if unix.Fstatat(int(s.dir.Fd()), storeStateName, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !samePin(st, pin) || !s.regular(st) || st.Size != int64(len(b)) {
		return ErrState
	}
	return nil
}
