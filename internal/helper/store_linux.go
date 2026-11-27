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
	"path/filepath"
	"strings"
	"sync"

	"github.com/netwizd/agp/internal/configmodel"
	"golang.org/x/sys/unix"
)

const (
	storeLockName   = "helper.lock"
	storeStateName  = "state.json"
	storeTempPrefix = ".state-"
	storeTempSuffix = ".tmp"
	maxStoreEntries = 256
)

type directoryAnchor struct {
	file *os.File
	name string
	pin  unix.Stat_t
}

// Store owns one exclusively locked, installation-bound local admission ledger.
// The descriptors for the complete trusted ancestry remain pinned until Close.
// It never opens an active configuration tree or executes a task.
type Store struct {
	mu           sync.Mutex
	installation Installation
	digest       string
	anchors      []directoryAnchor
	dir          *os.File
	lock         *os.File
	lockPin      unix.Stat_t
	stateFile    *os.File
	statePin     unix.Stat_t
	stateHash    [sha256.Size]byte
	hasState     bool
	closed       bool
	poisoned     bool
	// fault is an internal test-only checkpoint; no runtime API can install it.
	fault func(string) error
}

// CreateStore initializes an existing empty private directory exactly once.
// A partially initialized directory cannot be reset by calling CreateStore again.
func CreateStore(dir string, installation Installation) (*Store, error) {
	s, err := newStore(dir, installation)
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
	// Persist the non-resettable initialization marker before the first state.
	if s.lock.Sync() != nil || s.dir.Sync() != nil {
		return nil, ErrState
	}
	initial := diskState{
		APIVersion: StateVersion, InstallationDigest: s.digest,
		HighWater:      installation.Baseline.NodeDeploymentSequence,
		AuthorityEpoch: installation.AuthorityEpoch, WriterEpoch: installation.WriterEpoch,
		MinimumDenySequence: installation.MinimumDenySequence,
	}
	if err = s.writeSnapshot(initial); err != nil {
		return nil, err
	}
	ok = true
	return s, nil
}

// OpenStore opens only a complete existing ledger. It creates no marker or state
// and never removes leftover temporary files from an interrupted transaction.
func OpenStore(dir string, installation Installation) (*Store, error) {
	s, err := newStore(dir, installation)
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
	if err = s.checkAnchors(); err != nil || s.checkEntries() != nil {
		return nil, ErrState
	}
	ok = true
	return s, nil
}

func newStore(dir string, installation Installation) (*Store, error) {
	digest, err := installationDigest(installation)
	if err != nil {
		return nil, err
	}
	s := &Store{installation: installation, digest: digest}
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || dir == "/" {
		return nil, ErrState
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrState
	}
	s.anchors = append(s.anchors, directoryAnchor{file: os.NewFile(uintptr(fd), "/")})
	parts := strings.Split(strings.TrimPrefix(dir, "/"), "/")
	privateChild := false
	current := "/"
	for i := 0; i <= len(parts); i++ {
		a := &s.anchors[len(s.anchors)-1]
		if unix.Fstat(int(a.file.Fd()), &a.pin) != nil || a.pin.Mode&unix.S_IFMT != unix.S_IFDIR || (a.pin.Uid != 0 && a.pin.Uid != uint32(os.Geteuid())) {
			_ = s.Close()
			return nil, ErrState
		}
		final := i == len(parts)
		if (privateChild || final) && (a.pin.Uid != uint32(os.Geteuid()) || a.pin.Mode != unix.S_IFDIR|0700) {
			_ = s.Close()
			return nil, ErrState
		}
		privateChild = false
		if a.pin.Mode&0022 != 0 {
			if current != "/tmp" || a.pin.Uid != 0 || a.pin.Mode&unix.S_ISVTX == 0 || final {
				_ = s.Close()
				return nil, ErrState
			}
			privateChild = true
		}
		if final {
			s.dir = a.file
			return s, nil
		}
		next, e := unix.Openat(int(a.file.Fd()), parts[i], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			_ = s.Close()
			return nil, ErrState
		}
		s.anchors = append(s.anchors, directoryAnchor{file: os.NewFile(uintptr(next), parts[i]), name: parts[i]})
		current = filepath.Join(current, parts[i])
	}
	return nil, ErrState
}

func (s *Store) acquire() error {
	if err := unix.Flock(int(s.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return ErrBusy
		}
		return ErrState
	}
	return s.checkAnchors()
}

// Close releases all descriptors; closing the lock releases its flock. It is
// serialized with transactions and is safe to call more than once.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.stateFile != nil && s.stateFile.Close() != nil {
		err = ErrState
	}
	if s.lock != nil && s.lock.Close() != nil {
		err = ErrState
	}
	for i := len(s.anchors) - 1; i >= 0; i-- {
		if s.anchors[i].file.Close() != nil {
			err = ErrState
		}
	}
	return err
}

// transaction commits one whole snapshot, so its high-water, intent and
// historical receipt cannot become independently durable. A callback error or
// false result never changes storage. A durability error poisons this handle.
func (s *Store) transaction(ctx context.Context, fn func(*diskState) (bool, error)) error {
	if s == nil || ctx == nil || fn == nil {
		return ErrState
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.poisoned {
		return ErrState
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.checkAnchors() != nil || s.checkEntries() != nil {
		s.poisoned = true
		return ErrState
	}
	state, err := s.readSnapshot(true)
	if err != nil {
		s.poisoned = true
		return ErrState
	}
	changed, err := fn(&state)
	if err != nil || !changed {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return s.writeSnapshot(state)
}

func samePin(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode
}

func (s *Store) regular(st unix.Stat_t) bool {
	return st.Mode == unix.S_IFREG|0600 && st.Uid == uint32(os.Geteuid()) && st.Nlink == 1 && st.Dev == s.anchors[len(s.anchors)-1].pin.Dev
}

func (s *Store) checkAnchors() error {
	for i, a := range s.anchors {
		var st unix.Stat_t
		if unix.Fstat(int(a.file.Fd()), &st) != nil || !samePin(st, a.pin) || st.Nlink == 0 {
			return ErrState
		}
		if i > 0 && (unix.Fstatat(int(s.anchors[i-1].file.Fd()), a.name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !samePin(st, a.pin)) {
			return ErrState
		}
	}
	if s.lock != nil {
		var st unix.Stat_t
		if unix.Fstat(int(s.lock.Fd()), &st) != nil || !samePin(st, s.lockPin) || !s.regular(st) || st.Size != 0 {
			return ErrState
		}
		if unix.Fstatat(int(s.dir.Fd()), storeLockName, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !samePin(st, s.lockPin) || !s.regular(st) || st.Size != 0 {
			return ErrState
		}
	}
	if s.stateFile != nil {
		var st unix.Stat_t
		if unix.Fstat(int(s.stateFile.Fd()), &st) != nil || !samePin(st, s.statePin) || !s.regular(st) {
			return ErrState
		}
		if unix.Fstatat(int(s.dir.Fd()), storeStateName, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !samePin(st, s.statePin) || !s.regular(st) {
			return ErrState
		}
	}
	return nil
}

func (s *Store) directoryNames() ([]string, error) {
	fd, err := unix.Openat(int(s.dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrState
	}
	f := os.NewFile(uintptr(fd), ".")
	defer f.Close()
	names, err := f.Readdirnames(maxStoreEntries + 1)
	if (err != nil && err != io.EOF) || len(names) > maxStoreEntries {
		return nil, ErrState
	}
	return names, nil
}

func tempName(name string) bool {
	if !strings.HasPrefix(name, storeTempPrefix) || !strings.HasSuffix(name, storeTempSuffix) || len(name) != len(storeTempPrefix)+32+len(storeTempSuffix) {
		return false
	}
	_, err := hex.DecodeString(strings.TrimSuffix(strings.TrimPrefix(name, storeTempPrefix), storeTempSuffix))
	return err == nil
}

func (s *Store) checkEntries() error {
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
		if unix.Fstatat(int(s.dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !s.regular(st) || st.Size < 0 || st.Size > MaxStateBytes {
			return ErrState
		}
	}
	return nil
}

func (s *Store) readSnapshot(checkHash bool) (diskState, error) {
	var state diskState
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
	if unix.Fstat(fd, &st) != nil || !samePin(st, s.statePin) || !s.regular(st) || st.Size < 1 || st.Size > MaxStateBytes {
		return state, ErrState
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxStateBytes+1))
	if err != nil || len(b) > MaxStateBytes || int64(len(b)) != st.Size {
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
	if decodeClosed(b, &state, MaxStateBytes) != nil || validateState(state, s.installation) != nil {
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

func (s *Store) checkpoint(name string) error {
	if s.fault != nil && s.fault(name) != nil {
		return ErrState
	}
	return nil
}

func (s *Store) writeSnapshot(state diskState) (err error) {
	defer func() {
		if err != nil {
			s.poisoned = true
		}
	}()
	if validateState(state, s.installation) != nil {
		return ErrState
	}
	b, err := configmodel.CanonicalJSON(state)
	if err != nil || len(b) < 1 || len(b) > MaxStateBytes || s.checkAnchors() != nil || s.checkEntries() != nil {
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
