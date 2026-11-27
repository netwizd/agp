//go:build linux

package helper

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func storageInstallation() Installation {
	d := "sha256:" + strings.Repeat("a", 64)
	return Installation{
		APIVersion: InstallationVersion, NodeID: "node1", SiteID: "site1",
		IdentityDigest: d, OwnershipDigest: d, CapabilityDigest: d,
		ComponentProfileDigest: d, ReleaseManifestDigest: d, TupleDigest: d,
		CompilerDigest: d, TrustDigest: d, AuthorityID: "authority1",
		AuthorityEpoch: 1, WriterEpoch: 1, MinimumDenySequence: 2,
		Baseline: Baseline{RevisionID: "base1", BundleDigest: d, NodeDeploymentSequence: 7},
	}
}

func storageDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(storageTemp(t), "store")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func storageTemp(t *testing.T) string {
	t.Helper()
	// testing.T.TempDir may use GOTMPDIR and creates its nested numbered
	// directory with the process umask. Explicit private /tmp children keep
	// the production ancestry checks intact on group-writable workspaces.
	dir, err := os.MkdirTemp("/tmp", "agp-helper-store-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}

func storageCreate(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := CreateStore(dir, storageInstallation())
	if err != nil {
		t.Fatal("CreateStore:", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error("Close:", err)
		}
	})
	return s
}

func storageRead(t *testing.T, dir, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func storageStat(t *testing.T, name string) unix.Stat_t {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(name, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

func storageNoop(t *testing.T, s *Store, changed bool) {
	t.Helper()
	if err := s.transaction(context.Background(), func(state *diskState) (bool, error) {
		if state.HighWater != 7 || state.Intent != nil || state.RecoveryRequired {
			t.Error("unexpected baseline state")
		}
		return changed, nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestStoreCreateOpenExclusiveAndNoReset(t *testing.T) {
	dir := storageDir(t)
	s := storageCreate(t, dir)
	for _, name := range []string{storeLockName, storeStateName} {
		st := storageStat(t, filepath.Join(dir, name))
		if st.Mode != unix.S_IFREG|0600 || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) {
			t.Fatalf("unprotected %s", name)
		}
	}
	if other, err := OpenStore(dir, storageInstallation()); other != nil || !errors.Is(err, ErrBusy) {
		t.Fatalf("concurrent open: %v, %v", other, err)
	}
	if other, err := CreateStore(dir, storageInstallation()); other != nil || !errors.Is(err, ErrState) {
		t.Fatalf("reset existing store: %v, %v", other, err)
	}
	before := storageRead(t, dir, storeStateName)
	storageNoop(t, s, true)
	if !bytes.Equal(before, storageRead(t, dir, storeStateName)) {
		t.Fatal("unchanged transaction modified state value")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(dir, storageInstallation())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	storageNoop(t, reopened, false)
	if err := s.transaction(context.Background(), func(*diskState) (bool, error) { return false, nil }); !errors.Is(err, ErrState) {
		t.Fatal("closed handle accepted transaction:", err)
	}
}

func TestStoreIncompleteInitializationIsNotReset(t *testing.T) {
	dir := storageDir(t)
	if err := os.WriteFile(filepath.Join(dir, storeLockName), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if s, err := OpenStore(dir, storageInstallation()); s != nil || !errors.Is(err, ErrState) {
		t.Fatalf("incomplete open: %v, %v", s, err)
	}
	if s, err := CreateStore(dir, storageInstallation()); s != nil || !errors.Is(err, ErrState) {
		t.Fatalf("incomplete reset: %v, %v", s, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, storeStateName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("state was unexpectedly created:", err)
	}
}

func TestStoreCallbackAndCancellationDoNotMutate(t *testing.T) {
	dir := storageDir(t)
	s := storageCreate(t, dir)
	before := storageRead(t, dir, storeStateName)
	for _, callbackErr := range []error{nil, ErrConflict} {
		err := s.transaction(context.Background(), func(state *diskState) (bool, error) {
			state.HighWater = 100
			return false, callbackErr
		})
		if !errors.Is(err, callbackErr) || !bytes.Equal(before, storageRead(t, dir, storeStateName)) {
			t.Fatalf("callback mutation escaped: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	if err := s.transaction(ctx, func(*diskState) (bool, error) { called = true; return true, nil }); !errors.Is(err, context.Canceled) || called {
		t.Fatalf("cancelled transaction: called=%v, err=%v", called, err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	if err := s.transaction(ctx, func(*diskState) (bool, error) { cancel(); return true, nil }); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation before persistence:", err)
	}
	if !bytes.Equal(before, storageRead(t, dir, storeStateName)) {
		t.Fatal("cancelled transaction changed snapshot")
	}
	storageNoop(t, s, false)
}

func TestStoreConcurrentReadTransactionsAreSerialized(t *testing.T) {
	s := storageCreate(t, storageDir(t))
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.transaction(context.Background(), func(state *diskState) (bool, error) {
				state.HighWater = 99 // A discarded private decode, never shared state.
				return false, nil
			})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	storageNoop(t, s, false)
}

func TestStoreCloseRacesSafelyWithTransactions(t *testing.T) {
	s := storageCreate(t, storageDir(t))
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, 32)
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- s.transaction(context.Background(), func(*diskState) (bool, error) { return false, nil })
		}()
	}
	close(start)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil && !errors.Is(err, ErrState) {
			t.Error(err)
		}
	}
}

func TestStoreRejectsInsecureAncestryAndInstallation(t *testing.T) {
	dir := storageDir(t)
	for _, path := range []string{dir + "/", filepath.Join(dir, "..", "store") + "/../store", "relative", "/", "/tmp"} {
		if s, err := CreateStore(path, storageInstallation()); s != nil || !errors.Is(err, ErrState) {
			t.Fatalf("untrusted path accepted: %q, %v", path, err)
		}
	}
	outer := storageTemp(t)
	if err := os.Chmod(outer, 0770); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(outer, 0700)
	private := filepath.Join(outer, "store")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	if s, err := CreateStore(private, storageInstallation()); s != nil || !errors.Is(err, ErrState) {
		t.Fatalf("writable ancestor accepted: %v", err)
	}
	link := filepath.Join(storageTemp(t), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if s, err := CreateStore(link, storageInstallation()); s != nil || !errors.Is(err, ErrState) {
		t.Fatalf("symlink directory accepted: %v", err)
	}
	s := storageCreate(t, dir)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	i := storageInstallation()
	i.SiteID = "otherSite"
	if other, err := OpenStore(dir, i); other != nil || !errors.Is(err, ErrState) {
		t.Fatalf("installation substituted: %v", err)
	}
}

func TestStoreDetectsReplacementOrTamperingBeforeCallback(t *testing.T) {
	cases := map[string]func(*testing.T, string){
		"state_inode": func(t *testing.T, dir string) {
			b := storageRead(t, dir, storeStateName)
			if err := os.Remove(filepath.Join(dir, storeStateName)); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, storeStateName), b, 0600); err != nil {
				t.Fatal(err)
			}
		},
		"state_content": func(t *testing.T, dir string) {
			b := storageRead(t, dir, storeStateName)
			b = bytes.Replace(b, []byte(`"highWater":"7"`), []byte(`"highWater":"8"`), 1)
			if err := os.WriteFile(filepath.Join(dir, storeStateName), b, 0600); err != nil {
				t.Fatal(err)
			}
		},
		"state_mode": func(t *testing.T, dir string) {
			if err := os.Chmod(filepath.Join(dir, storeStateName), 0640); err != nil {
				t.Fatal(err)
			}
		},
		"state_hardlink": func(t *testing.T, dir string) {
			if err := os.Link(filepath.Join(dir, storeStateName), filepath.Join(storageTemp(t), "linked")); err != nil {
				t.Fatal(err)
			}
		},
		"lock_inode": func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, storeLockName)); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, storeLockName), nil, 0600); err != nil {
				t.Fatal(err)
			}
		},
		"directory_mode": func(t *testing.T, dir string) {
			if err := os.Chmod(dir, 0710); err != nil {
				t.Fatal(err)
			}
		},
		"directory_inode": func(t *testing.T, dir string) {
			if err := os.Rename(dir, dir+"-moved"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			dir := storageDir(t)
			s := storageCreate(t, dir)
			tamper(t, dir)
			called := false
			err := s.transaction(context.Background(), func(*diskState) (bool, error) { called = true; return true, nil })
			if !errors.Is(err, ErrState) || called || err.Error() != ErrState.Error() {
				t.Fatalf("tampered state used: called=%v, err=%v", called, err)
			}
		})
	}
}

func TestStoreOpenRejectsUnsafeFilesWithoutFollowing(t *testing.T) {
	cases := map[string]func(*testing.T, string){
		"state_symlink": func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, storeStateName)); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/dev/zero", filepath.Join(dir, storeStateName)); err != nil {
				t.Fatal(err)
			}
		},
		"state_fifo": func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, storeStateName)); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkfifo(filepath.Join(dir, storeStateName), 0600); err != nil {
				t.Fatal(err)
			}
		},
		"lock_symlink": func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, storeLockName)); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/dev/null", filepath.Join(dir, storeLockName)); err != nil {
				t.Fatal(err)
			}
		},
		"state_hardlink": func(t *testing.T, dir string) {
			if err := os.Link(filepath.Join(dir, storeStateName), filepath.Join(storageTemp(t), "linked")); err != nil {
				t.Fatal(err)
			}
		},
		"unrecognized_file": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "unexpected"), nil, 0600); err != nil {
				t.Fatal(err)
			}
		},
		"suspicious_temporary": func(t *testing.T, dir string) {
			name := storeTempPrefix + strings.Repeat("1", 32) + storeTempSuffix
			if err := os.Symlink("/dev/zero", filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			dir := storageDir(t)
			s := storageCreate(t, dir)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			tamper(t, dir)
			before, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			other, err := OpenStore(dir, storageInstallation())
			if other != nil || !errors.Is(err, ErrState) || err.Error() != ErrState.Error() {
				t.Fatalf("unsafe file accepted: %v", err)
			}
			after, err := os.ReadDir(dir)
			if err != nil || len(after) != len(before) {
				t.Fatal("OpenStore modified unsafe entries")
			}
		})
	}
}

func TestStorePreservesOrphanTemporary(t *testing.T) {
	dir := storageDir(t)
	s := storageCreate(t, dir)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	name := storeTempPrefix + strings.Repeat("2", 32) + storeTempSuffix
	if err := os.WriteFile(filepath.Join(dir, name), []byte("interrupted snapshot"), 0600); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(dir, storageInstallation())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	storageNoop(t, reopened, true)
	if string(storageRead(t, dir, name)) != "interrupted snapshot" {
		t.Fatal("orphan temporary was changed or removed")
	}
}

func TestStoreOpenRejectsMalformedOrUnboundSnapshot(t *testing.T) {
	cases := map[string]func([]byte) []byte{
		"truncated":       func(b []byte) []byte { return b[:len(b)/2] },
		"unknown_field":   func(b []byte) []byte { return append([]byte(`{"unknown":true,`), b[1:]...) },
		"duplicate_field": func(b []byte) []byte { return append([]byte(`{"highWater":"7",`), b[1:]...) },
		"noncanonical":    func(b []byte) []byte { return append(b, '\n') },
		"wrong_version":   func(b []byte) []byte { return bytes.Replace(b, []byte(StateVersion), []byte("agp.other/v1"), 1) },
		"unbound_counter": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"highWater":"7"`), []byte(`"highWater":"8"`), 1)
		},
		"wrong_installation": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"installationDigest":"sha256:`), []byte(`"installationDigest":"sha256:0`), 1)
		},
		"oversized": func([]byte) []byte { return bytes.Repeat([]byte("x"), MaxStateBytes+1) },
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			dir := storageDir(t)
			s := storageCreate(t, dir)
			before := storageRead(t, dir, storeStateName)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			bad := corrupt(bytes.Clone(before))
			if bytes.Equal(before, bad) {
				t.Fatal("test did not corrupt snapshot")
			}
			if err := os.WriteFile(filepath.Join(dir, storeStateName), bad, 0600); err != nil {
				t.Fatal(err)
			}
			if other, err := OpenStore(dir, storageInstallation()); other != nil || !errors.Is(err, ErrState) {
				t.Fatalf("invalid snapshot accepted: %v", err)
			}
			if !bytes.Equal(bad, storageRead(t, dir, storeStateName)) {
				t.Fatal("invalid snapshot was reset or repaired")
			}
		})
	}
}

func TestStoreDurabilityFailurePoisonsUntilReopen(t *testing.T) {
	for _, checkpoint := range []string{"write", "file_sync", "rename", "directory_sync"} {
		t.Run(checkpoint, func(t *testing.T) {
			dir := storageDir(t)
			s := storageCreate(t, dir)
			before := storageRead(t, dir, storeStateName)
			pin := storageStat(t, filepath.Join(dir, storeStateName))
			s.fault = func(stage string) error {
				if stage == checkpoint {
					return errors.New("private path /do/not/expose")
				}
				return nil
			}
			err := s.transaction(context.Background(), func(*diskState) (bool, error) { return true, nil })
			if !errors.Is(err, ErrState) || err.Error() != ErrState.Error() {
				t.Fatal("fault was not safely rejected:", err)
			}
			s.fault = nil
			called := false
			if err := s.transaction(context.Background(), func(*diskState) (bool, error) { called = true; return false, nil }); !errors.Is(err, ErrState) || called {
				t.Fatal("poisoned handle used")
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenStore(dir, storageInstallation())
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			storageNoop(t, reopened, false)
			if !bytes.Equal(before, storageRead(t, dir, storeStateName)) {
				t.Fatal("partial snapshot became visible")
			}
			after := storageStat(t, filepath.Join(dir, storeStateName))
			if (after.Ino != pin.Ino) != (checkpoint == "directory_sync") {
				t.Fatal("unexpected rename boundary")
			}
		})
	}
}

func TestStoreCrashChild(t *testing.T) {
	dir, checkpoint := os.Getenv("AGP_HELPER_TEST_CRASH_DIR"), os.Getenv("AGP_HELPER_TEST_CRASH_CHECKPOINT")
	if dir == "" || checkpoint == "" {
		return
	}
	s, err := OpenStore(dir, storageInstallation())
	if err != nil {
		t.Fatal(err)
	}
	s.fault = func(stage string) error {
		if stage == checkpoint {
			os.Exit(87)
		}
		return nil
	}
	_ = s.transaction(context.Background(), func(*diskState) (bool, error) { return true, nil })
	t.Fatal("crash checkpoint not reached")
}

func TestStoreActualProcessCrashReopensWholeSnapshot(t *testing.T) {
	for _, checkpoint := range []string{"write", "file_sync", "rename", "directory_sync"} {
		t.Run(checkpoint, func(t *testing.T) {
			dir := storageDir(t)
			s := storageCreate(t, dir)
			before := storageRead(t, dir, storeStateName)
			pin := storageStat(t, filepath.Join(dir, storeStateName))
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestStoreCrashChild$", "-test.count=1")
			cmd.Env = append(os.Environ(), "AGP_HELPER_TEST_CRASH_DIR="+dir, "AGP_HELPER_TEST_CRASH_CHECKPOINT="+checkpoint)
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 87 {
				t.Fatalf("child did not crash at checkpoint: %v, %s", err, out)
			}
			reopened, err := OpenStore(dir, storageInstallation())
			if err != nil {
				t.Fatal("crashed ledger did not reopen:", err)
			}
			defer reopened.Close()
			storageNoop(t, reopened, false)
			if !bytes.Equal(before, storageRead(t, dir, storeStateName)) {
				t.Fatal("crash exposed partial snapshot")
			}
			after := storageStat(t, filepath.Join(dir, storeStateName))
			if (after.Ino != pin.Ino) != (checkpoint == "directory_sync") {
				t.Fatal("crash crossed unexpected rename boundary")
			}
		})
	}
}
