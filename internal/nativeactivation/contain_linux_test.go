//go:build linux

package nativeactivation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/netwizd/agp/internal/configmodel"
)

func TestContainmentParsingRejectsAmbiguousMembershipAndEvents(t *testing.T) {
	for _, value := range []string{"", "1:cpu:/nginx", "0::/a\n0::/b", "0::/nginx/../helper", "0::/nginx\rtrick"} {
		if _, e := cgroupMembership([]byte(value)); e == nil {
			t.Fatalf("ambiguous membership accepted %q", value)
		}
	}
	if p, e := cgroupMembership([]byte("0::/agp/nginx\n")); e != nil || p != "/agp/nginx" {
		t.Fatal(p, e)
	}
	if !memberOf("/agp/nginx", "/agp/nginx") || !memberOf("/agp/nginx/workers", "/agp/nginx") || memberOf("/agp/nginx-helper", "/agp/nginx") {
		t.Fatal("helper containment boundary")
	}
	for _, value := range []string{"", "populated 2", "populated 0\npopulated 1", "frozen 0", "populated 0\nunknown 0"} {
		if _, e := populated([]byte(value)); e == nil {
			t.Fatalf("ambiguous events accepted %q", value)
		}
	}
	if p, e := populated([]byte("populated 1\nfrozen 0\n")); e != nil || !p {
		t.Fatal(p, e)
	}
	if p, e := populated([]byte("populated 0\nfrozen 0\n")); e != nil || p {
		t.Fatal(p, e)
	}
}
func TestContainmentAvailableAfterActivationHandlePoison(t *testing.T) {
	f := makeFixture(t)
	f.driver.poisoned = true
	if e := f.driver.Contain(context.Background()); e != nil || f.runtime.generation != "contained" {
		t.Fatalf("containment lost after durability failure: %v", e)
	}
	f.driver.Close()
	if e := f.driver.Contain(context.Background()); e == nil {
		t.Fatal("closed driver used")
	}
}
func TestContainmentRejectsUnqualifiedCgroupWithoutKernelMutation(t *testing.T) {
	for _, c := range []Config{{}, {CgroupDir: "/sys/fs/cgroup"}, {CgroupDir: "/tmp/fake-cgroup", CgroupMountID: 1, CgroupInode: 1}, {CgroupDir: "/sys/fs/cgroup/../other", CgroupMountID: 1, CgroupInode: 1}} {
		if d, _, e := openCgroup(c); e == nil {
			d.close()
			t.Fatal("unqualified cgroup accepted")
		}
	}
}

func TestCompleteQualifiedRuntimeRejectsLibraryMutationAndExtraFiles(t *testing.T) {
	for _, kind := range []string{"correct", "library", "extra", "executable-mode", "missing-loader"} {
		t.Run(kind, func(t *testing.T) {
			root, e := os.MkdirTemp("/tmp", "agp-native-runtime-test-")
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { os.RemoveAll(root) })
			for _, dir := range []string{"bin", "lib"} {
				os.Mkdir(filepath.Join(root, dir), 0700)
			}
			for _, file := range []string{"bin/nginx", "lib/ld-linux-x86-64.so.2", "lib/libssl.so"} {
				os.WriteFile(filepath.Join(root, file), []byte(file), 0500)
			}
			entries := []RuntimeEntry{{Path: ".", Kind: "directory", Mode: 0700}, {Path: "bin", Kind: "directory", Mode: 0700}, {Path: "lib", Kind: "directory", Mode: 0700}}
			for _, file := range []string{"bin/nginx", "lib/ld-linux-x86-64.so.2", "lib/libssl.so"} {
				entries = append(entries, RuntimeEntry{Path: file, Kind: "file", Mode: 0500, Size: len(file), Digest: configmodel.DigestBytes([]byte(file))})
			}
			switch kind {
			case "library":
				os.Chmod(filepath.Join(root, "lib/libssl.so"), 0700)
				os.WriteFile(filepath.Join(root, "lib/libssl.so"), []byte("mutated"), 0500)
				os.Chmod(filepath.Join(root, "lib/libssl.so"), 0500)
			case "extra":
				os.WriteFile(filepath.Join(root, "lib/extra.so"), []byte("extra"), 0500)
			case "executable-mode":
				os.Chmod(filepath.Join(root, "bin/nginx"), 0777)
			case "missing-loader":
				os.Remove(filepath.Join(root, "lib/ld-linux-x86-64.so.2"))
			}
			e = checkRuntimeTree(context.Background(), Config{RuntimeDir: root, RuntimeEntries: entries}, uint32(os.Geteuid()))
			if (kind == "correct") != (e == nil) {
				t.Fatalf("runtime %s: %v", kind, e)
			}
		})
	}
}
func TestProductionConstructorRequiresRootAndQualifiedRuntime(t *testing.T) {
	if os.Geteuid() != 0 {
		if r, e := OpenRepository("/tmp", configmodel.DigestBytes([]byte("pin"))); e == nil {
			r.Close()
			t.Fatal("non-root repository installation accepted")
		}
		if d, e := Open(Config{}, nil); e == nil {
			d.Close()
			t.Fatal("non-root native adapter accepted")
		}
	}
}

func TestAbsentMasterStillContainsInstallerPinnedOrphanGroup(t *testing.T) {
	root, e := os.MkdirTemp("/tmp", "agp-native-orphan-test-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(root)
	cfg := Config{PIDFile: filepath.Join(root, "nginx.pid")}
	killed := false
	events := 0
	e = containGroup(context.Background(), func() error {
		return checkContainmentMaster(context.Background(), cfg, "/agp/nginx", uint32(os.Geteuid()))
	}, func() error { killed = true; return nil }, func() ([]byte, error) {
		events++
		if events == 1 {
			return []byte("populated 1\nfrozen 0\n"), nil
		}
		return []byte("populated 0\nfrozen 0\n"), nil
	})
	if e != nil || !killed || events != 2 {
		t.Fatalf("orphan containment was blocked by absent master: %v killed=%v events=%d", e, killed, events)
	}
	killed = false
	e = containGroup(context.Background(), func() error { return ErrInstallation }, func() error { killed = true; return nil }, func() ([]byte, error) { return []byte("populated 0"), nil })
	if e != nil || !killed {
		t.Fatal("unconfirmed master incorrectly vetoed installer-pinned group containment")
	}
}

func TestReusedPIDAndMasterExitDoNotVetoPinnedGroupContainment(t *testing.T) {
	for _, mode := range []string{"reused-foreign-pid", "master-exit-during-proc-read"} {
		t.Run(mode, func(t *testing.T) {
			root, e := os.MkdirTemp("/tmp", "agp-native-stale-pid-")
			if e != nil {
				t.Fatal(e)
			}
			defer os.RemoveAll(root)
			cfg := Config{PIDFile: filepath.Join(root, "nginx.pid"), ExecutableDigest: configmodel.DigestBytes([]byte("qualified-nginx"))}
			os.WriteFile(cfg.PIDFile, []byte(fmt.Sprint(os.Getpid())+"\n"), 0600)
			observed := false
			kills := 0
			e = containGroup(context.Background(), func() error {
				observed = true
				if mode == "master-exit-during-proc-read" {
					return ErrRuntime
				}
				err := checkContainmentMaster(context.Background(), cfg, "/agp/nginx", uint32(os.Geteuid()))
				if err == nil {
					t.Fatal("foreign live PID unexpectedly confirmed as Nginx")
				}
				return err
			}, func() error { kills++; return nil }, func() ([]byte, error) { return []byte("populated 0\nfrozen 0\n"), nil })
			if e != nil || !observed || kills != 1 {
				t.Fatalf("%s blocked exact group containment: %v kills=%d", mode, e, kills)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	killed := false
	if e := containGroup(ctx, func() error { return ErrRuntime }, func() error { killed = true; return nil }, func() ([]byte, error) { return []byte("populated 0"), nil }); !errors.Is(e, context.Canceled) || killed {
		t.Fatal("cancelled containment still issued effect")
	}
}
