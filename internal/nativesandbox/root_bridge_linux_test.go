//go:build linux

package nativesandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// Root qualification is deliberately separate from self-owned UID1001 fixtures.
// The mandatory script fails rather than skipping when root is unavailable.
func TestRootBridgeNative(t *testing.T) {
	if os.Getenv("AGP_TEST_ROOT_BRIDGE_REQUIRED") != "1" {
		t.Skip("explicit root-supervisor qualification required")
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("actual real/effective root required; UID fixture is not qualification")
	}
	uid, e := strconv.ParseUint(os.Getenv("AGP_TEST_EXECUTION_UID"), 10, 32)
	if e != nil || uid == 0 || uid == 1<<32-1 {
		t.Fatal("explicit nonroot execution UID required")
	}
	gid, e := strconv.ParseUint(os.Getenv("AGP_TEST_EXECUTION_GID"), 10, 32)
	if e != nil || gid == 0 || gid == 1<<32-1 {
		t.Fatal("explicit nonroot execution GID required")
	}
	if os.Getenv("AGP_ROOT_BRIDGE_CHILD") == "1" {
		rootBridgeChild(t, uint32(uid), uint32(gid))
		return
	}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	source := filepath.Join(dir, "probe.go")
	if e = os.WriteFile(source, []byte(probeSource), 0600); e != nil {
		t.Fatal(e)
	}
	probe := filepath.Join(dir, "probe")
	build := exec.Command("go", "build", "-o", probe, source)
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if _, e = build.CombinedOutput(); e != nil {
		t.Fatal("static probe build failed")
	}
	child := exec.Command(os.Args[0], "-test.run=^TestRootBridgeNative$", "-test.v")
	child.Env = append(os.Environ(), "AGP_ROOT_BRIDGE_CHILD=1", "AGP_ROOT_BRIDGE_PROBE="+probe)
	if out, e := child.CombinedOutput(); e != nil {
		t.Fatalf("root bridge failed: %v %s", e, out)
	}
}
func rootBridgeChild(t *testing.T, uid, gid uint32) {
	if e := ApplyLocalProcessLimits(); e != nil {
		t.Fatal(e)
	}
	r, e := NewAsUser(Tool{os.Getenv("AGP_TEST_BWRAP_BIN"), os.Getenv("AGP_TEST_BWRAP_DIGEST")}, uid, gid)
	if e != nil {
		t.Fatal(e)
	}
	if b := r.Binding(); b.ExecutionUID != uid || b.ExecutionGID != gid || b.ProfileDigest != ExecutionProfileDigest(uid, gid) {
		t.Fatal("execution identity not bound")
	}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	runtimeDir, configDir := filepath.Join(dir, "runtime"), filepath.Join(dir, "config")
	for _, name := range []string{runtimeDir, filepath.Join(runtimeDir, "lib"), filepath.Join(runtimeDir, "bin"), configDir} {
		if e = os.Mkdir(name, 0700); e != nil {
			t.Fatal(e)
		}
	}
	probe, e := os.ReadFile(os.Getenv("AGP_ROOT_BRIDGE_PROBE"))
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"lib/ld-linux-x86-64.so.2", "bin/nginx"} {
		if e = os.WriteFile(filepath.Join(runtimeDir, name), probe, 0500); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.WriteFile(filepath.Join(configDir, "nginx.conf"), []byte("root-owned-private-input"), 0400); e != nil {
		t.Fatal(e)
	}
	spec := Spec{runtimeDir, configDir, "lib/ld-linux-x86-64.so.2", "bin/nginx"}
	if e = r.run(context.Background(), spec, []string{"/runtime/bin/nginx", "root-identity", strconv.FormatUint(uint64(uid), 10), strconv.FormatUint(uint64(gid), 10)}); e != nil {
		t.Fatal(e)
	}
	content, e := os.ReadFile(filepath.Join(configDir, "nginx.conf"))
	if e != nil || string(content) != "root-owned-private-input" {
		t.Fatal("root input changed")
	}
}
