//go:build linux

package nativeactivation

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/helper"
	"github.com/netwizd/agp/internal/nativesandbox"
	"golang.org/x/sys/unix"
)

// This opt-in test uses the production constructors, a real root Nginx master,
// SIGHUP, the nonroot syntax sandbox and kernel cgroup.kill. Its return-based
// auth/WAF observations exercise activation plumbing, not authentication or WAF
// correctness. The externally installed runtime and its pins are never changed.
func TestNativeActivationRoot(t *testing.T) {
	if os.Getenv("AGP_TEST_NATIVE_ROOT_REQUIRED") != "1" {
		t.Skip("explicit root/native activation acceptance required")
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("actual real/effective root required; unprivileged fixtures are not acceptance")
	}
	if os.Getenv("AGP_NATIVE_ACTIVATION_SUPERVISOR") != "1" {
		// Keep the sum of both subprocesses below the script's 4m test timeout,
		// leaving time for the outer descriptor-based drain and removal.
		ctx, cancel := context.WithTimeout(context.Background(), 210*time.Second)
		defer cancel()
		if !t.Run("abrupt_supervisor_cleanup", func(t *testing.T) { rootTestSupervisor(t, ctx, true) }) {
			return
		}
		if deadline, _ := ctx.Deadline(); time.Until(deadline) < 180*time.Second {
			t.Fatal("insufficient outer watchdog budget for the full native scenario")
		}
		t.Run("apply_recover_contain", func(t *testing.T) { rootTestSupervisor(t, ctx, false) })
		return
	}
	if err := nativesandbox.ApplyLocalProcessLimits(); err != nil {
		t.Fatalf("dedicated supervisor limits: %v", err)
	}
	nativeActivationRoot(t)
}

func rootTestSupervisor(t *testing.T, parentContext context.Context, abrupt bool) {
	t.Helper()
	// The outer process owns both resources before the bounded supervisor starts.
	// A Go test timeout exits without running child cleanups; Pdeathsig alone
	// would kill only the master and could leave its workers behind.
	drained := true // No process exists until the supervisor is started below.
	work := rootTestWork(t, func() bool { return drained })
	group, mount, inode := rootTestCgroup(t, rootTestPath(t, "AGP_TEST_NATIVE_CGROUP_PARENT"))
	ctx, cancel := context.WithTimeout(parentContext, 190*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeActivationRoot$", "-test.v", "-test.timeout=170s")
	child.WaitDelay = 2 * time.Second
	child.ExtraFiles = []*os.File{group}
	child.Env = append(os.Environ(), "AGP_NATIVE_ACTIVATION_SUPERVISOR=1",
		"AGP_NATIVE_ACTIVATION_CGROUP_PATH="+group.Name(),
		"AGP_NATIVE_ACTIVATION_CGROUP_MOUNT="+strconv.FormatUint(mount, 10),
		"AGP_NATIVE_ACTIVATION_CGROUP_INODE="+strconv.FormatUint(inode, 10),
		"AGP_NATIVE_ACTIVATION_WORK_DIR="+work,
		"AGP_NATIVE_ACTIVATION_ABRUPT_EXIT="+strconv.FormatBool(abrupt))
	drained = false
	out, err := child.CombinedOutput() // CommandContext kills and Waits before returning.
	drainErr := rootTestDrainCgroup(group, mount, inode)
	if drainErr != nil {
		t.Fatalf("outer owner could not drain supervisor scope: %v\n%s", drainErr, out)
	}
	drained = true
	if abrupt {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 73 || !bytes.Contains(out, []byte("real master and nonroot worker ready before abrupt supervisor exit")) {
			t.Fatalf("abrupt exit did not reach real owned processes: %v\n%s", err, out)
		}
		t.Log("PASS outer pinned descriptor drained the real master/worker scope after supervisor os.Exit bypassed all child cleanups")
		return
	}
	if err != nil {
		t.Fatalf("root supervisor: %v\n%s", err, out)
	}
	t.Logf("%s", out)
}

func rootTestWork(t *testing.T, canRemove func() bool) string {
	t.Helper()
	work, err := os.MkdirTemp("/tmp", "agp-native-root-")
	if err != nil {
		t.Fatal(err)
	}
	var pin unix.Stat_t
	if unix.Lstat(work, &pin) != nil || pin.Uid != 0 || pin.Mode != unix.S_IFDIR|0700 {
		t.Fatal("private root work tree required")
	}
	t.Cleanup(func() {
		if !canRemove() {
			t.Errorf("owned processes could not be drained; preserving private test work tree %s", work)
			return
		}
		var named unix.Stat_t
		if unix.Lstat(work, &named) != nil || !same(pin, named) {
			t.Error("private test work tree replaced; refusing removal")
			return
		}
		_ = filepath.WalkDir(work, func(path string, entry os.DirEntry, err error) error {
			if err == nil && entry.IsDir() {
				_ = os.Chmod(path, 0700)
			}
			return nil
		})
		if err := os.RemoveAll(work); err != nil {
			t.Errorf("private test tree cleanup: %v", err)
		}
	})
	return work
}

type rootMasterInput struct {
	Runtime, Installation, Scratch, Namespace string
	UID, GID                                  uint32
}

func nativeActivationRoot(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	group, mount, inode := rootTestInheritedCgroup(t)
	uid := rootTestID(t, "AGP_TEST_EXECUTION_UID")
	gid := rootTestID(t, "AGP_TEST_EXECUTION_GID")
	runtimeDir := rootTestPath(t, "AGP_TEST_NATIVE_RUNTIME_DIR")
	manifestPath := rootTestPath(t, "AGP_TEST_NATIVE_RUNTIME_MANIFEST")
	manifestDigest := rootTestDigest(t, "AGP_TEST_NATIVE_RUNTIME_MANIFEST_DIGEST")
	parent, err := openDir(filepath.Dir(manifestPath), 0)
	if err != nil {
		t.Fatalf("protected runtime descriptor parent: %v", err)
	}
	var entries []RuntimeEntry
	data, err := readFile(parent.file(), filepath.Base(manifestPath), maxMetadata, 0)
	parent.close()
	if err != nil || configmodel.DigestBytes(data) != manifestDigest || rootTestDecodeCanonical(data, &entries, maxMetadata) != nil {
		t.Fatal("root-owned canonical runtime descriptor and its separate digest must match")
	}
	work := rootTestPath(t, "AGP_NATIVE_ACTIVATION_WORK_DIR")
	protectedWork, err := openDir(work, 0)
	if err != nil {
		t.Fatalf("outer-owned work tree: %v", err)
	}
	if err := exactNames(protectedWork.file(), nil); err != nil {
		protectedWork.close()
		t.Fatal("outer-owned work tree must initially be empty")
	}
	protectedWork.close()
	installation, scratch, repoDir := filepath.Join(work, "installation"), filepath.Join(work, "control"), filepath.Join(work, "repository")
	for _, path := range []string{installation, scratch, repoDir} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	// The outer owner independently repeats this operation after any supervisor
	// exit, including a hard timeout, before removing its private work tree.
	t.Cleanup(func() {
		if err := rootTestDrainCgroup(group, mount, inode); err != nil {
			t.Errorf("supervisor cgroup cleanup: %v", err)
		}
	})
	cfg := Config{
		RootDir: installation, RuntimeDir: runtimeDir,
		PIDFile: filepath.Join(scratch, "nginx.pid"), ProbeSocket: filepath.Join(scratch, "probe.sock"),
		Executable: filepath.Join(runtimeDir, "bin/nginx"),
		NodeID:     "native-root-node", SiteID: "native-root-site",
		QualificationDigest:   rootTestDigest(t, "AGP_TEST_NATIVE_QUALIFICATION_DIGEST"),
		ReleaseManifestDigest: rootTestDigest(t, "AGP_TEST_NATIVE_RELEASE_MANIFEST_DIGEST"),
		SandboxTool:           nativesandbox.Tool{Path: rootTestPath(t, "AGP_TEST_BWRAP_BIN"), Digest: rootTestDigest(t, "AGP_TEST_BWRAP_DIGEST")},
		ExecutionUID:          uid, ExecutionGID: gid, RuntimeEntries: entries,
		CgroupDir: group.Name(), CgroupMountID: mount, CgroupInode: inode,
	}
	for _, entry := range entries {
		if entry.Path == "bin/nginx" && entry.Kind == "file" {
			cfg.ExecutableDigest = entry.Digest
		}
	}
	if err := checkRuntimeTree(ctx, cfg, 0); err != nil {
		t.Fatalf("complete externally pinned runtime: %v", err)
	}
	rootTestInterpreter(t, cfg.Executable)
	cfg.LayoutDigest, err = LayoutDigest(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a, b := rootTestBundle(cfg, "native-root-a", "revision-a"), rootTestBundle(cfg, "native-root-b", "revision-b")
	manifest := RepositoryManifest{APIVersion: RepositoryVersion}
	for _, bundle := range []Bundle{a, b} {
		body, err := configmodel.CanonicalJSON(bundle)
		if err != nil {
			t.Fatal(err)
		}
		rootTestWrite(t, filepath.Join(repoDir, strings.TrimPrefix(bundle.BundleDigest, "sha256:")+".json"), body, 0400)
		manifest.Bundles = append(manifest.Bundles, BundlePin{BundleDigest: bundle.BundleDigest, ManifestDigest: configmodel.DigestBytes(body)})
	}
	sort.Slice(manifest.Bundles, func(i, j int) bool { return manifest.Bundles[i].BundleDigest < manifest.Bundles[j].BundleDigest })
	body, err := configmodel.CanonicalJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	rootTestWrite(t, filepath.Join(repoDir, "repository.json"), body, 0400)
	repository, err := OpenRepository(repoDir, configmodel.DigestBytes(body))
	if err != nil {
		t.Fatalf("production repository: %v", err)
	}
	defer repository.Close()
	base, err := repository.InitialGeneration(ctx, cfg, helper.Baseline{RevisionID: a.RevisionID, BundleDigest: a.BundleDigest, NodeDeploymentSequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := Initialize(cfg, repository, base); err != nil {
		t.Fatalf("explicit initial staging: %v", err)
	}
	master, masterDone := rootTestMaster(t, rootMasterInput{runtimeDir, installation, scratch, filepath.Join(work, "namespace"), uid, gid}, group, work)
	if err := rootTestAwait(ctx, func() error { return rootTestMasterPin(cfg, master.Process.Pid) }); err != nil {
		t.Fatalf("master must execute the exact Nginx inode, not ld-linux or host Nginx: %v", err)
	}
	// Nginx creates its Unix listener with permissive socket bits. The root
	// installation lifecycle must tighten this dedicated, privately contained
	// probe before any native runtime constructor accepts it.
	var socket unix.Stat_t
	if unix.Lstat(cfg.ProbeSocket, &socket) != nil || socket.Uid != 0 || socket.Mode&unix.S_IFMT != unix.S_IFSOCK || os.Chmod(cfg.ProbeSocket, 0600) != nil {
		t.Fatal("could not establish root-only private probe socket")
	}
	driver, err := Open(cfg, repository)
	if err != nil {
		t.Fatalf("production native driver: %v", err)
	}
	defer driver.Close()
	if err := rootTestAwait(ctx, func() error {
		got, err := driver.Snapshot(ctx)
		if err == nil && got != base {
			return ErrRuntime
		}
		return err
	}); err != nil {
		t.Fatalf("live initial generation: %v", err)
	}
	rootTestWorker(t, cfg, master.Process.Pid, uid)
	if os.Getenv("AGP_NATIVE_ACTIVATION_ABRUPT_EXIT") == "true" {
		fmt.Fprintln(os.Stdout, "real master and nonroot worker ready before abrupt supervisor exit")
		os.Exit(73) // Deliberately bypass child cleanups, as a Go hard timeout does.
	}
	request := helper.Request{Task: helper.Task{NodeID: cfg.NodeID, NodeDeploymentSequence: 2,
		Preconditions: helper.Preconditions{BaseRevisionID: base.Baseline.RevisionID, ExpectedNodeDeploymentSequence: 1},
		Payload:       helper.Payload{TargetRevisionID: b.RevisionID, BundleDigest: b.BundleDigest, DeploymentGeneration: b.GenerationID, RecoveryBaseBundleDigest: base.Baseline.BundleDigest}},
		Permit: helper.Permit{Recovery: helper.Recovery{BaseRevisionID: base.Baseline.RevisionID, BaseBundleDigest: base.Baseline.BundleDigest}}}
	target, err := driver.Prepare(ctx, request, base)
	if err != nil {
		t.Fatalf("prepare B from live A: %v", err)
	}
	if err := driver.Validate(ctx, target); err != nil {
		t.Fatalf("real nonroot sealed sandbox nginx -t: %v", err)
	}
	if err := driver.Activate(ctx, base, target); err != nil {
		t.Fatalf("atomic activation: %v", err)
	}
	if err := driver.Reload(ctx, target); err != nil {
		t.Fatalf("pidfd SIGHUP: %v", err)
	}
	if err := driver.Verify(ctx, target); err != nil {
		t.Fatalf("live B generation/challenge probes immediately after Reload: %v", err)
	}
	if err := rootTestMasterPin(cfg, master.Process.Pid); err != nil {
		t.Fatalf("master identity changed across reload: %v", err)
	}
	if err := driver.Recover(ctx, target, base); err != nil {
		t.Fatalf("exact A recovery including live verification: %v", err)
	}
	got, err := driver.Snapshot(ctx)
	if err != nil || got != base {
		t.Fatalf("recovery must restore exact A including serving sequence 1: %+v %v", got, err)
	}
	if err := driver.Contain(ctx); err != nil {
		t.Fatalf("real pinned cgroup containment: %v", err)
	}
	events, err := os.ReadFile(filepath.Join(cfg.CgroupDir, "cgroup.events"))
	active, parseErr := populated(events)
	if err != nil || parseErr != nil || active {
		t.Fatalf("contained group still populated: %v %v", err, parseErr)
	}
	select {
	case <-masterDone:
	case <-time.After(5 * time.Second):
		t.Fatal("contained master was not reaped")
	}
	if err := master.Process.Signal(syscall.Signal(0)); !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, unix.ESRCH) {
		t.Fatalf("contained master remains live: %v", err)
	}
	t.Log("PASS real root Nginx A1 -> B2 -> exact A1, pinned master SIGHUP, nonroot syntax sandbox, generation/challenge Unix probes, and owned cgroup.kill; auth/WAF statuses are synthetic plumbing observations, NOT full auth/WAF qualification")
}

func rootTestBundle(cfg Config, id, revision string) Bundle {
	config := fmt.Sprintf(`daemon off;
master_process on;
worker_processes 1;
user agp_native_test agp_native_test;
pid /scratch/nginx.pid;
error_log stderr notice;
events { worker_connections 32; }
http {
  access_log off;
  client_body_temp_path /scratch/body;
  proxy_temp_path /scratch/proxy;
  fastcgi_temp_path /scratch/fastcgi;
  uwsgi_temp_path /scratch/uwsgi;
  scgi_temp_path /scratch/scgi;
  server {
    listen unix:/scratch/probe.sock;
    server_name native-root.test;
    add_header X-AGP-Generation %s always;
    add_header X-AGP-Probe-Challenge $http_x_agp_probe_challenge always;
    location = /route { return 200 'routed'; }
    location = /auth { return 401 'unauthorized'; }
    location = /waf { return 403 'blocked'; }
    location / { return 404; }
  }
}
`, id)
	b := Bundle{APIVersion: BundleVersion, NodeID: cfg.NodeID, RevisionID: revision, GenerationID: id,
		QualificationDigest: cfg.QualificationDigest, ReleaseManifestDigest: cfg.ReleaseManifestDigest,
		Files: []File{{Path: "nginx.conf", Content: config, Digest: configmodel.DigestBytes([]byte(config))}}}
	for _, p := range []struct {
		kind, path, body string
		status           int
	}{{"route", "/route", "routed", 200}, {"auth-deny", "/auth", "unauthorized", 401}, {"waf-deny", "/waf", "blocked", 403}} {
		b.Probes = append(b.Probes, Probe{Kind: p.kind, Path: p.path, Host: "native-root.test", Status: p.status, BodyDigest: configmodel.DigestBytes([]byte(p.body))})
	}
	// This local operational fixture is not a signed configuration materialization.
	b.BundleDigest, _ = configmodel.Digest(b)
	return b
}

func rootTestID(t *testing.T, key string) uint32 {
	t.Helper()
	v, err := strconv.ParseUint(os.Getenv(key), 10, 32)
	if err != nil || v == 0 || v == 1<<32-1 {
		t.Fatalf("%s must be an explicitly selected nonroot ID", key)
	}
	return uint32(v)
}

func rootTestPath(t *testing.T, key string) string {
	t.Helper()
	p := os.Getenv(key)
	if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, "\x00\r\n") {
		t.Fatalf("%s must be an explicit clean absolute path", key)
	}
	return p
}

func rootTestDigest(t *testing.T, key string) string {
	t.Helper()
	d := os.Getenv(key)
	if !configmodel.ValidDigest(d) {
		t.Fatalf("%s must be a separately supplied sha256 digest", key)
	}
	return d
}

func rootTestWrite(t *testing.T, path string, body []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, body, mode); err != nil {
		t.Fatal(err)
	}
}

func rootTestCgroup(t *testing.T, path string) (*os.File, uint64, uint64) {
	t.Helper()
	if path != "/sys/fs/cgroup" && !strings.HasPrefix(path, "/sys/fs/cgroup/") {
		t.Fatal("test cgroup parent must be on the actual /sys/fs/cgroup mount")
	}
	parent, err := openDirPolicy(path, 0, false)
	if err != nil {
		t.Fatalf("protected cgroup parent: %v", err)
	}
	defer parent.close()
	name, err := randomName("agp-native-test-")
	if err != nil || unix.Mkdirat(int(parent.file().Fd()), name, 0700) != nil {
		t.Fatal("could not create a dedicated child cgroup")
	}
	fullPath := filepath.Join(path, name)
	fd, err := unix.Open(fullPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = os.Remove(fullPath)
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), fullPath)
	var stat unix.Stat_t
	mount, err := mountID(fd)
	if err != nil || unix.Fstat(fd, &stat) != nil {
		f.Close()
		_ = os.Remove(fullPath)
		t.Fatal("could not pin child cgroup")
	}
	t.Cleanup(func() {
		defer f.Close()
		if err := rootTestDrainCgroup(f, mount, stat.Ino); err != nil {
			t.Errorf("outer test cgroup cleanup: %v", err)
			return
		}
		var named unix.Stat_t
		if unix.Lstat(fullPath, &named) != nil || !same(stat, named) {
			t.Error("test cgroup was replaced; refusing removal")
			return
		}
		if err := os.Remove(fullPath); err != nil {
			t.Errorf("test cgroup removal: %v", err)
		}
	})
	return f, mount, stat.Ino
}

func rootTestInheritedCgroup(t *testing.T) (*os.File, uint64, uint64) {
	t.Helper()
	// ExtraFiles slot 3 belongs only to the root supervisor. Do not leak a host
	// cgroup descriptor through a later sandbox or chroot/direct Nginx exec.
	unix.CloseOnExec(3)
	path := rootTestPath(t, "AGP_NATIVE_ACTIVATION_CGROUP_PATH")
	mount, mountErr := strconv.ParseUint(os.Getenv("AGP_NATIVE_ACTIVATION_CGROUP_MOUNT"), 10, 64)
	inode, inodeErr := strconv.ParseUint(os.Getenv("AGP_NATIVE_ACTIVATION_CGROUP_INODE"), 10, 64)
	if mountErr != nil || inodeErr != nil || mount == 0 || inode == 0 || !strings.HasPrefix(filepath.Base(path), "agp-native-test-") {
		t.Fatal("outer-owned pinned cgroup required")
	}
	f := os.NewFile(3, path)
	if f == nil {
		t.Fatal("inherited cgroup descriptor required")
	}
	t.Cleanup(func() { _ = f.Close() })
	actualMount, err := mountID(3)
	var inherited, named unix.Stat_t
	protected, _, openErr := openCgroup(Config{CgroupDir: path, CgroupMountID: mount, CgroupInode: inode})
	if openErr != nil {
		t.Fatalf("inherited cgroup protected identity: %v", openErr)
	}
	defer protected.close()
	if err != nil || actualMount != mount || unix.Fstat(3, &inherited) != nil || unix.Fstat(int(protected.file().Fd()), &named) != nil || !same(inherited, named) || inherited.Ino != inode || inherited.Uid != 0 || inherited.Mode&unix.S_IFMT != unix.S_IFDIR {
		t.Fatal("inherited cgroup descriptor does not match its protected device/inode/mount/path")
	}
	return f, mount, inode
}

// Drain uses the owner's descriptor rather than a freshly resolved path. It
// remains available after the supervisor dies and never selects another scope.
func rootTestDrainCgroup(group *os.File, mount, inode uint64) error {
	fd := int(group.Fd())
	actualMount, err := mountID(fd)
	var directory unix.Stat_t
	if err != nil || actualMount != mount || unix.Fstat(fd, &directory) != nil || directory.Ino != inode || directory.Uid != 0 || directory.Mode&unix.S_IFMT != unix.S_IFDIR || directory.Nlink == 0 {
		return errors.New("owned cgroup descriptor changed")
	}
	killfd, err := unix.Openat(fd, "cgroup.kill", unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	n, err := unix.Write(killfd, []byte("1\n"))
	unix.Close(killfd)
	if err != nil || n != 2 {
		return errors.New("owned cgroup kill failed")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		body, readErr := readKernelFile(group, "cgroup.events", 4096)
		active, parseErr := populated(body)
		if readErr == nil && parseErr == nil && !active {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("owned cgroup did not become empty during cleanup")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func rootTestMaster(t *testing.T, input rootMasterInput, group *os.File, work string) (*exec.Cmd, <-chan struct{}) {
	t.Helper()
	for _, path := range []string{input.Namespace, filepath.Join(input.Namespace, "runtime"), filepath.Join(input.Namespace, "installation"), filepath.Join(input.Namespace, "scratch"), filepath.Join(input.Namespace, "lib64"), filepath.Join(input.Namespace, "etc")} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	rootTestWrite(t, filepath.Join(input.Namespace, "etc/passwd"), []byte(fmt.Sprintf("agp_native_test:x:%d:%d:Native activation test:/nonexistent:/nonexistent\n", input.UID, input.GID)), 0400)
	rootTestWrite(t, filepath.Join(input.Namespace, "etc/group"), []byte(fmt.Sprintf("agp_native_test:x:%d:\n", input.GID)), 0400)
	data, err := configmodel.CanonicalJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(work, "master-input.json")
	rootTestWrite(t, inputPath, data, 0400)
	output, err := os.OpenFile(filepath.Join(work, "master.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	master := exec.Command(os.Args[0], "-test.run=^TestNativeActivationRootMaster$", "-test.v")
	master.Env = []string{"LANG=C", "LC_ALL=C", "AGP_TEST_NATIVE_ROOT_REQUIRED=1", "AGP_NATIVE_ACTIVATION_MASTER=" + inputPath}
	master.Stdout, master.Stderr = output, output
	master.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS | unix.CLONE_NEWNET, UseCgroupFD: true, CgroupFD: int(group.Fd()), Pdeathsig: syscall.SIGKILL}
	if err := master.Start(); err != nil {
		output.Close()
		t.Fatalf("root master namespace/cgroup spawn: %v", err)
	}
	done := make(chan struct{})
	go func() {
		_ = master.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		_ = master.Process.Kill()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("owned master did not exit during cleanup")
		}
		_ = output.Close()
		if t.Failed() {
			data, err := os.ReadFile(filepath.Join(work, "master.log"))
			if err == nil {
				if len(data) > 64<<10 {
					data = data[len(data)-(64<<10):]
				}
				t.Logf("synthetic master diagnostic:\n%s", data)
			}
		}
	})
	return master, done
}

func rootTestAwait(ctx context.Context, fn func() error) error {
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := fn()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return err
		case <-ticker.C:
		}
	}
}

func rootTestMasterPin(cfg Config, pid int) error {
	data, err := os.ReadFile(cfg.PIDFile)
	if err != nil || strings.TrimSpace(string(data)) != strconv.Itoa(pid) {
		return ErrRuntime
	}
	want, err := os.Stat(cfg.Executable)
	if err != nil {
		return err
	}
	got, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil || !os.SameFile(want, got) {
		return ErrRuntime
	}
	return nil
}

func rootTestWorker(t *testing.T, cfg Config, master int, uid uint32) {
	t.Helper()
	err := rootTestAwait(context.Background(), func() error {
		members, err := os.ReadFile(filepath.Join(cfg.CgroupDir, "cgroup.procs"))
		if err != nil {
			return err
		}
		for _, text := range strings.Fields(string(members)) {
			if text == strconv.Itoa(master) {
				continue
			}
			status, err := os.ReadFile("/proc/" + text + "/status")
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(status), "\n") {
				fields := strings.Fields(line)
				if len(fields) == 5 && fields[0] == "Uid:" && fields[1] == strconv.FormatUint(uint64(uid), 10) && fields[2] == fields[1] && fields[3] == fields[1] && fields[4] == fields[1] {
					return nil
				}
			}
		}
		return ErrRuntime
	})
	if err != nil {
		t.Fatalf("actual nonroot Nginx worker in owned cgroup: %v", err)
	}
}

func rootTestInterpreter(t *testing.T, executable string) {
	t.Helper()
	f, err := elf.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			value, err := io.ReadAll(io.LimitReader(p.Open(), 4096))
			if err != nil || !bytes.Equal(value, []byte("/lib64/ld-linux-x86-64.so.2\x00")) {
				t.Fatal("qualified Nginx requires an unsupported ELF interpreter; never substitute loader as executable pin")
			}
			return
		}
	}
	t.Fatal("qualified Nginx must have the expected pinned dynamic interpreter")
}

// This subprocess is selected only by the explicit root test. A private mount
// namespace supplies the qualified loader to direct ELF exec; it never mounts
// over host /lib, changes a platform allowlist, or invokes Nginx through loader
// argv (which would make /proc/<master>/exe name the wrong executable).
func TestNativeActivationRootMaster(t *testing.T) {
	path := os.Getenv("AGP_NATIVE_ACTIVATION_MASTER")
	if path == "" {
		t.Skip("internal real-master subprocess")
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("root master subprocess required")
	}
	if os.Getenv("AGP_TEST_NATIVE_ROOT_REQUIRED") != "1" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		t.Fatal("explicit private root master setup required")
	}
	// Refuse to mount or change propagation in the caller's mount namespace,
	// including accidental direct invocation of this internal subprocess test.
	for _, namespace := range []string{"mnt", "net"} {
		self, err := os.Stat("/proc/self/ns/" + namespace)
		parent, parentErr := os.Stat(fmt.Sprintf("/proc/%d/ns/%s", os.Getppid(), namespace))
		if err != nil || parentErr != nil || os.SameFile(self, parent) {
			t.Fatal("dedicated child mount and network namespaces required")
		}
	}
	parent, err := openDir(filepath.Dir(path), 0)
	if err != nil {
		t.Fatal(err)
	}
	data, err := readFile(parent.file(), filepath.Base(path), 4096, 0)
	parent.close()
	if err != nil {
		t.Fatal("protected child setup required")
	}
	var input rootMasterInput
	if rootTestDecodeCanonical(data, &input, 4096) != nil || input.UID == 0 || input.GID == 0 || input.UID == 1<<32-1 || input.GID == 1<<32-1 || input.Namespace != filepath.Join(filepath.Dir(path), "namespace") || input.Installation != filepath.Join(filepath.Dir(path), "installation") || input.Scratch != filepath.Join(filepath.Dir(path), "control") {
		t.Fatal("closed master setup required")
	}
	for _, directory := range []string{input.Runtime, input.Installation, input.Scratch, input.Namespace, filepath.Join(input.Namespace, "runtime"), filepath.Join(input.Namespace, "installation"), filepath.Join(input.Namespace, "scratch"), filepath.Join(input.Namespace, "lib64"), filepath.Join(input.Namespace, "etc")} {
		protected, err := openDir(directory, 0)
		if err != nil {
			t.Fatal("root-protected namespace sources and destinations required")
		}
		protected.close()
	}
	if err := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
		t.Fatalf("private mount namespace: %v", err)
	}
	for _, binding := range []struct {
		source, destination string
		readOnly            bool
	}{{input.Runtime, "runtime", true}, {filepath.Join(input.Runtime, "lib"), "lib64", true}, {input.Installation, "installation", true}, {input.Scratch, "scratch", false}} {
		destination := filepath.Join(input.Namespace, binding.destination)
		if err := unix.Mount(binding.source, destination, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			t.Fatalf("test namespace bind: %v", err)
		}
		flags := uintptr(unix.MS_BIND | unix.MS_REMOUNT | unix.MS_NOSUID | unix.MS_NODEV)
		if binding.readOnly {
			flags |= unix.MS_RDONLY
		}
		if err := unix.Mount("", destination, "", flags, ""); err != nil {
			t.Fatalf("test namespace mount policy: %v", err)
		}
	}
	if err := unix.Chroot(input.Namespace); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chdir("/scratch"); err != nil {
		t.Fatal(err)
	}
	unix.Umask(0077)
	if err := syscall.Exec("/runtime/bin/nginx", []string{"nginx", "-e", "stderr", "-p", "/scratch/", "-c", "/installation/active/nginx.conf"}, []string{"LANG=C", "LC_ALL=C", "LD_LIBRARY_PATH=/runtime/lib"}); err != nil {
		t.Fatalf("direct qualified Nginx exec: %v", err)
	}
}

// Installer types intentionally retain their Go field names and numeric fields.
// They are not HTTP DTOs accepted by configmodel.StrictJSON. Bound and preflight
// the complete value inside an object, then require exact canonical typed bytes
// so encoding/json's case-insensitive field aliases cannot become extra syntax.
func rootTestDecodeCanonical(data []byte, out any, limit int) error {
	if len(data) == 0 || len(data) > limit {
		return ErrInstallation
	}
	wrapped := make([]byte, 0, len(data)+10)
	wrapped = append(wrapped, `{"value":`...)
	wrapped = append(wrapped, data...)
	wrapped = append(wrapped, '}')
	if err := configmodel.ValidateJSON(wrapped); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return ErrInstallation
	}
	canonical, err := configmodel.CanonicalJSON(out)
	if err != nil || !bytes.Equal(canonical, data) {
		return ErrInstallation
	}
	return nil
}

func TestNativeActivationRootInstallerCodec(t *testing.T) {
	entries := []RuntimeEntry{
		{Path: ".", Kind: "directory", Mode: 0700},
		{Path: "bin", Kind: "directory", Mode: 0700},
		{Path: "bin/nginx", Kind: "file", Mode: 0500, Size: 12345, Digest: configmodel.DigestBytes([]byte("qualified-nginx"))},
	}
	canonical, err := configmodel.CanonicalJSON(entries)
	if err != nil {
		t.Fatal(err)
	}
	var got []RuntimeEntry
	if err := rootTestDecodeCanonical(canonical, &got, maxMetadata); err != nil || len(got) != len(entries) || got[2] != entries[2] {
		t.Fatalf("canonical uppercase installer fields and numeric modes/sizes: %+v %v", got, err)
	}
	for name, data := range map[string][]byte{
		"case_alias":   bytes.Replace(canonical, []byte(`"Path"`), []byte(`"path"`), 1),
		"unknown":      bytes.Replace(canonical, []byte(`"Path":"."`), []byte(`"Path":".","Unknown":true`), 1),
		"duplicate":    bytes.Replace(canonical, []byte(`"Path":"."`), []byte(`"Path":".","Path":"."`), 1),
		"string_mode":  bytes.Replace(canonical, []byte(`"Mode":448`), []byte(`"Mode":"448"`), 1),
		"trailing":     append(append([]byte(nil), canonical...), []byte(" null")...),
		"noncanonical": append([]byte(" "), canonical...),
	} {
		t.Run(name, func(t *testing.T) {
			var rejected []RuntimeEntry
			if err := rootTestDecodeCanonical(data, &rejected, maxMetadata); err == nil {
				t.Fatal("non-exact installer encoding accepted")
			}
		})
	}
	if err := rootTestDecodeCanonical(canonical, &got, len(canonical)-1); err == nil {
		t.Fatal("installer descriptor byte limit ignored")
	}
	input := rootMasterInput{Runtime: "/opt/agp-lab/native-runtime", Installation: "/tmp/private/installation", Scratch: "/tmp/private/control", Namespace: "/tmp/private/namespace", UID: 1001, GID: 1001}
	data, err := configmodel.CanonicalJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	var decoded rootMasterInput
	if err := rootTestDecodeCanonical(data, &decoded, 4096); err != nil || decoded != input {
		t.Fatalf("closed canonical master setup: %+v %v", decoded, err)
	}
}
