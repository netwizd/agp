//go:build linux

package nativeactivation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func cgroupMembership(b []byte) (string, error) {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "0::/") {
		return "", ErrInstallation
	}
	s := strings.TrimPrefix(lines[0], "0::")
	if filepath.Clean(s) != s || strings.ContainsAny(s, "\x00\r\n\\") {
		return "", ErrInstallation
	}
	return s, nil
}
func memberOf(actual, target string) bool {
	return actual == target || strings.HasPrefix(actual, target+"/")
}
func populated(b []byte) (bool, error) {
	seen := false
	value := false
	keys := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || keys[f[0]] || (f[1] != "0" && f[1] != "1") {
			return false, ErrRuntime
		}
		keys[f[0]] = true
		switch f[0] {
		case "populated":
			seen = true
			value = f[1] == "1"
		case "frozen":
		default:
			return false, ErrRuntime
		}
	}
	if !seen {
		return false, ErrRuntime
	}
	return value, nil
}
func openCgroup(c Config) (*protectedDir, string, error) {
	if !strings.HasPrefix(c.CgroupDir, "/sys/fs/cgroup/") || filepath.Clean(c.CgroupDir) != c.CgroupDir || c.CgroupMountID == 0 || c.CgroupInode == 0 {
		return nil, "", ErrInstallation
	}
	d, e := openDirPolicy(c.CgroupDir, 0, false)
	if e != nil {
		return nil, "", e
	}
	fail := func() (*protectedDir, string, error) { d.close(); return nil, "", ErrInstallation }
	last := d.pins[len(d.pins)-1]
	var fs unix.Statfs_t
	if last.mount != c.CgroupMountID || last.st.Ino != c.CgroupInode || unix.Fstatfs(int(d.file().Fd()), &fs) != nil || uint64(fs.Type) != uint64(unix.CGROUP2_SUPER_MAGIC) {
		return fail()
	}
	// A namespaced/subtree mount must be separately qualified; it cannot
	// reinterpret the installer-selected service cgroup identity.
	b, e := os.ReadFile("/proc/self/mountinfo")
	if e != nil || len(b) > 4<<20 {
		return fail()
	}
	valid := false
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		id, ie := strconv.ParseUint(f[0], 10, 64)
		if ie != nil || id != c.CgroupMountID {
			continue
		}
		sep := -1
		for i, s := range f {
			if s == "-" {
				sep = i
				break
			}
		}
		if f[3] == "/" && f[4] == "/sys/fs/cgroup" && sep > 0 && sep+1 < len(f) && f[sep+1] == "cgroup2" {
			valid = true
		}
	}
	if !valid {
		return fail()
	}
	target := strings.TrimPrefix(c.CgroupDir, "/sys/fs/cgroup")
	self, e := os.ReadFile("/proc/self/cgroup")
	if e != nil {
		return fail()
	}
	membership, e := cgroupMembership(self)
	if e != nil || memberOf(membership, target) {
		return fail()
	}
	if _, e = readKernelFile(d.file(), "cgroup.events", 4096); e != nil {
		return fail()
	}
	fd, e := unix.Openat(int(d.file().Fd()), "cgroup.kill", unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return fail()
	}
	unix.Close(fd)
	return d, target, nil
}
func readKernelFile(dir *os.File, name string, max int) ([]byte, error) {
	f, e := openChild(dir, name, false, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if e != nil || len(b) > max || len(b) == 0 {
		return nil, ErrRuntime
	}
	return b, nil
}

func checkContainmentMaster(ctx context.Context, cfg Config, target string, owner uint32) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	parent, e := openDir(filepath.Dir(cfg.PIDFile), owner)
	if e != nil {
		return ErrRuntime
	}
	defer parent.close()
	var pidFile unix.Stat_t
	if e = unix.Fstatat(int(parent.file().Fd()), filepath.Base(cfg.PIDFile), &pidFile, unix.AT_SYMLINK_NOFOLLOW); errors.Is(e, unix.ENOENT) {
		return parent.check()
	} else if e != nil {
		return ErrRuntime
	}
	bytes, e := readFile(parent.file(), filepath.Base(cfg.PIDFile), 32, owner)
	if e != nil {
		return ErrRuntime
	}
	text := strings.TrimSuffix(string(bytes), "\n")
	pid, e := strconv.Atoi(text)
	if e != nil || pid <= 1 || strconv.Itoa(pid) != text {
		return ErrRuntime
	}
	pidfd, e := unix.PidfdOpen(pid, 0)
	// An installer-pinned service cgroup still contains orphan workers after
	// its master disappears. Absence does not revoke containment authority.
	if errors.Is(e, unix.ESRCH) {
		return parent.check()
	}
	if e != nil {
		return ErrRuntime
	}
	defer unix.Close(pidfd)
	start, e := processStart(pid)
	if e != nil {
		return ErrRuntime
	}
	exe, e := os.Open("/proc/" + text + "/exe")
	if e != nil {
		return ErrRuntime
	}
	h := sha256.New()
	n, he := io.Copy(h, io.LimitReader(exe, (256<<20)+1))
	exe.Close()
	if he != nil || n < 1 || n > 256<<20 || "sha256:"+hex.EncodeToString(h.Sum(nil)) != cfg.ExecutableDigest {
		return ErrRuntime
	}
	status, e := os.ReadFile("/proc/" + text + "/status")
	if e != nil || !rootProcess(status) {
		return ErrRuntime
	}
	membershipBytes, e := os.ReadFile("/proc/" + text + "/cgroup")
	if e != nil {
		return ErrRuntime
	}
	membership, e := cgroupMembership(membershipBytes)
	if e != nil || membership != target {
		return ErrInstallation
	}
	end, e := processStart(pid)
	if e != nil || start != end || parent.check() != nil || unix.PidfdSendSignal(pidfd, 0, nil, 0) != nil {
		return ErrRuntime
	}
	return nil
}

func (r *nativeRuntime) contain(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if e := ctx.Err(); e != nil {
		return e
	}
	group, target, e := openCgroup(r.cfg)
	if e != nil {
		return e
	}
	defer group.close()
	return containGroup(ctx, func() error {
		err := checkContainmentMaster(ctx, r.cfg, target, 0)
		r.containmentMasterObservation = "confirmed"
		if err != nil {
			r.containmentMasterObservation = "unconfirmed"
		}
		return err
	}, func() error { return killGroup(group, r.cfg) }, func() ([]byte, error) {
		if group.check() != nil {
			return nil, ErrRuntime
		}
		return readKernelFile(group.file(), "cgroup.events", 4096)
	})
}

func killGroup(group *protectedDir, cfg Config) error {
	// Kernel recursive process containment avoids orphaned Nginx workers when
	// the master cannot reload or restore the verified previous generation.
	fd, e := unix.Openat(int(group.file().Fd()), "cgroup.kill", unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return ErrRuntime
	}
	f := os.NewFile(uintptr(fd), "cgroup.kill")
	var st, named unix.Stat_t
	mount, me := mountID(fd)
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0022 != 0 || mount != cfg.CgroupMountID || me != nil || unix.Fstatat(int(group.file().Fd()), "cgroup.kill", &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !same(st, named) || group.check() != nil {
		f.Close()
		return ErrRuntime
	}
	if n, e := f.Write([]byte("1\n")); e != nil || n != 2 {
		f.Close()
		return ErrRuntime
	}
	f.Close()
	return nil
}

// The independently verified installation-selected cgroup is the authority.
// PID reuse, an unrelated live PID or exit during observation does not change
// which group can be killed. Master observation is diagnostic only; it never
// selects a process/cgroup or vetoes containment of the already pinned group.
// This private seam permits nonprivileged tests without kernel cgroup writes.
func containGroup(ctx context.Context, checkMaster func() error, kill func() error, events func() ([]byte, error)) error {
	_ = checkMaster()
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := kill(); e != nil {
		return e
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		b, e := events()
		if e != nil {
			return e
		}
		active, e := populated(b)
		if e != nil {
			return e
		}
		if !active {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
