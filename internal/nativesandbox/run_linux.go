//go:build linux

package nativesandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// boundedDiscard deliberately never retains native diagnostics: arbitrary
// config and secret values in stderr must not enter a receipt or server log.
type boundedDiscard struct {
	mu       sync.Mutex
	count    int
	overflow bool
	cancel   context.CancelFunc
}

func (w *boundedDiscard) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.count += len(p)
	if w.count > 64<<10 {
		w.overflow = true
		w.cancel()
	}
	return len(p), nil
}
func (w *boundedDiscard) exceeded() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.overflow }

func (r *Runner) run(ctx context.Context, s Spec, argv []string) error {
	if r == nil || !r.currentIdentity() || !safeCredentials() {
		return ErrUnavailable
	}
	if e := CheckLimits(); e != nil {
		return e
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	limited, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tool, p, e := openTool(r.tool)
	if e != nil {
		return e
	}
	defer tool.Close()
	if !sameStat(r.pin, p) {
		return ErrTool
	}
	runtimeTree, e := capture(limited, s.RuntimeDir, false)
	if e != nil {
		return e
	}
	defer runtimeTree.close()
	configTree, e := capture(limited, s.ConfigDir, true)
	if e != nil {
		return e
	}
	defer configTree.close()
	if !hasFile(runtimeTree, s.LoaderPath, true) || !hasFile(runtimeTree, s.NginxPath, true) || !hasFile(configTree, "nginx.conf", false) {
		return ErrInput
	}
	args := []string{"--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-net", "--unshare-uts", "--disable-userns", "--assert-userns-disabled", "--cap-drop", "ALL", "--die-with-parent", "--new-session", "--clearenv", "--setenv", "LANG", "C", "--setenv", "LC_ALL", "C", "--setenv", "HOME", "/nonexistent", "--setenv", "TMPDIR", "/scratch", "--hostname", "agp-syntax", "--proc", "/proc", "--dev", "/dev", "--size", strconv.Itoa(64 << 20), "--tmpfs", "/scratch", "--dir", "/runtime", "--dir", "/config"}
	args = append(args, "--perms", "0000", "--ro-bind-data", "3", "/launcher-pin")
	files := []*os.File{tool}
	for i, tree := range []*snapshot{runtimeTree, configTree} {
		root := "/runtime"
		if i == 1 {
			root = "/config"
		}
		for _, item := range tree.entries {
			dest := root + "/" + item.name
			if item.file == nil {
				args = append(args, "--dir", dest)
				continue
			}
			fd := len(files) + 3
			files = append(files, item.file)
			args = append(args, "--perms", fmt.Sprintf("%04o", item.mode&0777), "--ro-bind-data", strconv.Itoa(fd), dest)
		}
	}
	args = append(args, "--remount-ro", "/dev", "--remount-ro", "/", "--chdir", "/config", "--")
	args = append(args, argv...)
	cmd := exec.CommandContext(limited, "/proc/self/fd/3", args...)
	cmd.Args[0] = "agp-syntax-sandbox"
	cmd.ExtraFiles = files
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL, AmbientCaps: nil}
	if r.rootBridge {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: r.executionUID, Gid: r.executionGID, Groups: []uint32{}, NoSetGroups: false}
	}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		e := unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
		if errors.Is(e, unix.ESRCH) {
			return os.ErrProcessDone
		}
		return e
	}
	cmd.WaitDelay = 2 * time.Second
	out := &boundedDiscard{cancel: cancel}
	cmd.Stdout = out
	cmd.Stderr = out
	e = cmd.Run()
	// Bubblewrap's PID-namespace reaper also kills setsid descendants when the
	// payload exits. This closes the outer process group on every return path.
	if cmd.Process != nil {
		_ = unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
	}
	// Reopen the root-owned tool and all source trees; execution used immutable
	// sealed snapshots, so drift never changes what the sandbox was given.
	verifyCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer stop()
	after, pin, te := openTool(r.tool)
	if after != nil {
		after.Close()
	}
	if te != nil || !sameStat(r.pin, pin) {
		return ErrTool
	}
	if runtimeTree.verify(verifyCtx) != nil || configTree.verify(verifyCtx) != nil {
		return ErrInput
	}
	if out.exceeded() {
		return ErrOutput
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if limited.Err() != nil {
		return limited.Err()
	}
	if e != nil {
		return ErrRejected
	}
	return nil
}
func hasFile(s *snapshot, name string, executable bool) bool {
	for _, e := range s.entries {
		if e.name == name && e.file != nil {
			return !executable || e.mode&0100 != 0
		}
	}
	return false
}

func (r *Runner) currentIdentity() bool {
	if r == nil || r.executionUID == 0 || r.executionGID == 0 || r.executionUID == ^uint32(0) || r.executionGID == ^uint32(0) || os.Getuid() != os.Geteuid() {
		return false
	}
	if r.rootBridge {
		return os.Geteuid() == 0 && r.callerUID == 0
	}
	return uint32(os.Geteuid()) == r.callerUID && r.callerUID == r.executionUID && uint32(os.Getegid()) == r.executionGID
}

// An inherited ambient capability or nonstandard securebits could otherwise
// survive exec or change the kernel's UID-drop rules. The profile does not try
// to repair its supervisor; an unexpected credential state fails closed.
func safeCredentials() bool {
	bits, e := unix.PrctlRetInt(unix.PR_GET_SECUREBITS, 0, 0, 0, 0)
	if e != nil || bits != 0 {
		return false
	}
	for cap := uintptr(0); cap < 64; cap++ {
		v, e := unix.PrctlRetInt(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_IS_SET, cap, 0, 0)
		if errors.Is(e, unix.EINVAL) && cap > 0 {
			break
		}
		if e != nil || v != 0 {
			return false
		}
	}
	return true
}
