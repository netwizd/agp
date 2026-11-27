//go:build linux

package nativeactivation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/helper"
	"github.com/netwizd/agp/internal/nativesandbox"
	"golang.org/x/sys/unix"
)

type nativeRuntime struct {
	cfg                          Config
	sandbox                      *nativesandbox.Runner
	containmentMasterObservation string
}

func newNativeRuntime(c Config) (*nativeRuntime, error) {
	for _, p := range []string{c.RootDir, c.RuntimeDir, c.PIDFile, c.Executable, c.ProbeSocket} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, "\x00\r\n") {
			return nil, ErrInstallation
		}
	}
	if !configmodel.ValidDigest(c.ExecutableDigest) || c.ExecutionUID == 0 || c.ExecutionGID == 0 {
		return nil, ErrInstallation
	}
	if e := checkRuntimeTree(context.Background(), c, 0); e != nil {
		return nil, e
	}
	group, _, e := openCgroup(c)
	if e != nil {
		return nil, e
	}
	group.close()
	r, e := nativesandbox.NewAsUser(c.SandboxTool, c.ExecutionUID, c.ExecutionGID)
	if e != nil {
		return nil, ErrInstallation
	}
	return &nativeRuntime{cfg: c, sandbox: r}, nil
}
func (r *nativeRuntime) validate(ctx context.Context, tree string) error {
	if e := checkRuntimeTree(ctx, r.cfg, 0); e != nil {
		return e
	}
	if e := r.sandbox.RunNginx(ctx, nativesandbox.Spec{RuntimeDir: r.cfg.RuntimeDir, ConfigDir: tree, LoaderPath: "lib/ld-linux-x86-64.so.2", NginxPath: "bin/nginx"}); e != nil {
		return e
	}
	return checkRuntimeTree(ctx, r.cfg, 0)
}

// reload signals an already-running, root-owned, executable-pinned master via
// pidfd. It never accepts a PID/argv/unit from a request or starts a process.
func (r *nativeRuntime) reload(ctx context.Context) error {
	if e := checkRuntimeTree(ctx, r.cfg, 0); e != nil {
		return e
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	parent, e := openDir(filepath.Dir(r.cfg.PIDFile), 0)
	if e != nil {
		return ErrRuntime
	}
	defer parent.close()
	bytes, e := readFile(parent.file(), filepath.Base(r.cfg.PIDFile), 32, 0)
	if e != nil {
		return ErrRuntime
	}
	pidText := strings.TrimSuffix(string(bytes), "\n")
	pid, e := strconv.Atoi(pidText)
	if e != nil || pid <= 1 || strconv.Itoa(pid) != pidText {
		return ErrRuntime
	}
	pidfd, e := unix.PidfdOpen(pid, 0)
	if e != nil {
		return ErrRuntime
	}
	defer unix.Close(pidfd)
	start, e := processStart(pid)
	if e != nil {
		return ErrRuntime
	}
	exe, e := os.Open("/proc/" + pidText + "/exe")
	if e != nil {
		return ErrRuntime
	}
	defer exe.Close()
	var before, after unix.Stat_t
	if unix.Fstat(int(exe.Fd()), &before) != nil || before.Uid != 0 || before.Mode&0022 != 0 || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size <= 0 || before.Size > 256<<20 {
		return ErrRuntime
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(exe, (256<<20)+1))
	if e != nil || n != before.Size || "sha256:"+hex.EncodeToString(h.Sum(nil)) != r.cfg.ExecutableDigest || unix.Fstat(int(exe.Fd()), &after) != nil || !fullSame(before, after) {
		return ErrRuntime
	}
	installed, e := openExecutable(r.cfg.Executable)
	if e != nil {
		return ErrRuntime
	}
	defer installed.Close()
	var pin unix.Stat_t
	if unix.Fstat(int(installed.Fd()), &pin) != nil || !fullSame(before, pin) {
		return ErrRuntime
	}
	status, e := os.ReadFile("/proc/" + pidText + "/status")
	if e != nil || !rootProcess(status) {
		return ErrRuntime
	}
	end, e := processStart(pid)
	if e != nil || start != end || parent.check() != nil {
		return ErrRuntime
	}
	again, e := readFile(parent.file(), filepath.Base(r.cfg.PIDFile), 32, 0)
	if e != nil || string(again) != string(bytes) {
		return ErrRuntime
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if unix.PidfdSendSignal(pidfd, unix.SIGHUP, nil, 0) != nil {
		return ErrRuntime
	}
	return nil
}
func rootProcess(b []byte) bool {
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			f := strings.Fields(line)
			return len(f) == 5 && f[1] == "0" && f[2] == "0" && f[3] == "0" && f[4] == "0"
		}
	}
	return false
}
func processStart(pid int) (string, error) {
	b, e := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if e != nil || len(b) > 8192 {
		return "", ErrRuntime
	}
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return "", ErrRuntime
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 20 {
		return "", ErrRuntime
	}
	return f[19], nil
}
func openExecutable(path string) (*os.File, error) {
	// Executable ancestors may be 0755; unlike mutable private state they are
	// still required root-owned and non-writable by any other principal.
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrRuntime
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, p := range parts {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&0022 != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR {
			unix.Close(fd)
			return nil, ErrRuntime
		}
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, e := unix.Openat(fd, p, flags, 0)
		unix.Close(fd)
		if e != nil {
			return nil, ErrRuntime
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), "native-executable"), nil
}
func (r *nativeRuntime) verify(ctx context.Context, g helper.ExecutionGeneration, probes []Probe) error {
	if e := checkRuntimeTree(ctx, r.cfg, 0); e != nil {
		return e
	}
	if e := verifyProbes(ctx, r.cfg, g, probes, 0); e != nil {
		return e
	}
	return checkRuntimeTree(ctx, r.cfg, 0)
}
func verifyProbes(ctx context.Context, cfg Config, g helper.ExecutionGeneration, probes []Probe, owner uint32) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// Pin the dedicated socket's protected ancestry and inode before connecting.
	parent, e := openDir(filepath.Dir(cfg.ProbeSocket), owner)
	if e != nil {
		return ErrRuntime
	}
	defer parent.close()
	var socket unix.Stat_t
	if unix.Fstatat(int(parent.file().Fd()), filepath.Base(cfg.ProbeSocket), &socket, unix.AT_SYMLINK_NOFOLLOW) != nil || socket.Uid != owner || socket.Mode&unix.S_IFMT != unix.S_IFSOCK || socket.Mode&0007 != 0 {
		return ErrRuntime
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 16 << 10, DialContext: func(c context.Context, network, address string) (net.Conn, error) {
		if parent.check() != nil {
			return nil, ErrRuntime
		}
		var now unix.Stat_t
		if unix.Fstatat(int(parent.file().Fd()), filepath.Base(cfg.ProbeSocket), &now, unix.AT_SYMLINK_NOFOLLOW) != nil || !same(socket, now) {
			return nil, ErrRuntime
		}
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(c, "unix", cfg.ProbeSocket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, p := range probes {
		var nonce [32]byte
		if _, e = rand.Read(nonce[:]); e != nil {
			return ErrRuntime
		}
		challenge := hex.EncodeToString(nonce[:])
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, "http://agp-probe"+p.Path, nil)
		if e != nil {
			return ErrRuntime
		}
		req.Host = p.Host
		req.Header.Set("X-AGP-Probe-Challenge", challenge)
		req.Header.Set("Cache-Control", "no-store")
		response, e := client.Do(req)
		if e != nil {
			return ErrRuntime
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
		response.Body.Close()
		if readErr != nil || len(body) > 1<<20 || response.StatusCode != p.Status || response.Header.Get("X-AGP-Generation") != g.GenerationID || response.Header.Get("X-AGP-Probe-Challenge") != challenge || configmodel.DigestBytes(body) != p.BodyDigest {
			return ErrRuntime
		}
	}
	var after unix.Stat_t
	if parent.check() != nil || unix.Fstatat(int(parent.file().Fd()), filepath.Base(cfg.ProbeSocket), &after, unix.AT_SYMLINK_NOFOLLOW) != nil || !same(socket, after) {
		return ErrRuntime
	}
	return nil
}
