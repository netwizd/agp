package agentvalidation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/repository"
	"golang.org/x/sys/unix"
)

// Native executes only the fixed typed policy probe with signed runtime bytes.
// This is an unprivileged private workspace, not a kernel filesystem/network
// sandbox and not the qualified remote NodeBundle helper from the target model.
// All fields are installation-owned settings; none is decoded from Request.
type Native struct {
	Store   repository.Store
	Clock   func(context.Context) (time.Time, error)
	TempDir string
	// A root supervisor must explicitly drop both IDs. Supplementary groups
	// are cleared. A nonroot process may use only its own identity.
	ExecutionUID uint32
	ExecutionGID uint32
	mu           sync.Mutex
	active       bool
}

type qualified struct {
	release *repository.VerifiedRelease
	profile *repository.QualifiedProfile
	now     time.Time
}

func (n *Native) current(ctx context.Context, pins Pins) (*qualified, error) {
	if n == nil || n.Clock == nil {
		return nil, ErrUnavailable
	}
	now, e := n.Clock(ctx)
	if e != nil || now.IsZero() {
		return nil, nativeFailure("journal_head_unavailable", e)
	}
	v, e := n.Store.Current(ctx, now)
	if e != nil {
		return nil, ErrStale
	}
	p, e := v.QualifiedProfile(now)
	if e != nil {
		return nil, ErrStale
	}
	t := p.Profile.Tuple
	if t.Nginx != "1.30.8" || t.Connector != "1.0.4" || t.LibModSecurity != "3.0.17" || t.CRS != "4.30.0" || p.Profile.LoaderPath != "lib/ld-linux-x86-64.so.2" || p.Profile.NginxPath != "bin/nginx" || p.Profile.ModulePath != "modules/ngx_http_modsecurity_module.so" || p.Profile.UnicodePath != "share/modsecurity/unicode.mapping" || p.Profile.RulesPath != "share/crs/rules" {
		return nil, ErrUnsupported
	}
	actual := Pins{v.ManifestDigest, p.ProfileDigest, p.TupleDigest, p.EvidenceDigest, p.Evidence.RendererDigest}
	if actual != pins {
		return nil, ErrStale
	}
	return &qualified{v, p, now}, nil
}

func matchNode(node inventory.Node, q *qualified) error {
	c := node.Capabilities
	p := q.profile.Profile
	if c.ProtocolVersion != inventory.ProtocolVersion || c.OS.ID != p.Platform.OS || c.OS.VersionID != p.Platform.OSVersion || c.OS.Architecture != p.Platform.Arch || c.OS.Kernel != q.profile.Evidence.HostKernel || c.Component == nil || c.Component.ProfileDigest != q.profile.ProfileDigest || len(c.Component.Files) != len(p.Files) {
		return ErrStale
	}
	files := map[string]string{}
	for _, f := range c.Component.Files {
		if files[f.Path] != "" {
			return ErrStale
		}
		files[f.Path] = f.Digest
	}
	for _, f := range p.Files {
		if files[f.Path] != f.Digest {
			return ErrStale
		}
	}
	return nil
}

func (n *Native) acquire() (func(), error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.active {
		return nil, ErrBusy
	}
	n.active = true
	return func() { n.mu.Lock(); n.active = false; n.mu.Unlock() }, nil
}

func (n *Native) identity() (*syscall.Credential, error) {
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if uid == 0 {
		if n.ExecutionUID == 0 || n.ExecutionGID == 0 {
			return nil, ErrUnavailable
		}
		return &syscall.Credential{Uid: n.ExecutionUID, Gid: n.ExecutionGID, Groups: []uint32{}}, nil
	}
	if n.ExecutionUID != 0 && n.ExecutionUID != uid || n.ExecutionGID != 0 && n.ExecutionGID != gid {
		return nil, ErrUnavailable
	}
	return nil, nil
}

var nativePath = regexp.MustCompile(`^/[A-Za-z0-9/_.+-]+$`)

func (n *Native) execute(ctx context.Context, in Request, q *qualified) error {
	if e := checkProcessLimits(); e != nil {
		return nativeFailure("resource_limits_required", e)
	}
	credential, e := n.identity()
	if e != nil {
		return nativeFailure("execution_identity_rejected", e)
	}
	if e = privateBase(n.TempDir); e != nil {
		return nativeFailure("workspace_parent_rejected", e)
	}
	if in.Policy.Spec.RulesetVersionID != q.profile.Profile.RulesetVersionID {
		return ErrStale
	}
	work, e := os.MkdirTemp(n.TempDir, "agp-local-syntax-")
	if e != nil {
		return nativeFailure("workspace_create_failed", e)
	}
	defer os.RemoveAll(work)
	if !nativePath.MatchString(work) {
		return ErrUnavailable
	}
	// The tree is newly created, inaccessible to other users and receives only
	// exact immutable object bytes. No archives, links or caller files enter it.
	for _, f := range q.profile.Profile.Files {
		raw, ok := q.release.Object(f.Digest)
		if !ok || repository.Hash(raw) != f.Digest {
			return ErrStale
		}
		name := filepath.Join(work, filepath.FromSlash(f.Path))
		if e = os.MkdirAll(filepath.Dir(name), 0700); e != nil {
			return nativeFailure("runtime_directory_failed", e)
		}
		mode := os.FileMode(0400)
		if f.Path == q.profile.Profile.LoaderPath || f.Path == q.profile.Profile.NginxPath {
			mode = 0500
		}
		if e = writeNew(name, raw, mode); e != nil {
			return nativeFailure("runtime_stage_failed", e)
		}
	}
	renderer, ok := q.release.Object(in.Pins.RendererDigest)
	if !ok || repository.Hash(renderer) != in.Pins.RendererDigest {
		return ErrStale
	}
	if e = writeNew(filepath.Join(work, "qualified-renderer"), renderer, 0500); e != nil {
		return nativeFailure("renderer_stage_failed", e)
	}
	policy, e := configmodel.CanonicalJSON(in.Policy)
	if e != nil {
		return ErrInvalid
	}
	if e = writeNew(filepath.Join(work, "policy.json"), policy, 0400); e != nil {
		return nativeFailure("input_stage_failed", e)
	}
	conf := fmt.Sprintf("load_module %s/modules/ngx_http_modsecurity_module.so;\npid %s/nginx.pid;\nerror_log stderr notice;\nevents {}\nhttp { access_log off; client_body_temp_path %s; server { listen 127.0.0.1:18080; modsecurity on; modsecurity_rules_file %s/policy.conf; location / { return 204; } } }\n", work, work, work, work)
	if e = writeNew(filepath.Join(work, "nginx.conf"), []byte(conf), 0400); e != nil {
		return nativeFailure("config_stage_failed", e)
	}
	if credential != nil {
		if e = filepath.WalkDir(work, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.Type()&os.ModeSymlink != 0 {
				return ErrUnavailable
			}
			return os.Chown(path, int(credential.Uid), int(credential.Gid))
		}); e != nil {
			return nativeFailure("workspace_owner_failed", e)
		}
	}
	limited, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	loader := filepath.Join(work, q.profile.Profile.LoaderPath)
	args := []string{"--library-path", filepath.Join(work, "lib"), filepath.Join(work, "qualified-renderer"), "waf-render", "--policy", filepath.Join(work, "policy.json"), "--bundle", work, "--work", work, "--mode", in.Mode}
	out, e := runFixed(limited, loader, args, work, credential, false)
	if e != nil || len(out) == 0 {
		return ErrNativeRejected
	}
	// Signed renderer output is bounded but deliberately never accepted from
	// an HTTP/task caller. It is consumed only inside this one private tree.
	if e = writeNew(filepath.Join(work, "policy.conf"), out, 0400); e != nil {
		return nativeFailure("rendered_policy_stage_failed", e)
	}
	if credential != nil {
		if e = os.Chown(filepath.Join(work, "policy.conf"), int(credential.Uid), int(credential.Gid)); e != nil {
			return nativeFailure("rendered_policy_owner_failed", e)
		}
	}
	args = []string{"--library-path", filepath.Join(work, "lib"), filepath.Join(work, q.profile.Profile.NginxPath), "-p", work + "/", "-c", filepath.Join(work, "nginx.conf"), "-t"}
	out, e = runFixed(limited, loader, args, work, credential, true)
	if e != nil || !bytes.Contains(out, []byte("test is successful")) {
		return ErrNativeRejected
	}
	return nil
}

// ApplyLocalProcessLimits is for the standalone one-shot validator process,
// before it loads a release or accepts input. A server must instead receive
// equivalent limits from its qualified installation; library calls never alter
// process-global resource limits of a running Control Plane.
func ApplyLocalProcessLimits() error {
	debug.SetMemoryLimit(512 << 20)
	for _, limit := range syntaxLimits {
		var current unix.Rlimit
		if unix.Getrlimit(limit.resource, &current) != nil {
			return ErrUnavailable
		}
		value := min(current.Cur, limit.maximum)
		if unix.Setrlimit(limit.resource, &unix.Rlimit{Cur: value, Max: min(current.Max, limit.maximum)}) != nil {
			return ErrUnavailable
		}
	}
	return nil
}

var syntaxLimits = []struct {
	resource int
	maximum  uint64
}{
	{unix.RLIMIT_AS, 4 << 30}, {unix.RLIMIT_CPU, 30}, {unix.RLIMIT_NOFILE, 256},
	// NPROC is a per-UID ceiling, not a private cgroup/process namespace. A
	// dedicated installed account can supply a stricter inherited bound.
	{unix.RLIMIT_NPROC, 4096}, {unix.RLIMIT_FSIZE, 64 << 20}, {unix.RLIMIT_CORE, 0},
}

func checkProcessLimits() error {
	for _, limit := range syntaxLimits {
		var current unix.Rlimit
		if unix.Getrlimit(limit.resource, &current) != nil || current.Cur > limit.maximum || current.Max > limit.maximum {
			return ErrUnavailable
		}
	}
	return nil
}

var ErrNativeRejected = fmt.Errorf("native_syntax_rejected")

func writeNew(name string, b []byte, mode os.FileMode) error {
	f, e := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}

type limitedOutput struct {
	mu       sync.Mutex
	b        bytes.Buffer
	total    int
	cancel   context.CancelFunc
	overflow bool
	budget   *outputBudget
}

type outputBudget struct {
	mu    sync.Mutex
	total int
}

func (w *limitedOutput) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.total += len(b)
	w.budget.mu.Lock()
	defer w.budget.mu.Unlock()
	left := MaxResultBytes - w.budget.total
	w.budget.total += len(b)
	if w.budget.total > MaxResultBytes {
		w.overflow = true
		w.cancel()
	}
	if left > 0 {
		w.b.Write(b[:min(left, len(b))])
	}
	return len(b), nil
}

// runFixed never exposes command text as a public API. Both executables and all
// argv are selected above from the verified typed profile and fixed renderer.
func runFixed(ctx context.Context, exe string, args []string, work string, credential *syscall.Credential, mergeDiagnostic bool) ([]byte, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	cmd := exec.Command(exe, args...)
	cmd.Dir = work
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "GOMAXPROCS=2", "GOMEMLIMIT=256MiB"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL, Credential: credential}
	cmd.WaitDelay = time.Second
	budget := &outputBudget{}
	w := &limitedOutput{cancel: cancel, budget: budget}
	diagnostic := &limitedOutput{cancel: cancel, budget: budget}
	cmd.Stdout = w
	cmd.Stderr = diagnostic
	if mergeDiagnostic {
		cmd.Stderr = w
	}
	if e := cmd.Start(); e != nil {
		return nil, ErrUnavailable
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var e error
	select {
	case e = <-done:
	case <-ctx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
		e = ctx.Err()
	}
	// Kill any descendant that kept the process group alive after its parent.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	w.mu.Lock()
	defer w.mu.Unlock()
	diagnostic.mu.Lock()
	defer diagnostic.mu.Unlock()
	if e != nil || w.overflow || diagnostic.overflow {
		return nil, ErrNativeRejected
	}
	return append([]byte(nil), w.b.Bytes()...), nil
}

// Check is useful to an unprivileged node-local agent. It verifies current
// signed bytes before and after execution. Admission/current agent identity and
// durable exact retry are supplied by Local or Service, never inferred here.
func (n *Native) Check(ctx context.Context, in Request) error {
	if n == nil || n.Clock == nil {
		return ErrUnavailable
	}
	if _, _, e := normalize(in); e != nil {
		return e
	}
	if e := checkProcessLimits(); e != nil {
		return nativeFailure("resource_limits_required", e)
	}
	if _, e := n.identity(); e != nil {
		return nativeFailure("execution_identity_rejected", e)
	}
	release, e := n.acquire()
	if e != nil {
		return e
	}
	defer release()
	q, e := n.current(ctx, in.Pins)
	if e != nil {
		return e
	}
	err := n.execute(ctx, in, q)
	if _, e = n.current(ctx, in.Pins); e != nil {
		return e
	}
	return err
}

// UnsupportedRemoteBundle makes the absent qualified NodeBundle sandbox
// explicit. Syntax probing never upgrades compiler Deployable=false.
func UnsupportedRemoteBundle() error { return ErrUnsupported }

func safeError(e error) string {
	var failure *nativeError
	if errors.As(e, &failure) {
		return failure.code
	}
	switch {
	case e == nil:
		return ""
	case e == ErrNativeRejected:
		return "native_syntax_rejected"
	case e == ErrStale:
		return "precondition_changed"
	case e == ErrUnsupported:
		return "operation_unsupported"
	default:
		return "validation_failed"
	}
}

// Native failure codes name fixed stages only. Neither underlying OS errors,
// native diagnostics, paths nor typed policy content enter a stored result.
type nativeError struct {
	code  string
	errno syscall.Errno
}

func (e *nativeError) Error() string {
	if e.errno != 0 {
		return fmt.Sprintf("%s (errno=%d)", e.code, uint64(e.errno))
	}
	return e.code
}
func (e *nativeError) Unwrap() error { return ErrUnavailable }
func nativeFailure(stage string, cause error) error {
	var errno syscall.Errno
	_ = errors.As(cause, &errno)
	switch {
	case errors.Is(cause, syscall.EACCES) || errors.Is(cause, syscall.EPERM):
		stage += "_permission"
	case errors.Is(cause, syscall.ENOSPC):
		stage += "_space"
	case errors.Is(cause, syscall.EEXIST):
		stage += "_exists"
	case errors.Is(cause, syscall.EFBIG):
		stage += "_file_limit"
	case errors.Is(cause, syscall.EDQUOT):
		stage += "_quota"
	case errors.Is(cause, syscall.EMFILE) || errors.Is(cause, syscall.ENFILE):
		stage += "_descriptors"
	case errors.Is(cause, syscall.EIO):
		stage += "_io"
	case errors.Is(cause, syscall.ENOMEM):
		stage += "_memory"
	case errors.Is(cause, syscall.EROFS):
		stage += "_readonly"
	case errors.Is(cause, io.ErrShortWrite):
		stage += "_short_write"
	}
	return &nativeError{code: stage, errno: errno}
}

func resultState(e error) string {
	if e == nil {
		return "validated"
	}
	if e == ErrNativeRejected || e == ErrStale || e == ErrUnsupported {
		return "rejected"
	}
	return "failed"
}

func privateBase(name string) error {
	if name == "" {
		name = os.TempDir()
	}
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return ErrUnavailable
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
	if e != nil {
		return ErrUnavailable
	}
	defer func() { _ = unix.Close(fd) }()
	current := "/"
	check := func() error {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 && st.Uid != uint32(os.Geteuid()) {
			return ErrUnavailable
		}
		if st.Mode&0022 != 0 && !(current == "/tmp" && st.Uid == 0 && st.Mode&unix.S_ISVTX != 0) {
			return ErrUnavailable
		}
		return nil
	}
	if e = check(); e != nil {
		return e
	}
	for _, p := range splitPath(name) {
		next, err := unix.Openat(fd, p, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return ErrUnavailable
		}
		_ = unix.Close(fd)
		fd = next
		current = filepath.Join(current, p)
		if e = check(); e != nil {
			return e
		}
	}
	return nil
}

func splitPath(name string) []string {
	if name == "/" {
		return nil
	}
	return strings.Split(strings.TrimPrefix(name, "/"), "/")
}
