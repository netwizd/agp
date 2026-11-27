// Package nativesandbox provides one installation-owned, read-only Linux Nginx
// syntax profile. Success reports process isolation and syntax only; it makes no
// statement about active configuration, approval, application or deployment.
package nativesandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
)

var (
	ErrUnavailable = errors.New("native_sandbox_unavailable")
	ErrTool        = errors.New("native_sandbox_tool_rejected")
	ErrInput       = errors.New("native_sandbox_input_rejected")
	ErrRejected    = errors.New("native_sandbox_syntax_rejected")
	ErrOutput      = errors.New("native_sandbox_output_limit")
)

const ProfileVersion = "agp.nginx-syntax-sandbox/v1alpha1"

// Tool is a separately qualified, root-owned installation executable. Digest
// uses the repository sha256:<lowercase hex> format. It is never task input.
type Tool struct{ Path, Digest string }

// Spec contains only local trusted staging paths. Callers must prove the
// artifact provenance before handing private trees to this profile. LoaderPath
// and NginxPath have fixed values, retained here to reject profile mismatch.
type Spec struct{ RuntimeDir, ConfigDir, LoaderPath, NginxPath string }

type Binding struct {
	ToolDigest, ProfileDigest  string
	ExecutionUID, ExecutionGID uint32
}

// ProfileDigest binds the fixed profile implementation version, argv policy,
// isolation, immutable snapshot method, limits and output behavior. It is not
// runtime qualification evidence; that must be established independently.
func ProfileDigest() string {
	const policy = ProfileVersion + "\nuser,ipc,pid,net,uts;disable-userns;assert-userns-disabled;cap-drop-ALL;die-with-parent;new-session;clearenv;LANG=C;LC_ALL=C;HOME=/nonexistent;TMPDIR=/scratch;empty-root-ro;fresh-dev-ro;private-proc;sealed-memfd-ro-bind-data;fd-exec-tool-consumed-ro-unreadable-launcher-pin;explicit-nonroot-execution-identity;root-bridge-drop-all-supplementary-groups;ambient-caps-empty;securebits-zero;tool-no-file-capabilities;runtime256MiB;config64MiB;config-file4MiB;entries4096;depth32;scratch64MiB;output64KiB-discard;deadline30s;AS4GiB;CPU30;NOFILE1024;NPROC4096;FSIZE64MiB;CORE0;loader=/runtime/lib/ld-linux-x86-64.so.2;--library-path=/runtime/lib;nginx=/runtime/bin/nginx;-t;-p=/config/;-c=/config/nginx.conf\n"
	sum := sha256.Sum256([]byte(policy))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// RunNginx accepts no shell, arbitrary argv, network address or JSON command.
func (r *Runner) RunNginx(ctx context.Context, s Spec) error {
	if s.LoaderPath != "lib/ld-linux-x86-64.so.2" || s.NginxPath != "bin/nginx" {
		return ErrInput
	}
	return r.run(ctx, s, []string{"/runtime/lib/ld-linux-x86-64.so.2", "--library-path", "/runtime/lib", "/runtime/bin/nginx", "-t", "-p", "/config/", "-c", "/config/nginx.conf"})
}

// ExecutionProfileDigest binds the fixed profile to the selected process identity.
// Zero and the kernel's invalid-ID sentinel are never valid execution identities.
func ExecutionProfileDigest(uid, gid uint32) string {
	if uid == 0 || gid == 0 || uid == ^uint32(0) || gid == ^uint32(0) {
		return ""
	}
	sum := sha256.Sum256([]byte(ProfileDigest() + "\nuid=" + strconv.FormatUint(uint64(uid), 10) + "\ngid=" + strconv.FormatUint(uint64(gid), 10) + "\n"))
	return "sha256:" + hex.EncodeToString(sum[:])
}
