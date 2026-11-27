package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/netwizd/agp/internal/repository"
	"github.com/netwizd/agp/internal/securityjournal"
	"golang.org/x/sys/unix"
)

type CollectorOptions struct {
	AgentVersion string
	DiskPath     string
	// ProfilePath is public metadata, not an authority. The server verifies its
	// digest and every observed runtime hash against its signed repository.
	ProfilePath string
	RuntimeRoot string
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.r.Read(b)
}
func readSmall(name string, limit int64) ([]byte, error) {
	f, e := os.Open(name)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > limit {
		return nil, ErrInvalid
	}
	return b, nil
}

// Collect reads a fixed Linux metadata vocabulary and optional bounded regular
// runtime files. It executes no programs, reads no environment and claims no
// service health, applied bundle or deployment baseline.
func Collect(ctx context.Context, opts CollectorOptions) (Observation, error) {
	var out Observation
	if runtime.GOOS != "linux" || !filepath.IsAbs(opts.DiskPath) || !boundedText(opts.AgentVersion, 64) || (opts.ProfilePath == "") != (opts.RuntimeRoot == "") {
		return out, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return out, e
	}
	b, e := readSmall("/proc/sys/kernel/random/boot_id", 128)
	if e != nil {
		return out, e
	}
	out.BootID = strings.TrimSpace(string(b))
	b, e = readSmall("/etc/os-release", 16<<10)
	if e != nil {
		return out, e
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key != "ID" && key != "VERSION_ID" {
			continue
		}
		if _, exists := values[key]; exists {
			return out, ErrInvalid
		}
		if len(value) >= 2 && (value[0] == '"' && value[len(value)-1] == '"' || value[0] == '\'' && value[len(value)-1] == '\'') {
			value = value[1 : len(value)-1]
		}
		if strings.ContainsAny(value, "\\$`\x00\r\n") {
			return out, ErrInvalid
		}
		values[key] = value
	}
	var uts unix.Utsname
	if e = unix.Uname(&uts); e != nil {
		return out, e
	}
	kernel := string(uts.Release[:])
	if i := strings.IndexByte(kernel, 0); i >= 0 {
		kernel = kernel[:i]
	}
	var st unix.Statfs_t
	if e = unix.Statfs(opts.DiskPath, &st); e != nil {
		return out, e
	}
	if st.Bsize <= 0 || uint64(st.Bavail) > uint64(securityjournal.MaxUInt63)/uint64(st.Bsize) {
		return out, ErrInvalid
	}
	out.FreeBytes = securityjournal.UInt63(uint64(st.Bavail) * uint64(st.Bsize))
	out.Capabilities = Capabilities{AgentVersion: opts.AgentVersion, ProtocolVersion: ProtocolVersion, OS: OS{ID: values["ID"], VersionID: values["VERSION_ID"], Kernel: kernel, Architecture: runtime.GOARCH}}
	if opts.ProfilePath != "" {
		component, e := collectComponent(ctx, opts)
		if e != nil {
			return out, e
		}
		out.Capabilities.Component = component
	}
	out, _, _, e = normalizeObservation(out)
	return out, e
}
func collectComponent(ctx context.Context, opts CollectorOptions) (*Component, error) {
	if !filepath.IsAbs(opts.ProfilePath) || !filepath.IsAbs(opts.RuntimeRoot) || filepath.Clean(opts.RuntimeRoot) != opts.RuntimeRoot {
		return nil, ErrInvalid
	}
	f, e := openPublicFile(opts.ProfilePath)
	if e != nil {
		return nil, e
	}
	profileRaw, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	_ = f.Close()
	if e != nil {
		return nil, e
	}
	if len(profileRaw) > 1<<20 {
		return nil, ErrInvalid
	}
	var p repository.ComponentProfile
	if e = decodeBounded(strings.NewReader(string(profileRaw)), &p, 1<<20); e != nil {
		return nil, e
	}
	if p.APIVersion != "agp.component-profile/v1alpha1" || len(p.Files) == 0 || len(p.Files) > 1000 {
		return nil, ErrInvalid
	}
	out := &Component{ProfileDigest: hash(profileRaw), Files: []File{}}
	var total int64
	seen := map[string]bool{}
	for _, pf := range p.Files {
		if !safePath(pf.Path) || seen[pf.Path] || !digestPattern.MatchString(pf.Digest) {
			return nil, ErrInvalid
		}
		seen[pf.Path] = true
		f, e := openPublicFile(filepath.Join(opts.RuntimeRoot, filepath.FromSlash(pf.Path)))
		if e != nil {
			return nil, e
		}
		st, e := f.Stat()
		if e != nil || st.Size() <= 0 || st.Size() > 256<<20 {
			_ = f.Close()
			return nil, ErrInvalid
		}
		total += st.Size()
		if total > 1<<30 {
			_ = f.Close()
			return nil, ErrInvalid
		}
		h := sha256.New()
		n, copyErr := io.Copy(h, io.LimitReader(contextReader{ctx, f}, st.Size()+1))
		closeErr := f.Close()
		if e = errors.Join(copyErr, closeErr); e != nil {
			return nil, e
		}
		if n != st.Size() {
			return nil, ErrInvalid
		}
		out.Files = append(out.Files, File{Path: pf.Path, Digest: "sha256:" + hex.EncodeToString(h.Sum(nil))})
	}
	return out, nil
}
