package agentvalidation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/repository"
	"github.com/netwizd/agp/internal/securityjournal"
	"golang.org/x/sys/unix"
)

// Local is a standalone, nonprivileged node-local syntax primitive. Authority
// supplies a fresh challenge-bound signed journal head, never request time.
// ReceiptDir is installation-owned state outside any CP database restore.
// It is not enrollment or a long-poll execution/receipt transport.
type Local struct {
	Native    *Native
	Authority interface {
		Head(context.Context) (securityjournal.Head, error)
	}
	ReceiptDir string
	Collector  inventory.CollectorOptions
}

type localIntent struct {
	APIVersion    string               `json:"apiVersion"`
	RequestDigest string               `json:"requestDigest"`
	Request       Request              `json:"request"`
	CreatedAt     securityjournal.Head `json:"head"`
}

// Validate durably writes an intent before execution and a terminal immutable
// result before returning. Exact retries return that result without execution.
// An interrupted intent fails closed; reboot does not authorize another run.
func (l *Local) Validate(ctx context.Context, in Request) (*Result, error) {
	if l == nil || l.Native == nil || l.Authority == nil || l.Collector.ProfilePath == "" || l.Collector.RuntimeRoot == "" {
		return nil, ErrUnavailable
	}
	raw, fp, e := normalize(in)
	if e != nil {
		return nil, e
	}
	// Normalize the value actually executed as well as its durable fingerprint.
	if e = json.Unmarshal(raw, &in); e != nil {
		return nil, ErrInvalid
	}
	if e = privateState(l.ReceiptDir); e != nil {
		return nil, e
	}
	lock, e := openLocal(l.ReceiptDir, "validation.lock", unix.O_RDWR|unix.O_CREAT, 0600)
	if e != nil {
		return nil, e
	}
	defer lock.Close()
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return nil, ErrBusy
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	h, e := l.Authority.Head(ctx)
	if e != nil || h.RecordedAt.IsZero() || h.Epoch != in.AuthorityEpoch || h.RecordedAt.Before(h.ReleaseAfter) {
		return nil, ErrStale
	}
	key := stringsWithoutPrefix(repository.Hash([]byte(in.RequestID)))
	intentName, resultName := key+".intent.json", key+".result.json"
	var intent localIntent
	b, e := readLocal(l.ReceiptDir, intentName, MaxRequestBytes+16384)
	if e == nil {
		if decodeLocal(b, &intent) != nil || intent.APIVersion != RequestVersion || intent.RequestDigest != fp || intent.Request.RequestID != in.RequestID || intent.CreatedAt.Epoch != h.Epoch || intent.CreatedAt.AuthorityID != h.AuthorityID {
			return nil, ErrConflict
		}
		b, e = readLocal(l.ReceiptDir, resultName, MaxResultBytes)
		if errors.Is(e, os.ErrNotExist) {
			return nil, ErrPending
		}
		if e != nil {
			return nil, e
		}
		var out Result
		if decodeLocal(b, &out) != nil || !validResult(out) || out.RequestDigest != fp || out.AuthorityEpoch != h.Epoch || out.ID != "lvr_"+key || out.RequestID != in.RequestID || out.Pins != in.Pins || out.CapabilityDigest != in.CapabilityDigest || out.ExecutionLocation != "local_process" || out.NodeID != "" || out.IdentityDigest != "" {
			return nil, ErrUnavailable
		}
		return &out, nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	entries, e := os.ReadDir(l.ReceiptDir)
	if e != nil || len(entries) > 8192 {
		return nil, ErrBusy
	}
	q, e := l.Native.current(ctx, in.Pins)
	if e != nil {
		return nil, e
	}
	if e = l.observe(ctx, in, q); e != nil {
		return nil, e
	}
	intent = localIntent{RequestVersion, fp, in, h}
	if e = durableLocal(l.ReceiptDir, intentName, intent); e != nil {
		return nil, e
	}
	validationErr := l.Native.Check(ctx, in)
	// A post-execution journal/observation or release failure never produces a
	// successful proof, even if native -t completed before that change.
	h2, e := l.Authority.Head(ctx)
	if e != nil || h2.AuthorityID != h.AuthorityID || h2.Epoch != h.Epoch || h2.RecordedAt.Before(h.RecordedAt) || h2.RecordedAt.Before(h2.ReleaseAfter) || !h2.RecordedAt.Before(h.RecordedAt.Add(RequestTTL)) {
		validationErr = ErrStale
	}
	if validationErr == nil {
		q, e = l.Native.current(ctx, in.Pins)
		if e != nil {
			validationErr = e
		} else if e = l.observe(ctx, in, q); e != nil {
			validationErr = e
		}
	}
	policyDigest, _ := configmodel.Digest(in.Policy)
	out := &Result{APIVersion: ResultVersion, ID: "lvr_" + key, RequestID: in.RequestID, AuthorityEpoch: in.AuthorityEpoch, RequestDigest: fp, CapabilityDigest: in.CapabilityDigest, PolicyDigest: policyDigest, Pins: in.Pins, State: resultState(validationErr), NativeSyntaxOnly: true, ExecutionLocation: "local_process", Isolation: "unprivileged_private_workspace", CreatedAt: h.RecordedAt, RecordedAt: h2.RecordedAt, ErrorCode: safeError(validationErr)}
	if h2.RecordedAt.IsZero() {
		out.RecordedAt = h.RecordedAt
	}
	if e = durableLocal(l.ReceiptDir, resultName, out); e != nil {
		return nil, e
	}
	return out, nil
}

func (l *Local) observe(ctx context.Context, in Request, q *qualified) error {
	o, e := inventory.Collect(ctx, l.Collector)
	if e != nil {
		return ErrStale
	}
	d, e := inventory.Digest(o.Capabilities)
	if e != nil || d != in.CapabilityDigest {
		return ErrStale
	}
	return matchNode(inventory.Node{Capabilities: o.Capabilities}, q)
}

func stringsWithoutPrefix(s string) string { return s[len("sha256:"):] }
func decodeLocal(b []byte, v any) error {
	if uniqueKeys(b) != nil {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func privateState(name string) error {
	if e := privateBase(name); e != nil {
		return e
	}
	st, e := os.Lstat(name)
	if e != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return ErrUnavailable
	}
	var s unix.Stat_t
	if unix.Lstat(name, &s) != nil || s.Uid != uint32(os.Geteuid()) {
		return ErrUnavailable
	}
	return nil
}
func openLocal(dir, name string, flags int, mode uint32) (*os.File, error) {
	fd, e := unix.Open(filepath.Join(dir, name), flags|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, mode)
	if e != nil {
		return nil, e
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
		_ = unix.Close(fd)
		return nil, ErrUnavailable
	}
	return os.NewFile(uintptr(fd), name), nil
}
func readLocal(dir, name string, max int64) ([]byte, error) {
	f, e := openLocal(dir, name, unix.O_RDONLY, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, ErrUnavailable
	}
	return b, nil
}
func durableLocal(dir, name string, v any) error {
	b, e := configmodel.CanonicalJSON(v)
	if e != nil || len(b) > MaxRequestBytes+16384 {
		return ErrUnavailable
	}
	f, e := openLocal(dir, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0400)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
