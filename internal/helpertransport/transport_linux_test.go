//go:build linux

package helpertransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/helper"
)

type transportExecutor func(context.Context, io.Reader) (*helper.ExecutionReceipt, error)

func (f transportExecutor) Execute(ctx context.Context, r io.Reader) (*helper.ExecutionReceipt, error) {
	return f(ctx, r)
}

func transportDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "agp-local-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
func transportRequest(t *testing.T) helper.Request {
	t.Helper()
	d := "sha256:" + strings.Repeat("1", 64)
	now := time.Now().UTC().Truncate(time.Second)
	r := helper.Request{Task: helper.Task{APIVersion: "agp.task/v1alpha1", ID: "task_one", NodeID: "node_one", Kind: "apply_config", IdempotencyKey: "abcdefghijklmnop", AuthorityEpoch: 1, WriterEpoch: 1, NodeDeploymentSequence: 8, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), PlanID: "plan_one", PlanDigest: d, Preconditions: helper.Preconditions{BaseRevisionID: "base", ExpectedNodeDeploymentSequence: 7, CapabilityDigest: d}, Payload: helper.Payload{TargetRevisionID: "target", DeploymentGeneration: "generation", BundleDigest: d, SecretVersionIDs: []string{}, RecoveryBaseBundleDigest: d}}, Permit: helper.Permit{APIVersion: helper.PermitVersion, KeyID: "permit_key", InstallationDigest: d, IdentityDigest: d, OwnershipDigest: d, ComponentProfileDigest: d, ReleaseManifestDigest: d, TupleDigest: d, CompilerDigest: d, Approval: helper.Approval{SiteID: "site_one", CreatedBy: "author", ApprovedBy: "reviewer", ApprovalDigest: d}, Recovery: helper.Recovery{BaseRevisionID: "base", BaseBundleDigest: d, OwnershipDigest: d}, Signature: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))}}
	r.Permit.TaskDigest, _ = helper.TaskDigest(r.Task)
	r.Task.PermitDigest, _ = helper.PermitDigest(r.Permit)
	return r
}
func transportReceipt() *helper.ExecutionReceipt {
	return &helper.ExecutionReceipt{APIVersion: helper.ExecutionReceiptVersion, Purpose: "local_execution_outcome", ReceiptID: "receipt_one", NodeID: "node_one", TaskID: "task_one", ReceiptSequence: 1, State: "succeeded"}
}
func transportServer(t *testing.T, uid uint32, executor Executor) (*Server, string) {
	t.Helper()
	path := filepath.Join(transportDir(t), "helper.sock")
	s, err := newServer(Config{SocketPath: path, AgentUID: uid, AgentGID: uint32(os.Getegid())}, executor, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := s.Close(ctx); err != nil {
			t.Error(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("server did not stop")
		}
	})
	return s, path
}
func rawLocalClient(t *testing.T, path string) *http.Client {
	t.Helper()
	tr := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	c := &http.Client{Transport: tr, Timeout: time.Second}
	t.Cleanup(tr.CloseIdleConnections)
	return c
}
func rawLocalRequest(t *testing.T, c *http.Client, method, path, content, body string, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	r, err := http.NewRequest(method, "http://helper"+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", content)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	resp, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, out
}

func TestProtectedFileBoundaries(t *testing.T) {
	dir := transportDir(t)
	path := filepath.Join(dir, "key")
	write := func(path string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte("private-payload"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	write(path, 0600)
	if b, err := readFile(path, true, 32, uint32(os.Geteuid())); err != nil || string(b) != "private-payload" {
		t.Fatalf("protected read: %q %v", b, err)
	}
	if b, err := ReadPrivateFile(path, 32); err != nil || string(b) != "private-payload" {
		t.Fatalf("private service read: %q %v", b, err)
	}
	for _, tc := range []struct {
		name    string
		mode    os.FileMode
		private bool
		allowed bool
	}{{"public-readable", 0644, false, true}, {"private-readable-by-group", 0640, true, false}, {"group-writable", 0620, false, false}, {"world-writable", 0602, false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			write(path, tc.mode)
			_, err := readFile(path, tc.private, 32, uint32(os.Geteuid()))
			if (err == nil) != tc.allowed {
				t.Fatalf("read allowed=%v, err=%v", tc.allowed, err)
			}
		})
	}
	write(path, 0600)
	for _, limit := range []int{0, 3} {
		if _, err := readFile(path, true, limit, uint32(os.Geteuid())); !errors.Is(err, ErrTransport) {
			t.Fatalf("limit %d: %v", limit, err)
		}
	}
	for _, bad := range []string{"relative/key", dir + "/../" + filepath.Base(dir) + "/key", dir} {
		if _, err := readFile(bad, true, 32, uint32(os.Geteuid())); !errors.Is(err, ErrTransport) {
			t.Fatalf("bad path %q: %v", bad, err)
		}
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readFile(link, true, 32, uint32(os.Geteuid())); !errors.Is(err, ErrTransport) {
		t.Fatalf("symlink file: %v", err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readFile(path, true, 32, uint32(os.Geteuid())); !errors.Is(err, ErrTransport) {
		t.Fatalf("hardlink substitution: %v", err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if _, err := ReadRootFile(path, true, 32); !errors.Is(err, ErrTransport) {
			t.Fatalf("nonroot file admitted as root input: %v", err)
		}
	}
	child := filepath.Join(dir, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(child, "key"), 0600)
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(child, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := readFile(filepath.Join(alias, "key"), true, 32, uint32(os.Geteuid())); !errors.Is(err, ErrTransport) {
		t.Fatalf("symlink ancestry: %v", err)
	}
	if err := os.Chmod(child, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := readFile(filepath.Join(child, "key"), true, 32, uint32(os.Geteuid())); !errors.Is(err, ErrTransport) {
		t.Fatalf("writable ancestry: %v", err)
	}
}

func TestUnixExecutePreservesRequestAndReceipt(t *testing.T) {
	in := transportRequest(t)
	receipt := transportReceipt()
	var calls atomic.Int32
	_, path := transportServer(t, uint32(os.Geteuid()), transportExecutor(func(ctx context.Context, r io.Reader) (*helper.ExecutionReceipt, error) {
		calls.Add(1)
		got, err := helper.Decode(r)
		if err != nil {
			return nil, err
		}
		if !reflect.DeepEqual(*got, in) {
			t.Error("task changed at local boundary")
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 175*time.Second {
			t.Error("missing bounded execution context")
		}
		return receipt, nil
	}))
	client, err := newClient(path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	got, err := client.Execute(context.Background(), in)
	if err != nil || !reflect.DeepEqual(got, receipt) || calls.Load() != 1 {
		t.Fatalf("execute = %#v %v, calls=%d", got, err, calls.Load())
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0660 {
		t.Fatalf("socket mode: %v %v", st, err)
	}
	bad := in
	bad.Task.ID = "invalid id"
	if _, err := client.Execute(context.Background(), bad); !errors.Is(err, helper.ErrInvalid) || calls.Load() != 1 {
		t.Fatalf("invalid request reached server: %v calls=%d", err, calls.Load())
	}
	if os.Geteuid() != 0 {
		if _, err := NewClient(path); !errors.Is(err, ErrTransport) {
			t.Fatalf("production root pin accepted own socket: %v", err)
		}
	}
}

func TestUnixProtocolRejectsExtraCapabilities(t *testing.T) {
	var effects atomic.Int32
	_, path := transportServer(t, uint32(os.Geteuid()), transportExecutor(func(_ context.Context, r io.Reader) (*helper.ExecutionReceipt, error) {
		if _, err := helper.Decode(r); err != nil {
			return nil, err
		}
		effects.Add(1)
		return transportReceipt(), nil
	}))
	client := rawLocalClient(t, path)
	in, _ := json.Marshal(transportRequest(t))
	for _, tc := range []struct {
		name, method, path, content, body string
		headers                           map[string]string
	}{
		{name: "ack", method: "POST", path: "/ack", content: "application/json", body: `{"receiptId":"receipt_one"}`},
		{name: "status", method: "GET", path: "/status", content: "application/json", body: `{}`},
		{name: "initialize", method: "POST", path: "/initialize", content: "application/json", body: `{}`},
		{name: "query", method: "POST", path: "/execute?ack=1", content: "application/json", body: string(in)},
		{name: "cookie", method: "POST", path: "/execute", content: "application/json", body: string(in), headers: map[string]string{"Cookie": "session=x"}},
		{name: "origin", method: "POST", path: "/execute", content: "application/json", body: string(in), headers: map[string]string{"Origin": "https://example.invalid"}},
		{name: "content", method: "POST", path: "/execute", content: "text/plain", body: string(in)},
		{name: "malformed", method: "POST", path: "/execute", content: "application/json", body: `{"task":`},
		{name: "unknown", method: "POST", path: "/execute", content: "application/json", body: `{"path":"/etc/secret"}`},
		{name: "oversize", method: "POST", path: "/execute", content: "application/json", body: strings.Repeat(" ", helper.MaxRequestBytes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, out := rawLocalRequest(t, client, tc.method, tc.path, tc.content, tc.body, tc.headers)
			if resp.StatusCode != 400 || bytes.Contains(out, []byte("/etc/secret")) {
				t.Fatalf("invalid request response %d %q", resp.StatusCode, out)
			}
		})
	}
	if effects.Load() != 0 {
		t.Fatalf("rejected envelopes caused %d effects", effects.Load())
	}
}

func TestUnixExecutorErrorsAreBoundedAndSanitized(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{{"invalid", helper.ErrInvalid, 400}, {"unauthorized", helper.ErrUnauthorized, 403}, {"pending", helper.ErrPending, 409}, {"stale", helper.ErrStale, 409}, {"conflict", helper.ErrConflict, 409}, {"private-error", errors.New("/root/receipt.key bytes=secret"), 503}, {"nil-receipt", nil, 503}} {
		t.Run(tc.name, func(t *testing.T) {
			_, path := transportServer(t, uint32(os.Geteuid()), transportExecutor(func(context.Context, io.Reader) (*helper.ExecutionReceipt, error) {
				if tc.err == nil {
					return nil, nil
				}
				return nil, fmt.Errorf("private /root/receipt.key: %w", tc.err)
			}))
			raw, _ := json.Marshal(transportRequest(t))
			resp, out := rawLocalRequest(t, rawLocalClient(t, path), "POST", "/execute", "application/json", string(raw), nil)
			if resp.StatusCode != tc.status || string(out) != `{"error":"helper_execution_unavailable"}` {
				t.Fatalf("error leaked or status changed: %d %q", resp.StatusCode, out)
			}
		})
	}
}

func TestUnixPeerUIDMismatchCannotExecute(t *testing.T) {
	var calls atomic.Int32
	_, path := transportServer(t, uint32(os.Geteuid())+1, transportExecutor(func(context.Context, io.Reader) (*helper.ExecutionReceipt, error) {
		calls.Add(1)
		return transportReceipt(), nil
	}))
	client, err := newClient(path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if got, err := client.Execute(context.Background(), transportRequest(t)); got != nil || !errors.Is(err, ErrTransport) {
		t.Fatalf("wrong peer admitted: %#v %v", got, err)
	}
	if calls.Load() != 0 {
		t.Fatal("unauthorized UID entered executor")
	}
}

func TestUnixClientRejectsUntrustedResponse(t *testing.T) {
	for _, tc := range []struct {
		name, body, content string
		status              int
	}{{"redirect", `{}`, "application/json", 302}, {"wrong-status", `{}`, "application/json", 204}, {"wrong-content", `{}`, "text/plain", 200}, {"oversize", strings.Repeat(" ", 65537), "application/json", 200}, {"duplicate", `{"nodeId":"first","nodeId":"second"}`, "application/json", 200}, {"unknown", `{"ack":true}`, "application/json", 200}, {"trailing", `{} {}`, "application/json", 200}, {"malformed", `{`, "application/json", 200}} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(transportDir(t), "helper.sock")
			s, err := newServer(Config{SocketPath: path, AgentUID: uint32(os.Geteuid()), AgentGID: uint32(os.Getegid())}, transportExecutor(func(context.Context, io.Reader) (*helper.ExecutionReceipt, error) {
				t.Error("fake transport invoked executor")
				return nil, nil
			}), uint32(os.Geteuid()))
			if err != nil {
				t.Fatal(err)
			}
			s.http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.content)
				w.Header().Set("Location", "http://example.invalid/leak")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})
			done := make(chan error, 1)
			go func() { done <- s.Serve() }()
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				_ = s.Close(ctx)
				if err := <-done; err != nil {
					t.Error(err)
				}
			}()
			client, err := newClient(path, uint32(os.Geteuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if got, err := client.Execute(context.Background(), transportRequest(t)); got != nil || !errors.Is(err, ErrTransport) {
				t.Fatalf("bad response accepted: %#v %v", got, err)
			}
		})
	}
}

func TestUnixServerRejectsLiveOrNonSocketAndReclaimsStale(t *testing.T) {
	executor := transportExecutor(func(context.Context, io.Reader) (*helper.ExecutionReceipt, error) { return nil, nil })
	dir := transportDir(t)
	path := filepath.Join(dir, "helper.sock")
	cfg := Config{SocketPath: path, AgentUID: uint32(os.Geteuid()), AgentGID: uint32(os.Getegid())}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0660); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := newServer(cfg, executor, uint32(os.Geteuid())); s != nil || !errors.Is(err, ErrTransport) {
		t.Fatalf("live listener replaced: %v %v", s, err)
	}
	after, _ := os.Stat(path)
	if !os.SameFile(before, after) {
		t.Fatal("live listener inode changed")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := newServer(cfg, executor, uint32(os.Geteuid()))
	if err != nil {
		t.Fatalf("stale socket not reclaimed: %v", err)
	}
	after, _ = os.Stat(path)
	if os.SameFile(before, after) {
		t.Fatal("stale inode reused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("closed socket not removed: %v", err)
	}
	if err := os.WriteFile(path, []byte("installer sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	if s, err := newServer(cfg, executor, uint32(os.Geteuid())); s != nil || !errors.Is(err, ErrTransport) {
		t.Fatalf("regular file replaced: %v %v", s, err)
	}
	if b, _ := os.ReadFile(path); string(b) != "installer sentinel" {
		t.Fatal("non-socket file mutated")
	}
	if os.Geteuid() != 0 {
		if s, err := NewServer(cfg, executor); s != nil || !errors.Is(err, ErrTransport) {
			t.Fatalf("unprivileged production server accepted: %v %v", s, err)
		}
	}
}

func TestUnixClosePreservesReplacedSocketIdentity(t *testing.T) {
	s, path := transportServer(t, uint32(os.Geteuid()), transportExecutor(func(context.Context, io.Reader) (*helper.ExecutionReceipt, error) { return nil, nil }))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "replacement" {
		t.Fatalf("close deleted replacement: %q %v", b, err)
	}
}

func TestUnixConnectionBudgetReleasesOnDisconnect(t *testing.T) {
	s, path := transportServer(t, uint32(os.Geteuid()), transportExecutor(func(context.Context, io.Reader) (*helper.ExecutionReceipt, error) { return transportReceipt(), nil }))
	var held []net.Conn
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	for i := 0; i < 4; i++ {
		c, err := net.DialTimeout("unix", path, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	deadline := time.Now().Add(time.Second)
	for len(s.listener.slots) != 4 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(s.listener.slots) != 4 {
		t.Fatalf("not all authorized connections accepted: %d", len(s.listener.slots))
	}
	extra, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = extra.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	n, err := extra.Read(one[:])
	_ = extra.Close()
	if n != 0 || err == nil {
		t.Fatalf("fifth connection admitted: %d %v", n, err)
	}
	if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("excess connection retained instead of rejected")
	}
	_ = held[0].Close()
	deadline = time.Now().Add(time.Second)
	for len(s.listener.slots) == 4 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	in, _ := json.Marshal(transportRequest(t))
	resp, _ := rawLocalRequest(t, rawLocalClient(t, path), "POST", "/execute", "application/json", string(in), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("released slot not reusable: %d", resp.StatusCode)
	}
}
