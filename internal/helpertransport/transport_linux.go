//go:build linux

// Package helpertransport exposes a small, credential-bound local execution
// channel. It never accepts installation paths or delivery acknowledgements.
package helpertransport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/netwizd/agp/internal/helper"
	"github.com/netwizd/agp/internal/inventory"
	"golang.org/x/sys/unix"
)

var ErrTransport = errors.New("helper_transport_unavailable")

// ReadRootFile requires a root-owned, non-writable ancestry and one regular
// file. It is used for installer inputs, including public trust and private keys.
func ReadRootFile(path string, private bool, limit int) ([]byte, error) {
	return readFile(path, private, limit, 0)
}

// ReadPrivateFile is for signed payload bytes owned by the service. Such bytes
// do not establish trust; their signature is checked against separate root pins.
func ReadPrivateFile(path string, limit int) ([]byte, error) {
	return readFile(path, true, limit, uint32(os.Geteuid()))
}

func ancestry(path string, owner uint32) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return ErrTransport
	}
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/") {
		if part != "" {
			current = filepath.Join(current, part)
		}
		st, err := os.Lstat(current)
		if err != nil || !st.IsDir() {
			return ErrTransport
		}
		s, ok := st.Sys().(*syscall.Stat_t)
		if !ok || (s.Uid != 0 && s.Uid != owner) {
			return ErrTransport
		}
		if st.Mode().Perm()&0022 != 0 && !(current == "/tmp" && s.Uid == 0 && st.Mode()&os.ModeSticky != 0) {
			return ErrTransport
		}
	}
	return nil
}

func readFile(path string, private bool, limit int, owner uint32) ([]byte, error) {
	if limit < 1 || ancestry(path, owner) != nil {
		return nil, ErrTransport
	}
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrTransport
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, ErrTransport
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || s.Uid != owner || s.Nlink != 1 || st.Mode().Perm()&0022 != 0 || (private && st.Mode().Perm()&0077 != 0) || st.Size() > int64(limit) {
		return nil, ErrTransport
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil || len(b) > limit {
		return nil, ErrTransport
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(st, after) || ancestry(path, owner) != nil {
		return nil, ErrTransport
	}
	return b, nil
}

func peerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, ErrTransport
	}
	var uid uint32
	var inner error
	err = raw.Control(func(fd uintptr) {
		var p *unix.Ucred
		p, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if inner == nil {
			uid = p.Uid
		}
	})
	if err != nil || inner != nil {
		return 0, ErrTransport
	}
	return uid, nil
}

func socketInfo(path string, owner uint32) (os.FileInfo, error) {
	if ancestry(path, owner) != nil {
		return nil, ErrTransport
	}
	st, err := os.Lstat(path)
	if err != nil {
		return nil, ErrTransport
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || st.Mode()&os.ModeSocket == 0 || s.Uid != owner || st.Mode().Perm()&0007 != 0 || s.Nlink != 1 {
		return nil, ErrTransport
	}
	return st, nil
}

type Client struct {
	path  string
	owner uint32
	http  *http.Client
}

func NewClient(path string) (*Client, error) { return newClient(path, 0) }
func newClient(path string, owner uint32) (*Client, error) {
	if ancestry(path, owner) != nil {
		return nil, ErrTransport
	}
	c := &Client{path: path, owner: owner}
	t := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		before, err := socketInfo(path, owner)
		if err != nil {
			return nil, err
		}
		conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", path)
		if err != nil {
			return nil, ErrTransport
		}
		u, ok := conn.(*net.UnixConn)
		if !ok {
			conn.Close()
			return nil, ErrTransport
		}
		uid, err := peerUID(u)
		after, e := socketInfo(path, owner)
		if err != nil || e != nil || uid != owner || !os.SameFile(before, after) {
			conn.Close()
			return nil, ErrTransport
		}
		return conn, nil
	}}
	c.http = &http.Client{Transport: t, Timeout: 180 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return c, nil
}
func (c *Client) Close() { c.http.CloseIdleConnections() }
func (c *Client) Execute(ctx context.Context, in helper.Request) (*helper.ExecutionReceipt, error) {
	b, err := json.Marshal(in)
	if err != nil {
		return nil, ErrTransport
	}
	if _, err = helper.Decode(bytes.NewReader(b)); err != nil {
		return nil, err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://helper/execute", bytes.NewReader(b))
	if err != nil {
		return nil, ErrTransport
	}
	r.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(r)
	if err != nil {
		return nil, ErrTransport
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/json" {
		return nil, ErrTransport
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(raw) > 65536 {
		return nil, ErrTransport
	}
	var out helper.ExecutionReceipt
	if inventory.Decode(bytes.NewReader(raw), &out) != nil {
		return nil, ErrTransport
	}
	return &out, nil
}

type Executor interface {
	Execute(context.Context, io.Reader) (*helper.ExecutionReceipt, error)
}
type Config struct {
	SocketPath         string
	AgentUID, AgentGID uint32
}
type Server struct {
	http     *http.Server
	listener *guardedListener
	path     string
	identity os.FileInfo
	owner    uint32
}
type guardedListener struct {
	*net.UnixListener
	uid   uint32
	slots chan struct{}
}
type trackedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *trackedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (l *guardedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		uid, err := peerUID(c)
		if err != nil || uid != l.uid {
			c.Close()
			continue
		}
		select {
		case l.slots <- struct{}{}:
			return &trackedConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			c.Close()
		}
	}
}
func NewServer(cfg Config, executor Executor) (*Server, error) {
	if os.Geteuid() != 0 {
		return nil, ErrTransport
	}
	return newServer(cfg, executor, 0)
}
func newServer(cfg Config, executor Executor, owner uint32) (*Server, error) {
	if executor == nil || cfg.AgentUID == 0 || cfg.AgentGID == 0 || len(cfg.SocketPath) > 100 || ancestry(cfg.SocketPath, owner) != nil {
		return nil, ErrTransport
	}
	// The caller already holds the exclusive execution-ledger lock. A stale
	// socket is removed only with the exact protected identity and no listener.
	if old, err := socketInfo(cfg.SocketPath, owner); err == nil {
		conn, e := net.DialTimeout("unix", cfg.SocketPath, 100*time.Millisecond)
		if e == nil {
			conn.Close()
			return nil, ErrTransport
		}
		if !errors.Is(e, syscall.ECONNREFUSED) {
			return nil, ErrTransport
		}
		now, e := socketInfo(cfg.SocketPath, owner)
		if e != nil || !os.SameFile(old, now) {
			return nil, ErrTransport
		}
		if os.Remove(cfg.SocketPath) != nil {
			return nil, ErrTransport
		}
	} else if _, e := os.Lstat(cfg.SocketPath); !errors.Is(e, os.ErrNotExist) {
		return nil, ErrTransport
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: cfg.SocketPath, Net: "unix"})
	if err != nil {
		return nil, ErrTransport
	}
	l.SetUnlinkOnClose(false)
	cleanup := func() { l.Close(); os.Remove(cfg.SocketPath) }
	if os.Chmod(cfg.SocketPath, 0660) != nil || os.Chown(cfg.SocketPath, int(owner), int(cfg.AgentGID)) != nil {
		cleanup()
		return nil, ErrTransport
	}
	identity, err := socketInfo(cfg.SocketPath, owner)
	if err != nil {
		cleanup()
		return nil, err
	}
	s := &Server{listener: &guardedListener{UnixListener: l, uid: cfg.AgentUID, slots: make(chan struct{}, 4)}, path: cfg.SocketPath, identity: identity, owner: owner}
	s.http = &http.Server{ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 180 * time.Second, IdleTimeout: 3 * time.Second, MaxHeaderBytes: 8192, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "POST" || r.URL.Path != "/execute" || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" || len(r.Header.Values("Cookie")) != 0 || len(r.Header.Values("Origin")) != 0 {
			w.WriteHeader(400)
			io.WriteString(w, "{\"error\":\"invalid_helper_request\"}")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 175*time.Second)
		defer cancel()
		out, e := executor.Execute(ctx, http.MaxBytesReader(w, r.Body, helper.MaxRequestBytes))
		if e != nil {
			status := 503
			if errors.Is(e, helper.ErrInvalid) {
				status = 400
			} else if errors.Is(e, helper.ErrUnauthorized) {
				status = 403
			} else if errors.Is(e, helper.ErrPending) || errors.Is(e, helper.ErrStale) || errors.Is(e, helper.ErrConflict) {
				status = 409
			}
			w.WriteHeader(status)
			io.WriteString(w, "{\"error\":\"helper_execution_unavailable\"}")
			return
		}
		if out == nil {
			w.WriteHeader(503)
			io.WriteString(w, "{\"error\":\"helper_execution_unavailable\"}")
			return
		}
		json.NewEncoder(w).Encode(out)
	})}
	return s, nil
}
func (s *Server) Serve() error {
	err := s.http.Serve(s.listener)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
func (s *Server) Close(ctx context.Context) error {
	err := s.http.Shutdown(ctx)
	if err != nil {
		s.http.Close()
	}
	s.listener.Close()
	if now, e := socketInfo(s.path, s.owner); e == nil && os.SameFile(now, s.identity) {
		if e = os.Remove(s.path); err == nil {
			err = e
		}
	}
	return err
}
