// Package oidcclient implements a bounded OIDC client transport. It does not
// create sessions, consume login state, link principals or grant permissions.
package oidcclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
)

var (
	ErrInvalid     = errors.New("invalid OIDC client configuration or request")
	ErrUnavailable = errors.New("OIDC provider unavailable")
	ErrRejected    = errors.New("OIDC proof rejected")
)

// NetworkPolicy is trusted installation configuration, never provider/browser
// input. Callers load it from their protected startup configuration boundary.
type NetworkPolicy struct {
	HTTPSOrigins      []string
	AllowedCIDRs      []netip.Prefix
	Timeout           time.Duration
	MaximumConcurrent int
}

// Secrets transfers a fresh owned ClientSecret buffer to the transport. The
// resolver must not retain/reuse it. CA roots replace the system trust store.
type Secrets struct{ ClientSecret, CACertificatesPEM []byte }
type SecretResolver interface {
	ResolveOIDCSecrets(context.Context, string, string) (Secrets, error)
}
type Connector struct {
	origins  map[string]bool
	prefixes []netip.Prefix
	timeout  time.Duration
	slots    chan struct{}
	secrets  SecretResolver
	lookup   func(context.Context, string) ([]netip.Addr, error)
	dial     func(context.Context, string, string) (net.Conn, error)
	now      func() time.Time
}

func New(policy NetworkPolicy, secrets SecretResolver) (*Connector, error) {
	if secrets == nil || len(policy.HTTPSOrigins) < 1 || len(policy.HTTPSOrigins) > 32 || len(policy.AllowedCIDRs) < 1 || len(policy.AllowedCIDRs) > 64 {
		return nil, ErrInvalid
	}
	if policy.Timeout == 0 {
		policy.Timeout = 5 * time.Second
	}
	if policy.MaximumConcurrent == 0 {
		policy.MaximumConcurrent = 4
	}
	if policy.Timeout < time.Second || policy.Timeout > 10*time.Second || policy.MaximumConcurrent < 1 || policy.MaximumConcurrent > 16 {
		return nil, ErrInvalid
	}
	c := &Connector{origins: map[string]bool{}, prefixes: append([]netip.Prefix{}, policy.AllowedCIDRs...), timeout: policy.Timeout, slots: make(chan struct{}, policy.MaximumConcurrent), secrets: secrets, now: time.Now}
	for _, origin := range policy.HTTPSOrigins {
		u, e := httpsURL(origin)
		if e != nil || u.Path != "" || c.origins[origin] {
			return nil, ErrInvalid
		}
		c.origins[origin] = true
	}
	for _, prefix := range c.prefixes {
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
			return nil, ErrInvalid
		}
	}
	c.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	c.dial = (&net.Dialer{KeepAlive: -1}).DialContext
	return c, nil
}
func httpsURL(raw string) (*url.URL, error) {
	if len(raw) < 9 || len(raw) > 2048 || strings.TrimSpace(raw) != raw {
		return nil, ErrInvalid
	}
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Host == "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" || u.String() != raw {
		return nil, ErrInvalid
	}
	host, e := configmodel.CanonicalHostname(u.Hostname())
	if e != nil || host != u.Hostname() {
		return nil, ErrInvalid
	}
	if u.Port() != "" {
		port, e := strconv.Atoi(u.Port())
		if e != nil || port < 1 || port > 65535 || port == 443 || strconv.Itoa(port) != u.Port() {
			return nil, ErrInvalid
		}
	}
	if u.Host != strings.ToLower(u.Host) || strings.Contains(u.Path, "//") || (u.Path != "" && strings.TrimSuffix(u.Path, "/") != strings.TrimSuffix(path.Clean(u.Path), "/")) {
		return nil, ErrInvalid
	}
	return u, nil
}
func origin(u *url.URL) string { return "https://" + u.Host }
func (c *Connector) allowedURL(raw string) bool {
	u, e := httpsURL(raw)
	return e == nil && c.origins[origin(u)]
}
func (c *Connector) allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	for _, prefix := range c.prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

type operation struct {
	ctx       context.Context
	cancel    context.CancelFunc
	c         *Connector
	secrets   Secrets
	client    *http.Client
	transport *http.Transport
	pins      map[string]netip.Addr
	mu        sync.Mutex
}

func (c *Connector) operation(ctx context.Context, config Config) (*operation, error) {
	bounded, cancel := context.WithTimeout(ctx, c.timeout)
	select {
	case c.slots <- struct{}{}:
	case <-bounded.Done():
		cancel()
		return nil, ErrUnavailable
	}
	op := &operation{ctx: bounded, cancel: cancel, c: c, pins: map[string]netip.Addr{}}
	secret, e := c.secrets.ResolveOIDCSecrets(bounded, config.ClientSecretVersionID, config.CASecretVersionID)
	op.secrets = secret
	fail := func() (*operation, error) { op.close(); return nil, ErrUnavailable }
	if e != nil || len(secret.ClientSecret) == 0 || len(secret.ClientSecret) > 65536 || len(secret.CACertificatesPEM) == 0 || len(secret.CACertificatesPEM) > 262144 {
		return fail()
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(secret.CACertificatesPEM) {
		return fail()
	}
	op.transport = &http.Transport{Proxy: nil, DialContext: op.dial, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, ForceAttemptHTTP2: false, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 32 << 10, ResponseHeaderTimeout: c.timeout, TLSHandshakeTimeout: c.timeout, MaxConnsPerHost: 1}
	op.client = &http.Client{Transport: boundedTransport{op}, Timeout: c.timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return op, nil
}
func (op *operation) close() {
	if op.transport != nil {
		op.transport.CloseIdleConnections()
	}
	for i := range op.secrets.ClientSecret {
		op.secrets.ClientSecret[i] = 0
	}
	op.cancel()
	<-op.c.slots
}
func (op *operation) dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, ErrUnavailable
	}
	op.mu.Lock()
	ip, ok := op.pins[host]
	op.mu.Unlock()
	if !ok {
		ips, e := op.c.lookup(ctx, host)
		if e != nil || len(ips) < 1 || len(ips) > 32 {
			return nil, ErrUnavailable
		}
		for _, candidate := range ips {
			if !op.c.allowed(candidate) {
				return nil, ErrUnavailable
			}
		}
		ip = ips[0].Unmap()
		op.mu.Lock()
		op.pins[host] = ip
		op.mu.Unlock()
	}
	conn, e := op.c.dial(ctx, network, net.JoinHostPort(ip.String(), port))
	if e != nil {
		return nil, ErrUnavailable
	}
	if deadline, ok := op.ctx.Deadline(); ok {
		if e := conn.SetDeadline(deadline); e != nil {
			_ = conn.Close()
			return nil, ErrUnavailable
		}
	}
	return conn, nil
}

// Read before handing the response to OAuth/JWK decoders. This also defeats
// valid-JSON-prefix truncation in an SDK's own io.LimitReader response parser.
type boundedTransport struct{ op *operation }

func (t boundedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.op.c.allowedURL(req.URL.String()) || (req.Method != "GET" && req.Method != "POST") {
		return nil, ErrUnavailable
	}
	response, e := t.op.transport.RoundTrip(req)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer response.Body.Close()
	if req.Method == http.MethodPost && !jsonMediaType(response.Header.Get("Content-Type")) {
		return nil, ErrUnavailable
	}
	const limit = 256 << 10
	if response.ContentLength > limit || (response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity") {
		return nil, ErrUnavailable
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if e != nil || len(raw) > limit {
		return nil, ErrUnavailable
	}
	if req.Method == http.MethodPost {
		// OAuth's decoder accepts duplicate fields and replaces invalid UTF-8.
		// Validate the whole bounded envelope before allowing the SDK to parse it.
		var envelope map[string]json.RawMessage
		if safeJSON(raw, &envelope) != nil || len(envelope) == 0 {
			return nil, ErrUnavailable
		}
	}
	response.Body = io.NopCloser(bytes.NewReader(raw))
	response.ContentLength = int64(len(raw))
	return response, nil
}
func jsonMediaType(value string) bool {
	mediaType, _, e := mime.ParseMediaType(value)
	return e == nil && mediaType == "application/json"
}
func secretDigest(s Secrets) [32]byte { return sha256.Sum256(s.ClientSecret) }
