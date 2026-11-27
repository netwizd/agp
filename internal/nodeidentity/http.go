package nodeidentity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/securityjournal"
)

const (
	IssuerServerURI = "spiffe://agp/node-issuer/agent"
	IssuerWriterURI = "spiffe://agp/control-plane/node-issuer"
	IssuerReaderURI = "spiffe://agp/control-plane/agent-registry"
)

type ClientConfig struct {
	URL                     string `json:"url"`
	ServerName              string `json:"serverName"`
	CertificateFile         string `json:"certificateFile"`
	KeyFile                 string `json:"keyFile"`
	RegistryCertificateFile string `json:"registryCertificateFile"`
	RegistryKeyFile         string `json:"registryKeyFile"`
	CAFile                  string `json:"caFile"`
	CAFingerprint           string `json:"caFingerprint"`
	TimeoutSeconds          int    `json:"timeoutSeconds,omitempty"`
}
type Client struct {
	base           string
	writer, reader *http.Client
}

func LoadClientConfig(path string) (*Client, error) {
	b, e := readProtected(path, false, 65536)
	if e != nil {
		return nil, e
	}
	var cfg ClientConfig
	if decode(bytes.NewReader(b), &cfg, 65536) != nil {
		return nil, ErrInvalid
	}
	return NewClient(cfg)
}
func NewClient(cfg ClientConfig) (*Client, error) {
	u, e := url.Parse(cfg.URL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || cfg.ServerName == "" || cfg.CertificateFile == cfg.RegistryCertificateFile || cfg.KeyFile == cfg.RegistryKeyFile {
		return nil, ErrInvalid
	}
	if cfg.TimeoutSeconds == 0 {
		cfg.TimeoutSeconds = 10
	}
	if cfg.TimeoutSeconds < 1 || cfg.TimeoutSeconds > 30 {
		return nil, ErrInvalid
	}
	ca, e := readProtected(cfg.CAFile, false, 131072)
	if e != nil {
		return nil, e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, ErrInvalid
	}
	certs, e := parseCertificates(ca)
	if e != nil || len(certs) != 1 || hash(certs[0].Raw) != cfg.CAFingerprint {
		return nil, ErrInvalid
	}
	makeClient := func(certFile, keyFile, role string) (*http.Client, error) {
		cert, e := readProtected(certFile, false, 131072)
		if e != nil {
			return nil, e
		}
		key, e := readProtected(keyFile, true, 32768)
		if e != nil {
			return nil, e
		}
		pair, e := tls.X509KeyPair(cert, key)
		if e != nil || len(pair.Certificate) == 0 {
			return nil, ErrInvalid
		}
		leaf, e := x509.ParseCertificate(pair.Certificate[0])
		if e != nil || !hasRole(leaf, role) {
			return nil, ErrInvalid
		}
		conf := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, RootCAs: roots, ServerName: cfg.ServerName, VerifyConnection: func(state tls.ConnectionState) error {
			// crypto/tls invokes this after certificate verification but before
			// marking the handshake complete. The callback itself is the fence.
			state.HandshakeComplete = true
			if !verifiedRole(&state, IssuerServerURI, time.Now().UTC()) {
				return ErrDenied
			}
			return nil
		}}
		return &http.Client{Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second, Transport: &http.Transport{TLSClientConfig: conf, Proxy: nil, DisableKeepAlives: true, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
	}
	writer, e := makeClient(cfg.CertificateFile, cfg.KeyFile, IssuerWriterURI)
	if e != nil {
		return nil, e
	}
	reader, e := makeClient(cfg.RegistryCertificateFile, cfg.RegistryKeyFile, IssuerReaderURI)
	if e != nil {
		return nil, e
	}
	return &Client{strings.TrimRight(cfg.URL, "/"), writer, reader}, nil
}
func (c *Client) CloseIdleConnections() {
	c.writer.CloseIdleConnections()
	c.reader.CloseIdleConnections()
}
func (c *Client) call(ctx context.Context, path string, in, out any) error {
	raw, e := json.Marshal(in)
	if e != nil {
		return ErrInvalid
	}
	req, e := http.NewRequestWithContext(ctx, "POST", c.base+path, bytes.NewReader(raw))
	if e != nil {
		return ErrInvalid
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	client := c.writer
	if path == "/issuer/v1/registry" {
		client = c.reader
	}
	resp, e := client.Do(req)
	if e != nil {
		return ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		switch resp.StatusCode {
		case 400:
			return ErrInvalid
		case 403:
			return ErrDenied
		case 409:
			return ErrConflict
		case 429:
			return ErrLimited
		default:
			return ErrUnavailable
		}
	}
	if resp.Header.Get("Content-Type") != "application/json" {
		return ErrUnavailable
	}
	if out == nil {
		out = &struct{}{}
	}
	if decode(resp.Body, out, 64<<20) != nil {
		return ErrUnavailable
	}
	return nil
}
func (c *Client) Reserve(ctx context.Context, r Reservation) error {
	return c.call(ctx, "/issuer/v1/reservations", r, nil)
}
func (c *Client) Issue(ctx context.Context, r IssueRequest) (out CertificateResult, e error) {
	e = c.call(ctx, "/issuer/v1/issuances", r, &out)
	return
}
func (c *Client) Cancel(ctx context.Context, id string, epoch securityjournal.UInt63) error {
	return c.call(ctx, "/issuer/v1/cancellations", cancelRequest{id, epoch}, nil)
}
func (c *Client) Renew(ctx context.Context, r RenewRequest) (out CertificateResult, e error) {
	e = c.call(ctx, "/issuer/v1/renewals", r, &out)
	return
}
func (c *Client) Registry(ctx context.Context, h securityjournal.Head) (out inventory.Registry, e error) {
	e = c.call(ctx, "/issuer/v1/registry", registryRequest{h.AuthorityID, h.Epoch}, &out)
	return
}

type cancelRequest struct {
	EnrollmentID string                 `json:"enrollmentId"`
	Epoch        securityjournal.UInt63 `json:"epoch"`
}
type registryRequest struct {
	AuthorityID string                 `json:"authorityId"`
	Epoch       securityjournal.UInt63 `json:"epoch"`
}

func hasRole(c *x509.Certificate, role string) bool {
	return !c.IsCA && len(c.URIs) == 1 && c.URIs[0].String() == role && c.KeyUsage&x509.KeyUsageDigitalSignature != 0
}
func verifiedRole(state *tls.ConnectionState, role string, now time.Time) bool {
	if state == nil || state.Version != tls.VersionTLS13 || !state.HandshakeComplete || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 || !hasRole(state.PeerCertificates[0], role) {
		return false
	}
	leaf := state.PeerCertificates[0]
	for _, chain := range state.VerifiedChains {
		if len(chain) < 2 || !bytes.Equal(chain[0].Raw, leaf.Raw) {
			continue
		}
		valid := true
		for _, c := range chain {
			if now.Before(c.NotBefore) || !now.Before(c.NotAfter) {
				valid = false
			}
		}
		if valid {
			return true
		}
	}
	return false
}
func Handler(issuer Issuer) http.Handler {
	slots := make(chan struct{}, 8)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		role := IssuerWriterURI
		if r.URL.Path == "/issuer/v1/registry" {
			role = IssuerReaderURI
		}
		if r.Method != "POST" || r.URL.RawQuery != "" || !verifiedRole(r.TLS, role, time.Now().UTC()) {
			w.WriteHeader(403)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			w.WriteHeader(429)
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(400)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		var out any = struct{}{}
		var e error
		switch r.URL.Path {
		case "/issuer/v1/reservations":
			var in Reservation
			e = decode(r.Body, &in, 65536)
			if e == nil {
				e = issuer.Reserve(ctx, in)
			}
		case "/issuer/v1/issuances":
			var in IssueRequest
			e = decode(r.Body, &in, 65536)
			if e == nil {
				out, e = issuer.Issue(ctx, in)
			}
		case "/issuer/v1/renewals":
			var in RenewRequest
			e = decode(r.Body, &in, 65536)
			if e == nil {
				out, e = issuer.Renew(ctx, in)
			}
		case "/issuer/v1/cancellations":
			var in cancelRequest
			e = decode(r.Body, &in, 1024)
			if e == nil {
				e = issuer.Cancel(ctx, in.EnrollmentID, in.Epoch)
			}
		case "/issuer/v1/registry":
			var in registryRequest
			e = decode(r.Body, &in, 1024)
			if e == nil {
				out, e = issuer.Registry(ctx, securityjournal.Head{AuthorityID: in.AuthorityID, Epoch: in.Epoch})
			}
		default:
			w.WriteHeader(404)
			return
		}
		if e != nil {
			switch {
			case errors.Is(e, ErrInvalid):
				w.WriteHeader(400)
			case errors.Is(e, ErrDenied):
				w.WriteHeader(403)
			case errors.Is(e, ErrConflict):
				w.WriteHeader(409)
			case errors.Is(e, ErrLimited):
				w.WriteHeader(429)
			default:
				w.WriteHeader(503)
			}
			return
		}
		json.NewEncoder(w).Encode(out)
	})
}
func parseCertificates(raw []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for len(bytes.TrimSpace(raw)) > 0 {
		b, rest := pemDecode(raw)
		if b == nil {
			return nil, ErrInvalid
		}
		c, e := x509.ParseCertificate(b)
		if e != nil {
			return nil, ErrInvalid
		}
		out = append(out, c)
		raw = rest
	}
	if len(out) == 0 {
		return nil, ErrInvalid
	}
	return out, nil
}
func pemDecode(raw []byte) ([]byte, []byte) {
	b, rest := pem.Decode(raw)
	if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) > 0 {
		return nil, nil
	}
	return b.Bytes, rest
}
func Fingerprint(c *x509.Certificate) string {
	s := sha256.Sum256(c.Raw)
	return "sha256:" + hex.EncodeToString(s[:])
}

// LoadIssuerTLS loads dedicated transport credentials using the same descriptor
// path protection as the issuing key. The signing CA chain is a separate file.
func LoadIssuerTLS(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, e := readProtected(certFile, false, 131072)
	if e != nil {
		return nil, e
	}
	key, e := readProtected(keyFile, true, 32768)
	if e != nil {
		return nil, e
	}
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		return nil, ErrInvalid
	}
	ca, e := readProtected(caFile, false, 131072)
	if e != nil {
		return nil, e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, ErrInvalid
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil || !hasRole(leaf, IssuerServerURI) {
		return nil, ErrInvalid
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}, nil
}
