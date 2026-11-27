package inventory

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ClientConfig struct {
	URL             string
	CAFile          string
	CAFingerprint   string
	CertificateFile string
	KeyFile         string
}
type Client struct {
	http       *http.Client
	base, node string
}

func NewClient(cfg ClientConfig) (*Client, error) {
	u, e := url.Parse(cfg.URL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || !digestPattern.MatchString(cfg.CAFingerprint) {
		return nil, ErrInvalid
	}
	b, e := readClientFile(cfg.CAFile, false)
	if e != nil {
		return nil, e
	}
	block, rest := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrInvalid
	}
	ca, e := x509.ParseCertificate(block.Bytes)
	if e != nil || !ca.IsCA || ca.KeyUsage&x509.KeyUsageCertSign == 0 || hash(ca.Raw) != cfg.CAFingerprint {
		return nil, ErrIdentity
	}
	certificatePEM, e := readClientFile(cfg.CertificateFile, false)
	if e != nil {
		return nil, e
	}
	privatePEM, e := readClientFile(cfg.KeyFile, true)
	if e != nil {
		return nil, e
	}
	defer clear(privatePEM)
	cert, e := tls.X509KeyPair(certificatePEM, privatePEM)
	if e != nil || len(cert.Certificate) == 0 {
		return nil, ErrIdentity
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil || len(leaf.URIs) != 1 {
		return nil, ErrIdentity
	}
	node := strings.TrimPrefix(leaf.URIs[0].String(), "spiffe://agp/agent/")
	if !idPattern.MatchString(node) || !agentLeaf(leaf, node) {
		return nil, ErrIdentity
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	t := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{cert}}, MaxIdleConns: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, ForceAttemptHTTP2: true}
	return &Client{http: &http.Client{Transport: t, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, base: strings.TrimRight(cfg.URL, "/"), node: node}, nil
}
func readClientFile(name string, private bool) ([]byte, error) {
	f, e := openPublicFile(name)
	if e != nil {
		return nil, ErrIdentity
	}
	defer f.Close()
	if private {
		st, e := f.Stat()
		if e != nil || st.Mode().Perm()&0077 != 0 {
			return nil, ErrIdentity
		}
	}
	b, e := io.ReadAll(io.LimitReader(f, 64<<10+1))
	if e != nil || len(b) > 64<<10 {
		return nil, ErrIdentity
	}
	return b, nil
}
func (c *Client) Close() { c.http.CloseIdleConnections() }
func (c *Client) post(ctx context.Context, path string, in, out any) error {
	b, e := Encode(in)
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(b))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, e := c.http.Do(req)
	if e != nil {
		return fmt.Errorf("%w: agent transport", ErrUnavailable)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8192))
		return fmt.Errorf("%w: agent response status %d", ErrUnavailable, resp.StatusCode)
	}
	mediaType, parameters, e := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if e != nil || mediaType != "application/json" {
		return fmt.Errorf("%w: response content type", ErrInvalid)
	}
	for parameter, value := range parameters {
		if parameter != "charset" || !strings.EqualFold(value, "utf-8") {
			return fmt.Errorf("%w: response JSON encoding", ErrInvalid)
		}
	}
	if e := Decode(resp.Body, out); e != nil {
		return fmt.Errorf("%w: response document", e)
	}
	return nil
}
func (c *Client) Challenge(ctx context.Context) (*Challenge, error) {
	var out Challenge
	if e := c.post(ctx, "/agent/v1/inventory-challenges", struct{}{}, &out); e != nil {
		return nil, e
	}
	if !idPattern.MatchString(out.ID) || !tokenPattern.MatchString(out.Challenge) || out.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("%w: challenge fields", ErrInvalid)
	}
	return &out, nil
}
func (c *Client) Submit(ctx context.Context, in Submission) (*Receipt, error) {
	var out Receipt
	if e := c.post(ctx, "/agent/v1/inventories", in, &out); e != nil {
		return nil, e
	}
	if out.NodeID != c.node || out.Sequence == 0 || out.RequestID != in.RequestID || !idPattern.MatchString(out.ID) || !digestPattern.MatchString(out.CapabilityDigest) || !digestPattern.MatchString(out.ObservationDigest) || out.ExpiresAt.Sub(out.ReceivedAt) != Freshness {
		return nil, fmt.Errorf("%w: receipt fields", ErrInvalid)
	}
	_, facts, observation, e := normalizeObservation(in.Observation)
	if e != nil || hash(facts) != out.CapabilityDigest || hash(observation) != out.ObservationDigest {
		return nil, fmt.Errorf("%w: receipt observation binding", ErrInvalid)
	}
	return &out, nil
}

// Report collects after a fresh challenge. A lost response can safely retry the
// exact Submission; its original receipt time is never extended by the server.
func (c *Client) Report(ctx context.Context, opts CollectorOptions) (*Receipt, error) {
	challenge, e := c.Challenge(ctx)
	if e != nil {
		return nil, fmt.Errorf("inventory challenge: %w", e)
	}
	observation, e := Collect(ctx, opts)
	if e != nil {
		return nil, fmt.Errorf("inventory collection: %w", e)
	}
	id, e := nonce()
	if e != nil {
		return nil, fmt.Errorf("inventory request identifier: %w", e)
	}
	in := Submission{RequestID: "ireq_" + id, ChallengeID: challenge.ID, Challenge: challenge.Challenge, Observation: observation}
	receipt, e := c.Submit(ctx, in)
	if e != nil {
		return nil, fmt.Errorf("inventory receipt: %w", e)
	}
	return receipt, nil
}
