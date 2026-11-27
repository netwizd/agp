package nodebootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/inventory"
)

var nodeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

type ClientConfig struct {
	URL                   string
	CAFile                string
	CAFingerprint         string
	IdentityCAFile        string
	IdentityCAFingerprint string
	Directory             string
	CurrentDirectory      string
	NodeID                string
}

type Client struct {
	http       *http.Client
	base       string
	cfg        ClientConfig
	identityCA *x509.Certificate
}

type CertificateResult struct {
	NodeID              string    `json:"nodeId"`
	CertificateChainPEM string    `json:"certificateChainPem"`
	Serial              string    `json:"serial"`
	ExpiresAt           time.Time `json:"expiresAt"`
}

type PendingRequest struct {
	ID              string    `json:"id"`
	EnrollmentID    string    `json:"enrollmentId"`
	NodeID          string    `json:"nodeId"`
	State           string    `json:"state"`
	PublicKeyDigest string    `json:"publicKeyDigest"`
	RequestDigest   string    `json:"requestDigest"`
	ExpiresAt       time.Time `json:"expiresAt"`
}

func NewClient(cfg ClientConfig) (*Client, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") || !nodeIDPattern.MatchString(cfg.NodeID) {
		return nil, ErrInvalid
	}
	ca, err := loadCA(cfg.CAFile, cfg.CAFingerprint)
	if err != nil {
		return nil, err
	}
	identityCA, err := loadCA(cfg.IdentityCAFile, cfg.IdentityCAFingerprint)
	if err != nil {
		return nil, err
	}
	dir, err := privateDirectory(cfg.Directory)
	if err != nil {
		return nil, err
	}
	dir.Close()
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}
	if cfg.CurrentDirectory != "" {
		oldDir, e := privateDirectory(cfg.CurrentDirectory)
		if e != nil {
			return nil, e
		}
		oldDir.Close()
		certPEM, e := inventory.ReadProtectedFile(cfg.CurrentDirectory+"/certificate.pem", false)
		if e != nil {
			return nil, ErrProtectedPath
		}
		keyPEM, e := inventory.ReadProtectedFile(cfg.CurrentDirectory+"/key.pem", true)
		if e != nil {
			return nil, ErrProtectedPath
		}
		defer clear(keyPEM)
		cert, e := tls.X509KeyPair(certPEM, keyPEM)
		if e != nil || len(cert.Certificate) == 0 {
			return nil, ErrInvalid
		}
		leaf, e := x509.ParseCertificate(cert.Certificate[0])
		if e != nil || len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://agp/agent/"+cfg.NodeID || !time.Now().Before(leaf.NotAfter) {
			return nil, ErrInvalid
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	t := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true, DisableKeepAlives: true, MaxIdleConns: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second}
	return &Client{http: &http.Client{Transport: t, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, base: strings.TrimRight(cfg.URL, "/"), cfg: cfg, identityCA: identityCA}, nil
}

func (c *Client) Close() { c.http.CloseIdleConnections() }

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, ErrResponse
	}
	return b, nil
}

// ReadToken accepts only a single short token. Callers provide stdin or a
// protected file; the token is never included in a URL, argument or error.
func ReadToken(r io.Reader) (string, error) {
	b, err := readBounded(r, 256)
	if err != nil {
		return "", ErrInvalid
	}
	defer clear(b)
	token := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	if !tokenPattern.MatchString(token) {
		return "", ErrInvalid
	}
	return token, nil
}

func (c *Client) post(ctx context.Context, path string, body any, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return ErrInvalid
	}
	defer clear(b)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(b))
	if err != nil {
		return ErrInvalid
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return ErrTransport
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8192))
		return ErrResponse
	}
	media, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return ErrResponse
	}
	for k, v := range params {
		if k != "charset" || !strings.EqualFold(v, "utf-8") {
			return ErrResponse
		}
	}
	data, err := readBounded(resp.Body, 64<<10)
	if err != nil || configmodel.DecodeEnvelopeJSON(data, out) != nil {
		return ErrResponse
	}
	return nil
}

func (c *Client) submission(token string) (map[string]string, error) {
	if !tokenPattern.MatchString(token) {
		return nil, ErrInvalid
	}
	csr, key, err := readRequest(c.cfg.Directory)
	if err != nil {
		return nil, err
	}
	clear(key)
	return map[string]string{"nodeId": c.cfg.NodeID, "enrollmentToken": token, "csrPem": string(csr)}, nil
}

func (c *Client) Request(ctx context.Context, token string) (*PendingRequest, error) {
	body, err := c.submission(token)
	if err != nil {
		return nil, err
	}
	var out PendingRequest
	if err = c.post(ctx, "/agent/v1/enrollment-requests", body, &out); err != nil {
		return nil, err
	}
	_, key, err := readRequest(c.cfg.Directory)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	if out.NodeID != c.cfg.NodeID || !nodeIDPattern.MatchString(out.ID) || !nodeIDPattern.MatchString(out.EnrollmentID) || out.PublicKeyDigest != fingerprint(mustSPKI(key.Public())) || !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(out.RequestDigest) || !time.Now().Before(out.ExpiresAt) {
		return nil, ErrResponse
	}
	switch out.State {
	case "csr_pending", "approved", "issued_certificate":
	default:
		return nil, ErrResponse
	}
	return &out, nil
}

// Renew authenticates with the old role certificate and requests a certificate
// for the new directory's CSR. Switching the running agent is an explicit later
// installation action, after the returned certificate has been verified.
func (c *Client) Renew(ctx context.Context) (*CertificateResult, error) {
	if c.cfg.CurrentDirectory == "" || c.cfg.CurrentDirectory == c.cfg.Directory {
		return nil, ErrInvalid
	}
	csr, key, err := readRequest(c.cfg.Directory)
	if err != nil {
		return nil, err
	}
	clear(key)
	var out CertificateResult
	if err = c.post(ctx, "/agent/v1/identities/renew", map[string]string{"csrPem": string(csr)}, &out); err != nil {
		return nil, err
	}
	if err = c.saveCertificate(out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Enroll completes only an already operator-approved CSR. A lost response can be
// retried with the same key and token, yielding the same issuer certificate.
func (c *Client) Enroll(ctx context.Context, token string) (*CertificateResult, error) {
	body, err := c.submission(token)
	if err != nil {
		return nil, err
	}
	var out CertificateResult
	if err = c.post(ctx, "/agent/v1/enroll", body, &out); err != nil {
		return nil, err
	}
	if err = c.saveCertificate(out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) saveCertificate(out CertificateResult) error {
	_, key, err := readRequest(c.cfg.Directory)
	if err != nil {
		return err
	}
	defer clear(key)
	if out.NodeID != c.cfg.NodeID || out.Serial == "" || len(out.CertificateChainPEM) > 32768 {
		return ErrResponse
	}
	var chain []*x509.Certificate
	rest := []byte(out.CertificateChainPEM)
	for len(bytes.TrimSpace(rest)) != 0 {
		block, tail := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(chain) >= 5 {
			return ErrResponse
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			return ErrResponse
		}
		chain = append(chain, cert)
		rest = tail
	}
	if len(chain) == 0 {
		return ErrResponse
	}
	leaf := chain[0]
	if !bytes.Equal(leaf.RawSubjectPublicKeyInfo, mustSPKI(key.Public())) || leaf.IsCA || leaf.SerialNumber.Sign() <= 0 || leaf.SerialNumber.Text(16) != out.Serial || !leaf.NotAfter.Equal(out.ExpiresAt) || leaf.NotAfter.Sub(leaf.NotBefore) > 24*time.Hour || leaf.KeyUsage != x509.KeyUsageDigitalSignature || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.UnknownExtKeyUsage) != 0 || len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://agp/agent/"+c.cfg.NodeID || len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses) != 0 {
		return ErrResponse
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(c.identityCA)
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return ErrResponse
	}
	dir, err := privateDirectory(c.cfg.Directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	// A successful retry leaves the same certificate in place. Arbitrary existing
	// files or a different certificate cannot be replaced by enrollment.
	name := dir.Name() + "/certificate.pem"
	if old, e := inventory.ReadProtectedFile(name, false); e == nil {
		if bytes.Equal(old, []byte(out.CertificateChainPEM)) {
			return nil
		}
		return ErrProtectedPath
	}
	return createAt(dir, "certificate.pem", []byte(out.CertificateChainPEM))
}
