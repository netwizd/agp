package edgeauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
)

type RedeemRequest = domain.HandoffRedeemRequest
type RedeemResponse = domain.HandoffRedeemResponse
type DecisionRequest = domain.EdgeDecisionRequest
type Decision domain.EdgeDecision
type Central interface {
	Redeem(context.Context, RedeemRequest) (RedeemResponse, error)
	Decide(context.Context, DecisionRequest) (Decision, error)
	Logout(context.Context, string, string) error
}
type Client struct {
	origin string
	http   *http.Client
}

func NewClient(c Config) (*Client, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	keyInfo, err := os.Lstat(c.ClientKeyFile)
	if err != nil {
		return nil, err
	}
	if !keyInfo.Mode().IsRegular() || keyInfo.Mode().Perm()&0027 != 0 {
		return nil, fmt.Errorf("EdgeAuth private key must be a protected regular file")
	}
	cert, err := tls.LoadX509KeyPair(c.ClientCertificateFile, c.ClientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load EdgeAuth certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	want := "spiffe://agp/edge/" + c.NodeID + "/" + c.GatewayID
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != want {
		return nil, fmt.Errorf("EdgeAuth certificate identity differs from deployment")
	}
	clientAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if !clientAuth {
		return nil, fmt.Errorf("EdgeAuth certificate requires ClientAuth EKU")
	}
	pem, err := os.ReadFile(c.ServerCAFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("invalid server CA")
	}
	u, _ := url.Parse(c.CentralOrigin)
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{cert}, ServerName: u.Hostname()}, MaxIdleConns: 10, MaxIdleConnsPerHost: 10, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 3 * time.Second}
	return &Client{origin: c.CentralOrigin, http: &http.Client{Transport: transport, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) Close() { c.http.CloseIdleConnections() }
func (c *Client) call(ctx context.Context, path string, input any, output any, status int) error {
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("central auth unavailable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != status {
		return fmt.Errorf("central auth status %d", resp.StatusCode)
	}
	if output == nil {
		_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return err
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return fmt.Errorf("central auth returned invalid content type")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(data) > 65536 {
		return fmt.Errorf("central auth returned oversized response")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err = d.Decode(output); err != nil {
		return fmt.Errorf("central auth returned invalid JSON: %w", err)
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("central auth returned trailing JSON")
	}
	return nil
}
func (c *Client) Redeem(ctx context.Context, in RedeemRequest) (RedeemResponse, error) {
	var out RedeemResponse
	err := c.call(ctx, "/auth/v2/handoffs/redeem", in, &out, http.StatusOK)
	if err == nil && (!validToken(out.SessionToken) || !opaqueID.MatchString(out.SessionID) || !opaqueID.MatchString(out.UserID) || !out.ExpiresAt.After(time.Now()) || out.ExpiresAt.After(time.Now().Add(30*24*time.Hour))) {
		err = fmt.Errorf("central auth returned invalid gateway session")
	}
	return out, err
}
func (c *Client) Decide(ctx context.Context, in DecisionRequest) (Decision, error) {
	var out Decision
	err := c.call(ctx, "/auth/v2/decisions", in, &out, http.StatusOK)
	if err == nil {
		err = out.Validate()
	}
	return out, err
}
func (c *Client) Logout(ctx context.Context, gateway, token string) error {
	return c.call(ctx, "/auth/v2/logout", struct {
		GatewayID    string `json:"gatewayId"`
		SessionToken string `json:"sessionToken"`
	}{gateway, token}, nil, http.StatusNoContent)
}

func (d Decision) Validate() error {
	if d.SecuritySequence > securityjournal.MaxUInt63 {
		return fmt.Errorf("invalid security sequence")
	}
	if d.Decision == "allow" {
		if d.ReasonCode != "allowed" || !opaqueID.MatchString(d.UserID) || d.GroupIDs == nil || len(d.GroupIDs) > 100 {
			return fmt.Errorf("invalid allow decision")
		}
		seen := map[string]bool{}
		for _, id := range d.GroupIDs {
			if !opaqueID.MatchString(id) || seen[id] {
				return fmt.Errorf("invalid groups")
			}
			seen[id] = true
		}
		return nil
	}
	if d.Decision != "deny" || d.UserID != "" || d.GroupIDs != nil {
		return fmt.Errorf("invalid deny decision")
	}
	switch d.ReasonCode {
	case "authentication_required", "session_expired", "mfa_required", "access_denied":
		return nil
	default:
		return fmt.Errorf("unknown denial reason")
	}
}

// UnmarshalJSON checks the closed union, including required fields, forbidden
// deny identity fields and duplicate keys. A JSON 200 alone is never an allow.
func (d *Decision) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return fmt.Errorf("expected decision object")
	}
	fields := map[string]json.RawMessage{}
	for dec.More() {
		token, err = dec.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("invalid decision key")
		}
		if _, ok = fields[key]; ok {
			return fmt.Errorf("duplicate decision key")
		}
		var raw json.RawMessage
		if err = dec.Decode(&raw); err != nil {
			return err
		}
		fields[key] = raw
	}
	if _, err = dec.Token(); err != nil {
		return err
	}
	if dec.Decode(new(any)) != io.EOF {
		return fmt.Errorf("trailing decision JSON")
	}
	var kind string
	if err = json.Unmarshal(fields["decision"], &kind); err != nil {
		return err
	}
	keys := []string{"decision", "reasonCode", "securitySequence"}
	if kind == "allow" {
		keys = append(keys, "userId", "groupIds")
	}
	if len(fields) != len(keys) {
		return fmt.Errorf("invalid decision fields")
	}
	for _, key := range keys {
		if _, ok := fields[key]; !ok {
			return fmt.Errorf("missing decision field %s", key)
		}
	}
	type plain Decision
	var out plain
	if err = json.Unmarshal(data, &out); err != nil {
		return err
	}
	*d = Decision(out)
	return d.Validate()
}
func uint63(s string) bool {
	if s == "" || len(s) > 19 || len(s) > 1 && s[0] == '0' {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	_, err := strconv.ParseInt(s, 10, 64)
	return err == nil
}
func validToken(s string) bool {
	if len(s) < 43 || len(s) > 512 || strings.Contains(s, "=") {
		return false
	}
	v, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(v) >= 32
}
