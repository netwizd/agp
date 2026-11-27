package securityjournal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type ClientConfig struct {
	URL, AuthorityID, KeyID string
	PublicKey               ed25519.PublicKey
	TLSConfig               *tls.Config
	Timeout                 time.Duration
}
type Client struct {
	cfg  ClientConfig
	base string
	http *http.Client
}

func NewClient(cfg ClientConfig) (*Client, error) {
	u, e := url.Parse(cfg.URL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || cfg.TLSConfig == nil || cfg.TLSConfig.InsecureSkipVerify || len(cfg.TLSConfig.Certificates) == 0 && cfg.TLSConfig.GetClientCertificate == nil || len(cfg.PublicKey) != ed25519.PublicKeySize || !objectID.MatchString(cfg.AuthorityID) || !objectID.MatchString(cfg.KeyID) {
		return nil, bad("HTTPS/mTLS journal client configuration")
	}
	t := cfg.TLSConfig.Clone()
	if t.MinVersion < tls.VersionTLS13 {
		t.MinVersion = tls.VersionTLS13
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if timeout > 30*time.Second {
		return nil, bad("journal timeout")
	}
	return &Client{cfg: cfg, base: strings.TrimRight(cfg.URL, "/"), http: &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: t, Proxy: nil, DisableKeepAlives: false, MaxIdleConns: 8, IdleConnTimeout: 30 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) CloseIdleConnections() { c.http.CloseIdleConnections() }

// SigningPublicKey returns a detached copy for cross-role trust separation.
func (c *Client) SigningPublicKey() ed25519.PublicKey {
	if c == nil {
		return nil
	}
	return append(ed25519.PublicKey(nil), c.cfg.PublicKey...)
}
func (c *Client) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, e := json.Marshal(in)
		if e != nil {
			return e
		}
		body = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if e != nil {
		return e
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, e := c.http.Do(req)
	if e != nil {
		return fmt.Errorf("%w: journal transport", ErrUnavailable)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case 404:
			return ErrNotFound
		case 409:
			return ErrConflict
		case 400:
			return ErrInvalid
		default:
			return ErrUnavailable
		}
	}
	if resp.Header.Get("Content-Type") != "application/json" {
		return bad("journal response content type")
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, 4<<20+1))
	if e != nil || len(b) > 4<<20 {
		return bad("journal response size")
	}
	return strictJSON(bytes.NewReader(b), out)
}
func (c *Client) Head(ctx context.Context) (Head, error) {
	challenge, e := randomID("")
	if e != nil {
		return Head{}, e
	}
	return c.HeadWithChallenge(ctx, challenge)
}

// HeadWithChallenge preserves a verifier's fresh challenge, rather than
// replacing it with an unrelated challenge at an intermediate transport.
func (c *Client) HeadWithChallenge(ctx context.Context, challenge string) (Head, error) {
	b, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != challenge {
		return Head{}, ErrInvalid
	}
	var h Head
	if e := c.call(ctx, "GET", "/checkpoint/v1/head?challenge="+url.QueryEscape(challenge), nil, &h); e != nil {
		return Head{}, e
	}
	if e := VerifyHead(h, challenge, c.cfg.AuthorityID, c.cfg.KeyID, c.cfg.PublicKey, time.Now().UTC()); e != nil {
		return Head{}, e
	}
	return h, nil
}
func (c *Client) Append(ctx context.Context, r AppendRequest) (Event, error) {
	if e := validateRequest(r); e != nil {
		return Event{}, e
	}
	var ev Event
	if e := c.call(ctx, "POST", "/checkpoint/v1/events", r, &ev); e != nil {
		return Event{}, e
	}
	if e := c.verify(ev); e != nil {
		return Event{}, e
	}
	d, e := RequestDigest(r)
	if e != nil || ev.RequestDigest != d {
		return Event{}, bad("receipt request mismatch")
	}
	return ev, nil
}
func (c *Client) Operation(ctx context.Context, id string) (Event, error) {
	if !objectID.MatchString(id) {
		return Event{}, bad("operation id")
	}
	var ev Event
	if e := c.call(ctx, "GET", "/checkpoint/v1/operations/"+id, nil, &ev); e != nil {
		return Event{}, e
	}
	if e := c.verify(ev); e != nil {
		return Event{}, e
	}
	if ev.Request.OperationID != id {
		return Event{}, bad("operation mismatch")
	}
	return ev, nil
}
func (c *Client) Events(ctx context.Context, after UInt63, limit int) ([]Event, error) {
	if after > MaxUInt63 || limit < 1 || limit > 1000 {
		return nil, bad("event cursor/limit")
	}
	var out struct {
		Events []Event `json:"events"`
	}
	if e := c.call(ctx, "GET", "/checkpoint/v1/events?afterSequence="+strconv.FormatUint(uint64(after), 10)+"&limit="+strconv.Itoa(limit), nil, &out); e != nil {
		return nil, e
	}
	if len(out.Events) > limit {
		return nil, bad("event page limit")
	}
	seq := after
	prev := ""
	for i, ev := range out.Events {
		if e := c.verify(ev); e != nil {
			return nil, e
		}
		if ev.Sequence != seq+1 || i > 0 && ev.PreviousDigest != prev {
			return nil, bad("event page gap/chain")
		}
		seq = ev.Sequence
		prev = ev.Digest
	}
	return out.Events, nil
}
func (c *Client) verify(ev Event) error {
	return VerifyEvent(ev, c.cfg.AuthorityID, c.cfg.KeyID, c.cfg.PublicKey)
}

type ServerConfig struct {
	ReadClientURIs   []string
	AppendClientURIs []string
}

// Handler only trusts peer certificates verified by the TLS server, never
// identity headers from a reverse proxy. Run on its own mTLS listener.
func Handler(store *Store, cfg ServerConfig) http.Handler {
	readers := map[string]bool{}
	writers := map[string]bool{}
	for _, u := range cfg.ReadClientURIs {
		readers[u] = true
	}
	for _, u := range cfg.AppendClientURIs {
		writers[u] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		identity := ""
		if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.PeerCertificates) > 0 && len(r.TLS.PeerCertificates[0].URIs) == 1 {
			identity = r.TLS.PeerCertificates[0].URIs[0].String()
		}
		permitted := identity != "" && ((r.Method == "GET" && readers[identity]) || (r.Method == "POST" && writers[identity]))
		if !permitted {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "client_role_required"})
			return
		}

		if len(r.URL.RawQuery) > 1024 {
			replyError(w, ErrInvalid)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		var out any
		var err error
		switch {
		case r.Method == "GET" && r.URL.Path == "/checkpoint/v1/head":
			challenge := r.URL.Query().Get("challenge")
			b, e := base64.RawURLEncoding.DecodeString(challenge)
			if e != nil || len(b) != 32 {
				err = ErrInvalid
				break
			}
			out, err = store.head(ctx, challenge)
		case r.Method == "POST" && r.URL.Path == "/checkpoint/v1/events":
			if r.Header.Get("Content-Type") != "application/json" {
				err = ErrInvalid
				break
			}
			r.Body = http.MaxBytesReader(w, r.Body, 262144)
			var req AppendRequest
			if e := strictJSON(r.Body, &req); e != nil {
				err = ErrInvalid
				break
			}
			out, err = store.Append(ctx, req)
		case r.Method == "GET" && r.URL.Path == "/checkpoint/v1/events":
			var after UInt63
			raw := r.URL.Query().Get("afterSequence")
			if e := after.UnmarshalJSON([]byte(strconv.Quote(raw))); e != nil {
				err = ErrInvalid
				break
			}
			limit, e := strconv.Atoi(r.URL.Query().Get("limit"))
			if e != nil {
				err = ErrInvalid
				break
			}
			var events []Event
			events, err = store.Events(ctx, after, limit)
			out = struct {
				Events []Event `json:"events"`
			}{events}
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/checkpoint/v1/operations/"):
			out, err = store.Operation(ctx, strings.TrimPrefix(r.URL.Path, "/checkpoint/v1/operations/"))
		default:
			http.NotFound(w, r)
			return
		}
		if err != nil {
			replyError(w, err)
			return
		}
		_ = json.NewEncoder(w).Encode(out)
	})
}
func replyError(w http.ResponseWriter, err error) {
	status := http.StatusServiceUnavailable
	message := "journal_unavailable"
	switch {
	case errors.Is(err, ErrConflict):
		status = 409
		message = "conflict"
	case errors.Is(err, ErrNotFound):
		status = 404
		message = "not_found"
	case errors.Is(err, ErrInvalid):
		status = 400
		message = "invalid_request"
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
func strictJSON(r io.Reader, out any) error {
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return bad("JSON body")
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return bad("trailing JSON")
	}
	return nil
}
