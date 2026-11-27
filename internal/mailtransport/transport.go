// Package mailtransport submits one in-memory message to one installation-owned
// SMTP endpoint. It does not queue, retry, grant identity, or prove delivery.
package mailtransport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/netip"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	ImplicitTLS      = "implicit_tls"
	RequiredSTARTTLS = "required_starttls"
	AuthPlain        = "plain"
	AuthNone         = "none"
	MaxTextBytes     = 256 << 10
	maxWireReadBytes = 256 << 10
)

var (
	ErrInvalid     = errors.New("mail transport: invalid input")
	ErrUnavailable = errors.New("mail transport: unavailable")
	ErrRejected    = errors.New("mail transport: rejected")
	ErrUnknown     = errors.New("mail transport: submission outcome unknown")
)

// Config is installation-owned, never supplied by the recipient or SMTP reply.
// Only ASCII mailbox/domain syntax is supported by this first profile. AuthNone
// is an explicit relay profile, never a fallback after an authentication failure.
type Config struct {
	Host, Transport, HelloName, From string
	Port                             int
	Authentication, Username         string
	PasswordVersionID, CAVersionID   string
	OperationTimeout                 time.Duration
}

// Secrets are fresh buffers transferred to Send, which clears both on return.
// Implementations must honor context and must not retain/reuse these buffers.
type Secrets struct {
	Password          []byte
	CACertificatesPEM []byte
}

type SecretResolver interface {
	ResolveMailSecrets(context.Context, string, string) (Secrets, error)
}

// Message contains plaintext only for the duration of Send. The outbox supplies
// the stable, non-secret ID and creation time; no recipient-controlled headers
// or raw MIME are accepted. The caller must not modify Text during Send.
type Message struct {
	ID, To, Subject string
	CreatedAt       time.Time
	Text            []byte
}

type State string

const (
	Accepted State = "accepted" // A final SMTP 250 after DATA, not delivery/read.
	Rejected State = "rejected" // Known not accepted, including pre-DATA failure.
	Unknown  State = "unknown"  // DATA started but no authoritative final reply.
)

// Result contains no server diagnostics, addresses, message, or credentials.
// Rejected is not a retry instruction: a future outbox must recheck the live
// challenge. Unknown must not be automatically resubmitted. A lost QUIT reply
// cannot undo an already observed final DATA acceptance.
type Result struct {
	State    State  `json:"state"`
	Reason   string `json:"reason,omitempty"`
	SMTPCode int    `json:"smtpCode,omitempty"`
}

type Sender struct {
	config   Config
	secrets  SecretResolver
	prefixes []netip.Prefix
	slots    chan struct{}
	lookup   func(context.Context, string) ([]netip.Addr, error)
	dial     func(context.Context, string, string) (net.Conn, error)
}

func New(config Config, resolver SecretResolver, prefixes []netip.Prefix) (*Sender, error) {
	if resolver == nil || len(prefixes) == 0 || len(prefixes) > 64 || !dnsName(config.Host) || !dnsName(config.HelloName) || !mailbox(config.From) || config.Port < 1 || config.Port > 65535 || !versionID(config.CAVersionID) || (config.Transport != ImplicitTLS && config.Transport != RequiredSTARTTLS) {
		return nil, ErrInvalid
	}
	if config.OperationTimeout == 0 {
		config.OperationTimeout = 15 * time.Second
	}
	if config.OperationTimeout < time.Second || config.OperationTimeout > 30*time.Second {
		return nil, ErrInvalid
	}
	switch config.Authentication {
	case AuthPlain:
		if len(config.Username) == 0 || len(config.Username) > 256 || !safeText(config.Username, false) || !versionID(config.PasswordVersionID) {
			return nil, ErrInvalid
		}
	case AuthNone:
		if config.Username != "" || config.PasswordVersionID != "" {
			return nil, ErrInvalid
		}
	default:
		return nil, ErrInvalid
	}
	s := &Sender{config: config, secrets: resolver, prefixes: append([]netip.Prefix(nil), prefixes...), slots: make(chan struct{}, 4)}
	for _, prefix := range s.prefixes {
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
			return nil, ErrInvalid
		}
	}
	s.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	s.dial = (&net.Dialer{KeepAlive: -1}).DialContext
	return s, nil
}

func (s *Sender) allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	for _, prefix := range s.prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// Send performs at most one TCP connection, one authentication and one DATA
// transaction. All DNS answers must pass installation policy before dialing the
// first pinned IP; TLS always verifies the original configured host.
func (s *Sender) Send(ctx context.Context, message Message) (Result, error) {
	if s == nil || ctx == nil {
		return Result{State: Rejected, Reason: "invalid_input"}, ErrInvalid
	}
	operation, cancel := context.WithTimeout(ctx, s.config.OperationTimeout)
	defer cancel()
	select {
	case s.slots <- struct{}{}:
	case <-operation.Done():
		return notAccepted(nil)
	}
	defer func() { <-s.slots }()
	if operation.Err() != nil {
		return notAccepted(nil)
	}
	// Allocate MIME only after acquiring a slot, so queued callers do not each
	// retain an additional encoded plaintext copy while waiting for the network.
	payload, err := encodeMessage(s.config, message)
	if err != nil {
		return Result{State: Rejected, Reason: "invalid_input"}, ErrInvalid
	}
	defer clear(payload)
	secret, err := s.secrets.ResolveMailSecrets(operation, s.config.PasswordVersionID, s.config.CAVersionID)
	defer clear(secret.Password)
	defer clear(secret.CACertificatesPEM)
	if err != nil || operation.Err() != nil || len(secret.CACertificatesPEM) == 0 || len(secret.CACertificatesPEM) > 256<<10 || (s.config.Authentication == AuthPlain && (len(secret.Password) == 0 || len(secret.Password) > 4096 || bytes.IndexByte(secret.Password, 0) >= 0)) || (s.config.Authentication == AuthNone && len(secret.Password) != 0) {
		return notAccepted(nil)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(secret.CACertificatesPEM) {
		return notAccepted(nil)
	}
	ips, err := s.lookup(operation, s.config.Host)
	if err != nil || operation.Err() != nil || len(ips) == 0 || len(ips) > 32 {
		return notAccepted(nil)
	}
	for _, ip := range ips {
		if !s.allowed(ip) {
			return notAccepted(nil)
		}
	}
	raw, err := s.dial(operation, "tcp", net.JoinHostPort(ips[0].Unmap().String(), strconv.Itoa(s.config.Port)))
	if err != nil {
		return notAccepted(nil)
	}
	defer raw.Close()
	stop := context.AfterFunc(operation, func() { _ = raw.Close() })
	defer stop()
	deadline, _ := operation.Deadline()
	if err = raw.SetDeadline(deadline); err != nil {
		return notAccepted(nil)
	}
	// Bound greeting, multiline replies, AUTH responses and TLS records together.
	// textproto otherwise permits an unbounded response line/continuation set.
	var connection net.Conn = &readBudgetConn{Conn: raw, remaining: maxWireReadBytes}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: s.config.Host}
	if s.config.Transport == ImplicitTLS {
		secure := tls.Client(connection, tlsConfig)
		if err = secure.HandshakeContext(operation); err != nil {
			return notAccepted(nil)
		}
		connection = secure
	}
	client, err := smtp.NewClient(connection, s.config.Host)
	if err != nil {
		return notAccepted(err)
	}
	defer client.Close()
	responses := &responseBudget{remaining: 64 << 10, lines: 128}
	boundResponses(client, responses)
	if err = client.Hello(s.config.HelloName); err != nil {
		return notAccepted(err)
	}
	if s.config.Transport == RequiredSTARTTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return notAccepted(nil)
		}
		if err = client.StartTLS(tlsConfig); err != nil {
			return notAccepted(err)
		}
		// The standard library performs its post-TLS EHLO inside StartTLS.
		// That exchange, like the initial greeting, is bounded by the cumulative
		// 256 KiB raw budget. Apply the additional plaintext line/count budget
		// to subsequent replies; it does not replace the all-stage raw bound.
		boundResponses(client, responses)
	}
	state, ok := client.TLSConnectionState()
	if !ok || !state.HandshakeComplete || len(state.VerifiedChains) == 0 || state.Version < tls.VersionTLS12 || operation.Err() != nil {
		return notAccepted(nil)
	}
	if s.config.Authentication == AuthPlain {
		advertised, mechanisms := client.Extension("AUTH")
		plain := false
		for _, mechanism := range strings.Fields(mechanisms) {
			plain = plain || mechanism == "PLAIN"
		}
		if !advertised || !plain {
			return notAccepted(nil)
		}
		authentication := &plainAuth{host: s.config.Host, username: s.config.Username, password: secret.Password}
		defer func() { clear(authentication.response) }()
		if err = client.Auth(authentication); err != nil {
			return notAccepted(err)
		}
		clear(secret.Password)
	}
	if err = client.Mail(s.config.From); err != nil {
		return notAccepted(err)
	}
	if err = client.Rcpt(message.To); err != nil {
		return notAccepted(err)
	}
	// Use the exported textproto connection for DATA so DotWriter.Close errors
	// are checked explicitly (smtp's dataCloser discards that write error).
	id, err := client.Text.Cmd("DATA")
	if err != nil {
		return notAccepted(err)
	}
	client.Text.StartResponse(id)
	_, _, err = client.Text.ReadResponse(354)
	client.Text.EndResponse(id)
	if err != nil {
		return notAccepted(err)
	}
	writer := client.Text.DotWriter()
	if _, err = writer.Write(payload); err != nil {
		return Result{State: Unknown, Reason: "outcome_unknown"}, ErrUnknown
	}
	if err = writer.Close(); err != nil {
		return Result{State: Unknown, Reason: "outcome_unknown"}, ErrUnknown
	}
	_, _, err = client.Text.ReadResponse(250)
	if err != nil {
		var response *textproto.Error
		if errors.As(err, &response) && response.Code >= 400 && response.Code <= 599 {
			return Result{State: Rejected, Reason: "smtp_rejected", SMTPCode: response.Code}, ErrRejected
		}
		return Result{State: Unknown, Reason: "outcome_unknown"}, ErrUnknown
	}
	// A definitive DATA 250 survives a QUIT timeout/lost response. Never resend.
	_ = client.Quit()
	return Result{State: Accepted}, nil
}

func notAccepted(err error) (Result, error) {
	var response *textproto.Error
	if errors.As(err, &response) && response.Code >= 400 && response.Code <= 599 {
		return Result{State: Rejected, Reason: "smtp_rejected", SMTPCode: response.Code}, ErrRejected
	}
	return Result{State: Rejected, Reason: "unavailable"}, ErrUnavailable
}

type readBudgetConn struct {
	net.Conn
	remaining int64
}

type responseBudget struct {
	remaining int
	lines     int
	lineBytes int
}

type responseReader struct {
	reader io.Reader
	budget *responseBudget
}

func boundResponses(client *smtp.Client, budget *responseBudget) {
	client.Text.Reader = *textproto.NewReader(bufio.NewReader(&responseReader{reader: client.Text.Reader.R, budget: budget}))
}

func (r *responseReader) Read(p []byte) (int, error) {
	if r.budget.remaining <= 0 || r.budget.lines <= 0 {
		return 0, io.ErrUnexpectedEOF
	}
	if len(p) > r.budget.remaining {
		p = p[:r.budget.remaining]
	}
	n, err := r.reader.Read(p)
	for i, value := range p[:n] {
		r.budget.remaining--
		r.budget.lineBytes++
		if r.budget.lineBytes > 2048 {
			r.budget.remaining = 0
			return i, io.ErrUnexpectedEOF
		}
		if value == '\n' {
			r.budget.lineBytes = 0
			r.budget.lines--
			if r.budget.lines == 0 {
				return i + 1, io.ErrUnexpectedEOF
			}
		}
	}
	return n, err
}

func (c *readBudgetConn) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, io.ErrUnexpectedEOF
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.Conn.Read(p)
	c.remaining -= int64(n)
	return n, err
}

// Keeping password bytes avoids an additional long-lived password string in
// smtp.PlainAuth. Neither server diagnostics nor this response escape Send.
type plainAuth struct {
	host, username string
	password       []byte
	response       []byte
}

func (a *plainAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS || server.Name != a.host {
		return "", nil, ErrUnavailable
	}
	a.response = make([]byte, 0, len(a.username)+len(a.password)+2)
	a.response = append(a.response, 0)
	a.response = append(a.response, a.username...)
	a.response = append(a.response, 0)
	a.response = append(a.response, a.password...)
	return "PLAIN", a.response, nil
}

func (a *plainAuth) Next(_ []byte, more bool) ([]byte, error) {
	clear(a.response)
	if more {
		return nil, ErrUnavailable
	}
	return nil, nil
}

func dnsName(value string) bool {
	if len(value) > 253 || !strings.Contains(value, ".") || strings.HasSuffix(value, ".") || strings.ToLower(value) != value {
		return false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func mailbox(value string) bool {
	if len(value) == 0 || len(value) > 254 || strings.ContainsAny(value, "<>(),;:\\\" \t\r\n") {
		return false
	}
	for _, r := range value {
		if r < 33 || r > 126 {
			return false
		}
	}
	local, domain, ok := strings.Cut(value, "@")
	if !ok || len(local) == 0 || len(local) > 64 || !dnsName(domain) {
		return false
	}
	parsed, err := mail.ParseAddress(value)
	return err == nil && parsed.Name == "" && parsed.Address == value
}

func versionID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func safeText(value string, multiline bool) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) && !(multiline && (r == '\t' || r == '\n')) {
			return false
		}
	}
	return true
}

func safeBody(body []byte) bool {
	if !utf8.Valid(body) {
		return false
	}
	for i := 0; i < len(body); {
		r, n := utf8.DecodeRune(body[i:])
		if r == '\r' {
			if i+1 >= len(body) || body[i+1] != '\n' {
				return false
			}
		} else if unicode.IsControl(r) && r != '\t' && r != '\n' {
			return false
		}
		i += n
	}
	return true
}

func encodeMessage(config Config, message Message) ([]byte, error) {
	if !versionID(message.ID) || !mailbox(message.To) || len(message.Subject) == 0 || len(message.Subject) > 512 || !safeText(message.Subject, false) || message.CreatedAt.IsZero() || message.CreatedAt.Year() < 1970 || message.CreatedAt.Year() > 9999 || len(message.Text) == 0 || len(message.Text) > MaxTextBytes || !safeBody(message.Text) {
		return nil, ErrInvalid
	}
	var out bytes.Buffer
	subject := mime.QEncoding.Encode("utf-8", message.Subject)
	if strings.HasPrefix(subject, "=?utf-8?q?") {
		// Encode splits at complete UTF-8 words but does not fold the header.
		// Fold only its generated word boundaries; preserve original subject
		// whitespace, and never accept caller-supplied CR/LF.
		subject = strings.ReplaceAll(subject, "?= =?", "?=\r\n =?")
	}
	fmt.Fprintf(&out, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s@%s>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n", config.From, message.To, subject, message.CreatedAt.UTC().Format(time.RFC1123Z), message.ID, config.HelloName)
	writer := quotedprintable.NewWriter(&out)
	if _, err := writer.Write(message.Text); err != nil {
		return nil, ErrInvalid
	}
	if err := writer.Close(); err != nil {
		return nil, ErrInvalid
	}
	return out.Bytes(), nil
}
