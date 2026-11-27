package mailtransport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/netip"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These synthetic SMTP/TLS peers exercise the actual socket/protocol stack;
// they do not qualify an organization's SMTP server or its delivery behavior.
const fixtureHost = "smtp.corp.example"

type fixtureOptions struct {
	transport, rejectAt string
	noSTARTTLS, noAUTH  bool
	wrongName           bool
	loseDATA, loseQUIT  bool
	stallGreeting       bool
	stallDATA           bool
	hugeGreeting        bool
	hugeEHLO            bool
	hugePostTLSEHLO     bool
	manyEHLOLines       bool
	authChallenge       bool
	finalCode           int
}

type smtpFixture struct {
	listener  net.Listener
	cert      tls.Certificate
	ca        []byte
	options   fixtureOptions
	port      int
	mu        sync.Mutex
	conns     []net.Conn
	events    []string
	message   []byte
	wg        sync.WaitGroup
	count     atomic.Int64
	auth      atomic.Int64
	data      atomic.Int64
	badAuth   atomic.Bool
	sni       atomic.Bool
	afterDATA chan struct{}
	once      sync.Once
}

func fixtureCertificate(t *testing.T, wrongName bool) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate synthetic CA")
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic SMTP CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal("sign synthetic CA")
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate synthetic leaf")
	}
	host := fixtureHost
	if wrongName {
		host = "other.corp.example"
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal("sign synthetic leaf")
	}
	return tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

func newSMTPFixture(t *testing.T, options fixtureOptions) *smtpFixture {
	t.Helper()
	cert, ca := fixtureCertificate(t, options.wrongName)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("open synthetic SMTP fixture socket")
	}
	f := &smtpFixture{listener: listener, cert: cert, ca: ca, options: options, port: listener.Addr().(*net.TCPAddr).Port, afterDATA: make(chan struct{})}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			f.count.Add(1)
			f.mu.Lock()
			f.conns = append(f.conns, conn)
			f.mu.Unlock()
			f.wg.Add(1)
			go func() { defer f.wg.Done(); f.serve(conn) }()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		f.mu.Lock()
		for _, conn := range f.conns {
			_ = conn.Close()
		}
		f.mu.Unlock()
		f.wg.Wait()
	})
	return f
}

func (f *smtpFixture) event(value string) {
	f.mu.Lock()
	f.events = append(f.events, value)
	f.mu.Unlock()
}

func (f *smtpFixture) serve(raw net.Conn) {
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	conn := raw
	secure := false
	upgrade := func() bool {
		server := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{f.cert}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			f.sni.Store(hello.ServerName == fixtureHost)
			return nil, nil
		}})
		if server.Handshake() != nil {
			return false
		}
		conn, secure = server, true
		f.event("tls")
		return true
	}
	if f.options.transport == ImplicitTLS && !upgrade() {
		return
	}
	if f.options.stallGreeting {
		_, _ = conn.Read(make([]byte, 1))
		return
	}
	if f.options.hugeGreeting {
		_, _ = io.WriteString(conn, "220 "+strings.Repeat("x", maxWireReadBytes+1024))
		return
	}
	reader := textproto.NewReader(bufio.NewReader(conn))
	write := func(value string) bool { _, err := io.WriteString(conn, value+"\r\n"); return err == nil }
	if !write("220 synthetic SMTP") {
		return
	}
	for {
		line, err := reader.ReadLine()
		if err != nil {
			return
		}
		command, _, _ := strings.Cut(line, " ")
		f.event(command)
		if f.options.rejectAt == command {
			if !write("550 private-diagnostic-material") {
				return
			}
			continue
		}
		switch command {
		case "EHLO":
			if secure && f.options.hugePostTLSEHLO {
				_, _ = io.WriteString(conn, "250 "+strings.Repeat("x", maxWireReadBytes+1024)+"\r\n")
				return
			}
			if f.options.hugeEHLO {
				if !write("250 " + strings.Repeat("x", 4096)) {
					return
				}
				continue
			}
			if f.options.manyEHLOLines {
				if !write(strings.Repeat("250-synthetic\r\n", 129) + "250 ok") {
					return
				}
				continue
			}
			response := "250-synthetic SMTP\r\n"
			if !secure && !f.options.noSTARTTLS {
				response += "250-STARTTLS\r\n"
			}
			if !f.options.noAUTH {
				response += "250-AUTH PLAIN\r\n"
			}
			if !write(response + "250 SIZE 1048576") {
				return
			}
		case "STARTTLS":
			if f.options.noSTARTTLS || secure || !write("220 begin TLS") || !upgrade() {
				return
			}
			reader = textproto.NewReader(bufio.NewReader(conn))
		case "AUTH":
			f.auth.Add(1)
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "AUTH PLAIN "))
			if !secure || err != nil || !bytes.Equal(decoded, []byte("\x00transport-user\x00synthetic-credential")) {
				f.badAuth.Store(true)
			}
			clear(decoded)
			if f.options.authChallenge {
				if !write("334 c3ludGhldGljLWNoYWxsZW5nZQ==") {
					return
				}
			} else if !write("235 authenticated") {
				return
			}
		case "MAIL", "RCPT":
			if !secure {
				f.badAuth.Store(true)
			}
			if !write("250 ok") {
				return
			}
		case "DATA":
			if !secure || !write("354 send message") {
				return
			}
			body, err := io.ReadAll(io.LimitReader(reader.DotReader(), 2<<20))
			if err != nil {
				return
			}
			f.data.Add(1)
			f.mu.Lock()
			f.message = body
			f.mu.Unlock()
			f.once.Do(func() { close(f.afterDATA) })
			if f.options.loseDATA {
				return
			}
			if f.options.stallDATA {
				_, _ = conn.Read(make([]byte, 1))
				return
			}
			code := f.options.finalCode
			if code == 0 {
				code = 250
			}
			if !write(strconv.Itoa(code) + " private-diagnostic-material") {
				return
			}
		case "QUIT":
			if !f.options.loseQUIT {
				write("221 bye")
			}
			return
		case "*":
			if !write("501 aborted") {
				return
			}
		default:
			if !write("500 unsupported") {
				return
			}
		}
	}
}

type fixtureSecrets struct {
	ca       []byte
	mu       sync.Mutex
	password [][]byte
	cas      [][]byte
	calls    atomic.Int64
	badRefs  atomic.Bool
	fail     bool
}

func (r *fixtureSecrets) ResolveMailSecrets(ctx context.Context, passwordID, caID string) (Secrets, error) {
	r.calls.Add(1)
	if caID != "secret_ca_v1" || (passwordID != "secret_password_v1" && passwordID != "") {
		r.badRefs.Store(true)
	}
	secret := Secrets{CACertificatesPEM: bytes.Clone(r.ca)}
	if passwordID != "" {
		secret.Password = []byte("synthetic-credential")
	}
	r.mu.Lock()
	r.password = append(r.password, secret.Password)
	r.cas = append(r.cas, secret.CACertificatesPEM)
	r.mu.Unlock()
	if r.fail {
		return secret, errors.New("private-diagnostic-material")
	}
	return secret, ctx.Err()
}

func (r *fixtureSecrets) assertCleared(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, buffers := range [][][]byte{r.password, r.cas} {
		for _, buffer := range buffers {
			for _, value := range buffer {
				if value != 0 {
					t.Fatal("resolver transfer buffer not cleared")
				}
			}
		}
	}
	if r.badRefs.Load() {
		t.Fatal("secret references changed")
	}
}

func fixtureConfig(port int, mode string) Config {
	return Config{Host: fixtureHost, Port: port, Transport: mode, HelloName: "portal.corp.example", From: "portal@corp.example", Authentication: AuthPlain, Username: "transport-user", PasswordVersionID: "secret_password_v1", CAVersionID: "secret_ca_v1", OperationTimeout: 2 * time.Second}
}

func fixtureMessage() Message {
	return Message{ID: "outbox_synthetic_1", To: "recipient@corp.example", Subject: "Проверка транспорта", CreatedAt: time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC), Text: []byte("Тестовое письмо.\r\n.first\n..second\n")}
}

func fixtureSender(t *testing.T, f *smtpFixture) (*Sender, *fixtureSecrets) {
	t.Helper()
	r := &fixtureSecrets{ca: f.ca}
	s, err := New(fixtureConfig(f.port, f.options.transport), r, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	if err != nil {
		t.Fatal("construct synthetic SMTP sender")
	}
	s.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		if host != fixtureHost {
			t.Error("DNS did not use configured host")
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, ctx.Err()
	}
	return s, r
}

func assertRedacted(t *testing.T, result Result, err error) {
	t.Helper()
	encoded, _ := json.Marshal(result)
	output := string(encoded)
	if err != nil {
		output += err.Error()
	}
	for _, forbidden := range []string{"private-diagnostic-material", "synthetic-credential", fixtureHost, "recipient@", "portal@", "Тестовое"} {
		if strings.Contains(output, forbidden) {
			t.Fatal("sensitive diagnostic escaped transport")
		}
	}
}

func TestSMTPVerifiedTLSSubmission(t *testing.T) {
	for _, mode := range []string{RequiredSTARTTLS, ImplicitTLS} {
		t.Run(mode, func(t *testing.T) {
			f := newSMTPFixture(t, fixtureOptions{transport: mode})
			s, secrets := fixtureSender(t, f)
			result, err := s.Send(context.Background(), fixtureMessage())
			if err != nil || result.State != Accepted || result.SMTPCode != 0 || result.Reason != "" {
				t.Fatal("verified TLS submission was not accepted")
			}
			assertRedacted(t, result, err)
			if f.count.Load() != 1 || f.data.Load() != 1 || f.auth.Load() != 1 || f.badAuth.Load() || !f.sni.Load() {
				t.Fatal("TLS/authentication/pinned single-submission invariant failed")
			}
			f.mu.Lock()
			message := bytes.Clone(f.message)
			events := append([]string(nil), f.events...)
			f.mu.Unlock()
			tlsAt, authAt := -1, -1
			for i, event := range events {
				if event == "tls" {
					tlsAt = i
				}
				if event == "AUTH" {
					authAt = i
				}
			}
			if tlsAt < 0 || authAt <= tlsAt {
				t.Fatal("authentication preceded verified TLS")
			}
			parsed, err := mail.ReadMessage(bytes.NewReader(message))
			if err != nil {
				t.Fatal("generated MIME cannot be parsed")
			}
			subject, err := new(mime.WordDecoder).DecodeHeader(parsed.Header.Get("Subject"))
			if err != nil || subject != fixtureMessage().Subject || parsed.Header.Get("Message-ID") != "<outbox_synthetic_1@portal.corp.example>" || parsed.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
				t.Fatal("fixed MIME headers changed")
			}
			body, err := io.ReadAll(quotedprintable.NewReader(parsed.Body))
			if err != nil || string(body) != strings.ReplaceAll(string(fixtureMessage().Text), "\r\n", "\n") {
				t.Fatal("quoted-printable or SMTP dot transparency changed body")
			}
			secrets.assertCleared(t)
		})
	}
}

func TestSMTPFailClosedTLSAndAuthentication(t *testing.T) {
	cases := []struct {
		name  string
		opts  fixtureOptions
		badCA bool
	}{
		{name: "missing_starttls", opts: fixtureOptions{noSTARTTLS: true}},
		{name: "starttls_rejected", opts: fixtureOptions{rejectAt: "STARTTLS"}},
		{name: "wrong_name_starttls", opts: fixtureOptions{wrongName: true}},
		{name: "wrong_name_implicit", opts: fixtureOptions{wrongName: true, transport: ImplicitTLS}},
		{name: "untrusted_ca_starttls", badCA: true},
		{name: "untrusted_ca_implicit", opts: fixtureOptions{transport: ImplicitTLS}, badCA: true},
		{name: "auth_not_advertised", opts: fixtureOptions{noAUTH: true}},
		{name: "auth_rejected", opts: fixtureOptions{rejectAt: "AUTH"}},
		{name: "unexpected_auth_challenge", opts: fixtureOptions{authChallenge: true}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if test.opts.transport == "" {
				test.opts.transport = RequiredSTARTTLS
			}
			f := newSMTPFixture(t, test.opts)
			s, secrets := fixtureSender(t, f)
			if test.badCA {
				_, secrets.ca = fixtureCertificate(t, false)
			}
			result, err := s.Send(context.Background(), fixtureMessage())
			if err == nil || result.State != Rejected || f.count.Load() != 1 || f.data.Load() != 0 || f.badAuth.Load() {
				t.Fatal("TLS/authentication failure did not close submission")
			}
			if (test.opts.noSTARTTLS || test.opts.wrongName || test.badCA) && f.auth.Load() != 0 {
				t.Fatal("credentials sent before verified TLS")
			}
			assertRedacted(t, result, err)
			secrets.assertCleared(t)
		})
	}
}

func TestSMTPRejectedAndAmbiguousOutcomes(t *testing.T) {
	cases := []struct {
		name    string
		opts    fixtureOptions
		state   State
		wantErr error
		code    int
		data    int64
	}{
		{name: "mail_rejected", opts: fixtureOptions{rejectAt: "MAIL"}, state: Rejected, wantErr: ErrRejected, code: 550},
		{name: "recipient_rejected", opts: fixtureOptions{rejectAt: "RCPT"}, state: Rejected, wantErr: ErrRejected, code: 550},
		{name: "data_command_rejected", opts: fixtureOptions{rejectAt: "DATA"}, state: Rejected, wantErr: ErrRejected, code: 550},
		{name: "body_rejected", opts: fixtureOptions{finalCode: 554}, state: Rejected, wantErr: ErrRejected, code: 554, data: 1},
		{name: "body_temporary_rejection", opts: fixtureOptions{finalCode: 451}, state: Rejected, wantErr: ErrRejected, code: 451, data: 1},
		{name: "lost_data_reply", opts: fixtureOptions{loseDATA: true}, state: Unknown, wantErr: ErrUnknown, data: 1},
		{name: "unexpected_data_reply", opts: fixtureOptions{finalCode: 251}, state: Unknown, wantErr: ErrUnknown, data: 1},
		{name: "lost_quit_reply", opts: fixtureOptions{loseQUIT: true}, state: Accepted, data: 1},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			test.opts.transport = RequiredSTARTTLS
			f := newSMTPFixture(t, test.opts)
			s, secrets := fixtureSender(t, f)
			result, err := s.Send(context.Background(), fixtureMessage())
			if !errors.Is(err, test.wantErr) || result.State != test.state || result.SMTPCode != test.code || f.data.Load() != test.data || f.count.Load() != 1 {
				t.Fatal("submission outcome or single-attempt invariant changed")
			}
			assertRedacted(t, result, err)
			secrets.assertCleared(t)
		})
	}
}

func TestSMTPDNSAllowlistAllAnswersAndPin(t *testing.T) {
	f := newSMTPFixture(t, fixtureOptions{transport: ImplicitTLS})
	for _, ips := range [][]netip.Addr{
		{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("203.0.113.1")},
		{netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("127.0.0.1")},
		{netip.IPv4Unspecified()}, {netip.MustParseAddr("224.0.0.1")}, {netip.MustParseAddr("fe80::1%eth0")},
		{netip.Addr{}}, {}, make([]netip.Addr, 33),
	} {
		s, secrets := fixtureSender(t, f)
		s.lookup = func(context.Context, string) ([]netip.Addr, error) { return ips, nil }
		var dials atomic.Int64
		s.dial = func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("private-diagnostic-material")
		}
		result, err := s.Send(context.Background(), fixtureMessage())
		if !errors.Is(err, ErrUnavailable) || result.State != Rejected || dials.Load() != 0 {
			t.Fatal("disallowed DNS answer reached dial")
		}
		assertRedacted(t, result, err)
		secrets.assertCleared(t)
	}
	s, secrets := fixtureSender(t, f)
	var lookups, dials atomic.Int64
	s.lookup = func(context.Context, string) ([]netip.Addr, error) {
		lookups.Add(1)
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::ffff:127.0.0.1")}, nil
	}
	s.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		if address != net.JoinHostPort("127.0.0.1", strconv.Itoa(f.port)) || network != "tcp" {
			t.Error("SMTP dial was not pinned to checked IP/port")
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	result, err := s.Send(context.Background(), fixtureMessage())
	if err != nil || result.State != Accepted || lookups.Load() != 1 || dials.Load() != 1 || !f.sni.Load() {
		t.Fatal("DNS pin/original SNI/single dial failed")
	}
	secrets.assertCleared(t)
}

func TestSMTPBoundedDiagnosticsAndCancellation(t *testing.T) {
	for _, test := range []struct {
		name string
		opts fixtureOptions
	}{
		{name: "oversized_plaintext_line", opts: fixtureOptions{transport: ImplicitTLS, hugeEHLO: true}},
		{name: "excessive_plaintext_lines", opts: fixtureOptions{transport: ImplicitTLS, manyEHLOLines: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newSMTPFixture(t, test.opts)
			s, secrets := fixtureSender(t, f)
			result, err := s.Send(context.Background(), fixtureMessage())
			if !errors.Is(err, ErrUnavailable) || result.State != Rejected || f.auth.Load() != 0 || f.data.Load() != 0 {
				t.Fatal("plaintext response exceeded its line/count budget")
			}
			assertRedacted(t, result, err)
			secrets.assertCleared(t)
		})
	}
	t.Run("oversized_greeting", func(t *testing.T) {
		f := newSMTPFixture(t, fixtureOptions{transport: RequiredSTARTTLS, hugeGreeting: true})
		s, secrets := fixtureSender(t, f)
		result, err := s.Send(context.Background(), fixtureMessage())
		if !errors.Is(err, ErrUnavailable) || result.State != Rejected || f.auth.Load() != 0 || f.count.Load() != 1 {
			t.Fatal("oversized reply was not bounded before credentials")
		}
		secrets.assertCleared(t)
	})
	t.Run("cancel_before_greeting", func(t *testing.T) {
		f := newSMTPFixture(t, fixtureOptions{transport: RequiredSTARTTLS, stallGreeting: true})
		s, secrets := fixtureSender(t, f)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		started := time.Now()
		result, err := s.Send(ctx, fixtureMessage())
		if !errors.Is(err, ErrUnavailable) || result.State != Rejected || time.Since(started) > time.Second || f.data.Load() != 0 {
			t.Fatal("context did not interrupt SMTP read before DATA")
		}
		secrets.assertCleared(t)
	})
	t.Run("cancel_after_data", func(t *testing.T) {
		f := newSMTPFixture(t, fixtureOptions{transport: RequiredSTARTTLS, stallDATA: true})
		s, secrets := fixtureSender(t, f)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		go func() {
			select {
			case <-f.afterDATA:
				cancel()
			case <-done:
			}
		}()
		started := time.Now()
		result, err := s.Send(ctx, fixtureMessage())
		close(done)
		if !errors.Is(err, ErrUnknown) || result.State != Unknown || time.Since(started) > time.Second || f.data.Load() != 1 || f.count.Load() != 1 {
			t.Fatal("cancellation after DATA was not ambiguous/single-attempt")
		}
		secrets.assertCleared(t)
	})
}

func TestSMTPBoundedConcurrency(t *testing.T) {
	f := newSMTPFixture(t, fixtureOptions{transport: RequiredSTARTTLS, stallGreeting: true})
	s, secrets := fixtureSender(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := s.Send(ctx, fixtureMessage())
			if result.State != Rejected || !errors.Is(err, ErrUnavailable) {
				t.Error("canceled concurrent submission changed outcome")
			}
		}()
	}
	deadline := time.Now().Add(time.Second)
	for f.count.Load() < 4 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if f.count.Load() != 4 || secrets.calls.Load() != 4 {
		t.Error("SMTP active work was not bounded to four")
	}
	cancel()
	wg.Wait()
	if f.count.Load() != 4 || len(s.slots) != 0 {
		t.Fatal("canceled waiter opened another connection or leaked slot")
	}
	secrets.assertCleared(t)
}

func TestSMTPInvalidMessagesNeverResolveOrDial(t *testing.T) {
	_, ca := fixtureCertificate(t, false)
	r := &fixtureSecrets{ca: ca}
	s, err := New(fixtureConfig(465, ImplicitTLS), r, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")})
	if err != nil {
		t.Fatal("construct sender")
	}
	var lookups atomic.Int64
	s.lookup = func(context.Context, string) ([]netip.Addr, error) { lookups.Add(1); return nil, nil }
	mutations := []func(*Message){
		func(m *Message) { m.To += "\r\nBcc: extra@corp.example" },
		func(m *Message) { m.To = "one@corp.example,two@corp.example" },
		func(m *Message) { m.To = "Display <one@corp.example>" },
		func(m *Message) { m.To = "unicode_я@corp.example" },
		func(m *Message) { m.To = "one@[127.0.0.1]" },
		func(m *Message) { m.Subject += "\nInjected: yes" },
		func(m *Message) { m.Subject = strings.Repeat("x", 513) },
		func(m *Message) { m.Subject = string([]byte{0xff}) },
		func(m *Message) { m.ID += "\r\nInjected: yes" },
		func(m *Message) { m.ID = "" },
		func(m *Message) { m.CreatedAt = time.Time{} },
		func(m *Message) { m.Text = bytes.Repeat([]byte("x"), MaxTextBytes+1) },
		func(m *Message) { m.Text = nil },
		func(m *Message) { m.Text = []byte("bare\rreturn") },
		func(m *Message) { m.Text = []byte{0xff} },
		func(m *Message) { m.Text = []byte{0} },
	}
	for _, mutate := range mutations {
		message := fixtureMessage()
		mutate(&message)
		result, err := s.Send(context.Background(), message)
		if !errors.Is(err, ErrInvalid) || result.State != Rejected || r.calls.Load() != 0 || lookups.Load() != 0 {
			t.Fatal("invalid message reached secret resolver/DNS")
		}
		assertRedacted(t, result, err)
	}
}

func TestSMTPInstallationConfigIsClosed(t *testing.T) {
	_, ca := fixtureCertificate(t, false)
	r := &fixtureSecrets{ca: ca}
	prefixes := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	mutations := []func(*Config){
		func(c *Config) { c.Host = "127.0.0.1" },
		func(c *Config) { c.Host = "https://smtp.corp.example" },
		func(c *Config) { c.Host += "." },
		func(c *Config) { c.Host = "SMTP.corp.example" },
		func(c *Config) { c.Host = "-bad.corp.example" },
		func(c *Config) { c.Port = 0 },
		func(c *Config) { c.Port = 65536 },
		func(c *Config) { c.Transport = "plaintext" },
		func(c *Config) { c.HelloName = "localhost" },
		func(c *Config) { c.From += "\nInjected: yes" },
		func(c *Config) { c.Authentication = "auto" },
		func(c *Config) { c.Authentication = AuthNone },
		func(c *Config) { c.Username += "\x00extra" },
		func(c *Config) { c.PasswordVersionID = "" },
		func(c *Config) { c.CAVersionID = "" },
		func(c *Config) { c.OperationTimeout = 31 * time.Second },
		func(c *Config) { c.OperationTimeout = time.Millisecond },
	}
	for _, mutate := range mutations {
		config := fixtureConfig(465, ImplicitTLS)
		mutate(&config)
		if _, err := New(config, r, prefixes); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid installation configuration accepted")
		}
	}
	for _, prefixes := range [][]netip.Prefix{nil, {{}}, {netip.MustParsePrefix("192.0.2.1/24")}, {netip.MustParsePrefix("::ffff:192.0.2.0/120")}, make([]netip.Prefix, 65)} {
		if _, err := New(fixtureConfig(465, ImplicitTLS), r, prefixes); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid installation network policy accepted")
		}
	}
	if _, err := New(fixtureConfig(465, ImplicitTLS), nil, prefixes); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil secret resolver accepted")
	}
}

func TestSMTPExplicitRelayProfile(t *testing.T) {
	f := newSMTPFixture(t, fixtureOptions{transport: ImplicitTLS, noAUTH: true})
	secrets := &fixtureSecrets{ca: f.ca}
	config := fixtureConfig(f.port, ImplicitTLS)
	config.Authentication, config.Username, config.PasswordVersionID = AuthNone, "", ""
	s, err := New(config, secrets, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	if err != nil {
		t.Fatal("explicit relay configuration rejected")
	}
	s.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	result, err := s.Send(context.Background(), fixtureMessage())
	if err != nil || result.State != Accepted || f.auth.Load() != 0 || f.data.Load() != 1 {
		t.Fatal("explicit TLS relay profile did not submit without AUTH")
	}
	secrets.assertCleared(t)
}

func TestSMTPMIMEHeaderFolding(t *testing.T) {
	for _, subject := range []string{strings.Repeat("Я", 256), strings.Repeat("x", 512), strings.Repeat("a Я  b ", 40)} {
		message := fixtureMessage()
		message.Subject = subject
		encoded, err := encodeMessage(fixtureConfig(465, ImplicitTLS), message)
		if err != nil {
			t.Fatal("valid long subject rejected")
		}
		for _, line := range bytes.Split(encoded, []byte("\r\n")) {
			if len(line) > 998 {
				t.Fatal("MIME generated an overlong RFC5322 line")
			}
		}
		parsed, err := mail.ReadMessage(bytes.NewReader(encoded))
		if err != nil {
			t.Fatal("folded header cannot be parsed")
		}
		decoded, err := new(mime.WordDecoder).DecodeHeader(parsed.Header.Get("Subject"))
		if err != nil || decoded != subject {
			t.Fatal("subject folding changed original text")
		}
	}
}

func TestSMTPNoIPFallbackOrRetry(t *testing.T) {
	_, ca := fixtureCertificate(t, false)
	secrets := &fixtureSecrets{ca: ca}
	s, err := New(fixtureConfig(465, ImplicitTLS), secrets, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")})
	if err != nil {
		t.Fatal("construct sender")
	}
	s.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}, nil
	}
	var dials atomic.Int64
	s.dial = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("private-diagnostic-material")
	}
	result, err := s.Send(context.Background(), fixtureMessage())
	if !errors.Is(err, ErrUnavailable) || result.State != Rejected || dials.Load() != 1 {
		t.Fatal("failed pinned dial retried another IP")
	}
	assertRedacted(t, result, err)
	secrets.assertCleared(t)
}

func TestSMTPSecretAndResolverFailuresRedacted(t *testing.T) {
	f := newSMTPFixture(t, fixtureOptions{transport: ImplicitTLS})
	s, secrets := fixtureSender(t, f)
	secrets.fail = true
	result, err := s.Send(context.Background(), fixtureMessage())
	if !errors.Is(err, ErrUnavailable) || result.State != Rejected || f.count.Load() != 0 {
		t.Fatal("failed secret resolution reached SMTP")
	}
	assertRedacted(t, result, err)
	secrets.assertCleared(t)
	secrets.fail = false
	s.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return nil, errors.New("private-diagnostic-material")
	}
	result, err = s.Send(context.Background(), fixtureMessage())
	if !errors.Is(err, ErrUnavailable) || result.State != Rejected || f.count.Load() != 0 {
		t.Fatal("failed DNS reached SMTP")
	}
	assertRedacted(t, result, err)
	secrets.assertCleared(t)
}

func TestPostSTARTTLSEHLOUsesAllStageWireBound(t *testing.T) {
	f := newSMTPFixture(t, fixtureOptions{transport: RequiredSTARTTLS, hugePostTLSEHLO: true})
	sender, secrets := fixtureSender(t, f)
	result, err := sender.Send(context.Background(), fixtureMessage())
	if err == nil || result.State != Rejected || f.auth.Load() != 0 || f.data.Load() != 0 || f.count.Load() != 1 {
		t.Fatalf("post-TLS EHLO escaped bound: state=%s auth=%d data=%d connections=%d", result.State, f.auth.Load(), f.data.Load(), f.count.Load())
	}
	if !f.sni.Load() {
		t.Fatal("did not exercise TLS upgrade")
	}
	secrets.assertCleared(t)
	assertRedacted(t, result, err)
}
