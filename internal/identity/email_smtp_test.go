package identity

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/netip"
	"net/textproto"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/mailtransport"
	"golang.org/x/net/dns/dnsmessage"
)

// This is a process-local DNS/TLS/SMTP composition fixture, not corporate SMTP
// qualification. No test in this package uses t.Parallel or host DNS mutation.
const emailWireHost = "smtp.identity.corp.test"

func emailWireDNS(t *testing.T) {
	t.Helper()
	socket, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal("open synthetic DNS")
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		buffer := make([]byte, 4096)
		for {
			n, peer, e := socket.ReadFrom(buffer)
			if e != nil {
				return
			}
			var request dnsmessage.Message
			if request.Unpack(buffer[:n]) != nil {
				continue
			}
			response := dnsmessage.Message{Header: dnsmessage.Header{ID: request.Header.ID, Response: true, Authoritative: true, RecursionAvailable: true}, Questions: request.Questions}
			for _, q := range request.Questions {
				if q.Name.String() != emailWireHost+"." {
					response.Header.RCode = dnsmessage.RCodeNameError
					continue
				}
				if q.Type == dnsmessage.TypeA {
					response.Answers = append(response.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 0}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}})
				}
			}
			packet, e := response.Pack()
			if e == nil {
				_, _ = socket.WriteTo(packet, peer)
			}
		}
	})
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp4", socket.LocalAddr().String())
	}}
	t.Cleanup(func() { net.DefaultResolver = previous; socket.Close(); wg.Wait() })
}

type emailWireSecrets struct{ ca []byte }

func (s emailWireSecrets) ResolveMailSecrets(context.Context, string, string) (mailtransport.Secrets, error) {
	return mailtransport.Secrets{CACertificatesPEM: bytes.Clone(s.ca)}, nil
}

type emailWireSMTP struct {
	listener                  net.Listener
	cert                      tls.Certificate
	ca                        []byte
	mu                        sync.Mutex
	conns                     []net.Conn
	message                   []byte
	wg                        sync.WaitGroup
	connections, transactions atomic.Int64
	loseDATA                  bool
}

func newEmailWireSMTP(t *testing.T, loseDATA bool) *emailWireSMTP {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic email integration CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	leafPub, leafKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{emailWireHost}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, ca, leafPub, key)
	if e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	f := &emailWireSMTP{listener: listener, cert: tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}, ca: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), loseDATA: loseDATA}
	f.wg.Go(func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			f.connections.Add(1)
			f.mu.Lock()
			f.conns = append(f.conns, conn)
			f.mu.Unlock()
			f.wg.Go(func() { defer conn.Close(); f.serve(conn) })
		}
	})
	t.Cleanup(func() {
		listener.Close()
		f.mu.Lock()
		for _, c := range f.conns {
			c.Close()
		}
		f.mu.Unlock()
		f.wg.Wait()
	})
	return f
}
func (f *emailWireSMTP) serve(raw net.Conn) {
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	conn := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{f.cert}})
	if conn.Handshake() != nil {
		return
	}
	r := textproto.NewReader(bufio.NewReader(conn))
	write := func(s string) bool { _, e := io.WriteString(conn, s+"\r\n"); return e == nil }
	if !write("220 synthetic SMTP") {
		return
	}
	for {
		line, e := r.ReadLine()
		if e != nil {
			return
		}
		switch {
		case strings.HasPrefix(line, "EHLO "):
			if !write("250-synthetic SMTP\r\n250 SIZE 262144") {
				return
			}
		case strings.HasPrefix(line, "MAIL FROM:"):
			if !write("250 sender accepted") {
				return
			}
		case strings.HasPrefix(line, "RCPT TO:"):
			if !write("250 recipient accepted") {
				return
			}
		case line == "DATA":
			if !write("354 send body") {
				return
			}
			message, e := io.ReadAll(io.LimitReader(r.DotReader(), 256<<10))
			if e != nil {
				return
			}
			f.mu.Lock()
			f.message = bytes.Clone(message)
			f.mu.Unlock()
			f.transactions.Add(1)
			if f.loseDATA {
				return
			}
			if !write("250 accepted") {
				return
			}
		case line == "QUIT":
			write("221 closing")
			return
		default:
			write("500 unsupported")
			return
		}
	}
}
func TestEmailSMTPWireSQLite(t *testing.T)   { testEmailSMTPWire(t, false) }
func TestEmailSMTPWirePostgres(t *testing.T) { testEmailSMTPWire(t, true) }
func testEmailSMTPWire(t *testing.T, pg bool) {
	for _, lost := range []bool{false, true} {
		name := "accepted"
		if lost {
			name = "unknown_no_retry"
		}
		t.Run(name, func(t *testing.T) {
			emailWireDNS(t)
			f := newEmailFixture(t, pg)
			peer := newEmailWireSMTP(t, lost)
			sender, e := mailtransport.New(mailtransport.Config{Host: emailWireHost, Port: peer.listener.Addr().(*net.TCPAddr).Port, Transport: mailtransport.ImplicitTLS, HelloName: "portal.corp.test", From: "portal@corp.test", Authentication: mailtransport.AuthNone, CAVersionID: "mail_ca_v1", OperationTimeout: 2 * time.Second}, emailWireSecrets{peer.ca}, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
			if e != nil {
				t.Fatal(e)
			}
			f.email.sender = sender
			c := f.contact(t, "proof-recipient@corp.example")
			a := f.flow(t)
			v := f.issue(t, a, c)
			yes, e := f.email.ProcessOne(f.ctx)
			if !yes {
				t.Fatal("job not claimed")
			}
			if !lost && e != nil {
				t.Fatal("real SMTP failed", e)
			}
			if lost && e == nil {
				t.Fatal("unknown submission claimed success")
			}
			if peer.connections.Load() != 1 || peer.transactions.Load() != 1 {
				t.Fatal("transport did not make exactly one DATA transaction")
			}
			view, e := f.email.Get(f.ctx, a, v.ID)
			want := "accepted"
			if lost {
				want = "failed"
			}
			if e != nil || view.DeliveryState != want {
				t.Fatal("wrong public delivery outcome", e)
			}
			if yes, e := f.email.ProcessOne(f.ctx); yes || e != nil {
				t.Fatal("terminal SMTP job retried", e)
			}
			peer.mu.Lock()
			wire := bytes.Clone(peer.message)
			peer.mu.Unlock()
			defer clear(wire)
			message, e := mail.ReadMessage(bytes.NewReader(wire))
			if e != nil || message.Header.Get("To") != "proof-recipient@corp.example" {
				t.Fatal("bound recipient changed")
			}
			body, e := io.ReadAll(quotedprintable.NewReader(message.Body))
			if e != nil {
				t.Fatal(e)
			}
			defer clear(body)
			code := regexp.MustCompile(`[0-9]{8}`).FindString(string(body))
			if len(code) != 8 {
				t.Fatal("SMTP payload had no code")
			}
			if _, e = f.email.Verify(f.ctx, a, v.ID, code); e != nil {
				t.Fatal("SMTP code failed purpose-bound confirmation", e)
			}
		})
	}
}
