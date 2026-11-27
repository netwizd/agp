package identity

import (
	"bytes"
	"io"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/netip"
	"regexp"
	"testing"

	"github.com/netwizd/agp/internal/mailtransport"
)

func inviteWireText(t *testing.T, peer *emailWireSMTP) string {
	t.Helper()
	peer.mu.Lock()
	raw := bytes.Clone(peer.message)
	peer.mu.Unlock()
	msg, e := mail.ReadMessage(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	text, e := io.ReadAll(quotedprintable.NewReader(msg.Body))
	if e != nil {
		t.Fatal(e)
	}
	return string(text)
}
func TestInvitationSMTPWireSQLite(t *testing.T)   { testInvitationSMTPWire(t, false) }
func TestInvitationSMTPWirePostgres(t *testing.T) { testInvitationSMTPWire(t, true) }
func testInvitationSMTPWire(t *testing.T, pg bool) {
	for _, lost := range []bool{false, true} {
		name := "accepted_full_setup"
		if lost {
			name = "unknown_single_send"
		}
		t.Run(name, func(t *testing.T) {
			emailWireDNS(t)
			f := newInviteFixture(t, pg)
			peer := newEmailWireSMTP(t, lost)
			sender, e := mailtransport.New(mailtransport.Config{Host: emailWireHost, Port: peer.listener.Addr().(*net.TCPAddr).Port, Transport: mailtransport.ImplicitTLS, HelloName: "portal.corp.test", From: "portal@corp.test", Authentication: mailtransport.AuthNone, CAVersionID: "mail_ca_v1", OperationTimeout: 2e9}, emailWireSecrets{peer.ca}, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
			if e != nil {
				t.Fatal(e)
			}
			f.email.sender = sender
			v, e := f.invites.CreateInvite(f.ctx, f.admin, f.pending.ID, "wire_invite", f.pending.Revision, InviteRequest{Email: "Recipient@corp.example", TTLSeconds: 3600})
			if e != nil {
				t.Fatal(e)
			}
			yes, e := f.invites.ProcessDeliveryOne(f.ctx)
			if !yes || (!lost && e != nil) || (lost && e == nil) {
				t.Fatal("SMTP outcome", yes, e)
			}
			if peer.connections.Load() != 1 || peer.transactions.Load() != 1 {
				t.Fatal("unexpected SMTP retry")
			}
			if yes, e := f.invites.ProcessDeliveryOne(f.ctx); yes || e != nil {
				t.Fatal("terminal delivery requeued", e)
			}
			view, e := f.invites.GetDelivery(f.ctx, f.admin, v.DeliveryOperationID)
			if e != nil {
				t.Fatal(e)
			}
			if lost {
				if view.State != "failed" {
					t.Fatal("unknown marked delivered")
				}
				return
			}
			if view.State != "accepted" {
				t.Fatal("SMTP accepted missing")
			}
			match := regexp.MustCompile(`#token=([A-Za-z0-9_-]{43})`).FindStringSubmatch(inviteWireText(t, peer))
			if len(match) != 2 {
				t.Fatal("encrypted preflow payload not delivered")
			}
			a := f.activation(t, match[1])
			f.assertPending(t)
			flow, e := f.s.SetPassword(f.ctx, a, "correct wire setup password")
			if e != nil {
				t.Fatal(e)
			}
			challenge, e := f.email.Issue(f.ctx, a, EmailIssue{Purpose: "invite_confirmation", ContactID: flow.ContactID}, "192.0.2.40")
			if e != nil {
				t.Fatal(e)
			}
			if yes, e := f.email.ProcessOne(f.ctx); !yes || e != nil {
				t.Fatal("OTP SMTP", e)
			}
			code := regexp.MustCompile(`[0-9]{8}`).FindString(inviteWireText(t, peer))
			if len(code) != 8 {
				t.Fatal("OTP absent")
			}
			if _, e = f.email.Verify(f.ctx, a, challenge.ID, code); e != nil {
				t.Fatal(e)
			}
			en, e := f.s.StartEnrollment(f.ctx, a)
			if e != nil {
				t.Fatal(e)
			}
			seed := inviteEnrollmentSeed(t, en.ProvisioningURI)
			if _, e = f.s.ConfirmEnrollment(f.ctx, a, en.EnrollmentID, TOTP(seed, f.now.Unix()/30)); e != nil {
				t.Fatal(e)
			}
			f.assertPending(t)
			completed, e := f.s.Complete(f.ctx, a, "192.0.2.40", "real-smtp-fixture")
			if e != nil {
				t.Fatal(e)
			}
			if completed.View.State != "completed" || completed.SessionToken != "" || completed.View.MFASatisfied {
				t.Fatal("SMTP email created session authority")
			}
			if peer.transactions.Load() != 2 {
				t.Fatal("unexpected SMTP message count")
			}
		})
	}
}
