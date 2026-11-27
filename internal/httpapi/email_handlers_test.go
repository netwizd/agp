package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/mailtransport"
	"github.com/netwizd/agp/internal/storage"
)

// This capture double tests the HTTP contract. Actual DNS/TLS/SMTP composition
// is covered by identity/email_smtp_test.go, not claimed by this fixture.
type httpEmailSender struct {
	code  string
	calls int
}

func (s *httpEmailSender) Send(_ context.Context, m mailtransport.Message) (mailtransport.Result, error) {
	s.calls++
	s.code = regexp.MustCompile(`[0-9]{8}`).FindString(string(m.Text))
	return mailtransport.Result{State: mailtransport.Accepted}, nil
}
func emailHTTPFixture(t *testing.T, login bool) (*Server, []*http.Cookie, map[string]string, *httpEmailSender) {
	t.Helper()
	s := secureHTTPFixture(t)
	s.identity.Coordinator.Authority = planHTTPAuthority{}
	keys, e := identity.NewEmailKeyring("email_enc", "email_mac", map[string][]byte{"email_enc": bytes.Repeat([]byte{61}, 32)}, map[string][]byte{"email_mac": bytes.Repeat([]byte{62}, 32)})
	if e != nil {
		t.Fatal(e)
	}
	sender := &httpEmailSender{}
	email, e := identity.NewEmailService(s.identity, keys, sender)
	if e != nil {
		t.Fatal(e)
	}
	s.identity.WithEmail(email)
	s.SetEmail(email)
	t.Cleanup(email.Close)
	ctx := context.Background()
	seed, e := s.store.FindUserByUsername(ctx, "root")
	if e != nil {
		t.Fatal(e)
	}
	user, e := s.store.CreateUser(ctx, domain.UserInput{Username: "email_owner", DisplayName: "Contact owner", PasswordHash: seed.PasswordHash, IsAdmin: false})
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	audience, origin, cookie := domain.SessionAudienceManagement, s.cfg.ManagementOrigin, domain.ManagementSessionCookieName
	if login {
		audience, origin, cookie = domain.SessionAudienceLogin, s.cfg.LoginOrigin, domain.LoginSessionCookieName
	}
	token, csrf := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"
	if e = s.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		return identity.InsertSession(ctx, tx, domain.Session{ID: "email_http_session", UserID: user.ID, TokenHash: auth.TokenHash(token), CSRFHash: auth.TokenHash(csrf), CreatedAt: now, ExpiresAt: now.Add(time.Hour), Audience: audience, AudienceOrigin: origin, AuthorityEpoch: 1, SecurityVersion: 1, PrimaryAt: &now, MFAAt: &now, LastSeenAt: &now})
	}); e != nil {
		t.Fatal(e)
	}
	return s, []*http.Cookie{{Name: cookie, Value: token}}, map[string]string{"Origin": origin, "X-CSRF-Token": csrf}, sender
}

func TestEmailContactsHTTPOriginCSRFCASAndFreshPrimary(t *testing.T) {
	for _, login := range []bool{false, true} {
		t.Run(map[bool]string{false: "management", true: "login"}[login], func(t *testing.T) {
			s, cookies, headers, _ := emailHTTPFixture(t, login)
			h := s.Handler()
			host := strings.TrimPrefix(headers["Origin"], "https://")
			path := "/api/v2/me/contacts"
			if w := identityHTTPRequest(t, h, "GET", host, path, nil, cookies, nil); w.Code != 200 || w.Body.String() != "{\"items\":[]}\n" {
				t.Fatal("own list", w.Code, w.Body.String())
			}
			for _, wrongHost := range []string{"portal.test", "api.other.test"} {
				if w := identityHTTPRequest(t, h, "GET", wrongHost, path, nil, cookies, nil); w.Code < 400 {
					t.Fatal("foreign origin contacts", wrongHost, w.Code)
				}
			}
			if w := identityHTTPRequest(t, h, "POST", host, path, map[string]string{"email": "person@corp.test"}, cookies, map[string]string{"Origin": headers["Origin"]}); w.Code != 403 {
				t.Fatal("missing csrf", w.Code)
			}
			bad := map[string]string{"Origin": "https://portal.test", "X-CSRF-Token": headers["X-CSRF-Token"]}
			if w := identityHTTPRequest(t, h, "POST", host, path, map[string]string{"email": "person@corp.test"}, cookies, bad); w.Code != 403 {
				t.Fatal("foreign write origin", w.Code)
			}
			if w := identityHTTPRequest(t, h, "POST", host, path, map[string]any{"email": "person@corp.test", "verified": true}, cookies, headers); w.Code != 400 {
				t.Fatal("caller verification", w.Code)
			}
			w := identityHTTPRequest(t, h, "POST", host, path, map[string]string{"email": "person@corp.test"}, cookies, headers)
			if w.Code != 201 || w.Header().Get("ETag") != `"1"` || strings.Contains(w.Body.String(), "person@") {
				t.Fatal("create", w.Code, w.Body.String())
			}
			var c identity.ContactView
			if e := json.Unmarshal(w.Body.Bytes(), &c); e != nil {
				t.Fatal(e)
			}
			if w := identityHTTPRequest(t, h, "PUT", host, path+"/"+c.ID, map[string]string{"email": "new@corp.test"}, cookies, headers); w.Code != 428 {
				t.Fatal("missing CAS", w.Code)
			}
			headers["If-Match"] = `"2"`
			if w := identityHTTPRequest(t, h, "PUT", host, path+"/"+c.ID, map[string]string{"email": "new@corp.test"}, cookies, headers); w.Code != 412 {
				t.Fatal("stale CAS", w.Code, w.Body.String())
			}
			if e := s.store.WriteIdentity(context.Background(), func(tx storage.IdentityTx) error {
				_, e := tx.Exec(context.Background(), `UPDATE sessions SET primary_at=? WHERE id='email_http_session'`, time.Now().Add(-6*time.Minute))
				return e
			}); e != nil {
				t.Fatal(e)
			}
			if w := identityHTTPRequest(t, h, "POST", host, path, map[string]string{"email": "next@corp.test"}, cookies, headers); w.Code != 403 || !strings.Contains(w.Body.String(), "step_up_required") {
				t.Fatal("stale primary", w.Code, w.Body.String())
			}
			if w := identityHTTPRequest(t, h, "GET", host, path, nil, cookies, nil); w.Code != 200 {
				t.Fatal("ordinary read incorrectly requires fresh primary", w.Code)
			}
		})
	}
}

func TestEmailConfirmationHTTPNeverIssuesSession(t *testing.T) {
	s, sessionCookies, sessionHeaders, sender := emailHTTPFixture(t, true)
	h := s.Handler()
	host := "login.test"
	w := identityHTTPRequest(t, h, "POST", host, "/api/v2/me/contacts", map[string]string{"email": "person@corp.test"}, sessionCookies, sessionHeaders)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var contact identity.ContactView
	_ = json.Unmarshal(w.Body.Bytes(), &contact)
	bootstrap := identityHTTPRequest(t, h, "GET", host, "/auth/v2/bootstrap", nil, nil, nil)
	flowCookies := append(append([]*http.Cookie{}, sessionCookies...), bootstrap.Result().Cookies()...)
	csrf := cookieValue(flowCookies, flowCSRFCookie)
	headers := map[string]string{"Origin": "https://login.test", "X-CSRF-Token": csrf}
	w = identityHTTPRequest(t, h, "POST", host, "/auth/v2/flows", map[string]string{"purpose": "verify_email", "audience": "login"}, flowCookies, headers)
	if w.Code != 201 {
		t.Fatal("start", w.Code, w.Body.String())
	}
	var flow identity.FlowView
	_ = json.Unmarshal(w.Body.Bytes(), &flow)
	flowCookies = append(flowCookies, w.Result().Cookies()...)
	base := "/auth/v2/flows/" + flow.ID
	w = identityHTTPRequest(t, h, "POST", host, base+"/email-challenges", identity.EmailIssue{Purpose: "verify_email", ContactID: contact.ID}, flowCookies, headers)
	if w.Code != 202 {
		t.Fatal("issue", w.Code, w.Body.String())
	}
	var challenge identity.ChallengeView
	_ = json.Unmarshal(w.Body.Bytes(), &challenge)
	if yes, e := s.email.ProcessOne(context.Background()); !yes || e != nil || sender.calls != 1 || len(sender.code) != 8 {
		t.Fatal("capture submit", yes, e)
	}
	w = identityHTTPRequest(t, h, "GET", host, base+"/email-challenges/"+challenge.ID, nil, flowCookies, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"deliveryState":"accepted"`) || strings.Contains(w.Body.String(), sender.code) {
		t.Fatal("status", w.Code, w.Body.String())
	}
	proofPath := base + "/email-challenges/" + challenge.ID + "/proofs"
	if w := identityHTTPRequest(t, h, "POST", host, proofPath, map[string]string{"code": sender.code}, sessionCookies, headers); w.Code < 400 {
		t.Fatal("missing flow binding")
	}
	w = identityHTTPRequest(t, h, "POST", host, proofPath, map[string]string{"code": sender.code}, flowCookies, headers)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"mfaSatisfied":false`) {
		t.Fatal("email proof", w.Code, w.Body.String())
	}
	if w := identityHTTPRequest(t, h, "POST", host, proofPath, map[string]string{"code": sender.code}, flowCookies, headers); w.Code < 400 {
		t.Fatal("replayed code admitted")
	}
	w = identityHTTPRequest(t, h, "POST", host, base+"/completions", map[string]any{}, flowCookies, headers)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"mfaSatisfied":false`) {
		t.Fatal("completion", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == domain.LoginSessionCookieName || c.Name == domain.ManagementSessionCookieName {
			t.Fatal("email minted session")
		}
	}
	var count int
	if e := s.store.WriteIdentity(context.Background(), func(tx storage.IdentityTx) error {
		rows, e := tx.Query(context.Background(), `SELECT count(*) FROM sessions`)
		if e != nil {
			return e
		}
		defer rows.Close()
		if rows.Next() {
			return rows.Scan(&count)
		}
		return rows.Err()
	}); e != nil || count != 1 {
		t.Fatal("email created hidden session", count, e)
	}
	w = identityHTTPRequest(t, h, "GET", host, "/api/v2/me/contacts", nil, sessionCookies, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"verified":true`) {
		t.Fatal("verified contact", w.Code, w.Body.String())
	}
}
