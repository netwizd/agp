package httpapi

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// This test composes the production HTTP handlers, coordinator and SQLite.
// Mail capture and journal are explicit doubles; protocol-wire and PostgreSQL
// qualification belong to the separate lifecycle native acceptance suites.
type lifecycleHTTPMail struct{ messages []mailtransport.Message }

func (m *lifecycleHTTPMail) Send(_ context.Context, message mailtransport.Message) (mailtransport.Result, error) {
	message.Text = bytes.Clone(message.Text)
	m.messages = append(m.messages, message)
	return mailtransport.Result{State: mailtransport.Accepted}, nil
}
func lifecycleCookies(previous, next []*http.Cookie) []*http.Cookie {
	values := map[string]*http.Cookie{}
	for _, c := range previous {
		values[c.Name] = c
	}
	for _, c := range next {
		values[c.Name] = c
	}
	out := []*http.Cookie{}
	for _, c := range values {
		out = append(out, c)
	}
	return out
}
func lifecycleNoSession(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == domain.ManagementSessionCookieName || c.Name == domain.LoginSessionCookieName {
			t.Fatal("setup issued a session cookie")
		}
	}
	if strings.Contains(w.Body.String(), `"mfaSatisfied":true`) {
		t.Fatal("setup asserted session MFA")
	}
}
func lifecycleHTTPFixture(t *testing.T) (*Server, []*http.Cookie, map[string]string, *lifecycleHTTPMail) {
	t.Helper()
	s := secureHTTPFixture(t)
	j := newOIDCHTTPWireJournal()
	j.head.AuthorityID = "http_test"
	j.head.Digest = ""
	s.identity.Coordinator.Authority = j
	keys, e := identity.NewEmailKeyring("lifecycle_enc", "lifecycle_mac", map[string][]byte{"lifecycle_enc": bytes.Repeat([]byte{81}, 32)}, map[string][]byte{"lifecycle_mac": bytes.Repeat([]byte{82}, 32)})
	if e != nil {
		t.Fatal(e)
	}
	sender := &lifecycleHTTPMail{}
	email, e := identity.NewEmailService(s.identity, keys, sender)
	if e != nil {
		t.Fatal(e)
	}
	s.identity.WithEmail(email)
	s.SetEmail(email)
	t.Cleanup(email.Close)
	t.Cleanup(s.identity.InvitationService().Close)
	ctx := context.Background()
	user, e := s.store.FindUserByUsername(ctx, "root")
	if e != nil {
		t.Fatal(e)
	}
	token, csrf := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"
	now := time.Now().UTC()
	e = s.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		return identity.InsertSession(ctx, tx, domain.Session{ID: "lifecycle_http_admin", UserID: user.ID, TokenHash: auth.TokenHash(token), CSRFHash: auth.TokenHash(csrf), CreatedAt: now, ExpiresAt: now.Add(time.Hour), Audience: domain.SessionAudienceManagement, AudienceOrigin: s.cfg.ManagementOrigin, AuthorityEpoch: 1, SecurityVersion: 1, PrimaryAt: &now, MFAAt: &now, LastSeenAt: &now})
	})
	if e != nil {
		t.Fatal(e)
	}
	return s, []*http.Cookie{{Name: domain.ManagementSessionCookieName, Value: token}}, map[string]string{"Origin": s.cfg.ManagementOrigin, "X-CSRF-Token": csrf}, sender
}
func TestInitialActivationHTTPStagedAndSessionless(t *testing.T) {
	s, admin, headers, mail := lifecycleHTTPFixture(t)
	h := s.Handler()
	ctx := context.Background()
	headers["Idempotency-Key"] = "create_pending_http"
	input := identity.PendingUserInput{ID: "usr_http_invited", Username: "New_Http_User", DisplayName: "New user", GroupIDs: []string{}}
	w := identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/users", input, admin, headers)
	if w.Code != 201 {
		t.Fatal("create pending", w.Code, w.Body.String())
	}
	var pending identity.LifecycleUserView
	if json.Unmarshal(w.Body.Bytes(), &pending) != nil || pending.LifecycleState != "invited" || pending.Username != "new_http_user" {
		t.Fatal("pending contract")
	}
	headers["Idempotency-Key"] = "invite_pending_http"
	headers["If-Match"] = `"2"`
	inviteInput := identity.InviteRequest{Email: "new-user@corp.test", TTLSeconds: 3600}
	if w = identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/users/"+pending.ID+"/invites", inviteInput, admin, headers); w.Code != 412 {
		t.Fatal("stale invitation CAS", w.Code)
	}
	headers["If-Match"] = `"1"`
	w = identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/users/"+pending.ID+"/invites", inviteInput, admin, headers)
	if w.Code != 201 {
		t.Fatal("invite", w.Code, w.Body.String())
	}
	if ok, e := s.identity.ProcessLifecycleDeliveryOne(ctx); !ok || e != nil {
		t.Fatal("deliver invite", ok, e)
	}
	if len(mail.messages) != 1 {
		t.Fatal("invitation submission count")
	}
	match := regexp.MustCompile(`#token=([A-Za-z0-9_-]{43})`).FindStringSubmatch(string(mail.messages[0].Text))
	if len(match) != 2 {
		t.Fatal("invitation landing fragment")
	}
	raw := match[1]
	if strings.Contains(w.Body.String(), raw) {
		t.Fatal("management response leaked invite token")
	}
	b := identityHTTPRequest(t, h, "GET", "login.test", "/auth/v2/bootstrap", nil, nil, nil)
	cookies := b.Result().Cookies()
	flowHeaders := map[string]string{"Origin": s.cfg.LoginOrigin, "X-CSRF-Token": cookieValue(cookies, flowCSRFCookie)}
	w = identityHTTPRequest(t, h, "POST", "login.test", "/auth/v2/flows", map[string]string{"purpose": "activate", "audience": "setup"}, cookies, flowHeaders)
	if w.Code != 201 {
		t.Fatal("activate start", w.Code, w.Body.String())
	}
	var f identity.FlowView
	_ = json.Unmarshal(w.Body.Bytes(), &f)
	cookies = lifecycleCookies(cookies, w.Result().Cookies())
	oldID := f.ID
	path := "/auth/v2/flows/" + f.ID
	if w = identityHTTPRequest(t, h, "POST", "login.test", path+"/password-setups", map[string]string{"newPassword": "before-binding-password"}, cookies, flowHeaders); w.Code < 400 {
		t.Fatal("password accepted before token binding")
	}
	if w = identityHTTPRequest(t, h, "POST", "login.test", path+"/primary-proofs", map[string]any{"method": "invitation", "token": raw, "username": nil}, cookies, flowHeaders); w.Code != 400 {
		t.Fatal("ambiguous proof union accepted", w.Code)
	}
	w = identityHTTPRequest(t, h, "POST", "login.test", path+"/primary-proofs", map[string]string{"method": "invitation", "token": raw}, cookies, flowHeaders)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &f) != nil || f.ID == oldID || f.NextStep != "password_setup" {
		t.Fatal("reservation rotation", w.Code, w.Body.String())
	}
	lifecycleNoSession(t, w)
	cookies = lifecycleCookies(cookies, w.Result().Cookies())
	path = "/auth/v2/flows/" + f.ID
	password := "  initial-http-password-秘密  "
	w = identityHTTPRequest(t, h, "POST", "login.test", path+"/password-setups", map[string]string{"newPassword": password}, cookies, flowHeaders)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &f) != nil || f.NextStep != "email_code" || f.ContactID == "" {
		t.Fatal("staged password/contact", w.Code, w.Body.String())
	}
	lifecycleNoSession(t, w)
	user, e := s.store.FindUserByUsername(ctx, pending.Username)
	if e != nil || user.PasswordHash != "" {
		t.Fatal("staged password published before completion")
	}
	if w = identityHTTPRequest(t, h, "POST", "login.test", path+"/totp-enrollments", struct{}{}, cookies, flowHeaders); w.Code < 400 {
		t.Fatal("TOTP setup bypassed email confirmation")
	}
	w = identityHTTPRequest(t, h, "POST", "login.test", path+"/email-challenges", identity.EmailIssue{Purpose: "invite_confirmation", ContactID: f.ContactID}, cookies, flowHeaders)
	if w.Code != 202 {
		t.Fatal("invitation OTP issue", w.Code, w.Body.String())
	}
	var challenge identity.ChallengeView
	_ = json.Unmarshal(w.Body.Bytes(), &challenge)
	if yes, e := s.email.ProcessOne(ctx); !yes || e != nil {
		t.Fatal("OTP submission", yes, e)
	}
	otp := regexp.MustCompile(`[0-9]{8}`).FindString(string(mail.messages[len(mail.messages)-1].Text))
	if len(otp) != 8 {
		t.Fatal("missing confirmation code")
	}
	w = identityHTTPRequest(t, h, "POST", "login.test", path+"/email-challenges/"+challenge.ID+"/proofs", map[string]string{"code": otp}, cookies, flowHeaders)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &f) != nil || f.NextStep != "totp_enrollment" {
		t.Fatal("email confirmation transition", w.Code, w.Body.String())
	}
	lifecycleNoSession(t, w)
	w = identityHTTPRequest(t, h, "POST", "login.test", path+"/totp-enrollments", struct{}{}, cookies, flowHeaders)
	var enrollment identity.Enrollment
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &enrollment) != nil {
		t.Fatal("staged enrollment", w.Code, w.Body.String())
	}
	uri, e := url.Parse(enrollment.ProvisioningURI)
	if e != nil {
		t.Fatal(e)
	}
	seed, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(uri.Query().Get("secret"))
	if e != nil {
		t.Fatal("TOTP seed")
	}
	w = identityHTTPRequest(t, h, "POST", "login.test", path+"/totp-enrollments/"+enrollment.EnrollmentID+"/confirmations", map[string]string{"code": identity.TOTP(seed, time.Now().Unix()/30)}, cookies, flowHeaders)
	if w.Code != 201 {
		t.Fatal("staged confirmation", w.Code, w.Body.String())
	}
	lifecycleNoSession(t, w)
	user, e = s.store.FindUserByUsername(ctx, pending.Username)
	if e != nil || user.PasswordHash != "" {
		t.Fatal("credentials published before final completion")
	}
	w = identityHTTPRequest(t, h, "POST", "login.test", path+"/completions", struct{}{}, cookies, flowHeaders)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &f) != nil || f.State != "completed" {
		t.Fatal("activation completion", w.Code, w.Body.String())
	}
	lifecycleNoSession(t, w)
	user, e = s.store.FindUserByUsername(ctx, pending.Username)
	if e != nil {
		t.Fatal(e)
	}
	valid, e := auth.VerifyPassword(password, user.PasswordHash)
	if e != nil || !valid {
		t.Fatal("final exact password was not published")
	}
	w = identityHTTPRequest(t, h, "GET", "management.test", "/api/v2/users/"+pending.ID, nil, admin, nil)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &pending) != nil || pending.LifecycleState != "active" || uint64(pending.Revision) != 2 {
		t.Fatal("activated management projection", w.Code, w.Body.String())
	}
	// A new ordinary login must resolve the same canonical account after setup.
	cookies = lifecycleCookies(cookies, w.Result().Cookies())
	w = identityHTTPRequest(t, h, "POST", "login.test", "/auth/v2/flows", map[string]string{"purpose": "login", "audience": "login"}, cookies, flowHeaders)
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &f) != nil {
		t.Fatal("new login flow", w.Code)
	}
	cookies = lifecycleCookies(cookies, w.Result().Cookies())
	w = identityHTTPRequest(t, h, "POST", "login.test", "/auth/v2/flows/"+f.ID+"/primary-proofs", map[string]string{"method": "local_password", "username": "New_Http_User", "password": password}, cookies, flowHeaders)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &f) != nil || f.State != "pending_mfa" || f.NextStep != "totp" {
		t.Fatal("mixed-case activated account cannot log in", w.Code, w.Body.String())
	}
	lifecycleNoSession(t, w)

}

func TestLifecycleInventoryHTTPReadOnlyAndPendingDenied(t *testing.T) {
	s, admin, headers, _ := lifecycleHTTPFixture(t)
	ctx := context.Background()
	h := s.Handler()
	group, e := s.store.CreateGroup(ctx, domain.GroupInput{Name: "Lifecycle audit reader", PermissionIDs: []string{"users.read"}})
	if e != nil {
		t.Fatal(e)
	}
	root, e := s.store.FindUserByUsername(ctx, "root")
	if e != nil {
		t.Fatal(e)
	}
	reader, e := s.store.CreateUser(ctx, domain.UserInput{Username: "lifecycle_reader", PasswordHash: root.PasswordHash, GroupIDs: []string{group.ID}})
	if e != nil {
		t.Fatal(e)
	}
	token, _, _ := auth.NewToken()
	csrf, _, _ := auth.NewToken()
	now := time.Now().UTC()
	if e = s.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		return identity.InsertSession(ctx, tx, domain.Session{ID: "lifecycle_reader_session", UserID: reader.ID, TokenHash: auth.TokenHash(token), CSRFHash: auth.TokenHash(csrf), CreatedAt: now, ExpiresAt: now.Add(time.Hour), Audience: domain.SessionAudienceManagement, AudienceOrigin: s.cfg.ManagementOrigin, AuthorityEpoch: 1, SecurityVersion: 1, MFAAt: &now, PrimaryAt: &now, LastSeenAt: &now})
	}); e != nil {
		t.Fatal(e)
	}
	cookies := []*http.Cookie{{Name: domain.ManagementSessionCookieName, Value: token}}
	w := identityHTTPRequest(t, h, "GET", "management.test", "/api/v2/identity-access", nil, cookies, nil)
	var access identity.LifecycleAccessView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &access) != nil || !access.UsersRead || access.UsersManage || access.PrivilegedManage || access.Approve {
		t.Fatal("read-only access", w.Code, w.Body.String())
	}
	w = identityHTTPRequest(t, h, "GET", "management.test", "/api/v2/users?limit=1", nil, cookies, nil)
	var list identity.LifecycleUserList
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &list) != nil || len(list.Items) != 1 || list.NextCursor == nil {
		t.Fatal("bounded read-only inventory", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "password") || strings.Contains(w.Body.String(), "tokenHash") {
		t.Fatal("credential data in redacted inventory")
	}
	input := identity.PendingUserInput{ID: "usr_http_pending_guard", Username: "pending_guard", GroupIDs: []string{}}
	deniedHeaders := map[string]string{"Origin": s.cfg.ManagementOrigin, "X-CSRF-Token": csrf, "Idempotency-Key": "reader_cannot_create"}
	if w = identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/users", input, cookies, deniedHeaders); w.Code != 403 {
		t.Fatal("read permission escalated to lifecycle write", w.Code)
	}
	headers["Idempotency-Key"] = "create_pending_guard"
	w = identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/users", input, admin, headers)
	if w.Code != 201 {
		t.Fatal("operator pending creation", w.Code, w.Body.String())
	}
	// Seed a forged/restored session projection to exercise the active-principal
	// invariant. The public activation API never creates this session.
	pendingToken, _, _ := auth.NewToken()
	e = s.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		return identity.InsertSession(ctx, tx, domain.Session{ID: "forged_pending_session", UserID: input.ID, TokenHash: auth.TokenHash(pendingToken), CreatedAt: now, ExpiresAt: now.Add(time.Hour), Audience: domain.SessionAudienceManagement, AudienceOrigin: s.cfg.ManagementOrigin, AuthorityEpoch: 1, SecurityVersion: 1, MFAAt: &now, PrimaryAt: &now, LastSeenAt: &now})
	})
	if e != nil {
		t.Fatal(e)
	}
	w = identityHTTPRequest(t, h, "GET", "management.test", "/api/v1/me", nil, []*http.Cookie{{Name: domain.ManagementSessionCookieName, Value: pendingToken}}, nil)
	if w.Code != 401 {
		t.Fatal("pending principal obtained ordinary session authority", w.Code)
	}
	for _, host := range []string{"login.test", "portal.test"} {
		if w = identityHTTPRequest(t, h, "GET", host, "/api/v2/users", nil, cookies, nil); w.Code < 400 {
			t.Fatal("inventory crossed management origin", host)
		}
	}
}
func TestPasswordResetHTTPUniformEmptyAcceptance(t *testing.T) {
	s, _, _, mail := lifecycleHTTPFixture(t)
	h := s.Handler()
	bootstrap := identityHTTPRequest(t, h, "GET", "login.test", "/auth/v2/bootstrap", nil, nil, nil)
	cookies := bootstrap.Result().Cookies()
	headers := map[string]string{"Origin": s.cfg.LoginOrigin, "X-CSRF-Token": cookieValue(cookies, flowCSRFCookie)}
	for _, input := range []identity.PasswordResetRequest{{Username: "does_not_exist", Email: "nobody@corp.test"}, {Username: "root", Email: "root@corp.test"}, {Username: "root", Email: "invalid-address"}} {
		w := identityHTTPRequest(t, h, "POST", "login.test", "/auth/v2/password-reset-requests", input, cookies, headers)
		if w.Code != 202 || w.Body.Len() != 0 || len(w.Result().Cookies()) != 0 {
			t.Fatal("reset request disclosed target state", w.Code)
		}
	}
	if len(mail.messages) != 0 {
		t.Fatal("invalid reset request sent a message")
	}
	if w := identityHTTPRequest(t, h, "POST", "login.test", "/auth/v2/password-reset-requests", identity.PasswordResetRequest{}, cookies, map[string]string{"Origin": s.cfg.LoginOrigin}); w.Code != 403 {
		t.Fatal("reset request bypassed pre-login CSRF", w.Code)
	}
}
