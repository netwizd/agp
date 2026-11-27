package httpapi

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/compiler"
	"github.com/netwizd/agp/internal/configuration"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type planHTTPAuthority struct{ httpIdentityAuthority }

func (planHTTPAuthority) Head(context.Context) (securityjournal.Head, error) {
	return securityjournal.Head{AuthorityID: "http_test", Epoch: 1, RecordedAt: time.Now().UTC()}, nil
}

func TestPlanProposalManagementHTTPBoundary(t *testing.T) {
	s := secureHTTPFixture(t)
	s.cfg.ConfigurationEnabled = true
	s.SetConfiguration(configuration.New(securitystate.New(s.store, planHTTPAuthority{}), s.cfg.ManagementOrigin, compiler.Options{Version: "http-plan-test", BuildDigest: "sha256:" + strings.Repeat("a", 64), MinimumWAFMode: "detection"}))
	ctx := context.Background()
	user, err := s.store.FindUserByUsername(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := s.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,csrf_hash,ip,user_agent,expires_at,created_at,audience,audience_origin,authority_epoch,security_version,mfa_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?,'management',?,1,1,?,?)`, "plan-http-session", user.ID, auth.TokenHash("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), auth.TokenHash("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"), "", "", now.Add(time.Hour), now, s.cfg.ManagementOrigin, now, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	cookies := []*http.Cookie{{Name: domain.ManagementSessionCookieName, Value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}
	headers := map[string]string{"Origin": s.cfg.ManagementOrigin, "X-CSRF-Token": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA", "Idempotency-Key": "plan_http_request_01"}
	h := s.Handler()
	path := "/api/v2/config/plan-proposals"
	if w := identityHTTPRequest(t, h, "GET", "management.test", path, nil, cookies, nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"items":[]`) {
		t.Fatalf("global-read list: %d %s", w.Code, w.Body.String())
	}
	if w := identityHTTPRequest(t, h, "GET", "management.test", path, nil, nil, nil); w.Code != 401 {
		t.Fatal("anonymous proposal access", w.Code)
	}
	if w := identityHTTPRequest(t, h, "POST", "management.test", path, map[string]any{}, cookies, map[string]string{"Origin": s.cfg.ManagementOrigin}); w.Code != 403 {
		t.Fatal("missing CSRF admitted", w.Code)
	}
	if w := identityHTTPRequest(t, h, "POST", "management.test", path, map[string]any{"baselineBundleDigest": "caller-baseline"}, cookies, headers); w.Code != 400 {
		t.Fatalf("caller evidence accepted: %d %s", w.Code, w.Body.String())
	}
	if w := identityHTTPRequest(t, h, "POST", "management.test", path+"/proposal/reviews", map[string]any{"proposalDigest": "sha256:" + strings.Repeat("a", 64), "reason": "Independent review"}, cookies, headers); w.Code != 403 {
		t.Fatalf("admin implicit approve: %d %s", w.Code, w.Body.String())
	}
	if w := identityHTTPRequest(t, h, "GET", "management.test", path+"?limit=51", nil, cookies, nil); w.Code != 400 {
		t.Fatal("unbounded list allowed", w.Code)
	}
	if w := identityHTTPRequest(t, h, "GET", "portal.test", path, nil, cookies, nil); w.Code < 400 {
		t.Fatal("public origin accessed planning resources", w.Code)
	}
}
