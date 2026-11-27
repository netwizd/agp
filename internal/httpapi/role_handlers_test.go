package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// Production HTTP handlers/coordinator/SQLite; journal and authenticated MG
// session setup are explicit doubles, separate from actual TLS LDAP tests.
func TestRoleBindingHTTPQuorumAndExactRevoke(t *testing.T) {
	s, admin, headers, _ := lifecycleHTTPFixture(t)
	journal := s.identity.Coordinator.Authority.(*oidcHTTPWireJournal)
	journal.mu.Lock()
	journal.head.Digest = securitystate.Digest("role_http_genesis")
	digest := journal.head.Digest
	journal.mu.Unlock()
	if e := s.store.WriteIdentity(context.Background(), func(tx storage.IdentityTx) error {
		_, e := tx.Exec(context.Background(), `UPDATE security_state SET digest=? WHERE id=1`, digest)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	insertActor := func(id, token string, adminFlag bool, permission string) ([]*http.Cookie, map[string]string) {
		t.Helper()
		csrf := "csrf_" + id
		e := s.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
			if _, e := tx.Exec(ctx, `INSERT INTO users(id,username,password_hash,is_admin) VALUES(?,?,?,?)`, id, id, "unused fixture password", adminFlag); e != nil {
				return e
			}
			if permission != "" {
				gid := "group_" + id
				if _, e := tx.Exec(ctx, `INSERT INTO groups(id,name) VALUES(?,?)`, gid, gid); e != nil {
					return e
				}
				if _, e := tx.Exec(ctx, `INSERT INTO group_permissions(group_id,permission_id) VALUES(?,?)`, gid, permission); e != nil {
					return e
				}
				if _, e := tx.Exec(ctx, `INSERT INTO user_groups(user_id,group_id) VALUES(?,?)`, id, gid); e != nil {
					return e
				}
			}
			return identity.InsertSession(ctx, tx, domain.Session{ID: "session_" + id, UserID: id, TokenHash: auth.TokenHash(token), CSRFHash: auth.TokenHash(csrf), Audience: "management", AudienceOrigin: s.cfg.ManagementOrigin, AuthorityEpoch: 1, SecurityVersion: 1, CreatedAt: now, ExpiresAt: now.Add(time.Hour), PrimaryAt: &now, MFAAt: &now, LastSeenAt: &now})
		})
		if e != nil {
			t.Fatal(e)
		}
		return []*http.Cookie{{Name: domain.ManagementSessionCookieName, Value: token}}, map[string]string{"Origin": s.cfg.ManagementOrigin, "X-CSRF-Token": csrf}
	}
	reviewer, reviewHeaders := insertActor("usr_role_reviewer", "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA", true, "config.approve")
	reader, readerHeaders := insertActor("usr_role_reader", "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE", false, "users.read")
	_, _ = insertActor("usr_role_target", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", false, "")
	h := s.Handler()
	for _, path := range []string{"/api/v2/permissions", "/api/v2/roles", "/api/v2/role-bindings?limit=1"} {
		w := identityHTTPRequest(t, h, "GET", "management.test", path, nil, reader, nil)
		if w.Code != 200 {
			t.Fatal("read-only metadata", path, w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("cacheable role metadata")
		}
	}
	request := map[string]any{"principalId": "usr_role_target", "roleId": "role_config_read", "scopeType": "global"}
	for _, extra := range []map[string]any{{"scopeId": ""}, {"scopeId": nil}, {"scopeId": "site_alpha"}, {"unknown": "field"}} {
		in := map[string]any{}
		for k, v := range request {
			in[k] = v
		}
		for k, v := range extra {
			in[k] = v
		}
		headers["Idempotency-Key"] = "invalid_role_union_request"
		w := identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/role-bindings", in, admin, headers)
		if w.Code != 400 {
			t.Fatal("global union", w.Code, w.Body.String())
		}
	}
	for _, scope := range []any{nil, ""} {
		headers["Idempotency-Key"] = "invalid_role_site_request"
		w := identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/role-bindings", map[string]any{"principalId": "usr_role_target", "roleId": "role_config_read", "scopeType": "site", "scopeId": scope}, admin, headers)
		if w.Code != 400 {
			t.Fatal("site scope required", w.Code, w.Body.String())
		}
	}
	headers["Idempotency-Key"] = "role_missing_scope_graph_request"
	if w := identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/role-bindings", map[string]any{"principalId": "usr_role_target", "roleId": "role_config_read", "scopeType": "site", "scopeId": "site_alpha"}, admin, headers); w.Code != 503 || !strings.Contains(w.Body.String(), "role_scope_unavailable") {
		t.Fatal("missing scope authority", w.Code, w.Body.String())
	}
	readerHeaders["Idempotency-Key"] = "reader_cannot_grant_role"
	if w := identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/role-bindings", request, reader, readerHeaders); w.Code != 403 {
		t.Fatal("reader mutation", w.Code, w.Body.String())
	}
	if w := identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/role-bindings", request, admin, map[string]string{"Origin": s.cfg.ManagementOrigin, "Idempotency-Key": "missing_role_csrf_request"}); w.Code != 403 {
		t.Fatal("missing CSRF", w.Code)
	}
	if w := identityHTTPRequest(t, h, "GET", "login.test", "/api/v2/roles", nil, admin, nil); w.Code < 400 {
		t.Fatal("role catalog crossed origin")
	}
	headers["Idempotency-Key"] = "create_role_http_request"
	w := identityHTTPRequest(t, h, "POST", "management.test", "/api/v2/role-bindings", request, admin, headers)
	if w.Code != 202 {
		t.Fatal("create", w.Code, w.Body.String())
	}
	var accepted struct {
		OperationID string `json:"operationId"`
		ResourceID  string `json:"resourceId"`
	}
	if json.Unmarshal(w.Body.Bytes(), &accepted) != nil || accepted.OperationID == "" {
		t.Fatal("accepted operation")
	}
	path := "/api/v2/security/operations/" + accepted.OperationID
	w = identityHTTPRequest(t, h, "GET", "management.test", path, nil, admin, nil)
	if w.Code != 200 {
		t.Fatal("operation namespace requires directory connector", w.Code, w.Body.String())
	}
	var op identity.RoleSecurityOperation
	if json.Unmarshal(w.Body.Bytes(), &op) != nil || op.RoleGrantRequest == nil || op.Family != "grant_role_binding" {
		t.Fatal("typed grant intent")
	}
	if accepted.ResourceID != op.RoleGrantRequest.BindingID || op.SubjectID != "usr_role_target" {
		t.Fatal("accepted binding resource or principal subject", accepted, op.SubjectID)
	}
	if e := s.identity.Coordinator.Ready(ctx); e != nil {
		t.Fatal("human approval global barrier", e)
	}
	assertEffective := func(want bool) {
		t.Helper()
		var grants securitystate.EffectiveGrants
		e := s.identity.Coordinator.Current(ctx, func(tx storage.IdentityTx, head securityjournal.Head) error {
			var e error
			grants, e = securitystate.ReadEffectiveGrants(ctx, tx, head, "usr_role_target")
			return e
		})
		if e != nil || (len(grants.Global) > 0) != want {
			t.Fatal("grant publication", grants, e)
		}
	}
	assertEffective(false)
	action := map[string]string{"requestDigest": op.RequestDigest, "reason": "independent exact role review"}
	headers["Idempotency-Key"] = "self_role_approval_request"
	if w = identityHTTPRequest(t, h, "POST", "management.test", path+"/approvals", action, admin, headers); w.Code != 403 {
		t.Fatal("self review", w.Code, w.Body.String())
	}
	reviewHeaders["Idempotency-Key"] = "approve_role_http_request"
	w = identityHTTPRequest(t, h, "POST", "management.test", path+"/approvals", action, reviewer, reviewHeaders)
	if w.Code != 201 {
		t.Fatal("approve", w.Code, w.Body.String())
	}
	assertEffective(false)
	headers["Idempotency-Key"] = "execute_role_http_request"
	w = identityHTTPRequest(t, h, "POST", "management.test", path+"/executions", action, admin, headers)
	if w.Code != 202 {
		t.Fatal("execute", w.Code, w.Body.String())
	}
	assertEffective(true)
	if w = identityHTTPRequest(t, h, "POST", "management.test", path+"/executions", action, admin, headers); w.Code != 202 {
		t.Fatal("lost execute response", w.Code, w.Body.String())
	}
	deleteReason := strings.Repeat("Ж", 2048) // Maximum public rune budget exceeds 4 KiB as UTF-8 JSON.
	deletePath := "/api/v2/role-bindings/" + op.RoleGrantRequest.BindingID
	headers["Idempotency-Key"] = "delete_role_http_request"
	headers["If-Match"] = `"2"`
	if w = identityHTTPRequest(t, h, "DELETE", "management.test", deletePath, map[string]string{"reason": deleteReason}, admin, headers); w.Code != 412 {
		t.Fatal("revoke CAS", w.Code, w.Body.String())
	}
	headers["If-Match"] = `"1"`
	w = identityHTTPRequest(t, h, "DELETE", "management.test", deletePath, map[string]string{"reason": deleteReason}, admin, headers)
	if w.Code != 202 {
		t.Fatal("revoke", w.Code, w.Body.String())
	}
	assertEffective(false)
	var revoked struct {
		ResourceID string `json:"resourceId"`
	}
	if json.Unmarshal(w.Body.Bytes(), &revoked) != nil || revoked.ResourceID != op.RoleGrantRequest.BindingID {
		t.Fatal("accepted revoke resource")
	}
	if w = identityHTTPRequest(t, h, "DELETE", "management.test", deletePath, map[string]string{"reason": deleteReason}, admin, headers); w.Code != 202 {
		t.Fatal("lost revoke response", w.Code, w.Body.String())
	}
}
