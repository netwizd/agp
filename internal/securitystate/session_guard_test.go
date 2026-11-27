package securitystate_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func TestDirectManagementGuardRequiresDirectoryValidator(t *testing.T) {
	testDirectManagementGuard(t, false)
}
func TestDirectManagementGuardPostgres(t *testing.T) {
	testDirectManagementGuard(t, true)
}
func testDirectManagementGuard(t *testing.T, pg bool) {
	ctx := context.Background()
	store := portalTestStore(t, pg)
	user, err := store.CreateUser(ctx, domain.UserInput{Username: "guard-test", PasswordHash: "synthetic-unused-hash", IsAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	token := "synthetic-token-hash"
	if err := store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		return identity.InsertSession(ctx, tx, domain.Session{ID: "guard_session", UserID: user.ID, TokenHash: token, CSRFHash: "synthetic-csrf-hash", CreatedAt: now, ExpiresAt: now.Add(time.Hour), Audience: "legacy", SecurityVersion: 1})
	}); err != nil {
		t.Fatal(err)
	}
	c := securitystate.New(store, nil)
	h := securityjournal.Head{AuthorityID: "guard_test", Epoch: 1, RecordedAt: now}
	check := func(want error) {
		t.Helper()
		if err := store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
			for _, current := range []any{nil, c} {
				err := securitystate.CheckManagementSession(ctx, tx, h, token, current)
				if !errors.Is(err, want) || (want == nil && err != nil) {
					t.Fatalf("unexpected direct guard result: %v, want %v", err, want)
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	check(nil)
	// A typed directory session is never treated as local when a CLI/service
	// omits the trusted identity wiring or the live request proof middleware.
	if err := store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET identity_kind='directory' WHERE id=?`, user.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	check(securitystate.ErrUnavailable)
	called := false
	denied := errors.New("private_proof_missing")
	c.RegisterSessionGuard(func(_ context.Context, _ storage.IdentityTx, head securityjournal.Head, value string) error {
		called = true
		if value != token || head.Epoch != h.Epoch {
			t.Fatal("guard changed session binding")
		}
		return denied
	})
	if err := store.WriteIdentity(ctx, func(tx storage.IdentityTx) error { return c.CheckManagementSession(ctx, tx, h, token) }); !errors.Is(err, denied) || !called {
		t.Fatal("configured proof validator bypassed", err)
	}
}

func installPortalDirectoryLink(t *testing.T, f *portalFixture) {
	t.Helper()
	raw := `{"apiVersion":"agp.identity/v1alpha1","kind":"DirectoryProvider","metadata":{"id":"dir_portal","versionId":"dirver_portal","securityGuardId":"guard_dir_portal","securityGuardVersion":"1"},"spec":{"forestGuid":"00000000-0000-0000-0000-000000000001","domainDns":"corp.example.net","transport":"ldaps","endpoints":[{"host":"dc01.corp.example.net","port":636}],"userBaseDns":["DC=corp,DC=example,DC=net"],"groupBaseDns":["DC=corp,DC=example,DC=net"],"bindDn":"CN=reader,DC=corp,DC=example,DC=net","bindSecretVersionId":"sec_bind_1","caSecretVersionId":"sec_ca_1","loginAttribute":"userPrincipalName","provisioning":"preprovisioned","groupResolution":"token_groups_security","accountCheck":"live_each_allow","operationTimeoutSeconds":1,"maximumGroups":2048,"groupMappings":[]}}`
	doc, e := identity.ParseDirectoryProvider(strings.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	canonical, e := configmodel.CanonicalJSON(doc)
	if e != nil {
		t.Fatal(e)
	}
	digest, e := configmodel.Digest(doc)
	if e != nil {
		t.Fatal(e)
	}
	f.write(t, func(tx storage.IdentityTx) error {
		if _, e := tx.Exec(f.ctx, `UPDATE users SET identity_kind='directory' WHERE id=?`, f.user.ID); e != nil {
			return e
		}
		if _, e := tx.Exec(f.ctx, `INSERT INTO directory_providers(id,name,forest_guid,guard_id,row_version,guard_version,enabled,active_version_id,created_at) VALUES('dir_portal','Portal directory',?,'guard_dir_portal',1,1,TRUE,'dirver_portal',?)`, doc.Spec.ForestGUID, f.now); e != nil {
			return e
		}
		if _, e := tx.Exec(f.ctx, `INSERT INTO directory_provider_versions(id,provider_id,guard_version,content_digest,canonical_json,author_id,author_fingerprint,created_at) VALUES('dirver_portal','dir_portal',1,?,?,?,?,?)`, digest, string(canonical), f.user.ID, "unused fixture author fingerprint", f.now); e != nil {
			return e
		}
		if _, e := tx.Exec(f.ctx, `INSERT INTO directory_identities(id,principal_id,provider_id,forest_guid,object_guid,authenticator_version,revoked,created_at) VALUES('directory_portal_identity',?,'dir_portal',?,'20112233-4455-6677-8899-aabbccddeeff',1,FALSE,?)`, f.user.ID, doc.Spec.ForestGUID, f.now); e != nil {
			return e
		}
		_, e := tx.Exec(f.ctx, `UPDATE sessions SET directory_identity_id='directory_portal_identity',directory_identity_version=1,directory_provider_version_id='dirver_portal',directory_provider_guard_version=1 WHERE id='portal_session'`)
		return e
	})
}
