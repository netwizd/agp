package nodeidentity

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

func TestNodeHistoricalDirectoryProofSQLite(t *testing.T) { testNodeHistoricalDirectoryProof(t, false) }
func TestNodeHistoricalDirectoryProofPostgres(t *testing.T) {
	testNodeHistoricalDirectoryProof(t, true)
}
func testNodeHistoricalDirectoryProof(t *testing.T, pg bool) {
	for _, tc := range []string{"local_legacy_control", "directory_legacy_no_fallback", "directory_missing_private_proof"} {
		t.Run(tc, func(t *testing.T) {
			f := setup(t, pg)
			f.node("node_one")
			en := f.enrollment("node_one")
			in := EnrollmentSubmission{NodeID: "node_one", EnrollmentToken: en.EnrollmentToken, CSRPEM: mustCSR(t)}
			f.approve(in)
			// Explicit trusted negative fixture: create a syntactically valid,
			// current AD provider/link, with no network observation or fake proof.
			// This is not an end-to-end AD enrollment qualification.
			raw, err := os.ReadFile("../../docs/v2/examples/directory-provider.json")
			if err != nil {
				t.Fatal(err)
			}
			doc, err := identity.ParseDirectoryProvider(strings.NewReader(string(raw)))
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := configmodel.CanonicalJSON(doc)
			if err != nil {
				t.Fatal(err)
			}
			err = f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
				if tc != "directory_missing_private_proof" {
					if _, e := tx.Exec(f.ctx, `DELETE FROM node_identity_requests WHERE operation='enrollment_approval_evidence'`); e != nil {
						return e
					}
					r, e := enrollmentBy(f.ctx, tx, "id", en.ID)
					if e != nil {
						return e
					}
					legacy := legacyEnrollmentApproval(r.ApprovedBy, r.ID, r.PublicKeyDigest, r.RequestDigest, r.ApprovalSecurityVersion, r.ApprovalPasswordVersion, 1)
					if _, e = tx.Exec(f.ctx, `UPDATE node_enrollments SET approval_digest=? WHERE id=?`, legacy, en.ID); e != nil {
						return e
					}
				}
				if tc == "local_legacy_control" {
					return nil
				}
				if _, e := tx.Exec(f.ctx, `INSERT INTO directory_providers(id,name,forest_guid,guard_id,row_version,guard_version,enabled,active_version_id,created_at) VALUES(?,'Synthetic negative directory',?,?,1,1,TRUE,?,?)`, doc.Metadata.ID, doc.Spec.ForestGUID, doc.Metadata.SecurityGuardID, doc.Metadata.VersionID, f.authority.head.RecordedAt); e != nil {
					return e
				}
				if _, e := tx.Exec(f.ctx, `INSERT INTO directory_provider_versions(id,provider_id,guard_version,content_digest,canonical_json,author_id,author_fingerprint,created_at) VALUES(?,?,1,?,?,'trusted_fixture','trusted_fixture',?)`, doc.Metadata.VersionID, doc.Metadata.ID, configmodel.DigestBytes(canonical), string(canonical), f.authority.head.RecordedAt); e != nil {
					return e
				}
				if _, e := tx.Exec(f.ctx, `INSERT INTO directory_identities(id,principal_id,provider_id,forest_guid,object_guid,authenticator_version,created_at) VALUES('directory_admin','admin',?,?,?,1,?)`, doc.Metadata.ID, doc.Spec.ForestGUID, "11112233-4455-6677-8899-aabbccddeeff", f.authority.head.RecordedAt); e != nil {
					return e
				}
				if _, e := tx.Exec(f.ctx, `UPDATE users SET identity_kind='directory' WHERE id='admin'`); e != nil {
					return e
				}
				_, e := tx.Exec(f.ctx, `UPDATE sessions SET directory_identity_id='directory_admin',directory_identity_version=1,directory_provider_version_id=?,directory_provider_guard_version=1 WHERE user_id='admin'`, doc.Metadata.VersionID)
				return e
			})
			if err != nil {
				t.Fatal(err)
			}
			if tc != "local_legacy_control" {
				err = f.coordinator.Current(f.ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
					_, e := identity.DirectorySubjectFingerprint(f.ctx, tx, h, "admin")
					if !errors.Is(e, identity.ErrDirectoryUnavailable) {
						t.Fatal("missing private observation became proof", e)
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			cert, err := f.service.Enroll(f.ctx, in)
			var count int
			if e := f.issuer.db.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM issuer_certificates`).Scan(&count); e != nil {
				t.Fatal(e)
			}
			if tc == "local_legacy_control" {
				if err != nil || count != 1 || cert.CertificatePEM == "" {
					t.Fatal("local legacy compatibility", count, err)
				}
			} else if err == nil || count != 0 || cert.CertificatePEM != "" {
				t.Fatal("AD fallback minted certificate", count, err)
			}
		})
	}
}

type postIssueAuthorityAdvance struct {
	Issuer
	authority *fakeAuthority
	calls     int
}

func (i *postIssueAuthorityAdvance) Issue(ctx context.Context, in IssueRequest) (CertificateResult, error) {
	i.calls++
	out, err := i.Issuer.Issue(ctx, in)
	if err == nil {
		i.authority.advance(time.Minute)
	}
	return out, err
}
func TestNodePostIssuerFinalDenialSQLite(t *testing.T)   { testNodePostIssuerFinalDenial(t, false) }
func TestNodePostIssuerFinalDenialPostgres(t *testing.T) { testNodePostIssuerFinalDenial(t, true) }
func testNodePostIssuerFinalDenial(t *testing.T, pg bool) {
	f := scopeFixture(t, pg)
	expires := f.authority.head.RecordedAt.Add(time.Minute)
	a := f.scopeActor(t, "late_enroller", "nodes.enroll", "site", "site_one", &expires)
	en, err := f.service.CreateEnrollment(f.ctx, a, "node_one", "post_issuer_enroll", EnrollmentRequest{Role: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	in := EnrollmentSubmission{NodeID: "node_one", EnrollmentToken: en.EnrollmentToken, CSRPEM: mustCSR(t)}
	pending, err := f.service.RequestEnrollment(f.ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.ApproveEnrollment(f.ctx, a, "node_one", en.ID, "post_issuer_approve", ApprovalRequest{ExpectedPublicKeyDigest: pending.PublicKeyDigest, RequestDigest: pending.RequestDigest}); err != nil {
		t.Fatal(err)
	}
	interposed := &postIssueAuthorityAdvance{Issuer: f.issuer, authority: f.authority}
	f.service.issuer = interposed
	for attempt := 0; attempt < 2; attempt++ {
		cert, e := f.service.Enroll(f.ctx, in)
		if e == nil || cert.CertificatePEM != "" {
			t.Fatal("late local final check exposed issuance", attempt, e)
		}
	}
	if interposed.calls != 1 {
		t.Fatal("retry reached issuer again", interposed.calls)
	}
	var count int
	if err = f.issuer.db.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM issuer_certificates`).Scan(&count); err != nil || count != 1 {
		t.Fatal("durable CA result was silently lost or duplicated", count, err)
	}
	h, _ := f.authority.Head(f.ctx)
	registry, err := f.issuer.Registry(f.ctx, h)
	if err != nil || len(registry.Nodes) != 1 {
		t.Fatal("durable external admission must remain visible", len(registry.Nodes), err)
	}
	err = f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		r, e := enrollmentBy(f.ctx, tx, "id", en.ID)
		if e != nil {
			return e
		}
		if r.State != "approved" || r.CertificateJSON != "" {
			t.Fatal("failed local final check committed certificate state", r.State)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
