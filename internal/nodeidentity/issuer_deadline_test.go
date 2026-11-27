package nodeidentity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

type issuerDeadlineAuthority struct {
	*fakeAuthority
	calls int
}

func (a *issuerDeadlineAuthority) Head(ctx context.Context) (securityjournal.Head, error) {
	a.calls++
	if a.calls == 2 {
		a.advance(time.Minute)
	}
	return a.fakeAuthority.Head(ctx)
}
func TestIssuerAuthorizationDeadlineBeforeDurablePublication(t *testing.T) {
	f := setup(t, false)
	f.node("node_deadline")
	en := f.enrollment("node_deadline")
	in := EnrollmentSubmission{NodeID: "node_deadline", EnrollmentToken: en.EnrollmentToken, CSRPEM: mustCSR(t)}
	pending, err := f.service.RequestEnrollment(f.ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	var reservation Reservation
	err = f.store.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		r, err := enrollmentBy(f.ctx, tx, "id", pending.EnrollmentID)
		if err != nil {
			return err
		}
		return decodeJSON(r.ReservationJSON, &reservation)
	})
	if err != nil {
		t.Fatal(err)
	}
	h, _ := f.authority.Head(f.ctx)
	deadline := h.RecordedAt.Add(30 * time.Second)
	f.issuer.authority = &issuerDeadlineAuthority{fakeAuthority: f.authority}
	out, err := f.issuer.Issue(f.ctx, IssueRequest{AuthorizationHead: authorizationHead(h), Reservation: reservation, ApprovalDigest: hash([]byte("trusted-test-approval")), AuthorizationExpiresAt: &deadline})
	if !errors.Is(err, ErrDenied) {
		t.Fatal("late durable issuance succeeded", err)
	}
	// A generated in-memory result is not admission. No serial or active
	// registration may survive the external ledger rollback.
	if out.CertificatePEM != "" {
		t.Fatal("rejected ledger transaction exposed certificate")
	}
	var count int
	if err = f.issuer.db.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM issuer_certificates`).Scan(&count); err != nil || count != 0 {
		t.Fatal("deadline crossed before ledger COMMIT", count, err)
	}
	var result string
	if err = f.issuer.db.QueryRowContext(f.ctx, `SELECT result FROM issuer_enrollments WHERE id=?`, en.ID).Scan(&result); err != nil || result != "" {
		t.Fatal("late issuance left public receipt", result, err)
	}
}

type deadlineCapturingIssuer struct {
	Issuer
	deadlines chan time.Time
}

func (s *deadlineCapturingIssuer) Issue(ctx context.Context, in IssueRequest) (CertificateResult, error) {
	if in.AuthorizationExpiresAt == nil || in.AuthorizationExpiresAt.IsZero() || in.AuthorizationExpiresAt.After(in.Reservation.ExpiresAt) {
		return CertificateResult{}, errors.New("transport lost mandatory CP authorization deadline")
	}
	s.deadlines <- *in.AuthorizationExpiresAt
	return s.Issuer.Issue(ctx, in)
}
