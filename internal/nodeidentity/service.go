package nodeidentity

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"sort"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type Service struct {
	current   Current
	issuer    Issuer
	inventory *inventory.Service
	origin    string
}

func New(current Current, issuer Issuer, agents *inventory.Service, origin string) (*Service, error) {
	if current == nil || issuer == nil || agents == nil || origin == "" {
		return nil, ErrUnavailable
	}
	s := &Service{current, issuer, agents, origin}
	if c, ok := current.(*securitystate.Coordinator); ok {
		RegisterRecovery(c)
	}
	return s, nil
}
func (s *Service) withAccess(ctx context.Context, a Actor, permission string, write bool, fn func(storage.IdentityTx, securityjournal.Head, *inventory.NodeAccess) error) error {
	if a.Origin != s.origin {
		return storage.ErrPermissionDenied
	}
	return s.current.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		access, err := inventory.ReadNodeAccess(ctx, tx, h, s.current, a.TokenHash, a.Origin, permission, write)
		if err != nil {
			return err
		}
		if err = fn(tx, h, access); err != nil {
			return err
		}
		return access.Finish(ctx, tx, s.current, a.TokenHash, a.Origin, write)
	})
}
func requireNode(ctx context.Context, tx storage.IdentityTx, access *inventory.NodeAccess, id string) error {
	ok, err := access.AllowsNode(ctx, tx, id)
	if err != nil {
		return err
	}
	if !ok {
		return storage.ErrPermissionDenied
	}
	return nil
}
func loadNode(ctx context.Context, tx storage.IdentityTx, id string) (Node, error) {
	var raw string
	var n Node
	e := securitystate.One(ctx, tx, `SELECT node_json FROM managed_nodes WHERE id=?`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&raw) })
	if e != nil {
		return n, e
	}
	if decodeJSON(raw, &n) != nil {
		return n, ErrUnavailable
	}
	return n, nil
}
func decodeJSON(s string, v any) error { return decodeString(s, v) }
func replay(ctx context.Context, tx storage.IdentityTx, actor, op, key, fp string, epoch securityjournal.UInt63, out any) (bool, error) {
	var d, raw string
	var ep int64
	e := securitystate.One(ctx, tx, `SELECT request_digest,result_json,authority_epoch FROM node_identity_requests WHERE actor_id=? AND operation=? AND request_key=?`, []any{actor, op, key}, func(r storage.IdentityRows) error { return r.Scan(&d, &raw, &ep) })
	if e == storage.ErrNotFound {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	if d != fp || ep != int64(epoch) {
		return false, ErrConflict
	}
	return true, decodeJSON(raw, out)
}
func remember(ctx context.Context, tx storage.IdentityTx, actor, op, key, fp string, epoch securityjournal.UInt63, out any) error {
	b, e := json.Marshal(out)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO node_identity_requests(actor_id,operation,request_key,request_digest,result_json,authority_epoch) VALUES(?,?,?,?,?,?)`, actor, op, key, fp, string(b), int64(epoch))
	return e
}
func notRevoked(ctx context.Context, tx storage.IdentityTx, node string) error {
	ids, e := securitystate.Strings(ctx, tx, `SELECT node_id FROM security_node_revocations WHERE node_id=?`, node)
	if e != nil {
		return e
	}
	if len(ids) > 0 {
		return ErrDenied
	}
	return nil
}
func (s *Service) CreateNode(ctx context.Context, a Actor, key string, in CreateNodeRequest) (out Node, err error) {
	n, e := validateNode(in)
	if e != nil || !idPattern.MatchString(key) {
		return out, ErrInvalid
	}
	sort.Strings(n.GroupIDs)
	fp := digest(n)
	err = s.withAccess(ctx, a, "nodes.enroll", true, func(tx storage.IdentityTx, h securityjournal.Head, access *inventory.NodeAccess) error {
		actor := access.ID
		ok, e := replay(ctx, tx, actor, "create_node", key, fp, h.Epoch, &out)
		if e != nil {
			return e
		}
		if ok {
			return requireNode(ctx, tx, access, n.ID)
		}
		n.CreatedAt = h.RecordedAt.UTC()
		raw, e := json.Marshal(n)
		if e != nil {
			return e
		}
		if _, e = loadNode(ctx, tx, n.ID); e == nil {
			return ErrConflict
		} else if e != storage.ErrNotFound {
			return e
		}
		var existingNodes int
		if e = securitystate.One(ctx, tx, `SELECT COUNT(*) FROM managed_nodes`, nil, func(r storage.IdentityRows) error { return r.Scan(&existingNodes) }); e != nil {
			return e
		}
		if existingNodes >= 10000 {
			return ErrConflict
		}
		if e = notRevoked(ctx, tx, n.ID); e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO managed_nodes(id,site_id,node_json,authority_epoch,created_at) VALUES(?,?,?,?,?)`, n.ID, n.SiteID, string(raw), int64(h.Epoch), n.CreatedAt)
		if e != nil {
			return e
		}
		if e = requireNode(ctx, tx, access, n.ID); e != nil {
			return e
		}
		out = n
		if e = remember(ctx, tx, actor, "create_node", key, fp, h.Epoch, out); e != nil {
			return e
		}
		return securitystate.Audit(ctx, tx, "node.created", actor, map[string]string{"nodeId": n.ID, "siteId": n.SiteID})
	})
	if err != nil {
		out = Node{}
	}
	return
}
func (s *Service) ListNodes(ctx context.Context, a Actor) (out []Node, err error) {
	out = []Node{}
	err = s.withAccess(ctx, a, "nodes.read", false, func(tx storage.IdentityTx, h securityjournal.Head, access *inventory.NodeAccess) error {
		if e := access.Resolve(ctx, tx); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT node_json FROM managed_nodes ORDER BY id LIMIT 10001`)
		if e != nil {
			return e
		}
		var nodes []Node
		for rows.Next() {
			var raw string
			var n Node
			if len(nodes) >= 10000 || rows.Scan(&raw) != nil || decodeJSON(raw, &n) != nil {
				rows.Close()
				return ErrUnavailable
			}
			nodes = append(nodes, n)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		for _, n := range nodes {
			allowed, e := access.AllowsNode(ctx, tx, n.ID)
			if e != nil {
				return e
			}
			if allowed {
				out = append(out, n)
			}
		}
		return nil
	})
	if err != nil {
		out = nil
	}
	return
}
func (s *Service) CreateEnrollment(ctx context.Context, a Actor, nodeID, key string, in EnrollmentRequest) (out Enrollment, err error) {
	if !idPattern.MatchString(nodeID) || !idPattern.MatchString(key) || in.Role != "agent" || in.TTLSeconds < 0 || in.TTLSeconds > 900 || in.TTLSeconds > 0 && in.TTLSeconds < 60 {
		return out, ErrInvalid
	}
	if in.TTLSeconds == 0 {
		in.TTLSeconds = 600
	}
	fp := digest(struct {
		Node    string
		Request EnrollmentRequest
	}{nodeID, in})
	err = s.withAccess(ctx, a, "nodes.enroll", true, func(tx storage.IdentityTx, h securityjournal.Head, access *inventory.NodeAccess) error {
		if err := requireNode(ctx, tx, access, nodeID); err != nil {
			return err
		}
		actor := access.ID
		ok, e := replay(ctx, tx, actor, "enrollment", key, fp, h.Epoch, &out)
		if e != nil || ok {
			return e
		}
		if _, e = loadNode(ctx, tx, nodeID); e != nil {
			return e
		}
		if e = notRevoked(ctx, tx, nodeID); e != nil {
			return e
		}
		var count int
		e = securitystate.One(ctx, tx, `SELECT COUNT(*) FROM node_enrollments WHERE node_id=? AND role='agent' AND state IN ('issued','csr_pending','approved') AND expires_at>? AND authority_epoch=?`, []any{nodeID, h.RecordedAt, int64(h.Epoch)}, func(r storage.IdentityRows) error { return r.Scan(&count) })
		if e != nil {
			return e
		}
		if count > 0 {
			return ErrConflict
		}
		token, _, e := auth.NewToken()
		if e != nil {
			return e
		}
		id := securitystate.ID("enroll")
		out = Enrollment{ID: id, NodeID: nodeID, Role: "agent", State: "issued", ExpiresAt: h.RecordedAt.UTC().Add(time.Duration(in.TTLSeconds) * time.Second)}
		_, e = tx.Exec(ctx, `INSERT INTO node_enrollments(id,node_id,role,token_hash,authority_epoch,state,expires_at,created_at) VALUES(?,?,?, ?,?,'issued',?,?)`, id, nodeID, "agent", hash([]byte(token)), int64(h.Epoch), out.ExpiresAt, h.RecordedAt)
		if e != nil {
			return e
		}
		if e = remember(ctx, tx, actor, "enrollment", key, fp, h.Epoch, out); e != nil {
			return e
		}
		if e = securitystate.Audit(ctx, tx, "node.enrollment.created", actor, map[string]string{"nodeId": nodeID, "enrollmentId": id}); e != nil {
			return e
		}
		out.EnrollmentToken = token
		out.TokenAvailable = true
		return nil
	})
	if err != nil {
		out = Enrollment{}
	}
	return
}

type enrollmentRow struct {
	ApprovedBy                                                                                                             string
	ApprovalSecurityVersion, ApprovalPasswordVersion                                                                       uint64
	ID, NodeID, State, TokenHash, RequestDigest, PublicKeyDigest, CSRPEM, ReservationJSON, ApprovalDigest, CertificateJSON string
	Epoch                                                                                                                  int64
	ExpiresAt                                                                                                              time.Time
}

func enrollmentBy(ctx context.Context, tx storage.IdentityTx, field, value string) (*enrollmentRow, error) {
	r := &enrollmentRow{}
	q := `SELECT id,node_id,state,token_hash,authority_epoch,expires_at,request_digest,public_key_digest,csr_pem,reservation_json,approval_digest,certificate_json,approved_by,approval_security_version,approval_password_version FROM node_enrollments WHERE ` + field + `=?`
	e := securitystate.One(ctx, tx, q, []any{value}, func(rows storage.IdentityRows) error {
		return rows.Scan(&r.ID, &r.NodeID, &r.State, &r.TokenHash, &r.Epoch, &r.ExpiresAt, &r.RequestDigest, &r.PublicKeyDigest, &r.CSRPEM, &r.ReservationJSON, &r.ApprovalDigest, &r.CertificateJSON, &r.ApprovedBy, &r.ApprovalSecurityVersion, &r.ApprovalPasswordVersion)
	})
	return r, e
}
func (r *enrollmentRow) view() EnrollmentRequestView {
	return EnrollmentRequestView{ID: r.ID, EnrollmentID: r.ID, NodeID: r.NodeID, State: r.State, PublicKeyDigest: r.PublicKeyDigest, RequestDigest: r.RequestDigest, ExpiresAt: r.ExpiresAt}
}
func (s *Service) RequestEnrollment(ctx context.Context, in EnrollmentSubmission) (out EnrollmentRequestView, err error) {
	return s.submit(ctx, in, false, &out, nil)
}
func (s *Service) Enroll(ctx context.Context, in EnrollmentSubmission) (out CertificateResult, err error) {
	if !idPattern.MatchString(in.NodeID) || !tokenPattern.MatchString(in.EnrollmentToken) {
		return out, ErrDenied
	}
	err = s.withEnrollmentApproval(ctx, in, func(fresh context.Context) error { _, e := s.submit(fresh, in, true, nil, &out); return e })
	if err != nil {
		out = CertificateResult{}
	}
	return
}
func (s *Service) submit(ctx context.Context, in EnrollmentSubmission, issue bool, view *EnrollmentRequestView, result *CertificateResult) (out EnrollmentRequestView, err error) {
	if !idPattern.MatchString(in.NodeID) || !tokenPattern.MatchString(in.EnrollmentToken) {
		return out, ErrDenied
	}
	csr, pk, e := parseCSR(in.CSRPEM)
	if e != nil {
		return out, e
	}
	csrHash := hash(csr.Raw)
	tokenHash := hash([]byte(in.EnrollmentToken))
	var semantic error
	err = s.current.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		// Issuance was rate-limited before any live approver refresh outside
		// the writer. CSR submission retains its original durable limits.
		if !issue {
			if e := limit(ctx, tx, "enrollment_global", h.RecordedAt, 120); e != nil {
				semantic = e
				return nil
			}
			if e := limit(ctx, tx, "enrollment_"+tokenHash, h.RecordedAt, 15); e != nil {
				semantic = e
				return nil
			}
		}
		r, e := enrollmentBy(ctx, tx, "token_hash", tokenHash)
		if e == storage.ErrNotFound {
			semantic = ErrDenied
			return nil
		}
		if e != nil {
			return e
		}
		if r.NodeID != in.NodeID || r.Epoch != int64(h.Epoch) || r.State == "revoked" {
			semantic = ErrDenied
			return nil
		}
		if e = notRevoked(ctx, tx, r.NodeID); e != nil {
			semantic = e
			return nil
		}
		// Once a certificate exists, an exact replay returns only the public cert;
		// it does not mint a serial or extend its original validity.
		if r.State == "issued_certificate" {
			if r.RequestDigest != csrHash {
				semantic = ErrConflict
				return nil
			}
			var cert CertificateResult
			if decodeJSON(r.CertificateJSON, &cert) != nil {
				return ErrUnavailable
			}
			if result != nil {
				*result = cert
			}
			out = r.view()
			if view != nil {
				*view = out
			}
			return nil
		}
		if !h.RecordedAt.Before(r.ExpiresAt) {
			semantic = ErrDenied
			return nil
		}
		if r.RequestDigest != "" && r.RequestDigest != csrHash {
			semantic = ErrConflict
			return nil
		}
		n, e := loadNode(ctx, tx, r.NodeID)
		if e != nil {
			return e
		}
		reservation := Reservation{EnrollmentID: r.ID, TokenHash: tokenHash, Node: n, Role: "agent", Epoch: h.Epoch, CSRPEM: in.CSRPEM, RequestDigest: csrHash, ExpiresAt: r.ExpiresAt}
		if r.ReservationJSON != "" {
			if decodeJSON(r.ReservationJSON, &reservation) != nil {
				return ErrUnavailable
			}
		}
		if !issue {
			if e = s.issuer.Reserve(ctx, reservation); e != nil {
				return e
			}
			if r.State == "issued" {
				raw, e := json.Marshal(reservation)
				if e != nil {
					return e
				}
				affected, e := tx.Exec(ctx, `UPDATE node_enrollments SET state='csr_pending',request_digest=?,public_key_digest=?,csr_pem=?,reservation_json=? WHERE id=? AND state='issued'`, csrHash, pk, in.CSRPEM, string(raw), r.ID)
				if e != nil {
					return e
				}
				if affected != 1 {
					return ErrConflict
				}
				r.State = "csr_pending"
				r.RequestDigest = csrHash
				r.PublicKeyDigest = pk
				if e = securitystate.Audit(ctx, tx, "node.enrollment.requested", "agent", map[string]string{"nodeId": r.NodeID, "enrollmentId": r.ID, "publicKeyDigest": pk}); e != nil {
					return e
				}
			}
			out = r.view()
			if view != nil {
				*view = out
			}
			return nil
		}
		if r.State != "approved" || r.ApprovalDigest == "" {
			semantic = ErrDenied
			return nil
		}
		_, deadline, e := s.approvalAccess(ctx, tx, h, r)
		if e != nil {
			semantic = e
			return nil
		}
		cert, e := s.issuer.Issue(ctx, IssueRequest{AuthorizationHead: authorizationHead(h), Reservation: reservation, ApprovalDigest: r.ApprovalDigest, AuthorizationExpiresAt: &deadline})
		if e != nil {
			return e
		}
		if _, _, e = s.approvalAccess(ctx, tx, h, r); e != nil {
			return e
		}
		if cert.NodeID != r.NodeID || cert.Role != "agent" || cert.PublicKeyDigest != pk {
			return ErrUnavailable
		}
		raw, e := json.Marshal(cert)
		if e != nil {
			return e
		}
		affected, e := tx.Exec(ctx, `UPDATE node_enrollments SET state='issued_certificate',certificate_json=? WHERE id=? AND state='approved'`, string(raw), r.ID)
		if e != nil {
			return e
		}
		if affected != 1 {
			return ErrConflict
		}
		if e = securitystate.Audit(ctx, tx, "node.certificate.issued", "agent", map[string]string{"nodeId": r.NodeID, "enrollmentId": r.ID, "serial": cert.Serial}); e != nil {
			return e
		}
		if result != nil {
			*result = cert
		}
		return nil
	})
	if err == nil {
		err = semantic
	}
	return
}
func limit(ctx context.Context, tx storage.IdentityTx, bucket string, now time.Time, max int) error {
	if _, e := tx.Exec(ctx, `DELETE FROM node_enrollment_limits WHERE window_start<?`, now.Add(-time.Hour)); e != nil {
		return e
	}
	var start time.Time
	var count int
	e := securitystate.One(ctx, tx, `SELECT window_start,attempts FROM node_enrollment_limits WHERE bucket=?`, []any{bucket}, func(r storage.IdentityRows) error { return r.Scan(&start, &count) })
	if e == storage.ErrNotFound {
		_, e = tx.Exec(ctx, `INSERT INTO node_enrollment_limits(bucket,window_start,attempts) VALUES(?,?,1)`, bucket, now)
		return e
	}
	if e != nil {
		return e
	}
	if now.Before(start) {
		return ErrUnavailable
	}
	if now.Sub(start) >= time.Minute {
		_, e = tx.Exec(ctx, `UPDATE node_enrollment_limits SET window_start=?,attempts=1 WHERE bucket=?`, now, bucket)
		return e
	}
	if count >= max {
		return ErrLimited
	}
	_, e = tx.Exec(ctx, `UPDATE node_enrollment_limits SET attempts=attempts+1 WHERE bucket=?`, bucket)
	return e
}
func (s *Service) GetEnrollment(ctx context.Context, a Actor, nodeID, id string) (out EnrollmentRequestView, err error) {
	err = s.withAccess(ctx, a, "nodes.read", false, func(tx storage.IdentityTx, h securityjournal.Head, access *inventory.NodeAccess) error {
		if err := requireNode(ctx, tx, access, nodeID); err != nil {
			return err
		}
		r, e := enrollmentBy(ctx, tx, "id", id)
		if e != nil {
			return e
		}
		if r.NodeID != nodeID {
			return storage.ErrNotFound
		}
		out = r.view()
		return nil
	})
	if err != nil {
		out = EnrollmentRequestView{}
	}
	return
}
func (s *Service) ApproveEnrollment(ctx context.Context, a Actor, nodeID, id, key string, in ApprovalRequest) (out EnrollmentRequestView, err error) {
	if !digestPattern.MatchString(in.ExpectedPublicKeyDigest) || !digestPattern.MatchString(in.RequestDigest) || !idPattern.MatchString(key) {
		return out, ErrInvalid
	}
	fp := digest(struct {
		NodeID   string
		ID       string
		Approval ApprovalRequest
	}{nodeID, id, in})
	err = s.withAccess(ctx, a, "nodes.enroll", true, func(tx storage.IdentityTx, h securityjournal.Head, access *inventory.NodeAccess) error {
		if err := requireNode(ctx, tx, access, nodeID); err != nil {
			return err
		}
		actor := access.ID
		ok, e := replay(ctx, tx, actor, "enrollment_approve", key, fp, h.Epoch, &out)
		if e != nil || ok {
			return e
		}
		r, e := enrollmentBy(ctx, tx, "id", id)
		if e != nil {
			return e
		}
		if r.NodeID != nodeID {
			return storage.ErrNotFound
		}
		if r.Epoch != int64(h.Epoch) || !h.RecordedAt.Before(r.ExpiresAt) || r.State != "csr_pending" || r.PublicKeyDigest != in.ExpectedPublicKeyDigest || r.RequestDigest != in.RequestDigest {
			return ErrDenied
		}
		if e = notRevoked(ctx, tx, nodeID); e != nil {
			return e
		}
		var sv, pv uint64
		if e = securitystate.One(ctx, tx, `SELECT security_version,password_version FROM users WHERE id=?`, []any{actor}, func(rows storage.IdentityRows) error { return rows.Scan(&sv, &pv) }); e != nil {
			return e
		}
		directory, e := identity.DirectorySubjectFingerprint(ctx, tx, h, actor)
		if e != nil {
			return e
		}
		evidence := enrollmentApprovalEvidence{Version: 1, Actor: actor, EnrollmentID: id, NodeID: nodeID, TokenHash: a.TokenHash, Origin: a.Origin, Epoch: h.Epoch, ExpiresAt: access.AuthorizationDeadline(r.ExpiresAt), AccessFingerprint: access.Fingerprint(), DirectoryFingerprint: directory}
		approval := enrollmentApprovalDigest(actor, id, in.ExpectedPublicKeyDigest, in.RequestDigest, sv, pv, h.Epoch, digest(evidence))
		if e = remember(ctx, tx, actor, "enrollment_approval_evidence", id, approval, h.Epoch, evidence); e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `UPDATE node_enrollments SET state='approved',approval_digest=?,approved_by=?,approval_security_version=?,approval_password_version=? WHERE id=? AND state='csr_pending'`, approval, actor, int64(sv), int64(pv), id)
		if e != nil {
			return e
		}
		r.State = "approved"
		out = r.view()
		if e = remember(ctx, tx, actor, "enrollment_approve", key, fp, h.Epoch, out); e != nil {
			return e
		}
		return securitystate.Audit(ctx, tx, "node.enrollment.approved", actor, map[string]string{"nodeId": nodeID, "enrollmentId": id, "publicKeyDigest": in.ExpectedPublicKeyDigest})
	})
	if err != nil {
		out = EnrollmentRequestView{}
	}
	return
}
func (s *Service) RevokeEnrollment(ctx context.Context, a Actor, nodeID, id, key string) (out EnrollmentRequestView, err error) {
	if !idPattern.MatchString(key) {
		return out, ErrInvalid
	}
	fp := digest([]string{nodeID, id})
	err = s.withAccess(ctx, a, "nodes.revoke", true, func(tx storage.IdentityTx, h securityjournal.Head, access *inventory.NodeAccess) error {
		if err := requireNode(ctx, tx, access, nodeID); err != nil {
			return err
		}
		actor := access.ID
		done, e := replay(ctx, tx, actor, "enrollment_revoke", key, fp, h.Epoch, &out)
		if e != nil || done {
			return e
		}
		r, e := enrollmentBy(ctx, tx, "id", id)
		if e != nil {
			return e
		}
		if r.NodeID != nodeID {
			return storage.ErrNotFound
		}
		if r.State == "issued_certificate" {
			return ErrConflict
		}
		if e = s.issuer.Cancel(ctx, id, h.Epoch); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE node_enrollments SET state='revoked' WHERE id=?`, id); e != nil {
			return e
		}
		r.State = "revoked"
		out = r.view()
		if e = remember(ctx, tx, actor, "enrollment_revoke", key, fp, h.Epoch, out); e != nil {
			return e
		}
		return securitystate.Audit(ctx, tx, "node.enrollment.revoked", actor, map[string]string{"nodeId": nodeID, "enrollmentId": id})
	})
	if err != nil {
		out = EnrollmentRequestView{}
	}
	return
}
func (s *Service) Renew(ctx context.Context, peer *tls.ConnectionState, in RenewalRequest) (out CertificateResult, err error) {
	if _, _, e := parseCSR(in.CSRPEM); e != nil {
		return out, e
	}
	var request RenewRequest
	err = s.inventory.WithIdentity(ctx, peer, func(tx storage.IdentityTx, h securityjournal.Head, r inventory.Registration) error {
		request = RenewRequest{NodeID: r.NodeID, CertificateDigest: r.CertificateDigest, CSRPEM: in.CSRPEM, Epoch: h.Epoch}
		return nil
	})
	if err != nil {
		return
	}
	out, err = s.issuer.Renew(ctx, request)
	if err != nil {
		return
	}
	err = s.current.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		if h.Epoch != request.Epoch {
			return ErrDenied
		}
		if e := notRevoked(ctx, tx, request.NodeID); e != nil {
			return e
		}
		registry, e := s.issuer.Registry(ctx, h)
		if e != nil {
			return e
		}
		chain, e := parseCertificates([]byte(out.CertificateChainPEM))
		if e != nil {
			return ErrUnavailable
		}
		certDigest := hash(chain[0].Raw)
		found := false
		for _, r := range registry.Nodes {
			if r.NodeID == request.NodeID && r.CertificateDigest == certDigest && r.AcceptUntil == nil && r.IssuanceEpoch == h.Epoch {
				found = true
				break
			}
		}
		if !found {
			return ErrDenied
		}
		return securitystate.Audit(ctx, tx, "node.certificate.renewed", "agent", map[string]string{"nodeId": request.NodeID, "serial": out.Serial})
	})
	return
}

func legacyEnrollmentApproval(actor, id, key, request string, sv, pv uint64, epoch securityjournal.UInt63) string {
	return digest(struct {
		Actor, ID, Fingerprint, Request  string
		SecurityVersion, PasswordVersion securityjournal.UInt63
		Epoch                            securityjournal.UInt63
	}{actor, id, key, request, securityjournal.UInt63(sv), securityjournal.UInt63(pv), epoch})
}
func enrollmentApprovalDigest(actor, id, key, request string, sv, pv uint64, epoch securityjournal.UInt63, witness string) string {
	return digest([]any{"node-enrollment-approval-v2", legacyEnrollmentApproval(actor, id, key, request, sv, pv, epoch), witness})
}
