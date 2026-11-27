package nodeidentity

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/securityjournal"
	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

type IssuerConfig struct {
	LedgerFile                 string `json:"ledgerFile"`
	IssuingCertificateFile     string `json:"issuingCertificateFile"`
	IssuingKeyFile             string `json:"issuingKeyFile"`
	CertificateLifetimeSeconds int    `json:"certificateLifetimeSeconds"`
	RenewalOverlapSeconds      int    `json:"renewalOverlapSeconds"`
}

// LocalIssuer belongs exclusively to a separate issuer process/account. Its
// private SQLite ledger and issuing key must never enter CP backups/restores.
type LocalIssuer struct {
	mu                sync.Mutex
	db                *sql.DB
	authority         securityjournal.Authority
	cert              *x509.Certificate
	chain             []*x509.Certificate
	chainPEM          string
	key               crypto.Signer
	lifetime, overlap time.Duration
}

func protectedFile(name string, private bool) (*os.File, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return nil, ErrUnavailable
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrUnavailable
	}
	parts := strings.Split(strings.TrimPrefix(name, "/"), "/")
	mustPrivate := false
	for i, p := range parts {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) {
			unix.Close(fd)
			return nil, ErrUnavailable
		}
		if st.Mode&0022 != 0 {
			if i == 1 && parts[0] == "tmp" && st.Uid == 0 && st.Mode&unix.S_ISVTX != 0 {
				mustPrivate = true
			} else {
				unix.Close(fd)
				return nil, ErrUnavailable
			}
		}
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, e := unix.Openat(fd, p, flags, 0)
		unix.Close(fd)
		if e != nil {
			return nil, ErrUnavailable
		}
		fd = next
		if mustPrivate {
			var child unix.Stat_t
			if unix.Fstat(fd, &child) != nil || child.Mode&unix.S_IFMT != unix.S_IFDIR || child.Uid != uint32(os.Geteuid()) || child.Mode&0077 != 0 {
				unix.Close(fd)
				return nil, ErrUnavailable
			}
			mustPrivate = false
		}
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || st.Mode&0022 != 0 || private && (st.Mode&0077 != 0 || st.Uid != uint32(os.Geteuid())) {
		unix.Close(fd)
		return nil, ErrUnavailable
	}
	return os.NewFile(uintptr(fd), name), nil
}
func readProtected(name string, private bool, max int64) ([]byte, error) {
	f, e := protectedFile(name, private)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var b bytes.Buffer
	if _, e = b.ReadFrom(io.LimitReader(f, max+1)); e != nil || int64(b.Len()) > max {
		return nil, ErrUnavailable
	}
	return b.Bytes(), nil
}
func OpenIssuer(ctx context.Context, cfg IssuerConfig, authority securityjournal.Authority) (*LocalIssuer, error) {
	if authority == nil || cfg.CertificateLifetimeSeconds < 3600 || cfg.CertificateLifetimeSeconds > 86400 || cfg.RenewalOverlapSeconds < 0 || cfg.RenewalOverlapSeconds > 900 || !filepath.IsAbs(cfg.LedgerFile) || filepath.Clean(cfg.LedgerFile) != cfg.LedgerFile {
		return nil, ErrInvalid
	}
	raw, e := readProtected(cfg.IssuingCertificateFile, false, 131072)
	if e != nil {
		return nil, e
	}
	var chain []*x509.Certificate
	rest := raw
	for len(bytes.TrimSpace(rest)) > 0 {
		b, r := pem.Decode(rest)
		if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) > 0 {
			return nil, ErrInvalid
		}
		c, e := x509.ParseCertificate(b.Bytes)
		if e != nil {
			return nil, ErrInvalid
		}
		chain = append(chain, c)
		rest = r
	}
	if len(chain) < 2 || len(chain) > 4 {
		return nil, ErrInvalid
	}
	cert := chain[0]
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 || cert.CheckSignatureFrom(cert) == nil || !cert.MaxPathLenZero {
		return nil, ErrInvalid
	}
	now := time.Now().UTC()
	roots := x509.NewCertPool()
	roots.AddCert(chain[len(chain)-1])
	inter := x509.NewCertPool()
	for _, c := range chain[1 : len(chain)-1] {
		inter.AddCert(c)
	}
	if _, e = cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); e != nil {
		return nil, ErrInvalid
	}
	raw, e = readProtected(cfg.IssuingKeyFile, true, 32768)
	if e != nil {
		return nil, e
	}
	b, r := pem.Decode(raw)
	if b == nil || b.Type != "PRIVATE KEY" || len(bytes.TrimSpace(r)) > 0 || len(b.Headers) > 0 {
		return nil, ErrInvalid
	}
	keyAny, e := x509.ParsePKCS8PrivateKey(b.Bytes)
	if e != nil {
		return nil, ErrInvalid
	}
	key, ok := keyAny.(crypto.Signer)
	if !ok {
		return nil, ErrInvalid
	}
	pub, e := x509.MarshalPKIXPublicKey(key.Public())
	if e != nil || !bytes.Equal(pub, cert.RawSubjectPublicKeyInfo) {
		return nil, ErrInvalid
	}
	// A newly created file is 0600 before SQLite sees it. Opening the parent via
	// a protected sentinel rejects writable ancestors/symlinks before creation.
	if _, e = os.Lstat(cfg.LedgerFile); errors.Is(e, os.ErrNotExist) {
		parent := filepath.Dir(cfg.LedgerFile)
		info, err := os.Stat(parent)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			return nil, ErrUnavailable
		}
		f, err := os.OpenFile(cfg.LedgerFile, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			return nil, ErrUnavailable
		}
		f.Close()
	}
	f, e := protectedFile(cfg.LedgerFile, true)
	if e != nil {
		return nil, e
	}
	f.Close()
	db, e := sql.Open("sqlite", cfg.LedgerFile+"?_pragma=busy_timeout(5000)&_pragma=synchronous(FULL)&_pragma=journal_mode(DELETE)")
	if e != nil {
		return nil, ErrUnavailable
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	_, e = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS issuer_head(id INTEGER PRIMARY KEY CHECK(id=1),authority TEXT NOT NULL,epoch INTEGER NOT NULL,sequence INTEGER NOT NULL,digest TEXT NOT NULL,last_time INTEGER NOT NULL);CREATE TABLE IF NOT EXISTS issuer_revokes(node_id TEXT PRIMARY KEY);CREATE TABLE IF NOT EXISTS issuer_enrollments(id TEXT PRIMARY KEY,digest TEXT NOT NULL,reservation TEXT NOT NULL,canceled INTEGER NOT NULL DEFAULT 0,approval_digest TEXT NOT NULL DEFAULT '',result TEXT NOT NULL DEFAULT '');CREATE TABLE IF NOT EXISTS issuer_cancellations(id TEXT PRIMARY KEY);CREATE TABLE IF NOT EXISTS issuer_certificates(digest TEXT PRIMARY KEY,node_id TEXT NOT NULL,registration TEXT NOT NULL,public_key_digest TEXT UNIQUE NOT NULL,serial TEXT UNIQUE NOT NULL,result TEXT NOT NULL,epoch INTEGER NOT NULL,expires_at INTEGER NOT NULL,accept_until INTEGER NOT NULL DEFAULT 0);CREATE TABLE IF NOT EXISTS issuer_renewals(parent_digest TEXT PRIMARY KEY,csr_digest TEXT NOT NULL,result TEXT NOT NULL);`)
	if e != nil {
		db.Close()
		return nil, ErrUnavailable
	}
	var chainBytes []byte
	for _, c := range chain {
		chainBytes = append(chainBytes, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return &LocalIssuer{db: db, authority: authority, cert: cert, chain: chain, chainPEM: string(chainBytes), key: key, lifetime: time.Duration(cfg.CertificateLifetimeSeconds) * time.Second, overlap: time.Duration(cfg.RenewalOverlapSeconds) * time.Second}, nil
}
func (s *LocalIssuer) Close() error { return s.db.Close() }

// transact first durably advances external journal floors even if the requested
// positive action fails. A transient error must never roll a deny floor back.
func (s *LocalIssuer) transact(ctx context.Context, epoch securityjournal.UInt63, fn func(*sql.Tx, securityjournal.Head) error) error {
	return s.transactDeadline(ctx, epoch, nil, fn)
}
func (s *LocalIssuer) transactDeadline(ctx context.Context, epoch securityjournal.UInt63, deadline *time.Time, fn func(*sql.Tx, securityjournal.Head) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, e := s.sync(ctx)
	if e != nil {
		return e
	}
	if epoch != 0 && epoch != h.Epoch {
		return ErrDenied
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return ErrUnavailable
	}
	defer tx.Rollback()
	if e = fn(tx, h); e != nil {
		return e
	}
	after, e := s.authority.Head(ctx)
	if e != nil || !h.SameState(after) || after.RecordedAt.IsZero() || after.RecordedAt.Before(h.RecordedAt) {
		return ErrUnavailable
	}
	if deadline != nil && !after.RecordedAt.Before(*deadline) {
		return ErrDenied
	}
	return tx.Commit()
}
func (s *LocalIssuer) sync(ctx context.Context) (securityjournal.Head, error) {
	h, e := s.authority.Head(ctx)
	if e != nil || h.AuthorityID == "" || h.Epoch == 0 || h.RecordedAt.IsZero() || h.RecordedAt.Before(h.ReleaseAfter) {
		return h, ErrUnavailable
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return h, ErrUnavailable
	}
	defer tx.Rollback()
	var authority, previous string
	var ep, seq, lastTime int64
	e = tx.QueryRowContext(ctx, `SELECT authority,epoch,sequence,digest,last_time FROM issuer_head WHERE id=1`).Scan(&authority, &ep, &seq, &previous, &lastTime)
	if e != nil && e != sql.ErrNoRows {
		return h, ErrUnavailable
	}
	if e == nil && (h.RecordedAt.UnixNano() < lastTime || authority != h.AuthorityID || ep > int64(h.Epoch) || seq > int64(h.Sequence) || seq == int64(h.Sequence) && previous != h.Digest) {
		return h, ErrDenied
	}
	for securityjournal.UInt63(seq) < h.Sequence {
		events, e := s.authority.Events(ctx, securityjournal.UInt63(seq), 1000)
		if e != nil || len(events) == 0 {
			return h, ErrUnavailable
		}
		for _, ev := range events {
			if ev.Sequence > h.Sequence {
				break
			}
			if ev.AuthorityID != h.AuthorityID || ev.Sequence != securityjournal.UInt63(seq+1) || ev.PreviousDigest != previous {
				return h, ErrDenied
			}
			seq = int64(ev.Sequence)
			previous = ev.Digest
			if ev.Request.Kind == "revoke_node" {
				node := ev.Request.Payload.NodeID
				if !idPattern.MatchString(node) {
					return h, ErrDenied
				}
				if _, e = tx.ExecContext(ctx, `INSERT INTO issuer_revokes(node_id) VALUES(?) ON CONFLICT DO NOTHING`, node); e != nil {
					return h, ErrUnavailable
				}
			}
		}
	}
	if seq != int64(h.Sequence) || previous != h.Digest {
		return h, ErrDenied
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO issuer_head(id,authority,epoch,sequence,digest,last_time) VALUES(1,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET epoch=excluded.epoch,sequence=excluded.sequence,digest=excluded.digest,last_time=excluded.last_time`, h.AuthorityID, int64(h.Epoch), seq, h.Digest, h.RecordedAt.UnixNano())
	if e != nil {
		return h, ErrUnavailable
	}
	if e = tx.Commit(); e != nil {
		return h, ErrUnavailable
	}
	return h, nil
}
func issuerActive(ctx context.Context, tx *sql.Tx, node string) error {
	var n int
	if e := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM issuer_revokes WHERE node_id=?`, node).Scan(&n); e != nil {
		return ErrUnavailable
	}
	if n > 0 {
		return ErrDenied
	}
	return nil
}
func (s *LocalIssuer) Reserve(ctx context.Context, r Reservation) error {
	if !idPattern.MatchString(r.EnrollmentID) || !digestPattern.MatchString(r.TokenHash) || r.Role != "agent" || r.Epoch == 0 {
		return ErrInvalid
	}
	n, e := validateNode(CreateNodeRequest{ID: r.Node.ID, SiteID: r.Node.SiteID, Name: r.Node.Name, Labels: r.Node.Labels, GroupIDs: r.Node.GroupIDs})
	if e != nil || n.ID == "" {
		return ErrInvalid
	}
	csr, _, e := parseCSR(r.CSRPEM)
	if e != nil || hash(csr.Raw) != r.RequestDigest {
		return ErrInvalid
	}
	raw, e := json.Marshal(r)
	if e != nil {
		return ErrInvalid
	}
	fp := hash(raw)
	return s.transact(ctx, r.Epoch, func(tx *sql.Tx, h securityjournal.Head) error {
		if !h.RecordedAt.Before(r.ExpiresAt) || r.ExpiresAt.Sub(h.RecordedAt) > 15*time.Minute {
			return ErrDenied
		}
		if e := issuerActive(ctx, tx, r.Node.ID); e != nil {
			return e
		}
		var canceled int
		if e := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM issuer_cancellations WHERE id=?`, r.EnrollmentID).Scan(&canceled); e != nil {
			return ErrUnavailable
		}
		if canceled > 0 {
			return ErrDenied
		}
		var old string
		e := tx.QueryRowContext(ctx, `SELECT digest FROM issuer_enrollments WHERE id=?`, r.EnrollmentID).Scan(&old)
		if e == nil {
			if old != fp {
				return ErrConflict
			}
			return nil
		}
		if e != sql.ErrNoRows {
			return ErrUnavailable
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO issuer_enrollments(id,digest,reservation) VALUES(?,?,?)`, r.EnrollmentID, fp, string(raw))
		return e
	})
}
func (s *LocalIssuer) Issue(ctx context.Context, in IssueRequest) (out CertificateResult, err error) {
	r := in.Reservation
	deadline := r.ExpiresAt
	if in.AuthorizationExpiresAt != nil {
		if in.AuthorizationExpiresAt.IsZero() || in.AuthorizationExpiresAt.After(r.ExpiresAt) {
			return out, ErrInvalid
		}
		deadline = *in.AuthorizationExpiresAt
	}
	if !digestPattern.MatchString(in.ApprovalDigest) || !in.AuthorizationHead.valid() {
		return out, ErrInvalid
	}
	raw, _ := json.Marshal(r)
	fp := hash(raw)
	err = s.transactDeadline(ctx, r.Epoch, &deadline, func(tx *sql.Tx, h securityjournal.Head) error {
		// Check the CP authorization state against the issuer's own fresh signed
		// journal head before generating a certificate or recording any admission.
		// transact checks the same head again before committing the external ledger.
		if !in.AuthorizationHead.matches(h) || !h.RecordedAt.Before(deadline) {
			return ErrDenied
		}
		if e := issuerActive(ctx, tx, r.Node.ID); e != nil {
			return e
		}
		var old, result, approval string
		var canceled int
		e := tx.QueryRowContext(ctx, `SELECT digest,canceled,result,approval_digest FROM issuer_enrollments WHERE id=?`, r.EnrollmentID).Scan(&old, &canceled, &result, &approval)
		if e != nil || canceled != 0 || old != fp {
			return ErrDenied
		}
		if result != "" {
			if approval != in.ApprovalDigest {
				return ErrConflict
			}
			return decodeJSON(result, &out)
		}
		if !h.RecordedAt.Before(r.ExpiresAt) {
			return ErrDenied
		}
		var active int
		if e = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM issuer_certificates WHERE node_id=? AND epoch=? AND accept_until=0 AND expires_at>?`, r.Node.ID, int64(h.Epoch), h.RecordedAt.UnixNano()).Scan(&active); e != nil {
			return ErrUnavailable
		}
		if active > 0 {
			return ErrConflict
		}
		out, e = s.issueCertificate(ctx, tx, h, r.Node, r.CSRPEM)
		if e != nil {
			return e
		}
		resultBytes, _ := json.Marshal(out)
		_, e = tx.ExecContext(ctx, `UPDATE issuer_enrollments SET result=?,approval_digest=? WHERE id=?`, string(resultBytes), in.ApprovalDigest, r.EnrollmentID)
		return e
	})
	if err != nil {
		out = CertificateResult{}
	}
	return
}
func (s *LocalIssuer) Cancel(ctx context.Context, id string, epoch securityjournal.UInt63) error {
	if !idPattern.MatchString(id) {
		return ErrInvalid
	}
	return s.transact(ctx, epoch, func(tx *sql.Tx, h securityjournal.Head) error {
		var result string
		e := tx.QueryRowContext(ctx, `SELECT result FROM issuer_enrollments WHERE id=?`, id).Scan(&result)
		if e != nil && e != sql.ErrNoRows {
			return ErrUnavailable
		}
		if result != "" {
			return ErrConflict
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO issuer_cancellations(id) VALUES(?) ON CONFLICT DO NOTHING`, id); e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, `UPDATE issuer_enrollments SET canceled=1 WHERE id=?`, id)
		return e
	})
}
func (s *LocalIssuer) issueCertificate(ctx context.Context, tx *sql.Tx, h securityjournal.Head, n Node, csrPEM string) (CertificateResult, error) {
	var out CertificateResult
	csr, pk, e := parseCSR(csrPEM)
	if e != nil {
		return out, e
	}
	var existing int
	if e = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM issuer_certificates WHERE public_key_digest=?`, pk).Scan(&existing); e != nil {
		return out, ErrUnavailable
	}
	if existing > 0 {
		return out, ErrConflict
	}
	now := h.RecordedAt.UTC().Truncate(time.Second)
	end := now.Add(s.lifetime)
	for _, c := range s.chain {
		if now.Before(c.NotBefore) || !end.Before(c.NotAfter) {
			return out, ErrUnavailable
		}
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if e != nil || serial.Sign() <= 0 {
		return out, ErrUnavailable
	}
	uri, _ := url.Parse("spiffe://agp/agent/" + n.ID)
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{}, NotBefore: now, NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, s.cert, csr.PublicKey, s.key)
	if e != nil {
		return out, ErrUnavailable
	}
	leaf, e := x509.ParseCertificate(der)
	if e != nil {
		return out, ErrUnavailable
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	out = CertificateResult{NodeID: n.ID, Role: "agent", CertificatePEM: certPEM, CertificateChainPEM: certPEM + s.chainPEM, Serial: serial.Text(16), ExpiresAt: end, PublicKeyDigest: pk}
	reg := inventory.Registration{NodeID: n.ID, SiteID: n.SiteID, Name: n.Name, Labels: n.Labels, GroupIDs: n.GroupIDs, CertificatePEM: certPEM, CertificateDigest: hash(der), PublicKeyDigest: pk, IssuerDigest: hash(s.cert.Raw), Serial: leaf.SerialNumber.Text(16), IssuanceEpoch: h.Epoch}
	regBytes, _ := json.Marshal(reg)
	resultBytes, _ := json.Marshal(out)
	_, e = tx.ExecContext(ctx, `INSERT INTO issuer_certificates(digest,node_id,registration,public_key_digest,serial,result,epoch,expires_at) VALUES(?,?,?,?,?,?,?,?)`, reg.CertificateDigest, n.ID, string(regBytes), pk, out.Serial, string(resultBytes), int64(h.Epoch), end.UnixNano())
	return out, e
}
func (s *LocalIssuer) Renew(ctx context.Context, in RenewRequest) (out CertificateResult, err error) {
	csr, pk, e := parseCSR(in.CSRPEM)
	if e != nil || !idPattern.MatchString(in.NodeID) || !digestPattern.MatchString(in.CertificateDigest) {
		return out, ErrInvalid
	}
	fp := hash(csr.Raw)
	err = s.transact(ctx, in.Epoch, func(tx *sql.Tx, h securityjournal.Head) error {
		if e := issuerActive(ctx, tx, in.NodeID); e != nil {
			return e
		}
		var raw string
		var epoch, expiry, accept int64
		e := tx.QueryRowContext(ctx, `SELECT registration,epoch,expires_at,accept_until FROM issuer_certificates WHERE digest=? AND node_id=?`, in.CertificateDigest, in.NodeID).Scan(&raw, &epoch, &expiry, &accept)
		if e != nil || epoch != int64(h.Epoch) || h.RecordedAt.UnixNano() >= expiry || accept > 0 && h.RecordedAt.UnixNano() >= accept {
			return ErrDenied
		}
		var reg inventory.Registration
		if decodeJSON(raw, &reg) != nil {
			return ErrUnavailable
		}
		var previous, result string
		e = tx.QueryRowContext(ctx, `SELECT csr_digest,result FROM issuer_renewals WHERE parent_digest=?`, in.CertificateDigest).Scan(&previous, &result)
		if e == nil {
			if previous != fp {
				return ErrConflict
			}
			return decodeJSON(result, &out)
		}
		if e != sql.ErrNoRows {
			return ErrUnavailable
		}
		if accept != 0 || pk == reg.PublicKeyDigest {
			return ErrDenied
		}
		n := Node{ID: reg.NodeID, SiteID: reg.SiteID, Name: reg.Name, Labels: reg.Labels, GroupIDs: reg.GroupIDs}
		out, e = s.issueCertificate(ctx, tx, h, n, in.CSRPEM)
		if e != nil {
			return e
		}
		until := h.RecordedAt.Add(s.overlap)
		if until.UnixNano() > expiry {
			until = time.Unix(0, expiry).UTC()
		}
		_, e = tx.ExecContext(ctx, `UPDATE issuer_certificates SET accept_until=? WHERE digest=?`, until.UnixNano(), in.CertificateDigest)
		if e != nil {
			return e
		}
		b, _ := json.Marshal(out)
		_, e = tx.ExecContext(ctx, `INSERT INTO issuer_renewals(parent_digest,csr_digest,result) VALUES(?,?,?)`, in.CertificateDigest, fp, string(b))
		return e
	})
	return
}
func (s *LocalIssuer) Registry(ctx context.Context, expected securityjournal.Head) (out inventory.Registry, err error) {
	out = inventory.Registry{APIVersion: "agp.agent-registry/v1alpha1", AuthorityID: expected.AuthorityID, Nodes: []inventory.Registration{}}
	err = s.transact(ctx, expected.Epoch, func(tx *sql.Tx, h securityjournal.Head) error {
		if h.AuthorityID != expected.AuthorityID {
			return ErrDenied
		}
		rows, e := tx.QueryContext(ctx, `SELECT c.registration,c.accept_until,CASE WHEN r.node_id IS NULL THEN 0 ELSE 1 END FROM issuer_certificates c LEFT JOIN issuer_revokes r ON r.node_id=c.node_id WHERE c.rowid IN (SELECT MAX(rowid) FROM issuer_certificates GROUP BY node_id) OR (c.epoch=? AND c.expires_at>? AND c.accept_until>?) ORDER BY c.node_id,c.accept_until`, int64(h.Epoch), h.RecordedAt.UnixNano(), h.RecordedAt.UnixNano())
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			if len(out.Nodes) >= 20000 {
				return ErrUnavailable
			}
			var raw string
			var until int64
			var revoked int
			var r inventory.Registration
			if rows.Scan(&raw, &until, &revoked) != nil || decodeJSON(raw, &r) != nil {
				return ErrUnavailable
			}
			r.Revoked = revoked != 0
			if until > 0 {
				t := time.Unix(0, until).UTC()
				r.AcceptUntil = &t
			}
			out.Nodes = append(out.Nodes, r)
		}
		return rows.Err()
	})
	return
}
