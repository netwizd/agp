package nodeidentity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/inventory"
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var labelPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,62}$`)
var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func digest(v any) string {
	d, e := inventory.Digest(v)
	if e != nil {
		return ""
	}
	return d
}
func hash(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }
func decode(r io.Reader, v any, max int64) error {
	raw, e := io.ReadAll(io.LimitReader(r, max+1))
	if e != nil || int64(len(raw)) > max || !utf8.Valid(raw) || configmodel.ValidateJSON(raw) != nil {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func parseCSR(s string) (*x509.CertificateRequest, string, error) {
	if len(s) > 32768 {
		return nil, "", ErrInvalid
	}
	b, rest := pem.Decode([]byte(s))
	if b == nil || b.Type != "CERTIFICATE REQUEST" || len(b.Headers) > 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, "", ErrInvalid
	}
	csr, e := x509.ParseCertificateRequest(b.Bytes)
	if e != nil || csr.CheckSignature() != nil {
		return nil, "", ErrInvalid
	}
	// No identity claims from the applicant: only the public key is used. Reject
	// even syntactically valid SAN/extension requests rather than silently accept.
	if len(csr.DNSNames) > 0 || len(csr.IPAddresses) > 0 || len(csr.URIs) > 0 || len(csr.EmailAddresses) > 0 || len(csr.Extensions) > 0 || len(csr.Subject.Names) > 0 {
		return nil, "", ErrInvalid
	}
	switch k := csr.PublicKey.(type) {
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return nil, "", ErrInvalid
		}
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return nil, "", ErrInvalid
		}
	case *rsa.PublicKey:
		if k.N.BitLen() < 3072 || k.N.BitLen() > 4096 || k.E != 65537 {
			return nil, "", ErrInvalid
		}
	default:
		return nil, "", ErrInvalid
	}
	return csr, hash(csr.RawSubjectPublicKeyInfo), nil
}
func validateNode(in CreateNodeRequest) (Node, error) {
	if !idPattern.MatchString(in.ID) || !idPattern.MatchString(in.SiteID) || len(in.Name) < 1 || len(in.Name) > 128 || !utf8.ValidString(in.Name) || strings.ContainsAny(in.Name, "\x00\r\n") || len(in.Labels) > 32 || len(in.GroupIDs) > 100 {
		return Node{}, ErrInvalid
	}
	n := Node{ID: in.ID, SiteID: in.SiteID, Name: in.Name, Labels: map[string]string{}, GroupIDs: []string{}}
	for k, v := range in.Labels {
		if !labelPattern.MatchString(k) || len(v) > 128 || !utf8.ValidString(v) || strings.ContainsAny(v, "\x00\r\n") {
			return Node{}, ErrInvalid
		}
		n.Labels[k] = v
	}
	seen := map[string]bool{}
	for _, g := range in.GroupIDs {
		if !idPattern.MatchString(g) || seen[g] {
			return Node{}, ErrInvalid
		}
		seen[g] = true
		n.GroupIDs = append(n.GroupIDs, g)
	}
	return n, nil
}
func decodeString(s string, v any) error { return decode(strings.NewReader(s), v, 1<<20) }
