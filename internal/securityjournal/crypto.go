package securityjournal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"time"
)

var objectID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func randomID(prefix string) (string, error) {
	var b [32]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// The journal DTOs deliberately use only ASCII strings (including UInt63) and
// booleans/null. Sorting the decoded object keys with HTML escaping disabled
// produces RFC8785 canonical bytes for this restricted, typed JSON vocabulary.
// Reject numbers/Unicode here rather than silently introducing an approximate
// general-purpose JCS implementation for future fields.
func hash(v any) (string, error) {
	raw, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	var value any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if e = d.Decode(&value); e != nil {
		return "", e
	}
	if e = canonicalVocabulary(value); e != nil {
		return "", e
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if e = encoder.Encode(value); e != nil {
		return "", e
	}
	b := bytes.TrimSuffix(output.Bytes(), []byte("\n"))
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
func canonicalVocabulary(value any) error {
	switch v := value.(type) {
	case nil, bool:
		return nil
	case string:
		for _, r := range v {
			if r > 127 {
				return bad("non-ASCII canonical journal field")
			}
		}
		return nil
	case []any:
		for _, item := range v {
			if e := canonicalVocabulary(item); e != nil {
				return e
			}
		}
		return nil
	case map[string]any:
		for key, item := range v {
			if e := canonicalVocabulary(key); e != nil {
				return e
			}
			if e := canonicalVocabulary(item); e != nil {
				return e
			}
		}
		return nil
	default:
		return bad("non-string numeric canonical journal field")
	}
}
func RequestDigest(r AppendRequest) (string, error)  { return hash(r) }
func ApprovalDigest(r AppendRequest) (string, error) { r.ApprovalSignature = ""; return hash(r) }
func SignApproval(r *AppendRequest, key ed25519.PrivateKey) error {
	d, e := ApprovalDigest(*r)
	if e != nil {
		return e
	}
	r.ApprovalSignature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte("AGP-JOURNAL-APPROVAL-v1\n"+d)))
	return nil
}
func eventDigest(e Event) (string, error) { e.Digest = ""; e.Signature = ""; return hash(e) }
func signEvent(e *Event, key ed25519.PrivateKey) error {
	d, err := eventDigest(*e)
	if err != nil {
		return err
	}
	e.Digest = d
	e.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte("AGP-JOURNAL-EVENT-v1\n"+d)))
	return nil
}
func signHead(h *Head, key ed25519.PrivateKey) error {
	h.Signature = ""
	d, e := hash(*h)
	if e != nil {
		return e
	}
	h.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte("AGP-JOURNAL-HEAD-v1\n"+d)))
	return nil
}
func VerifyEvent(e Event, authorityID, keyID string, key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize || e.AuthorityID != authorityID || e.KeyID != keyID || !objectID.MatchString(e.ID) || e.Epoch == 0 || e.Sequence == 0 || e.Epoch > MaxUInt63 || e.Sequence > MaxUInt63 || e.RecordedAt.IsZero() {
		return bad("event metadata")
	}
	if err := validateRequest(e.Request); err != nil {
		return err
	}
	rd, err := RequestDigest(e.Request)
	if err != nil || rd != e.RequestDigest {
		return bad("request digest")
	}
	d, err := eventDigest(e)
	if err != nil || d != e.Digest {
		return bad("event digest")
	}
	sig, err := base64.RawURLEncoding.DecodeString(e.Signature)
	if err != nil || !ed25519.Verify(key, []byte("AGP-JOURNAL-EVENT-v1\n"+d), sig) {
		return bad("event signature")
	}
	return nil
}
func VerifyHead(h Head, challenge, authorityID, keyID string, key ed25519.PublicKey, now time.Time) error {
	if len(key) != ed25519.PublicKeySize || h.AuthorityID != authorityID || h.KeyID != keyID || h.Challenge != challenge || h.Epoch == 0 || h.Epoch > MaxUInt63 || h.Sequence > MaxUInt63 || (h.Sequence == 0) != (h.Digest == "") || h.Sequence > 0 && !digestPattern.MatchString(h.Digest) || h.RecordedAt.Before(now.Add(-30*time.Second)) || h.RecordedAt.After(now.Add(5*time.Second)) {
		return bad("head metadata/freshness")
	}

	if h.Epoch == 1 {
		if !h.RestoreCutoff.IsZero() || !h.ReleaseAfter.IsZero() {
			return bad("unexpected head restore metadata")
		}
	} else if h.RestoreCutoff.IsZero() || h.ReleaseAfter.Before(h.RestoreCutoff.Add(90*time.Second)) || h.RestoreCutoff.After(h.RecordedAt.Add(5*time.Second)) {
		return bad("invalid head restore metadata")
	}
	sig, err := base64.RawURLEncoding.DecodeString(h.Signature)
	if err != nil {
		return bad("head signature")
	}
	h.Signature = ""
	d, err := hash(h)
	if err != nil || !ed25519.Verify(key, []byte("AGP-JOURNAL-HEAD-v1\n"+d), sig) {
		return bad("head signature")
	}
	return nil
}

func validateRequest(r AppendRequest) error {
	for _, id := range []string{r.OperationID, r.TargetID, r.ActorID} {
		if !objectID.MatchString(id) {
			return bad("object id")
		}
	}
	if r.ExpectedEpoch == 0 || r.ExpectedEpoch > MaxUInt63 || r.ExpectedSequence > MaxUInt63 || (r.ExpectedSequence == 0) != (r.ExpectedDigest == "") || r.ExpectedSequence > 0 && !digestPattern.MatchString(r.ExpectedDigest) || !digestPattern.MatchString(r.AuthorizationDigest) || r.RecordedAt.IsZero() {
		return bad("request metadata")
	}
	// Typed union: reject extra, ambiguous fields. Events carry revocations/floors,
	// never SQL, credentials, or positive authorization grants.
	p := r.Payload
	want := Payload{}
	switch r.Kind {
	case "block_principal", "unblock_principal", "raise_security_floor":
		if r.TargetType != "principal" || p.PrincipalID != r.TargetID {
			return bad("principal subject")
		}
		want.PrincipalID = p.PrincipalID
		if r.Kind == "raise_security_floor" {
			if p.MinimumVersion == 0 {
				return bad("security floor")
			}
			want.MinimumVersion = p.MinimumVersion
		}
	case "revoke_session":
		if r.TargetType != "session" || p.SessionID != r.TargetID {
			return bad("session subject")
		}
		want.SessionID = p.SessionID
	case "revoke_node":
		if r.TargetType != "node" || p.NodeID != r.TargetID {
			return bad("node subject")
		}
		want.NodeID = p.NodeID
	case "disable_resource", "enable_resource", "deny_route", "clear_route_deny":
		if r.TargetType != "resource" && r.TargetType != "route" || p.ResourceID != r.TargetID {
			return bad("resource subject")
		}
		want.ResourceID = p.ResourceID
	case "remove_membership", "revoke_role_binding":
		if r.TargetType != "grant" || p.GrantID != r.TargetID {
			return bad("grant subject")
		}
		want.GrantID = p.GrantID
	case "revoke_secret", "bump_authenticator_floor":
		if r.TargetType != "authenticator" || p.AuthenticatorID != r.TargetID || !objectID.MatchString(p.PrincipalID) || p.MinimumVersion == 0 || p.MinimumVersion > MaxUInt63 {
			return bad("authenticator floor")
		}
		want.PrincipalID = p.PrincipalID
		want.AuthenticatorID = p.AuthenticatorID
		want.MinimumVersion = p.MinimumVersion
	case "advance_authority_epoch":
		if r.TargetType != "authority" || p.NewEpoch != r.ExpectedEpoch+1 || p.NewEpoch > MaxUInt63 || p.RestoreCutoff.IsZero() || p.ReleaseAfter.Before(p.RestoreCutoff.Add(90*time.Second)) {
			return bad("restore epoch/cutoff")
		}
		want.NewEpoch = p.NewEpoch
		want.RestoreCutoff = p.RestoreCutoff
		want.ReleaseAfter = p.ReleaseAfter
	default:
		return bad("event kind")
	}
	if r.Kind == "unblock_principal" || r.Kind == "enable_resource" || r.Kind == "clear_route_deny" {
		if !objectID.MatchString(p.OriginalEventID) {
			return bad("lift reference")
		}
		want.OriginalEventID = p.OriginalEventID
	}
	if p != want {
		return bad("unexpected payload fields")
	}
	return nil
}
func needsApproval(kind string) bool {
	return kind == "unblock_principal" || kind == "enable_resource" || kind == "clear_route_deny" || kind == "advance_authority_epoch"
}
