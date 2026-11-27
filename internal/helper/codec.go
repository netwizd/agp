package helper

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"regexp"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/deploymentplan"
	"github.com/netwizd/agp/internal/securityjournal"
)

var idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

func decodeClosed(raw []byte, out any, max int) error {
	if len(raw) > max || configmodel.StrictJSON(bytes.NewReader(raw), out, max) != nil {
		return ErrInvalid
	}
	return nil
}

// Decode accepts only closed apply/rollback envelopes. Parser details never
// cross the helper boundary (they can contain attacker-controlled field names).
func Decode(r io.Reader) (*Request, error) {
	raw, err := io.ReadAll(io.LimitReader(r, MaxRequestBytes+1))
	if err != nil {
		return nil, ErrInvalid
	}
	var request Request
	if decodeClosed(raw, &request, MaxRequestBytes) != nil || validateRequest(request) != nil {
		return nil, ErrInvalid
	}
	if request.SignedPlan != nil {
		// Preserve wire presence checks (in particular v1 forbids even an
		// empty capacityProfile). A typed round trip would erase that fact.
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			return nil, ErrInvalid
		}
		plan, err := deploymentplan.ParseSigned(bytes.NewReader(fields["signedPlan"]))
		if err != nil {
			return nil, ErrInvalid
		}
		request.SignedPlan = plan
	}
	return &request, nil
}

func validCounters(values ...UInt63) bool {
	for _, v := range values {
		if v > securityjournal.MaxUInt63 {
			return false
		}
	}
	return true
}

func utc(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.IsZero() || t.Format(time.RFC3339Nano) != s || t.Location() != time.UTC {
		return time.Time{}, ErrInvalid
	}
	return t, nil
}

func installationDigest(i Installation) (string, error) {
	if i.APIVersion != InstallationVersion || !configmodel.ValidID(i.NodeID) || !configmodel.ValidID(i.SiteID) || !configmodel.ValidID(i.AuthorityID) || !configmodel.ValidID(i.Baseline.RevisionID) || i.AuthorityEpoch == 0 || i.WriterEpoch == 0 || !validCounters(i.AuthorityEpoch, i.WriterEpoch, i.MinimumDenySequence, i.Baseline.NodeDeploymentSequence) {
		return "", ErrInvalid
	}
	for _, d := range []string{i.IdentityDigest, i.OwnershipDigest, i.CapabilityDigest, i.ComponentProfileDigest, i.ReleaseManifestDigest, i.TupleDigest, i.CompilerDigest, i.TrustDigest, i.Baseline.BundleDigest} {
		if !configmodel.ValidDigest(d) {
			return "", ErrInvalid
		}
	}
	return configmodel.Digest(i)
}

func validateRequest(r Request) error {
	t, p := r.Task, r.Permit
	if t.APIVersion != "agp.task/v1alpha1" || (t.Kind != "apply_config" && t.Kind != "rollback_config") || !idempotencyPattern.MatchString(t.IdempotencyKey) || t.AuthorityEpoch == 0 || t.WriterEpoch == 0 || t.NodeDeploymentSequence == 0 || t.NodeDeploymentSequence <= t.Preconditions.ExpectedNodeDeploymentSequence || !validCounters(t.AuthorityEpoch, t.WriterEpoch, t.NodeDeploymentSequence, t.Preconditions.ExpectedNodeDeploymentSequence, t.Payload.MinimumDenySequence, p.Recovery.MinimumDenySequence) {
		return ErrInvalid
	}
	for _, id := range []string{t.ID, t.NodeID, t.PlanID, t.Preconditions.BaseRevisionID, t.Payload.TargetRevisionID, t.Payload.DeploymentGeneration, p.KeyID, p.Approval.SiteID, p.Approval.CreatedBy, p.Approval.ApprovedBy, p.Recovery.BaseRevisionID} {
		if !configmodel.ValidID(id) {
			return ErrInvalid
		}
	}
	for _, d := range []string{t.PlanDigest, t.PermitDigest, t.Preconditions.CapabilityDigest, t.Payload.BundleDigest, t.Payload.RecoveryBaseBundleDigest, p.TaskDigest, p.InstallationDigest, p.IdentityDigest, p.OwnershipDigest, p.ComponentProfileDigest, p.ReleaseManifestDigest, p.TupleDigest, p.CompilerDigest, p.Approval.ApprovalDigest, p.Recovery.BaseBundleDigest, p.Recovery.OwnershipDigest} {
		if !configmodel.ValidDigest(d) {
			return ErrInvalid
		}
	}
	issued, e1 := utc(t.IssuedAt)
	expires, e2 := utc(t.ExpiresAt)
	if e1 != nil || e2 != nil || !expires.After(issued) || expires.Sub(issued) > MaxPermitTTL || p.APIVersion != PermitVersion || p.Approval.CreatedBy == p.Approval.ApprovedBy || t.Payload.SecretVersionIDs == nil || len(t.Payload.SecretVersionIDs) > 100 {
		return ErrInvalid
	}
	seen := make(map[string]bool, len(t.Payload.SecretVersionIDs))
	for _, id := range t.Payload.SecretVersionIDs {
		if !configmodel.ValidID(id) || seen[id] {
			return ErrInvalid
		}
		seen[id] = true
	}
	d, err := TaskDigest(t)
	if err != nil || d != p.TaskDigest {
		return ErrInvalid
	}
	d, err = PermitDigest(p)
	if err != nil || d != t.PermitDigest || !signatureShape(p.Signature) {
		return ErrInvalid
	}
	return nil
}

// TaskDigest includes every task field with permitDigest set to the empty
// string. PermitDigest then hashes the complete signed permit. This ordering
// avoids a recursive hash while binding the exact final envelope.
func TaskDigest(t Task) (string, error) {
	t.PermitDigest = ""
	return configmodel.Digest(t)
}
func PermitDigest(p Permit) (string, error) { return configmodel.Digest(p) }

func signatureShape(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == ed25519.SignatureSize && base64.RawURLEncoding.EncodeToString(b) == s
}

func verifySignature(v any, signature, purpose string, key ed25519.PublicKey) bool {
	if len(key) != ed25519.PublicKeySize || !signatureShape(signature) {
		return false
	}
	d, err := configmodel.Digest(v)
	if err != nil {
		return false
	}
	b, _ := base64.RawURLEncoding.DecodeString(signature)
	return ed25519.Verify(key, []byte(purpose+"\n"+d), b)
}

func verifyPermit(p Permit, trust Trust) bool {
	signature := p.Signature
	p.Signature = ""
	return p.KeyID == trust.PermitKeyID && verifySignature(p, signature, "AGP-HELPER-PERMIT-v1", trust.PermitKey)
}

func verifyProof(p StartProof, trust Trust) bool {
	signature := p.Signature
	p.Signature = ""
	return p.KeyID == trust.ControlKeyID && verifySignature(p, signature, "AGP-HELPER-START-v1", trust.ControlKey)
}

func pin(h securityjournal.Head) HeadPin {
	return HeadPin{AuthorityID: h.AuthorityID, Epoch: h.Epoch, Sequence: h.Sequence, Digest: h.Digest}
}

// validateState checks cross-field consistency in trusted local storage; this
// is not a replacement for signatures on NEW admission or rollback protection
// against restoring the entire helper state volume.
func validateState(s diskState, i Installation) error {
	d, err := installationDigest(i)
	if err != nil || s.APIVersion != StateVersion || s.InstallationDigest != d || s.AuthorityEpoch < i.AuthorityEpoch || s.WriterEpoch < i.WriterEpoch || s.HighWater < i.Baseline.NodeDeploymentSequence || s.MinimumDenySequence < i.MinimumDenySequence || !validCounters(s.HighWater, s.AuthorityEpoch, s.WriterEpoch, s.MinimumDenySequence) {
		return ErrState
	}
	if s.Intent == nil {
		if s.HighWater != i.Baseline.NodeDeploymentSequence || s.AuthorityEpoch != i.AuthorityEpoch || s.WriterEpoch != i.WriterEpoch || s.MinimumDenySequence != i.MinimumDenySequence || s.RecoveryRequired {
			return ErrState
		}
		return nil
	}
	in := s.Intent
	r, p, t := in.Receipt, in.Request.Permit, in.Request.Task
	if in.Request.SignedPlan != nil && deploymentplan.VerifyDigest(in.Request.SignedPlan.Plan) != nil {
		return ErrState
	}
	d, err = configmodel.Digest(in.Request)
	if err != nil || validateRequest(in.Request) != nil || d != in.RequestDigest || checkInstallation(in.Request, i, s.InstallationDigest) != nil || r.APIVersion != AdmissionVersion || r.State != "accepted" || !r.NoExecution || r.RequestDigest != d || r.TaskID != t.ID || r.NodeID != i.NodeID || r.NodeDeploymentSequence != t.NodeDeploymentSequence || r.AuthorityEpoch != t.AuthorityEpoch || r.WriterEpoch != t.WriterEpoch || s.HighWater != t.NodeDeploymentSequence || s.AuthorityEpoch != t.AuthorityEpoch || s.WriterEpoch != t.WriterEpoch || t.Preconditions.ExpectedNodeDeploymentSequence != i.Baseline.NodeDeploymentSequence || in.Head.Epoch != t.AuthorityEpoch || in.Head.AuthorityID != i.AuthorityID || in.Head.Sequence != s.MinimumDenySequence || in.Head.Sequence < t.Payload.MinimumDenySequence || in.Head.Sequence < p.Recovery.MinimumDenySequence || in.Proof.Query.RequestDigest != d || in.Proof.Query.InstallationDigest != s.InstallationDigest || in.Proof.Query.Head != pin(in.Head) || in.Proof.WriterEpoch != t.WriterEpoch || in.Proof.Query.APIVersion != StartVersion || !idempotencyPattern.MatchString(in.Proof.Query.Challenge) || !signatureShape(in.Proof.Signature) {
		return ErrState
	}
	if _, err := utc(r.RecordedAt); err != nil || in.Head.RecordedAt.IsZero() || in.Head.RecordedAt.Format(time.RFC3339Nano) != r.RecordedAt {
		return ErrState
	}
	return nil
}
