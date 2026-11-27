package executionsources

import (
	"context"
	"strings"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/helper"
	"github.com/netwizd/agp/internal/nativeactivation"
	"github.com/netwizd/agp/internal/repository"
	"github.com/netwizd/agp/internal/rolloutexecution"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

func (s *Service) Resolve(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, in rolloutexecution.Selection) (*rolloutexecution.Snapshot, error) {
	if tx == nil || len(in.NodeIDs) < 1 || len(in.NodeIDs) > 500 || len(unique(in.NodeIDs)) != len(in.NodeIDs) || (in.Kind != "apply_config" && in.Kind != "rollback_config") {
		return nil, ErrUnavailable
	}
	c, err := s.config(ctx)
	if err != nil {
		return nil, err
	}
	v, p, err := s.release(ctx, h)
	if err != nil {
		return nil, err
	}
	pr, err := s.inspect(ctx, tx, h, c, in.RevisionID, in.SiteID, v, p)
	if err != nil {
		return nil, err
	}
	if in.Kind == "apply_config" && pr.head != in.RevisionID {
		return nil, ErrStale
	}
	out := &rolloutexecution.Snapshot{Authors: pr.authors, ResolvedInputs: pr.inputs, Targets: []rolloutexecution.TargetSnapshot{}}
	for _, node := range unique(in.NodeIDs) {
		t, version, e := s.target(ctx, tx, h, c, pr, v, p, node, in.RevisionID)
		if e != nil {
			return nil, e
		}
		if out.CompilerVersion != "" && out.CompilerVersion != version {
			return nil, ErrUnavailable
		}
		out.CompilerVersion = version
		out.Targets = append(out.Targets, t)
	}
	if err = s.witness(ctx); err != nil {
		return nil, ErrUnavailable
	}
	return out, nil
}

func (s *Service) release(ctx context.Context, h securityjournal.Head) (*repository.VerifiedRelease, *repository.QualifiedProfile, error) {
	if h.RecordedAt.IsZero() || h.Epoch == 0 {
		return nil, nil, ErrUnavailable
	}
	v, err := s.repository.Current(ctx, h.RecordedAt)
	if err != nil {
		return nil, nil, err
	}
	p, err := v.QualifiedProfile(h.RecordedAt)
	if err != nil {
		return nil, nil, err
	}
	return v, p, nil
}

func (s *Service) target(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, c *trustedConfig, pr *revisionProjection, v *repository.VerifiedRelease, p *repository.QualifiedProfile, node, revision string) (rolloutexecution.TargetSnapshot, string, error) {
	var empty rolloutexecution.TargetSnapshot
	b, ok := c.bindings[node]
	np, selected := pr.nodes[node]
	if !ok || !selected {
		return empty, "", ErrUnavailable
	}
	i := b.Anchor.Installation
	if i.SiteID != np.Node.SiteID || i.AuthorityID != h.AuthorityID || i.AuthorityEpoch != h.Epoch || i.WriterEpoch != c.config.WriterEpoch || i.IdentityDigest != np.Node.IdentityDigest || i.CapabilityDigest != np.Node.CapabilityDigest || i.ComponentProfileDigest != p.ProfileDigest || i.ReleaseManifestDigest != v.ManifestDigest || i.TupleDigest != p.TupleDigest || b.Native.QualificationDigest != p.EvidenceDigest {
		return empty, "", ErrStale
	}
	baseline, err := readBaseline(ctx, tx, node, b.Anchor)
	if err != nil {
		return empty, "", err
	}
	if baseline.Frozen || baseline.BootDigest != np.Node.BootDigest || baseline.Epoch != h.Epoch || baseline.Writer != c.config.WriterEpoch || baseline.Deny > h.Sequence || h.RecordedAt.Before(baseline.VerifiedAt) || h.RecordedAt.Sub(baseline.VerifiedAt) > BaselineFreshness {
		return empty, "", ErrCapture
	}
	var material *Materialization
	for n := range c.config.Materials {
		m := &c.config.Materials[n]
		if m.Attestation.NodeID == node && m.Attestation.RevisionID == revision {
			material = m
			break
		}
	}
	if material == nil {
		return empty, "", ErrUnavailable
	}
	a := material.Attestation
	if VerifyAttestation(a, c.keys[a.KeyID]) != nil {
		return empty, "", ErrUnavailable
	}
	issued, _ := parseUTC(a.IssuedAt)
	expiry, _ := parseUTC(a.ExpiresAt)
	secrets := []string{}
	for _, secret := range np.SecretVersions {
		secrets = append(secrets, secret.ID)
	}
	if a.SiteID != i.SiteID || a.ConfigurationDigest != pr.doc.Digest || a.ResolvedSourceDigest != hash(np) || a.CompilerDigest != i.CompilerDigest || a.RendererDigest != p.Evidence.RendererDigest || a.ProfileDigest != p.ProfileDigest || a.ReleaseManifestDigest != v.ManifestDigest || a.TupleDigest != p.TupleDigest || a.EvidenceDigest != p.EvidenceDigest || a.NativeReportDigest != p.Evidence.NativeReportDigest || a.HarnessDigest != p.Evidence.HarnessDigest || issued.After(h.RecordedAt) || !h.RecordedAt.Before(expiry) || expiry.After(v.ExpiresAt) || hash(secrets) != hash(a.SecretVersionIDs) {
		return empty, "", ErrStale
	}
	if hash(material.Bundle) != a.BundleFileDigest || material.Bundle.NodeID != node || material.Bundle.RevisionID != revision || material.Bundle.BundleDigest != a.BundleDigest || material.Bundle.GenerationID != a.GenerationID || material.Bundle.QualificationDigest != p.EvidenceDigest || material.Bundle.ReleaseManifestDigest != v.ManifestDigest {
		return empty, "", ErrUnavailable
	}
	generation, err := nativeactivation.ProjectedGeneration(b.Native, material.Bundle, 1)
	if err != nil || generation.TreeDigest != a.TargetTreeDigest {
		return empty, "", ErrUnavailable
	}
	t := rolloutexecution.TargetSnapshot{Installation: i, Baseline: baseline.Active, AcceptedSequence: baseline.Accepted, NodeGroupIDs: unique(np.Node.GroupIDs), BundleDigest: a.BundleDigest, TargetTreeDigest: generation.TreeDigest, DeploymentGeneration: a.GenerationID, SecretVersionIDs: secrets, ReceiptKeyID: b.Anchor.ReceiptKeyID, ReceiptPublicKey: b.Anchor.ReceiptPublicKey}
	// Baseline proof refresh timestamps and receipt IDs are deliberately not
	// plan inputs. Actual baseline, counters, floors and catalog identity are.
	t.SourceDigest = hash(struct {
		Purpose                                string
		Projection                             string
		Anchor                                 helper.ExecutionAnchor
		Materialization                        string
		HeadRevision                           string
		BootDigest                             string
		Active                                 helper.ExecutionGeneration
		Accepted, Receipt, Epoch, Writer, Deny securityjournal.UInt63
	}{"execution_sources/v1", hash(np), b.Anchor, hash(a), pr.head, baseline.BootDigest, baseline.Active, baseline.Accepted, baseline.Receipt, baseline.Epoch, baseline.Writer, baseline.Deny})
	return t, a.CompilerVersion, nil
}

func (s *Service) Recheck(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, saved rolloutexecution.TargetSnapshot) error {
	c, err := s.config(ctx)
	if err != nil {
		return err
	}
	var revision string
	for _, m := range c.config.Materials {
		a := m.Attestation
		if a.NodeID == saved.Installation.NodeID && a.BundleDigest == saved.BundleDigest && a.GenerationID == saved.DeploymentGeneration {
			if revision != "" {
				return ErrUnavailable
			}
			revision = a.RevisionID
		}
	}
	if revision == "" {
		return ErrUnavailable
	}
	v, p, err := s.release(ctx, h)
	if err != nil {
		return err
	}
	pr, err := s.inspect(ctx, tx, h, c, revision, saved.Installation.SiteID, v, p)
	if err != nil {
		return err
	}
	current, _, err := s.target(ctx, tx, h, c, pr, v, p, saved.Installation.NodeID, revision)
	if err != nil {
		return err
	}
	if hash(current) != hash(saved) {
		return ErrStale
	}
	if err = s.witness(ctx); err != nil {
		return ErrUnavailable
	}
	return nil
}

// MaterializationInputs exposes only stable source digests for an independent
// materializer. It supplies no qualification, baseline or execution permission.
// The caller must already own the current fenced transaction.
func (s *Service) MaterializationInputs(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, revision, site string) (map[string]string, error) {
	c, err := s.config(ctx)
	if err != nil {
		return nil, err
	}
	v, p, err := s.release(ctx, h)
	if err != nil {
		return nil, err
	}
	pr, err := s.inspect(ctx, tx, h, c, revision, site, v, p)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for id, p := range pr.nodes {
		out[id] = hash(p)
	}
	return out, nil
}

func decodeCanonical(raw string, dst any, max int) error {
	if configmodel.StrictJSON(strings.NewReader(raw), dst, max) != nil {
		return ErrUnavailable
	}
	b, e := configmodel.CanonicalJSON(dst)
	if e != nil || string(b) != raw {
		return ErrUnavailable
	}
	return nil
}
