package executionsources

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"sort"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/helper"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/nativeactivation"
	"github.com/netwizd/agp/internal/repository"
	"github.com/netwizd/agp/internal/rolloutexecution"
	"github.com/netwizd/agp/internal/securityjournal"
)

type Service struct {
	current    Current
	inventory  *inventory.Service
	repository repository.Store
	load       LoadConfig
	witness    func(context.Context) error
}

// New requires a live single-writer witness supplied by installation runtime.
// Neither a configured epoch number nor an operator boolean is such a witness.
func New(current Current, agents *inventory.Service, repo repository.Store, load LoadConfig, witness func(context.Context) error) (*Service, error) {
	if current == nil || agents == nil || load == nil || witness == nil || repo.Dir == "" || repo.AnchorPath == "" {
		return nil, ErrUnavailable
	}
	s := &Service{current: current, inventory: agents, repository: repo, load: load, witness: witness}
	if _, err := s.config(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

var _ rolloutexecution.Sources = (*Service)(nil)

func (s *Service) config(ctx context.Context) (*trustedConfig, error) {
	if s == nil || ctx == nil || s.load == nil || s.witness == nil {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.witness(ctx); err != nil {
		return nil, ErrUnavailable
	}
	c, err := s.load(ctx)
	if err != nil {
		return nil, ErrUnavailable
	}
	// Detach every map/slice, including native bundle bytes, from the loader.
	raw, err := configmodel.CanonicalJSON(c)
	if err != nil || len(raw) > MaxCatalogBytes {
		return nil, ErrUnavailable
	}
	var detached Config
	if json.Unmarshal(raw, &detached) != nil {
		return nil, ErrUnavailable
	}
	c = detached
	if c.APIVersion != CatalogVersion || c.WriterEpoch == 0 || c.WriterEpoch > securityjournal.MaxUInt63 || len(c.Bindings) < 1 || len(c.Bindings) > 500 || c.QualificationKeys == nil || len(c.QualificationKeys) > 32 || len(c.Materials) > 256 || c.SecretVersions == nil || len(c.SecretVersions) > 10000 {
		return nil, ErrUnavailable
	}
	out := &trustedConfig{config: c, bindings: map[string]Binding{}, keys: map[string]ed25519.PublicKey{}, secrets: map[string]SecretVersion{}}
	for id, raw := range c.QualificationKeys {
		key, e := publicKey(raw)
		if e != nil || !configmodel.ValidID(id) {
			return nil, ErrUnavailable
		}
		for _, old := range out.keys {
			if bytes.Equal(key, old) {
				return nil, ErrUnavailable
			}
		}
		out.keys[id] = key
	}
	for _, b := range c.Bindings {
		a := b.Anchor
		i := a.Installation
		if a.APIVersion != helper.ExecutionAnchorVersion || i.APIVersion != helper.InstallationVersion || !configmodel.ValidID(i.NodeID) || !configmodel.ValidID(i.SiteID) || !configmodel.ValidID(i.AuthorityID) || !configmodel.ValidID(i.Baseline.RevisionID) || i.AuthorityEpoch == 0 || i.WriterEpoch != c.WriterEpoch || i.MinimumDenySequence > securityjournal.MaxUInt63 || i.Baseline.NodeDeploymentSequence > securityjournal.MaxUInt63 || out.bindings[i.NodeID].Anchor.APIVersion != "" || a.LayoutDigest != i.OwnershipDigest || b.Native.NodeID != i.NodeID || b.Native.SiteID != i.SiteID || b.Native.LayoutDigest != a.LayoutDigest || b.Native.ReleaseManifestDigest != i.ReleaseManifestDigest {
			return nil, ErrUnavailable
		}
		for _, d := range []string{a.LayoutDigest, i.IdentityDigest, i.CapabilityDigest, i.ComponentProfileDigest, i.ReleaseManifestDigest, i.TupleDigest, i.CompilerDigest, i.TrustDigest, i.Baseline.BundleDigest, b.Native.QualificationDigest} {
			if !configmodel.ValidDigest(d) {
				return nil, ErrUnavailable
			}
		}
		layout, e := nativeactivation.LayoutDigest(b.Native)
		if e != nil || layout != a.LayoutDigest {
			return nil, ErrUnavailable
		}
		key, e := publicKey(a.ReceiptPublicKey)
		if e != nil || !configmodel.ValidID(a.ReceiptKeyID) {
			return nil, ErrUnavailable
		}
		for id, q := range out.keys {
			if id == a.ReceiptKeyID || bytes.Equal(q, key) {
				return nil, ErrUnavailable
			}
		}
		out.bindings[i.NodeID] = b
	}
	for _, v := range c.SecretVersions {
		if !configmodel.ValidID(v.ID) || !configmodel.ValidID(v.SiteID) || !configmodel.ValidDigest(v.Digest) || v.AuthorityEpoch == 0 || v.AuthorityEpoch > securityjournal.MaxUInt63 || out.secrets[v.ID].ID != "" {
			return nil, ErrUnavailable
		}
		out.secrets[v.ID] = v
	}
	seen := map[string]bool{}
	for _, m := range c.Materials {
		a := m.Attestation
		if !configmodel.ValidID(a.NodeID) || !configmodel.ValidID(a.RevisionID) || seen[a.NodeID+"/"+a.RevisionID] {
			return nil, ErrUnavailable
		}
		seen[a.NodeID+"/"+a.RevisionID] = true
	}
	return out, nil
}

func publicKey(v string) (ed25519.PublicKey, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(v)
	if err != nil || len(b) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(b) != v {
		return nil, ErrUnavailable
	}
	return ed25519.PublicKey(b), nil
}

// VerifyAttestation authenticates immutable materialization evidence. Consumers
// must additionally compare its release, SQL inputs, secrets and full bytes.
func VerifyAttestation(a Attestation, key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize || a.APIVersion != MaterializationVersion || a.Purpose != "qualified_native_materialization" || !configmodel.ValidID(a.ID) || !configmodel.ValidID(a.NodeID) || !configmodel.ValidID(a.SiteID) || !configmodel.ValidID(a.RevisionID) || !configmodel.ValidID(a.GenerationID) || !configmodel.ValidID(a.KeyID) || a.CompilerVersion == "" || len(a.CompilerVersion) > 128 || a.SecretVersionIDs == nil || len(a.SecretVersionIDs) > 100 {
		return ErrUnavailable
	}
	for _, d := range []string{a.ConfigurationDigest, a.ResolvedSourceDigest, a.BundleDigest, a.BundleFileDigest, a.TargetTreeDigest, a.CompilerDigest, a.RendererDigest, a.ProfileDigest, a.ReleaseManifestDigest, a.TupleDigest, a.EvidenceDigest, a.NativeReportDigest, a.HarnessDigest} {
		if !configmodel.ValidDigest(d) {
			return ErrUnavailable
		}
	}
	for n, id := range a.SecretVersionIDs {
		if !configmodel.ValidID(id) || n > 0 && id <= a.SecretVersionIDs[n-1] {
			return ErrUnavailable
		}
	}
	issued, e := parseUTC(a.IssuedAt)
	expires, e2 := parseUTC(a.ExpiresAt)
	if e != nil || e2 != nil || !expires.After(issued) {
		return ErrUnavailable
	}
	sig, e := base64.RawURLEncoding.Strict().DecodeString(a.Signature)
	if e != nil || len(sig) != ed25519.SignatureSize {
		return ErrUnavailable
	}
	a.Signature = ""
	d, e := configmodel.Digest(a)
	if e != nil || !ed25519.Verify(key, []byte(MaterializationDomain+"\n"+d), sig) {
		return ErrUnavailable
	}
	return nil
}

func parseUTC(v string) (time.Time, error) {
	t, e := time.Parse(time.RFC3339Nano, v)
	if e != nil || t.IsZero() || t.Location() != time.UTC || t.Format(time.RFC3339Nano) != v {
		return time.Time{}, ErrUnavailable
	}
	return t, nil
}
func hash(v any) string { d, _ := configmodel.Digest(v); return d }
func unique(v []string) []string {
	out := append([]string{}, v...)
	sort.Strings(out)
	r := out[:0]
	for _, id := range out {
		if len(r) == 0 || r[len(r)-1] != id {
			r = append(r, id)
		}
	}
	return r
}
func utc(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
