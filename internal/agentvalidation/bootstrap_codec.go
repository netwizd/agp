package agentvalidation

import (
	"io"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/nativesandbox"
)

// ParseBootstrapCandidate checks the closed local evidence format and its
// content digest. It does not authenticate its producer, establish freshness,
// or promote syntax evidence to a verified active baseline.
func ParseBootstrapCandidate(r io.Reader) (*BootstrapCandidate, error) {
	if r == nil {
		return nil, ErrBootstrap
	}
	var c BootstrapCandidate
	if configmodel.StrictJSON(r, &c, 64<<10) != nil {
		return nil, ErrBootstrap
	}
	if c.APIVersion != BootstrapCandidateVersion || c.Purpose != "baseline_candidate" || c.Provenance != "managed_bootstrap" || c.BootstrapProfile != BootstrapProfile || !c.SyntaxValidated || c.ActiveConfigurationVerified || c.BaselineVerified || c.Deployable || !c.NoApply || !configmodel.ValidID(c.NodeID) || !configmodel.ValidID(c.SiteID) || !configmodel.ValidID(c.AuthorityID) || c.AuthorityEpoch == 0 || c.CheckedAt.IsZero() || !c.ExpiresAt.After(c.CheckedAt) || c.ExpiresAt.After(c.CheckedAt.Add(5*time.Minute)) {
		return nil, ErrBootstrap
	}
	for _, digest := range []string{c.CandidateDigest, c.OwnershipDigest, c.TreeDigest, c.BundleDigest, c.BootstrapProfileDigest, c.SandboxToolDigest, c.SandboxProfileDigest, c.ExecutionBootDigest, c.Pins.ManifestDigest, c.Pins.ProfileDigest, c.Pins.TupleDigest, c.Pins.EvidenceDigest, c.Pins.RendererDigest} {
		if !configmodel.ValidDigest(digest) {
			return nil, ErrBootstrap
		}
	}
	if c.ExecutionUID <= 0 || uint64(c.ExecutionUID) >= 1<<32-1 || c.ExecutionGID <= 0 || uint64(c.ExecutionGID) >= 1<<32-1 || c.SandboxProfileDigest != nativesandbox.ExecutionProfileDigest(uint32(c.ExecutionUID), uint32(c.ExecutionGID)) {
		return nil, ErrBootstrap
	}
	for _, value := range []string{c.ExecutionHost.ID, c.ExecutionHost.VersionID, c.ExecutionHost.Kernel, c.ExecutionHost.Architecture} {
		if value == "" || len(value) > 256 {
			return nil, ErrBootstrap
		}
		for _, b := range value {
			if b < 32 || b == 127 {
				return nil, ErrBootstrap
			}
		}
	}
	want := c.CandidateDigest
	c.CandidateDigest = ""
	digest, err := configmodel.Digest(c)
	if err != nil || want != digest {
		return nil, ErrBootstrap
	}
	c.CandidateDigest = want
	return &c, nil
}
