package runtime

import (
	"context"
	"fmt"
	"sort"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/configuration"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
	"github.com/netwizd/agp/internal/wafnative"
)

// TrustedInventory compares authenticated observations with the current signed
// compatibility closure. It grants neither apply nor a healthy traffic state.
type TrustedInventory struct {
	Inventory *inventory.Service
	Provider  *wafnative.Provider
}

func (v *TrustedInventory) Current(ctx context.Context, tx storage.IdentityTx, epoch securityjournal.UInt63, site string, qualifications []configuration.WAFQualification) (*configuration.TrustedInventorySnapshot, error) {
	if v == nil || v.Inventory == nil || v.Provider == nil || v.Provider.Clock == nil || len(qualifications) == 0 {
		return nil, fmt.Errorf("%w: signed component qualification required", inventory.ErrUnavailable)
	}
	var err error
	for i := range qualifications {
		if err = v.Provider.Current(ctx, &qualifications[i]); err != nil {
			return nil, err
		}
	}
	now, err := v.Provider.Clock(ctx)
	if err != nil || now.IsZero() {
		return nil, inventory.ErrUnavailable
	}
	release, err := v.Provider.Store.Current(ctx, now)
	if err != nil {
		return nil, err
	}
	profile, err := release.QualifiedProfile(now)
	if err != nil {
		return nil, err
	}
	for _, q := range qualifications {
		if q.ProfileDigest != profile.ProfileDigest || q.ManifestDigest != release.ManifestDigest || q.TupleDigest != profile.TupleDigest || q.EvidenceDigest != profile.EvidenceDigest {
			return nil, inventory.ErrNotFresh
		}
	}
	// Refresh observations after the potentially long signed artifact reads.
	// A lease obtained before verification cannot authorize a later mutation.
	nodes, err := v.Inventory.CurrentNodes(ctx, tx, epoch, site)
	if err != nil {
		return nil, err
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	out := &configuration.TrustedInventorySnapshot{Nodes: []configmodel.CatalogNode{}}
	type stableNode struct {
		ID               string            `json:"id"`
		SiteID           string            `json:"siteId"`
		IdentityDigest   string            `json:"identityDigest"`
		CapabilityDigest string            `json:"capabilityDigest"`
		Labels           map[string]string `json:"labels"`
		Groups           []string          `json:"groups"`
	}
	stable := []stableNode{}
	for _, node := range nodes {
		c := node.Capabilities
		p := profile.Profile.Platform
		if c.ProtocolVersion != inventory.ProtocolVersion || c.OS.ID != p.OS || c.OS.VersionID != p.OSVersion || c.OS.Architecture != p.Arch || c.OS.Kernel != profile.Evidence.HostKernel || c.Component == nil || c.Component.ProfileDigest != profile.ProfileDigest || len(c.Component.Files) != len(profile.Profile.Files) {
			return nil, fmt.Errorf("%w: node %s does not match the qualified component platform", inventory.ErrNotFresh, node.ID)
		}
		observed := make(map[string]string, len(c.Component.Files))
		for _, file := range c.Component.Files {
			if observed[file.Path] != "" {
				return nil, inventory.ErrNotFresh
			}
			observed[file.Path] = file.Digest
		}
		for _, file := range profile.Profile.Files {
			if observed[file.Path] != file.Digest {
				return nil, fmt.Errorf("%w: node %s component drift", inventory.ErrNotFresh, node.ID)
			}
		}
		groups := append([]string{}, node.GroupIDs...)
		sort.Strings(groups)
		stable = append(stable, stableNode{node.ID, node.SiteID, node.IdentityDigest, node.CapabilityDigest, node.Labels, groups})
		out.Nodes = append(out.Nodes, configmodel.CatalogNode{ID: node.ID, SiteID: node.SiteID, Labels: node.Labels, NodeGroupIDs: groups, CapabilityDigest: node.CapabilityDigest})
	}
	out.SourceDigest, err = configmodel.Digest(struct {
		Epoch    securityjournal.UInt63 `json:"epoch"`
		Site     string                 `json:"site"`
		Manifest string                 `json:"manifestDigest"`
		Profile  string                 `json:"profileDigest"`
		Tuple    string                 `json:"tupleDigest"`
		Evidence string                 `json:"evidenceDigest"`
		Nodes    []stableNode           `json:"nodes"`
	}{epoch, site, release.ManifestDigest, profile.ProfileDigest, profile.TupleDigest, profile.EvidenceDigest, stable})
	if err != nil {
		return nil, err
	}
	return out, nil
}
