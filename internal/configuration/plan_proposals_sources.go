package configuration

import (
	"context"
	"sort"
	"time"

	"github.com/netwizd/agp/internal/compiler"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type planProposalSources struct {
	preview          *compiler.Result
	dependencyDigest string
	inventoryDigest  string
	catalogID        string
	catalogDigest    string
	targetIDs        map[string]bool
	expiresAt        time.Time
}

// The full declared Site is refreshed, before a requested subset is frozen.
// Operator nodes and baseline claims never cross this observation boundary.
func (s *Service) planSources(ctx context.Context, tx storage.IdentityTx, p *Principal, revision, site string, now time.Time) (*planProposalSources, error) {
	if s.trustedInventory == nil || s.wafQualifier == nil {
		return nil, ErrUnavailable
	}
	head, _, e := readHead(ctx, tx)
	if e != nil {
		return nil, e
	}
	if head != revision {
		return nil, ErrRevisionMismatch
	}
	doc, e := baseDocument(ctx, tx, revision)
	if e != nil {
		return nil, e
	}
	if e = verifyOwnership(ctx, tx, doc); e != nil {
		return nil, e
	}
	// Inherited policy qualification is not yet available. Do not pretend a
	// compiler preview proves its native lineage.
	if len(doc.Configuration.ProfileAssignments) > 0 {
		return nil, ErrUnavailable
	}
	catalog, e := loadCatalog(ctx, tx, "")
	if e != nil {
		return nil, e
	}
	if catalog == nil {
		return nil, ErrUnavailable
	}
	if e = validateGroups(ctx, tx, catalog.Catalog); e != nil {
		return nil, e
	}
	cache := map[string]*publishedPolicyPin{}
	proofs := map[string]WAFQualification{}
	pins := []string{}
	overrides := map[string]configmodel.CatalogInput{}
	siteFound := false
	for _, g := range doc.Configuration.Gateways {
		if g.Metadata.SiteID != site {
			continue
		}
		siteFound = true
		var ownerSite string
		e = securitystate.One(ctx, tx, `SELECT site_id FROM config_gateway_ownership WHERE gateway_id=?`, []any{g.Metadata.ID}, func(r storage.IdentityRows) error { return r.Scan(&ownerSite) })
		if e != nil {
			return nil, e
		}
		if ownerSite != site {
			return nil, storage.ErrConflict
		}
		pin, e := s.publishedZonePolicy(ctx, tx, p, g.Spec.WAF.PolicyRevisionID, site, cache)
		if e != nil {
			return nil, e
		}
		proof := pin.proof
		if g.Spec.ComponentProfileRef.ID != proof.ProfileID || g.Spec.ComponentProfileRef.Digest != proof.ProfileDigest {
			return nil, storage.ErrConflict
		}
		for _, r := range g.Spec.Routes {
			if len(r.WAFExceptionIDs) > 0 {
				return nil, ErrUnavailable
			}
		}
		proofs[digest(proof)] = proof
		pins = append(pins, digest([]any{pin.publicationID, pin.record.revision.ContentDigest, proof}))
		for _, in := range []configmodel.CatalogInput{
			{Kind: "waf_policy", ID: pin.record.revision.ID, Digest: pin.record.revision.ContentDigest, SiteID: site, State: "published"},
			{Kind: "component_profile", ID: proof.ProfileID, Digest: proof.ProfileDigest, SiteID: site, State: "published"},
			{Kind: "ruleset", ID: proof.RulesetVersionID, Digest: proof.RulesetDigest, SiteID: site, State: "published"},
		} {
			key := in.Kind + "/" + in.ID
			if prev, ok := overrides[key]; ok && prev.Digest != in.Digest {
				return nil, storage.ErrConflict
			}
			overrides[key] = in
		}
	}
	if !siteFound {
		return nil, storage.ErrNotFound
	}
	qualifications := make([]WAFQualification, 0, len(proofs))
	keys := make([]string, 0, len(proofs))
	for id := range proofs {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	expires := now.Add(30 * time.Minute)
	for _, id := range keys {
		proof := proofs[id]
		qualifications = append(qualifications, proof)
		if proof.ExpiresAt.Before(expires) {
			expires = proof.ExpiresAt
		}
	}
	if !expires.After(now) {
		return nil, storage.ErrConflict
	}
	observation, e := s.trustedInventory.Current(ctx, tx, securityjournal.UInt63(p.Epoch), site, qualifications)
	if e != nil {
		return nil, e
	}
	if observation == nil || !configmodel.ValidDigest(observation.SourceDigest) || len(observation.Nodes) > 500 {
		return nil, storage.ErrConflict
	}
	seen := map[string]bool{}
	trusted := make([]configmodel.CatalogNode, 0, len(observation.Nodes))
	for _, node := range observation.Nodes {
		if node.SiteID != site || !validID.MatchString(node.ID) || seen[node.ID] || !configmodel.ValidDigest(node.CapabilityDigest) {
			return nil, storage.ErrConflict
		}
		seen[node.ID] = true
		node.BaselineBundleDigest = ""
		trusted = append(trusted, node)
	}
	sort.Slice(trusted, func(i, j int) bool { return trusted[i].ID < trusted[j].ID })
	full := catalog.Catalog
	full.Nodes = make([]configmodel.CatalogNode, 0, len(full.Nodes)+len(trusted))
	for _, node := range catalog.Catalog.Nodes {
		if node.SiteID != site {
			node.BaselineBundleDigest = ""
			full.Nodes = append(full.Nodes, node)
		}
	}
	full.Nodes = append(full.Nodes, trusted...)
	// Replace the exact qualified inputs; an operator declaration cannot shadow
	// a trusted WAF policy, profile or ruleset with the same ID.
	full.Inputs = make([]configmodel.CatalogInput, 0, len(catalog.Catalog.Inputs)+len(overrides))
	for _, in := range catalog.Catalog.Inputs {
		if _, ok := overrides[in.Kind+"/"+in.ID]; !ok {
			full.Inputs = append(full.Inputs, in)
		}
	}
	inputKeys := make([]string, 0, len(overrides))
	for key := range overrides {
		inputKeys = append(inputKeys, key)
	}
	sort.Strings(inputKeys)
	for _, key := range inputKeys {
		full.Inputs = append(full.Inputs, overrides[key])
	}
	preview, e := compiler.Preview(ctx, doc.Configuration, full, s.compiler)
	if e != nil {
		return nil, e
	}
	sort.Strings(pins)
	dependency := digest([]any{"agp.plan-proposal-sources/v1", p.Epoch, revision, doc.Digest, catalog.Catalog.ID, catalog.Digest, observation.SourceDigest, trusted, pins, preview.CompilerDigest, preview.PreviewDigest})
	inventory, e := configmodel.Digest(trusted)
	if e != nil {
		return nil, e
	}
	return &planProposalSources{preview, dependency, inventory, catalog.Catalog.ID, catalog.Digest, seen, expires.Truncate(time.Microsecond)}, nil
}

type planSourcesResult struct {
	sources *planProposalSources
	err     error
}

func (s *Service) planProposalCurrent(ctx context.Context, tx storage.IdentityTx, p *Principal, v *storedPlanProposal, now time.Time, caches ...map[string]planSourcesResult) error {
	proposal := &v.proposal
	if v.epoch != p.Epoch || !now.Before(proposal.ExpiresAt) || now.Before(proposal.CreatedAt) {
		return storage.ErrConflict
	}
	fp, e := planSubject(ctx, tx, proposal.AuthorID, p.head, "config.read", "config.edit")
	if e != nil {
		return e
	}
	if fp != v.authorFingerprint {
		return storage.ErrConflict
	}
	// Optional memoization belongs to this fenced transaction only. Every new
	// request obtains fresh independent observations before any current claim.
	cacheKey := proposal.RevisionID + "/" + proposal.SiteID
	var sources *planProposalSources
	cached := false
	if len(caches) > 0 {
		if result, ok := caches[0][cacheKey]; ok {
			sources, e = result.sources, result.err
			cached = true
		}
	}
	if !cached {
		sources, e = s.planSources(ctx, tx, p, proposal.RevisionID, proposal.SiteID, now)
		if len(caches) > 0 {
			caches[0][cacheKey] = planSourcesResult{sources, e}
		}
	}
	if e != nil {
		return e
	}
	if sources.dependencyDigest != proposal.DependencyDigest || sources.inventoryDigest != proposal.InventoryDigest || sources.catalogID != proposal.CatalogID || sources.catalogDigest != proposal.CatalogDigest || sources.preview.PreviewDigest != proposal.PreviewDigest || sources.preview.CompilerDigest != proposal.CompilerDigest || sources.preview.CompilerVersion != proposal.CompilerVersion {
		return storage.ErrConflict
	}
	return nil
}
