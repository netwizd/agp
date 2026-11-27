package executionsources

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/configuration"
	"github.com/netwizd/agp/internal/deploymentplan"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/repository"
	"github.com/netwizd/agp/internal/rolescope"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type projection struct {
	RevisionID                                                 string                        `json:"revisionId"`
	ConfigurationDigest                                        string                        `json:"configurationDigest"`
	Node                                                       stableNode                    `json:"node"`
	Recipients                                                 []rolescope.GatewayRecipients `json:"recipients"`
	Resources                                                  []rolescope.ResourceAuthority `json:"resources"`
	WAF                                                        []policyPin                   `json:"waf"`
	SecretVersions                                             []SecretVersion               `json:"secretVersions"`
	Groups                                                     []string                      `json:"groups"`
	ProfileDigest, ManifestDigest, TupleDigest, EvidenceDigest string
}
type stableNode struct {
	ID, SiteID, IdentityDigest, CapabilityDigest string
	Labels                                       map[string]string
	GroupIDs                                     []string
	BootDigest                                   string `json:"-"` // live runtime fence, not materializer input
}
type policyPin struct {
	RevisionID, ContentDigest, PublicationID, PublicationDigest string
}
type revisionProjection struct {
	doc     *configmodel.Document
	head    string
	authors []string
	inputs  []deploymentplan.ResolvedInput
	nodes   map[string]projection
}

// inspect reconstructs the materializer's exact stable input from sealed SQL
// and current independent facts. Heartbeat IDs and timestamps are excluded.
func (s *Service) inspect(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, c *trustedConfig, revision, site string, v *repository.VerifiedRelease, p *repository.QualifiedProfile) (*revisionProjection, error) {
	if !configmodel.ValidID(revision) || !configmodel.ValidID(site) || h.RecordedAt.IsZero() {
		return nil, ErrUnavailable
	}
	var raw, pin, author, parent string
	err := securitystate.One(ctx, tx, `SELECT r.canonical_json,r.content_digest,r.created_by,COALESCE(r.parent_id,'') FROM config_revisions r JOIN config_revision_seals s ON s.revision_id=r.id WHERE r.id=?`, []any{revision}, func(r storage.IdentityRows) error { return r.Scan(&raw, &pin, &author, &parent) })
	if err != nil {
		return nil, err
	}
	doc, err := configmodel.ParseConfiguration(strings.NewReader(raw), configmodel.JSON)
	if err != nil || doc.Digest != pin || string(doc.Canonical) != raw || !configmodel.ValidID(author) {
		return nil, ErrUnavailable
	}
	out := &revisionProjection{doc: doc, authors: []string{author}, inputs: []deploymentplan.ResolvedInput{{Kind: "component_profile", ID: p.Profile.ID, Digest: p.ProfileDigest}, {Kind: "ruleset", ID: p.Profile.RulesetVersionID, Digest: p.RulesetDigest}}, nodes: map[string]projection{}}
	if err = securitystate.One(ctx, tx, `SELECT COALESCE(revision_id,'') FROM config_head WHERE id=1`, nil, func(r storage.IdentityRows) error { return r.Scan(&out.head) }); err != nil {
		return nil, err
	}
	seen := map[string]bool{revision: true}
	for parent != "" {
		if seen[parent] || len(seen) >= 128 {
			return nil, ErrUnavailable
		}
		seen[parent] = true
		var next string
		if err = securitystate.One(ctx, tx, `SELECT r.created_by,COALESCE(r.parent_id,'') FROM config_revisions r JOIN config_revision_seals s ON s.revision_id=r.id WHERE r.id=?`, []any{parent}, func(r storage.IdentityRows) error { return r.Scan(&author, &next) }); err != nil {
			return nil, err
		}
		if !configmodel.ValidID(author) {
			return nil, ErrUnavailable
		}
		out.authors = append(out.authors, author)
		parent = next
	}
	// These features require a separate lineage/materialization reader. Their
	// absence is checked in SQL as well as in the canonical document.
	var zoneCount int64
	if err = securitystate.One(ctx, tx, `SELECT COUNT(*) FROM config_revision_zone_assignments WHERE revision_id=?`, []any{revision}, func(r storage.IdentityRows) error { return r.Scan(&zoneCount) }); err != nil {
		return nil, err
	}
	if len(doc.Configuration.ProfileAssignments) != 0 || zoneCount != 0 {
		return nil, ErrUnavailable
	}
	nodes, err := s.inventory.CurrentNodes(ctx, tx, h.Epoch, site)
	if err != nil {
		return nil, err
	}
	for _, n := range nodes {
		if err = qualifiedNode(n, p); err != nil {
			return nil, err
		}
		boot, e := currentNodeBoot(ctx, tx, n)
		if e != nil {
			return nil, e
		}
		out.nodes[n.ID] = projection{RevisionID: revision, ConfigurationDigest: pin, Node: stableNode{n.ID, n.SiteID, n.IdentityDigest, n.CapabilityDigest, n.Labels, unique(n.GroupIDs), boot}, Recipients: []rolescope.GatewayRecipients{}, Resources: []rolescope.ResourceAuthority{}, WAF: []policyPin{}, SecretVersions: []SecretVersion{}, Groups: []string{}, ProfileDigest: p.ProfileDigest, ManifestDigest: v.ManifestDigest, TupleDigest: p.TupleDigest, EvidenceDigest: p.EvidenceDigest}
	}
	resolver, err := rolescope.NewGatewayRecipientResolver(ctx, tx, h)
	if err != nil {
		return nil, err
	}
	policies := map[string]policyPin{}
	resources, err := rolescope.NewResourceAuthorityResolver(ctx, tx, h)
	if err != nil {
		return nil, err
	}
	for _, g := range doc.Configuration.Gateways {
		if g.Metadata.SiteID != site {
			continue
		}
		if g.Spec.ComponentProfileRef.ID != p.Profile.ID || g.Spec.ComponentProfileRef.Digest != p.ProfileDigest {
			return nil, ErrStale
		}
		recipients, e := resolver.Resolve(g)
		if e != nil || len(recipients.Nodes) == 0 {
			return nil, ErrUnavailable
		}
		wp, ok := policies[g.Spec.WAF.PolicyRevisionID]
		if !ok {
			var policyAuthor string
			wp, policyAuthor, e = readPolicy(ctx, tx, h, g.Spec.WAF.PolicyRevisionID, site, v, p, c)
			if e != nil {
				return nil, e
			}
			policies[wp.RevisionID] = wp
			out.authors = append(out.authors, policyAuthor)
			out.inputs = append(out.inputs, deploymentplan.ResolvedInput{Kind: "waf_policy", ID: wp.RevisionID, Digest: wp.ContentDigest})
		}
		secretIDs := []string{g.Spec.TLS.CertificateVersionID}
		groups := []string{}
		resourcePins := []rolescope.ResourceAuthority{}
		for _, route := range g.Spec.Routes {
			resourceID, e := resources.LookupRoute(g.Metadata.ID, route.ID)
			if e != nil {
				return nil, e
			}
			if resourceID != "" {
				fact, e := resources.Resolve(resourceID)
				if e != nil {
					return nil, e
				}
				resourcePins = append(resourcePins, fact)
			}
			if len(route.WAFExceptionIDs) != 0 {
				return nil, ErrUnavailable
			}
			if route.Upstream.TLS.CASecretVersionID != "" {
				secretIDs = append(secretIDs, route.Upstream.TLS.CASecretVersionID)
			}
			groups = append(groups, route.Access.GroupIDs...)
		}
		groups = unique(groups)
		for _, id := range groups {
			var found string
			if e = securitystate.One(ctx, tx, `SELECT id FROM groups WHERE id=?`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&found) }); e != nil {
				return nil, e
			}
		}
		secrets := []SecretVersion{}
		for _, id := range unique(secretIDs) {
			sv, ok := c.secrets[id]
			if !ok || sv.SiteID != site || sv.Revoked || sv.AuthorityEpoch != h.Epoch {
				return nil, ErrUnavailable
			}
			secrets = append(secrets, sv)
		}
		for _, n := range recipients.Nodes {
			pr, ok := out.nodes[n.NodeID]
			if !ok || hash(unique(n.GroupIDs)) != hash(pr.Node.GroupIDs) {
				return nil, ErrUnavailable
			}
			pr.Recipients = append(pr.Recipients, recipients)
			pr.Resources = append(pr.Resources, resourcePins...)
			pr.WAF = append(pr.WAF, wp)
			pr.SecretVersions = append(pr.SecretVersions, secrets...)
			pr.Groups = append(pr.Groups, groups...)
			out.nodes[n.NodeID] = pr
		}
	}
	for id, pr := range out.nodes {
		if len(pr.Recipients) == 0 {
			delete(out.nodes, id)
			continue
		}
		sort.Slice(pr.Recipients, func(i, j int) bool { return pr.Recipients[i].GatewayID < pr.Recipients[j].GatewayID })
		w := map[string]policyPin{}
		for _, x := range pr.WAF {
			w[x.RevisionID] = x
		}
		pr.WAF = pr.WAF[:0]
		keys := []string{}
		for k := range w {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			pr.WAF = append(pr.WAF, w[k])
		}
		sp := map[string]SecretVersion{}
		for _, x := range pr.SecretVersions {
			sp[x.ID] = x
		}
		pr.SecretVersions = pr.SecretVersions[:0]
		keys = keys[:0]
		for k := range sp {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			pr.SecretVersions = append(pr.SecretVersions, sp[k])
		}
		pr.Groups = unique(pr.Groups)
		rp := map[string]rolescope.ResourceAuthority{}
		for _, x := range pr.Resources {
			rp[x.ResourceID] = x
		}
		pr.Resources = pr.Resources[:0]
		keys = keys[:0]
		for k := range rp {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			pr.Resources = append(pr.Resources, rp[k])
		}
		out.nodes[id] = pr
	}
	out.authors = unique(out.authors)
	return out, nil
}

func qualifiedNode(n inventory.Node, p *repository.QualifiedProfile) error {
	c := n.Capabilities
	platform := p.Profile.Platform
	if c.ProtocolVersion != inventory.ProtocolVersion || c.OS.ID != platform.OS || c.OS.VersionID != platform.OSVersion || c.OS.Architecture != platform.Arch || c.OS.Kernel != p.Evidence.HostKernel || c.Component == nil || c.Component.ProfileDigest != p.ProfileDigest || len(c.Component.Files) != len(p.Profile.Files) {
		return ErrUnavailable
	}
	files := map[string]string{}
	for _, f := range c.Component.Files {
		if files[f.Path] != "" {
			return ErrUnavailable
		}
		files[f.Path] = f.Digest
	}
	for _, f := range p.Profile.Files {
		if files[f.Path] != f.Digest {
			return ErrStale
		}
	}
	return nil
}

func readPolicy(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, id, site string, v *repository.VerifiedRelease, p *repository.QualifiedProfile, c *trustedConfig) (policyPin, string, error) {
	var raw, content, author, publication, publicationContent, qualification, report, head string
	var epoch int64
	err := securitystate.One(ctx, tx, `SELECT r.canonical_json,r.content_digest,r.created_by,p.id,p.content_digest,p.qualification_digest,p.authority_epoch,v.report_json,h.revision_id FROM config_waf_policy_revisions r JOIN config_waf_policy_publications p ON p.policy_revision_id=r.id JOIN config_waf_policy_approvals a ON a.id=p.approval_id JOIN config_waf_policy_validations v ON v.id=a.validation_id JOIN config_waf_policy_heads h ON h.policy_id=r.policy_id AND h.site_id=r.site_id WHERE r.id=? AND r.site_id=?`, []any{id, site}, func(r storage.IdentityRows) error {
		return r.Scan(&raw, &content, &author, &publication, &publicationContent, &qualification, &epoch, &report, &head)
	})
	if err != nil {
		return policyPin{}, "", err
	}
	policy, err := configmodel.ParseWafPolicy(strings.NewReader(raw), configmodel.JSON)
	if err != nil || hash(policy) != content || publicationContent != content || head != id || epoch != int64(h.Epoch) || len(policy.Spec.Exceptions) != 0 || !configmodel.ValidID(author) {
		return policyPin{}, "", ErrUnavailable
	}
	canon, err := configmodel.CanonicalJSON(policy)
	if err != nil || !bytes.Equal(canon, []byte(raw)) {
		return policyPin{}, "", ErrUnavailable
	}
	var validation configuration.WafPolicyValidation
	if configmodel.StrictJSON(strings.NewReader(report), &validation, 2<<20) != nil || !validation.Valid || validation.PolicyRevisionID != id || validation.ContentDigest != content || validation.Qualification == nil || ordinaryHash(validation.Qualification) != qualification || validation.QualificationDigest != qualification {
		return policyPin{}, "", ErrUnavailable
	}
	q := validation.Qualification
	if q.ContentDigest != content || q.ProfileID != p.Profile.ID || q.ProfileDigest != p.ProfileDigest || q.TupleDigest != p.TupleDigest || q.EvidenceDigest != p.EvidenceDigest || q.ManifestDigest != v.ManifestDigest || q.ReleaseSequence != v.Manifest.Signed.Sequence || q.RulesetVersionID != p.Profile.RulesetVersionID || q.RulesetDigest != p.RulesetDigest || !h.RecordedAt.Before(q.ExpiresAt) || q.ExpiresAt.After(v.ExpiresAt) || policy.Spec.RulesetVersionID != p.Profile.RulesetVersionID {
		return policyPin{}, "", ErrStale
	}
	compilerAllowed := false
	for _, b := range c.bindings {
		if b.Anchor.Installation.SiteID == site && b.Anchor.Installation.CompilerDigest == q.CompilerDigest {
			compilerAllowed = true
		}
	}
	if !compilerAllowed {
		return policyPin{}, "", ErrUnavailable
	}
	// Existing policy proof IDs deliberately hash the historical ordinary JSON
	// projection. Preserve that contract rather than silently normalizing it.
	copyQ := *q
	copyQ.ID = ""
	if q.ID != "wafq_"+strings.TrimPrefix(ordinaryHash(copyQ), "sha256:") {
		return policyPin{}, "", ErrUnavailable
	}
	return policyPin{id, content, publication, hash([]any{publication, publicationContent, qualification, epoch, validation})}, author, nil
}
func ordinaryHash(v any) string { b, _ := json.Marshal(v); return configmodel.DigestBytes(b) }

func currentNodeBoot(ctx context.Context, tx storage.IdentityTx, n inventory.Node) (string, error) {
	var raw string
	e := securitystate.One(ctx, tx, `SELECT observation_json FROM fleet_inventory_receipts WHERE id=? AND node_id=?`, []any{n.ReceiptID, n.ID}, func(r storage.IdentityRows) error { return r.Scan(&raw) })
	if e != nil {
		return "", e
	}
	var observation inventory.Observation
	if inventory.Decode(strings.NewReader(raw), &observation) != nil {
		return "", ErrCapture
	}
	return configmodel.DigestBytes([]byte(observation.BootID)), nil
}
