package configuration

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type ZonePreviewRequest struct {
	BaseRevisionID         string                              `json:"baseRevisionId"`
	CatalogSnapshotID      string                              `json:"catalogSnapshotId"`
	CapacityProfile        string                              `json:"capacityProfile"`
	Action                 string                              `json:"action"`
	ReplacementAssignments []configmodel.ReplacementAssignment `json:"replacementAssignments,omitempty"`
}

type ZonePin struct {
	ZoneRevisionID string `json:"zoneRevisionId"`
	ZoneID         string `json:"zoneId"`
	ContentDigest  string `json:"contentDigest"`
}

// ZonePreview is deliberately NOT WafZoneResolution. In particular it has no
// resolutionDigest and cannot be supplied to the materialization primitive.
// The inventory is an operator declaration and all assignments are hypothetical.
type ZonePreview struct {
	ID                string                     `json:"id"`
	Purpose           string                     `json:"purpose"`
	AuthorID          string                     `json:"authorId"`
	ZoneRevisionID    string                     `json:"zoneRevisionId"`
	SiteID            string                     `json:"siteId"`
	BaseRevisionID    string                     `json:"baseRevisionId"`
	ConfigDigest      string                     `json:"configDigest"`
	CatalogSnapshotID string                     `json:"catalogSnapshotId"`
	CatalogDigest     string                     `json:"catalogDigest"`
	ResolverDigest    string                     `json:"resolverDigest"`
	InventoryDigest   string                     `json:"inventoryDigest"`
	HeadsDigest       string                     `json:"headsDigest"`
	PreviewDigest     string                     `json:"previewDigest"`
	CapacityProfile   string                     `json:"capacityProfile"`
	Action            string                     `json:"action"`
	AssignmentSource  string                     `json:"assignmentSource"`
	AuthoringValid    bool                       `json:"authoringValid"`
	Deployable        bool                       `json:"deployable"`
	Pins              []ZonePin                  `json:"pins"`
	Members           []configmodel.ZoneMember   `json:"members"`
	Conflicts         []configmodel.ZoneConflict `json:"conflicts"`
	Issues            []configmodel.Issue        `json:"issues"`
	CreatedAt         time.Time                  `json:"createdAt"`
	ExpiresAt         time.Time                  `json:"expiresAt"`
}

const zoneAuthoringAlgorithm = "agp.waf-zone-authoring/v1alpha1"

func readZonePreview(ctx context.Context, tx storage.IdentityTx, id string) (*ZonePreview, error) {
	if !validID.MatchString(id) {
		return nil, ErrInvalidRequest
	}
	var raw, expected, zoneID, site, base, catalog, author string
	err := securitystate.One(ctx, tx, `SELECT report_json,preview_digest,zone_revision_id,site_id,base_revision_id,catalog_id,created_by FROM config_zone_previews WHERE id=?`, []any{id}, func(r storage.IdentityRows) error {
		return r.Scan(&raw, &expected, &zoneID, &site, &base, &catalog, &author)
	})
	if err != nil {
		return nil, err
	}
	out := &ZonePreview{}
	if err = json.Unmarshal([]byte(raw), out); err != nil {
		return nil, err
	}
	actual, err := zonePreviewDigest(*out)
	if err != nil {
		return nil, err
	}
	if actual != expected || out.PreviewDigest != expected || out.ID != id || out.ZoneRevisionID != zoneID || out.SiteID != site || out.BaseRevisionID != base || out.CatalogSnapshotID != catalog || out.Purpose != "authoring_preview" || out.AuthorID != author || out.Deployable {
		return nil, fmt.Errorf("zone preview integrity mismatch")
	}
	return out, nil
}

func zonePreviewDigest(report ZonePreview) (string, error) {
	// Omit only the digest itself. The purpose, absence of runtime qualification,
	// complete membership, exact pins and expiry all belong to the digest.
	raw, err := json.Marshal(report)
	if err != nil {
		return "", err
	}
	var value map[string]any
	if err = json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	delete(value, "previewDigest")
	return configmodel.Digest(value)
}

func (s *Service) GetZonePreview(ctx context.Context, a Actor, id string) (out *ZonePreview, err error) {
	err = s.transactScoped(ctx, a, false, func(tx storage.IdentityTx, p *Principal) error {
		out, err = readZonePreview(ctx, tx, id)
		if err != nil {
			return err
		}
		if e := authorizeZonePreview(ctx, tx, p, out, "config.read"); e != nil {
			return storage.ErrNotFound
		}
		return nil
	})
	return
}

func (s *Service) PreviewZone(ctx context.Context, a Actor, id, key string, in ZonePreviewRequest) (out *ZonePreview, err error) {
	if !validID.MatchString(id) || !validID.MatchString(in.BaseRevisionID) || !validID.MatchString(in.CatalogSnapshotID) || (in.CapacityProfile != "pilot-500" && in.CapacityProfile != "fleet-10k") || (in.Action != "reconcile" && in.Action != "retire") || len(in.ReplacementAssignments) > 10000 {
		return nil, ErrInvalidRequest
	}
	// Reordering the same set is a retry, never a different operation.
	in.ReplacementAssignments = append([]configmodel.ReplacementAssignment{}, in.ReplacementAssignments...)
	sort.Slice(in.ReplacementAssignments, func(i, j int) bool {
		return in.ReplacementAssignments[i].GatewayID < in.ReplacementAssignments[j].GatewayID
	})
	for i, r := range in.ReplacementAssignments {
		if !validID.MatchString(r.GatewayID) || !validID.MatchString(r.ZoneRevisionID) || (i > 0 && in.ReplacementAssignments[i-1].GatewayID == r.GatewayID) {
			return nil, ErrInvalidRequest
		}
	}
	op := "zone.preview:" + id
	fp := digest(in)
	var target *ZoneRevision
	var doc *configmodel.Document
	var catalog *configmodel.CatalogDocument
	var frozen []*ZoneRevision
	var headsDigest string
	err = s.transactScoped(ctx, a, true, func(tx storage.IdentityTx, p *Principal) error {
		actor := p.ID
		var e error
		target, e = readZoneRevision(ctx, tx, id)
		if e != nil {
			return e
		}
		if e = p.Require("config.edit", target.SiteID); e != nil {
			return storage.ErrNotFound
		}
		if e = validateZoneOwner(ctx, tx, target.OwnerID); e != nil {
			return e
		}
		doc, e = baseDocument(ctx, tx, in.BaseRevisionID)
		if e != nil {
			return e
		}
		if e = authorizeZoneGateways(ctx, tx, p, doc, target.SiteID, "config.edit"); e != nil {
			return storage.ErrNotFound
		}
		h, e := request(ctx, tx, actor, op, key, fp)
		if e != nil {
			return e
		}
		if h != nil {
			out, e = readZonePreview(ctx, tx, h.id)
			return e
		}
		if doc.Capacity.Profile != in.CapacityProfile {
			return zoneIssue("/capacityProfile", "capacity_profile_mismatch", "Explicit capacity profile must match the exact Configuration revision")
		}
		catalog, e = loadCatalog(ctx, tx, in.CatalogSnapshotID)
		if e != nil {
			return e
		}
		if e = validateGroups(ctx, tx, catalog.Catalog); e != nil {
			return e
		}
		headsDigest, e = zoneHeadsDigest(ctx, tx, target.SiteID)
		if e != nil {
			return e
		}
		frozen, e = zoneHeadRevisions(ctx, tx, target.SiteID)
		if e != nil {
			return e
		}
		// Freeze both sides of every changed stable zone. A receiving revision
		// may exclude one of its own former members; its exact parent is just as
		// necessary as the target parent's body for the complete old closure.
		byID := map[string]*ZoneRevision{}
		frozenBytes := 0
		for _, z := range frozen {
			byID[z.ID] = z
			frozenBytes += len(z.Content)
		}
		loadExact := func(exact string) (*ZoneRevision, error) {
			if z := byID[exact]; z != nil {
				return z, nil
			}
			z, e := readZoneRevision(ctx, tx, exact)
			if e != nil {
				return nil, e
			}
			if z.SiteID != target.SiteID {
				return nil, zoneIssue("/replacementAssignments", "waf_zone_site_mismatch", "All pinned authoring zones must belong to the same Site")
			}
			frozenBytes += len(z.Content)
			if frozenBytes > 64<<20 || len(frozen) >= 2000 {
				return nil, zoneIssue("/replacementAssignments", "zone_preview_capacity_exceeded", "Complete pinned authoring inventory exceeds 64 MiB or 2000 exact revisions")
			}
			frozen = append(frozen, z)
			byID[exact] = z
			return z, nil
		}
		changedIDs := append([]string{id}, replacementZoneIDs(in.ReplacementAssignments)...)
		for _, exact := range changedIDs {
			z, e := loadExact(exact)
			if e != nil {
				return e
			}
			if z.BaseRevisionID == "" || (exact == id && in.Action == "retire") {
				continue
			}
			parent, e := loadExact(z.BaseRevisionID)
			if e != nil {
				return e
			}
			if parent.ZoneID != z.ZoneID || parent.SiteID != z.SiteID || parent.OwnerID != z.OwnerID {
				return fmt.Errorf("zone parent identity mismatch")
			}
		}
		return nil
	})
	if err != nil || out != nil {
		return out, err
	}
	out, err = s.compileZonePreview(ctx, target, doc, catalog, frozen, in, headsDigest)
	if err != nil {
		return nil, err
	}
	err = s.transactScoped(ctx, a, true, func(tx storage.IdentityTx, p *Principal) error {
		actor := p.ID
		if e := authorizeZonePreview(ctx, tx, p, out, "config.edit"); e != nil {
			return storage.ErrNotFound
		}
		h, e := request(ctx, tx, actor, op, key, fp)
		if e != nil {
			return e
		}
		if h != nil {
			out, e = readZonePreview(ctx, tx, h.id)
			return e
		}
		if e = validateZoneOwner(ctx, tx, target.OwnerID); e != nil {
			return e
		}
		if e = validateGroups(ctx, tx, catalog.Catalog); e != nil {
			return e
		}
		out.AuthorID = actor
		out.PreviewDigest, e = zonePreviewDigest(*out)
		if e != nil {
			return e
		}
		if e = saveZonePreview(ctx, tx, actor, out); e != nil {
			return e
		}
		return remember(ctx, tx, actor, op, key, fp, responseHandle{"zone_preview", out.ID, 0})
	})
	return
}

func authorizeZoneGateways(ctx context.Context, tx storage.IdentityTx, p *Principal, doc *configmodel.Document, site, permission string) error {
	if err := p.Require(permission, site); err != nil {
		return err
	}
	for _, g := range doc.Configuration.Gateways {
		if g.Metadata.SiteID == site {
			if err := p.RequireGateway(ctx, tx, permission, g); err != nil {
				return err
			}
		}
	}
	return nil
}

func authorizeZonePreview(ctx context.Context, tx storage.IdentityTx, p *Principal, out *ZonePreview, permission string) error {
	if err := p.Require(permission, out.SiteID); err != nil {
		return err
	}
	target, err := readZoneRevision(ctx, tx, out.ZoneRevisionID)
	if err != nil {
		return err
	}
	if err = validateZoneOwner(ctx, tx, target.OwnerID); err != nil {
		return err
	}
	doc, err := baseDocument(ctx, tx, out.BaseRevisionID)
	if err != nil {
		return err
	}
	return authorizeZoneGateways(ctx, tx, p, doc, out.SiteID, permission)
}

func replacementZoneIDs(in []configmodel.ReplacementAssignment) []string {
	out := make([]string, 0, len(in))
	for _, r := range in {
		out = append(out, r.ZoneRevisionID)
	}
	return out
}

func saveZonePreview(ctx context.Context, tx storage.IdentityTx, actor string, report *ZonePreview) error {
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	if len(raw) > 64<<20 {
		return zoneIssue("", "zone_preview_capacity_exceeded", "Complete zone preview exceeds the 64 MiB report envelope")
	}
	_, err = tx.Exec(ctx, `INSERT INTO config_zone_previews(id,zone_revision_id,site_id,base_revision_id,catalog_id,preview_digest,report_json,created_by,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, report.ID, report.ZoneRevisionID, report.SiteID, report.BaseRevisionID, report.CatalogSnapshotID, report.PreviewDigest, string(raw), actor, report.CreatedAt, report.ExpiresAt)
	if err != nil {
		return err
	}
	return securitystate.Audit(ctx, tx, "config.zone.preview.completed", actor, map[string]any{"previewId": report.ID, "zoneRevisionId": report.ZoneRevisionID, "siteId": report.SiteID, "previewDigest": report.PreviewDigest, "authoringValid": report.AuthoringValid, "deployable": false})
}

func (s *Service) compileZonePreview(ctx context.Context, target *ZoneRevision, doc *configmodel.Document, catalog *configmodel.CatalogDocument, frozen []*ZoneRevision, in ZonePreviewRequest, headsDigest string) (*ZonePreview, error) {
	siteExists := false
	for _, site := range catalog.Catalog.Sites {
		if site.ID == target.SiteID {
			siteExists = true
		}
	}
	if !siteExists {
		return nil, zoneIssue("/catalogSnapshotId", "waf_zone_site_mismatch", "The declared catalog does not contain this zone's Site")
	}
	// PostgreSQL timestamps preserve microseconds. Freeze one common instant
	// before hashing/encoding so JSON, SQL and review expiry remain identical.
	created := time.Now().UTC().Truncate(time.Microsecond)
	out := &ZonePreview{ID: securitystate.ID("zone_preview"), Purpose: "authoring_preview", ZoneRevisionID: target.ID, SiteID: target.SiteID, BaseRevisionID: in.BaseRevisionID, ConfigDigest: doc.Digest, CatalogSnapshotID: catalog.Catalog.ID, CatalogDigest: catalog.Digest, HeadsDigest: headsDigest, CapacityProfile: in.CapacityProfile, Action: in.Action, AssignmentSource: "hypothetical_authoring_membership", AuthoringValid: true, Deployable: false, Pins: []ZonePin{}, Members: []configmodel.ZoneMember{}, Conflicts: []configmodel.ZoneConflict{}, Issues: []configmodel.Issue{}, CreatedAt: created}
	out.ExpiresAt = out.CreatedAt.Add(30 * time.Minute)
	var err error
	out.ResolverDigest, err = s.zoneResolverDigest()
	if err != nil {
		return nil, err
	}
	orderedPins := append([]*ZoneRevision{}, frozen...)
	sort.Slice(orderedPins, func(i, j int) bool { return orderedPins[i].ID < orderedPins[j].ID })
	for _, z := range orderedPins {
		out.Pins = append(out.Pins, ZonePin{ZoneRevisionID: z.ID, ZoneID: z.ZoneID, ContentDigest: z.ContentDigest})
	}
	out.InventoryDigest, err = configmodel.Digest(struct {
		Purpose, AssignmentSource, ConfigDigest, CatalogDigest, ResolverDigest, HeadsDigest string
		Pins                                                                                []ZonePin
		Request                                                                             ZonePreviewRequest
	}{out.Purpose, out.AssignmentSource, out.ConfigDigest, out.CatalogDigest, out.ResolverDigest, out.HeadsDigest, out.Pins, in})
	if err != nil {
		return nil, err
	}
	out.Members, out.Conflicts, err = hypotheticalZoneMembership(ctx, target, doc, catalog, frozen, in, out.CreatedAt, s.compiler.MinimumWAFMode)
	if err != nil {
		return nil, err
	}
	for _, c := range out.Conflicts {
		out.Issues = append(out.Issues, configmodel.Issue{Path: c.Path, Code: c.Code, Message: c.Message, Severity: "error"})
	}
	out.AuthoringValid = len(out.Conflicts) == 0
	out.Issues = append(out.Issues,
		configmodel.Issue{Path: "", Code: "native_qualification_required", Message: "Operator-declared inputs and authored zones provide no native WAF qualification or publication evidence", Severity: "error"},
		configmodel.Issue{Path: "", Code: "hypothetical_assignments", Message: "Membership is a hypothetical authoring proposal; this Configuration has no trusted runtime zone-assignment provenance", Severity: "warning"})
	out.PreviewDigest, err = zonePreviewDigest(*out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// hypotheticalZoneMembership is an explicitly isolated authoring adapter. The
// resolver's Published flag is set ONLY on private ephemeral copies to exercise
// its membership checks. Neither these copies nor a runtime resolution escape
// this function. Stored revisions remain draft, reports remain nondeployable.
func hypotheticalZoneMembership(ctx context.Context, target *ZoneRevision, doc *configmodel.Document, catalog *configmodel.CatalogDocument, frozen []*ZoneRevision, in ZonePreviewRequest, created time.Time, minimumMode string) ([]configmodel.ZoneMember, []configmodel.ZoneConflict, error) {
	byID := map[string]configmodel.ZoneRevision{}
	selected := map[string]configmodel.ZoneRevision{}
	for _, z := range frozen {
		var body configmodel.WafZone
		if err := json.Unmarshal(z.Content, &body); err != nil {
			return nil, nil, err
		}
		ephemeral := configmodel.ZoneRevision{ID: z.ID, Digest: z.ContentDigest, Content: body, Published: true}
		byID[z.ID] = ephemeral
		// The supplied slice starts with one current head per stable zone;
		// explicit historical dependencies are excluded from this selection.
		if _, ok := selected[z.ZoneID]; !ok {
			selected[z.ZoneID] = ephemeral
		}
	}
	if err := boundZonePreviewWork(doc.Configuration, catalog.Catalog, zonesFromMap(byID)); err != nil {
		return nil, nil, err
	}
	gatewaySets := map[string]map[string]bool{}
	for id, z := range byID {
		if z.Content.Spec.Membership.GatewayIDs != nil {
			set := make(map[string]bool, len(z.Content.Spec.Membership.GatewayIDs))
			for _, gatewayID := range z.Content.Spec.Membership.GatewayIDs {
				set[gatewayID] = true
			}
			gatewaySets[id] = set
		}
	}
	chosen := byID[target.ID]
	// Capture the Site's immutable authoring heads before replacing any of
	// them. Each changed stable zone is compared with its own exact parent,
	// including receiving zones selected through replacementAssignments.
	before := map[string]configmodel.ZoneRevision{}
	for stable, z := range selected {
		before[stable] = z
	}
	changed := map[string]configmodel.ZoneRevision{target.ZoneID: chosen}
	for _, r := range in.ReplacementAssignments {
		z := byID[r.ZoneRevisionID]
		if z.ID == "" {
			return nil, nil, storage.ErrNotFound
		}
		stable := z.Content.Metadata.ID
		if old, ok := changed[stable]; ok && old.ID != z.ID {
			return nil, nil, zoneIssue("/replacementAssignments", "waf_zone_lineage_conflict", "Replacement revisions disagree for one stable zone")
		}
		if stable == target.ZoneID && in.Action == "retire" {
			return nil, nil, zoneIssue("/replacementAssignments", "waf_zone_lineage_conflict", "A retiring zone cannot receive replacement assignments")
		}
		changed[stable] = z
	}
	parents := map[string]string{}
	for _, z := range frozen {
		parents[z.ID] = z.BaseRevisionID
	}
	affectedStable := map[string]bool{}
	for stable, z := range changed {
		affectedStable[stable] = true
		selected[stable] = z
		if stable == target.ZoneID && in.Action == "retire" {
			before[stable] = chosen
			delete(selected, stable)
		} else if parentID := parents[z.ID]; parentID == "" {
			delete(before, stable)
		} else {
			parent, ok := byID[parentID]
			if !ok || parent.Content.Metadata.ID != stable || parent.Content.Metadata.SiteID != target.SiteID {
				return nil, nil, fmt.Errorf("incomplete frozen zone parent closure")
			}
			before[stable] = parent
		}
	}
	current := map[string]string{}
	for _, g := range doc.Configuration.Gateways {
		if g.Metadata.SiteID != target.SiteID {
			continue
		}
		matches, defaults := authoringZoneMatches(g, before, gatewaySets)
		if len(matches) == 0 {
			matches = defaults
		}
		if len(matches) == 1 {
			current[g.Metadata.ID] = matches[0].ID
		}
	}
	zones := make([]configmodel.ZoneRevision, 0, len(byID))
	for _, z := range byID {
		zones = append(zones, z)
	}
	if err := boundZonePreviewExpansion(doc.Configuration, catalog.Catalog, target.SiteID); err != nil {
		return nil, nil, err
	}
	resolved, err := configmodel.ResolveZones(ctx, doc.Configuration, catalog.Catalog, configmodel.ResolveRequest{ID: "authoring_adapter", SiteID: target.SiteID, ZoneRevisionID: target.ID, BaseConfigRevisionID: in.BaseRevisionID, Action: in.Action, CapacityProfile: in.CapacityProfile, CreatedAt: created, CurrentAssignments: current, ReplacementAssignments: in.ReplacementAssignments, ZoneRevisions: zones, AllowLegacyMigration: true})
	if err != nil {
		return nil, nil, err
	}
	priorMembers := map[string]configmodel.ZoneMember{}
	for _, m := range resolved.Members {
		priorMembers[m.GatewayID] = m
	}
	policy := map[string]configmodel.CatalogInput{}
	for _, p := range catalog.Catalog.Inputs {
		if p.Kind == "waf_policy" {
			policy[p.ID] = p
		}
	}
	replacements := map[string]string{}
	for _, r := range in.ReplacementAssignments {
		replacements[r.GatewayID] = r.ZoneRevisionID
	}
	members, conflicts := []configmodel.ZoneMember{}, []configmodel.ZoneConflict{}
	for _, g := range doc.Configuration.Gateways {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if g.Metadata.SiteID != target.SiteID {
			continue
		}
		matches, defaults := authoringZoneMatches(g, selected, gatewaySets)
		candidate := matches
		if len(candidate) == 0 {
			candidate = defaults
		}
		source := byID[current[g.Metadata.ID]]
		previousMatches, previousDefaults := authoringZoneMatches(g, before, gatewaySets)
		if len(previousMatches) == 0 {
			previousMatches = previousDefaults
		}
		previousAmbiguityAffected := false
		if len(previousMatches) > 1 {
			for _, z := range previousMatches {
				if affectedStable[z.Content.Metadata.ID] {
					previousAmbiguityAffected = true
				}
			}
		}
		affected := previousAmbiguityAffected || (source.ID != "" && affectedStable[source.Content.Metadata.ID])
		if zoneMatchesGateway(chosen, g, gatewaySets) && (chosen.Content.Spec.Membership.SiteDefault == nil || len(matches) == 0) {
			affected = true
		}
		for _, z := range candidate {
			if affectedStable[z.Content.Metadata.ID] {
				affected = true
			}
		}
		if replacements[g.Metadata.ID] != "" {
			affected = true
		}
		if !affected {
			continue
		}
		member, ok := priorMembers[g.Metadata.ID]
		if !ok {
			member = authoringZoneMember(g, catalog.Catalog.Nodes, current[g.Metadata.ID])
		}
		member.Disposition = "conflict"
		member.TargetZoneRevisionID, member.TargetPolicyRevisionID, member.TargetBindingDigest = "", "", ""
		code, message := "", ""
		candidateIDs := []string{}
		var destination configmodel.ZoneRevision
		switch {
		case len(candidate) > 1:
			code, message = "waf_zone_ambiguous", "Several authored zones match; explicit membership has no priority over selectors or defaults"
			for _, z := range candidate {
				candidateIDs = append(candidateIDs, z.ID)
			}
		case len(candidate) == 0:
			code, message = "waf_zone_unassigned", "No ordinary authored zone or unique Site default matches"
		default:
			destination = candidate[0]
		}
		if code == "" && previousAmbiguityAffected {
			code, message = "waf_zone_lineage_conflict", "Previous hypothetical membership is ambiguous; leaving members cannot be omitted from the authoring closure"
		}
		leaving := source.ID != "" && affectedStable[source.Content.Metadata.ID] && destination.Content.Metadata.ID != source.Content.Metadata.ID
		if code == "" && leaving && replacements[g.Metadata.ID] == "" {
			code, message = "waf_zone_replacement_required", "Leaving a hypothetical zone requires an explicit safe replacement"
		}
		if code == "" && replacements[g.Metadata.ID] != "" && replacements[g.Metadata.ID] != destination.ID {
			code, message = "waf_zone_ambiguous", "Replacement must satisfy unique ordinary membership"
		}
		if code == "" {
			p, ok := policy[destination.Content.Spec.PolicyRevisionID]
			if !ok || p.SiteID != target.SiteID || p.State != "published" {
				code, message = "waf_zone_policy_not_published", "Exact same-Site policy is absent from the declared authoring catalog"
			} else if p.BaseExceptionCount != 0 {
				code, message = "waf_zone_base_exceptions", "A shared zone base policy cannot contain route exceptions"
			}
		}
		if code == "" {
			for _, route := range g.Spec.Routes {
				if len(route.WAFExceptionIDs) > 0 {
					code, message = "waf_zone_lineage_conflict", "Local exceptions require qualified derivation and three-way rebase evidence"
					break
				}
			}
		}
		if code == "" && (len(member.NodeIDs) == 0 || !authoringCompleteNodes(g, catalog.Catalog.Nodes)) {
			code, message = "waf_zone_node_unresolved", "Gateway resolves to no complete declared node target set"
		}
		if code == "" && minimumMode == "blocking" && destination.Content.Spec.Mode != "blocking" {
			code, message = "waf_zone_security_minimum", "Zone mode falls below the server's required WAF minimum"
		}
		if code == "" {
			binding := configmodel.WAFBinding{Engine: "modsecurity", PolicyRevisionID: destination.Content.Spec.PolicyRevisionID, Mode: destination.Content.Spec.Mode}
			member.Disposition = "inherited"
			member.TargetZoneRevisionID = destination.ID
			member.TargetPolicyRevisionID = binding.PolicyRevisionID
			member.TargetBindingDigest, err = configmodel.Digest(binding)
			if err != nil {
				return nil, nil, err
			}
		} else {
			conflict := configmodel.ZoneConflict{GatewayID: g.Metadata.ID, Code: code, Path: "/gateways/" + g.Metadata.ID, Message: message}
			if len(candidateIDs) > 0 && len(candidateIDs) <= 100 {
				sort.Strings(candidateIDs)
				conflict.CandidateZoneRevisionIDs = candidateIDs
			}
			conflicts = append(conflicts, conflict)
		}
		members = append(members, member)
	}
	if in.CapacityProfile == "pilot-500" && len(members) > 500 {
		return nil, nil, zoneIssue("/members", "zone_preview_capacity_exceeded", "pilot-500 permits at most 500 complete members")
	}
	sort.Slice(members, func(i, j int) bool { return members[i].GatewayID < members[j].GatewayID })
	sort.Slice(conflicts, func(i, j int) bool {
		return conflicts[i].GatewayID+"/"+conflicts[i].Code < conflicts[j].GatewayID+"/"+conflicts[j].Code
	})
	return members, conflicts, nil
}

func authoringZoneMatches(g configmodel.Gateway, selected map[string]configmodel.ZoneRevision, gatewaySets map[string]map[string]bool) (matches, defaults []configmodel.ZoneRevision) {
	matches, defaults = []configmodel.ZoneRevision{}, []configmodel.ZoneRevision{}
	for _, z := range selected {
		if z.Content.Spec.Membership.SiteDefault != nil {
			defaults = append(defaults, z)
		} else if zoneMatchesGateway(z, g, gatewaySets) {
			matches = append(matches, z)
		}
	}
	return
}

func zoneMatchesGateway(revision configmodel.ZoneRevision, g configmodel.Gateway, gatewaySets map[string]map[string]bool) bool {
	z := revision.Content
	if z.Metadata.SiteID != g.Metadata.SiteID {
		return false
	}
	m := z.Spec.Membership
	if m.SiteDefault != nil {
		return true
	}
	if m.GatewayIDs != nil {
		return gatewaySets[revision.ID][g.Metadata.ID]
	}
	return authoringLabels(*m.MatchLabels, g.Metadata.Labels)
}

func authoringLabels(selector, labels configmodel.Labels) bool {
	for key, value := range selector {
		if labels[key] != value {
			return false
		}
	}
	return true
}

func authoringZoneMember(g configmodel.Gateway, nodes []configmodel.CatalogNode, source string) configmodel.ZoneMember {
	binding, _ := configmodel.Digest(g.Spec.WAF)
	m := configmodel.ZoneMember{GatewayID: g.Metadata.ID, RouteIDs: []string{}, NodeIDs: []string{}, SourceZoneRevisionID: source, SourcePolicyRevisionID: g.Spec.WAF.PolicyRevisionID, BaseBindingDigest: binding, Disposition: "conflict"}
	for _, route := range g.Spec.Routes {
		m.RouteIDs = append(m.RouteIDs, route.ID)
	}
	explicitNodes := make(map[string]bool, len(g.Spec.NodeSelector.NodeIDs))
	for _, id := range g.Spec.NodeSelector.NodeIDs {
		explicitNodes[id] = true
	}
	for _, node := range nodes {
		if node.SiteID != g.Metadata.SiteID {
			continue
		}
		if g.Spec.NodeSelector.NodeIDs != nil {
			if explicitNodes[node.ID] {
				m.NodeIDs = append(m.NodeIDs, node.ID)
			}
		} else if authoringLabels(*g.Spec.NodeSelector.MatchLabels, node.Labels) {
			m.NodeIDs = append(m.NodeIDs, node.ID)
		}
	}
	sort.Strings(m.RouteIDs)
	sort.Strings(m.NodeIDs)
	return m
}

func authoringCompleteNodes(g configmodel.Gateway, nodes []configmodel.CatalogNode) bool {
	if g.Spec.NodeSelector.NodeIDs == nil {
		return true
	}
	found := map[string]bool{}
	for _, n := range nodes {
		if n.SiteID == g.Metadata.SiteID {
			found[n.ID] = true
		}
	}
	for _, id := range g.Spec.NodeSelector.NodeIDs {
		if !found[id] {
			return false
		}
	}
	return true
}

// Bound the largest Site closure before ResolveZones allocates its member
// slices. A selector can repeat all 500 node IDs for every Gateway; checking
// only the final encoded report would detect that expansion too late.
func boundZonePreviewExpansion(c configmodel.Configuration, catalog configmodel.Catalog, site string) error {
	budget := 0
	for _, g := range c.Gateways {
		if g.Metadata.SiteID != site {
			continue
		}
		budget += 4096 // scalar pins, member envelope and conflict/issue diagnostics
		for _, route := range g.Spec.Routes {
			budget += len(route.ID) + 3
		}
		explicitNodes := make(map[string]bool, len(g.Spec.NodeSelector.NodeIDs))
		for _, id := range g.Spec.NodeSelector.NodeIDs {
			explicitNodes[id] = true
		}
		for _, node := range catalog.Nodes {
			if node.SiteID != site {
				continue
			}
			matches := false
			if g.Spec.NodeSelector.NodeIDs != nil {
				matches = explicitNodes[node.ID]
			} else {
				matches = authoringLabels(*g.Spec.NodeSelector.MatchLabels, node.Labels)
			}
			if matches {
				budget += len(node.ID) + 3
			}
		}
		if budget > 64<<20 {
			return zoneIssue("/members", "zone_preview_capacity_exceeded", "Potential complete Site membership exceeds the 64 MiB preview budget")
		}
	}
	return nil
}

func (s *Service) zoneResolverDigest() (string, error) {
	return configmodel.Digest(map[string]any{"algorithm": zoneAuthoringAlgorithm, "compilerOptions": s.compiler})
}

func zonesFromMap(byID map[string]configmodel.ZoneRevision) []configmodel.ZoneRevision {
	zones := make([]configmodel.ZoneRevision, 0, len(byID))
	for _, zone := range byID {
		zones = append(zones, zone)
	}
	return zones
}

// Work admission is independent of elapsed time and checked before allocating
// membership indices or entering Gateway x Zone loops. It deliberately bounds
// hypothetical authoring; it is not a runtime qualification or fleet SLO.
func boundZonePreviewWork(c configmodel.Configuration, catalog configmodel.Catalog, zones []configmodel.ZoneRevision) error {
	const maximumWork uint64 = 64 << 20
	const maximumExplicitIDs uint64 = 1 << 20
	var zoneChecks, explicitIDs, gatewayCount, nodeChecks uint64
	for _, z := range zones {
		zoneChecks++
		explicitIDs += uint64(len(z.Content.Spec.Membership.GatewayIDs))
		if z.Content.Spec.Membership.MatchLabels != nil {
			zoneChecks += uint64(len(*z.Content.Spec.Membership.MatchLabels))
		}
	}
	for _, g := range c.Gateways {
		gatewayCount++
		nodeChecks += uint64(len(g.Spec.NodeSelector.NodeIDs))
		if g.Spec.NodeSelector.MatchLabels != nil {
			nodeChecks += uint64(len(catalog.Nodes)) * uint64(len(*g.Spec.NodeSelector.MatchLabels))
		}
	}
	// before selection, core resolver, after selection and old-closure checks.
	work := 4*gatewayCount*zoneChecks + 3*gatewayCount*uint64(len(catalog.Nodes)) + nodeChecks + explicitIDs
	if explicitIDs > maximumExplicitIDs || work > maximumWork {
		return zoneIssue("/members", "zone_capacity_exceeded", "Hypothetical authoring inventory exceeds the bounded membership work budget")
	}
	return nil
}
