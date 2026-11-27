package configuration

import (
	"bytes"
	"context"
	"sort"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// TrustedInventory is an installation-owned, read-only observation boundary.
// Current runs inside the caller's already fenced identity transaction. It must
// refresh certificate authorization, revocation, epoch, observation freshness and
// the signed component closure without recursively opening another transaction.
// Its digest binds stable facts, not heartbeat receipt IDs or lease timestamps.
type TrustedInventory interface {
	Current(context.Context, storage.IdentityTx, securityjournal.UInt63, string, []WAFQualification) (*TrustedInventorySnapshot, error)
}
type TrustedInventorySnapshot struct {
	Nodes        []configmodel.CatalogNode `json:"nodes"`
	SourceDigest string                    `json:"sourceDigest"`
}

func (s *Service) WithTrustedInventory(source TrustedInventory) *Service {
	s.trustedInventory = source
	return s
}

type ZoneValidation struct {
	ID                  string              `json:"id"`
	ZoneRevisionID      string              `json:"zoneRevisionId"`
	ContentDigest       string              `json:"contentDigest"`
	PolicyRevisionID    string              `json:"policyRevisionId"`
	PolicyPublicationID string              `json:"policyPublicationId"`
	Qualification       *WAFQualification   `json:"qualification"`
	DependencyDigest    string              `json:"dependencyDigest"`
	Valid               bool                `json:"valid"`
	Current             bool                `json:"current"`
	Deployable          bool                `json:"deployable"`
	Issues              []configmodel.Issue `json:"issues"`
	CreatedAt           time.Time           `json:"createdAt"`
	ExpiresAt           time.Time           `json:"expiresAt"`
}
type zoneRecord struct {
	revision *ZoneRevision
	zone     *configmodel.WafZone
	author   string
	number   int64
}

func loadZoneRecord(ctx context.Context, tx storage.IdentityTx, id string) (*zoneRecord, error) {
	r, e := readZoneRevision(ctx, tx, id)
	if e != nil {
		return nil, e
	}
	z, e := configmodel.ParseWafZone(bytes.NewReader(r.Content), configmodel.JSON)
	if e != nil {
		return nil, e
	}
	out := &zoneRecord{revision: r, zone: z}
	e = securitystate.One(ctx, tx, `SELECT created_by,revision_number FROM config_zone_revisions WHERE id=?`, []any{id}, func(rows storage.IdentityRows) error { return rows.Scan(&out.author, &out.number) })
	return out, e
}

func zoneHeadCurrent(ctx context.Context, tx storage.IdentityTx, r *zoneRecord) error {
	var head string
	e := securitystate.One(ctx, tx, `SELECT revision_id FROM config_zone_heads WHERE zone_id=? AND site_id=?`, []any{r.revision.ZoneID, r.revision.SiteID}, func(rows storage.IdentityRows) error { return rows.Scan(&head) })
	if e != nil {
		return e
	}
	if head != r.revision.ID {
		return ErrRevisionMismatch
	}
	return nil
}

type publishedPolicyPin struct {
	record        *wafPolicyRecord
	publicationID string
	proof         WAFQualification
}

// Publication is a historical fact. Consumption rechecks its exact proof and
// current authority epoch, not the now-expired publication approval or a mutable
// authoring head. An unrelated successor draft cannot invalidate an exact pin.
func (s *Service) publishedZonePolicy(ctx context.Context, tx storage.IdentityTx, p *Principal, id, site string, caches ...map[string]*publishedPolicyPin) (*publishedPolicyPin, error) {
	if len(caches) > 0 {
		if pin := caches[0][id]; pin != nil && pin.record.siteID == site {
			return pin, nil
		}
	}
	r, e := readWafPolicyRecord(ctx, tx, id)
	if e != nil {
		return nil, e
	}
	if r.siteID != site {
		return nil, storage.ErrNotFound
	}
	if len(r.policy.Spec.Exceptions) != 0 {
		return nil, zoneIssue("/policyRevisionId", "waf_zone_base_exceptions", "An exact published same-Site base policy with no exceptions is required")
	}
	var publication, approval, content, proofDigest string
	var epoch int64
	e = securitystate.One(ctx, tx, `SELECT id,approval_id,authority_epoch,content_digest,qualification_digest FROM config_waf_policy_publications WHERE policy_revision_id=?`, []any{id}, func(rows storage.IdentityRows) error {
		return rows.Scan(&publication, &approval, &epoch, &content, &proofDigest)
	})
	if e != nil {
		return nil, e
	}
	a, e := readWafApproval(ctx, tx, approval)
	if e != nil {
		return nil, e
	}
	v, e := loadWafPolicyValidation(ctx, tx, a.validationID)
	if e != nil {
		return nil, e
	}
	if epoch != p.Epoch || a.epoch != p.Epoch || v.epoch != p.Epoch || content != r.revision.ContentDigest || a.revisionID != id || a.contentDigest != content || a.qualificationDigest != proofDigest || v.report.PolicyRevisionID != id || v.report.ContentDigest != content || v.report.QualificationDigest != proofDigest {
		return nil, storage.ErrConflict
	}
	if e = s.wafProofCurrent(ctx, r, v.report.Qualification); e != nil {
		return nil, e
	}
	pin := &publishedPolicyPin{record: r, publicationID: publication, proof: *v.report.Qualification}
	if len(caches) > 0 {
		caches[0][id] = pin
	}
	return pin, nil
}
func (s *Service) zoneDependency(ctx context.Context, tx storage.IdentityTx, p *Principal, r *zoneRecord, caches ...map[string]*publishedPolicyPin) (*publishedPolicyPin, string, error) {
	if e := validateZoneOwner(ctx, tx, r.revision.OwnerID); e != nil {
		return nil, "", e
	}
	for _, gatewayID := range r.zone.Spec.Membership.GatewayIDs {
		var site string
		err := securitystate.One(ctx, tx, `SELECT site_id FROM config_gateway_ownership WHERE gateway_id=?`, []any{gatewayID}, func(rows storage.IdentityRows) error { return rows.Scan(&site) })
		if err == storage.ErrNotFound || (err == nil && site != r.revision.SiteID) {
			return nil, "", zoneIssue("/spec/membership/gatewayIds", "waf_zone_site_mismatch", "An explicit member must have immutable ownership in this Site")
		}
		if err != nil {
			return nil, "", err
		}
	}
	ownerFP, e := subjectFingerprint(ctx, tx, r.revision.OwnerID, p.head)
	if e != nil {
		return nil, "", e
	}
	policy, e := s.publishedZonePolicy(ctx, tx, p, r.zone.Spec.PolicyRevisionID, r.revision.SiteID, caches...)
	if e != nil {
		return nil, "", e
	}
	minimum := s.compiler.MinimumWAFMode
	if minimum == "" {
		minimum = "detection"
	}
	if minimum != "detection" && minimum != "blocking" {
		return nil, "", ErrUnavailable
	}
	if minimum == "blocking" && r.zone.Spec.Mode != "blocking" {
		return nil, "", zoneIssue("/spec/mode", "waf_zone_security_minimum", "Zone mode is below the server's required WAF minimum")
	}
	d := digest([]any{"agp.trusted-zone-dependency/v1", p.Epoch, r.revision.ContentDigest, ownerFP, policy.publicationID, policy.record.revision.ContentDigest, policy.proof, minimum})
	return policy, d, nil
}

type zoneAssignment struct{ zoneID, resolutionID, bindingDigest string }

func readZoneAssignments(ctx context.Context, tx storage.IdentityTx, revision string) (map[string]zoneAssignment, error) {
	out := map[string]zoneAssignment{}
	rows, e := tx.Query(ctx, `SELECT gateway_id,zone_revision_id,resolution_id,binding_digest FROM config_revision_zone_assignments WHERE revision_id=? ORDER BY gateway_id`, revision)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var gateway string
		var a zoneAssignment
		if e = rows.Scan(&gateway, &a.zoneID, &a.resolutionID, &a.bindingDigest); e != nil {
			return nil, e
		}
		out[gateway] = a
	}
	return out, rows.Err()
}

// gatewaySecurityDigest excludes only human display names. All routing,
// authorization, target and component fields remain bound to the historical
// resolution. Detach the route slice before removing names from the local copy.
func gatewaySecurityDigest(g configmodel.Gateway) (string, error) {
	g.Metadata.Name = ""
	g.Spec.Routes = append([]configmodel.Route{}, g.Spec.Routes...)
	for i := range g.Spec.Routes {
		g.Spec.Routes[i].Name = ""
	}
	return configmodel.Digest(g)
}

func insertZoneAssignments(ctx context.Context, tx storage.IdentityTx, base, id string, doc *configmodel.Document, overrides map[string]zoneAssignment) error {
	assignments, e := readZoneAssignments(ctx, tx, base)
	if e != nil {
		return e
	}
	baseGateways := map[string]configmodel.Gateway{}
	var baseProfiles []configmodel.ProfileAssignment
	if len(assignments) > 0 {
		baseDoc, err := baseDocument(ctx, tx, base)
		if err != nil {
			return err
		}
		for _, g := range baseDoc.Configuration.Gateways {
			baseGateways[g.Metadata.ID] = g
		}
		baseProfiles = baseDoc.Configuration.ProfileAssignments
	}
	for gateway, a := range overrides {
		assignments[gateway] = a
	}
	gateways := map[string]configmodel.Gateway{}
	for _, g := range doc.Configuration.Gateways {
		gateways[g.Metadata.ID] = g
	}
	ids := make([]string, 0, len(assignments))
	for gateway := range assignments {
		ids = append(ids, gateway)
	}
	sort.Strings(ids)
	for _, gateway := range ids {
		a := assignments[gateway]
		g, ok := gateways[gateway]
		if !ok {
			return zoneIssue("/gateways", "zone_change_required", "An assigned Gateway requires the controlled zone workflow")
		}
		if _, explicit := overrides[gateway]; !explicit {
			previous, exists := baseGateways[gateway]
			if !exists {
				return storage.ErrConflict
			}
			before, err := gatewaySecurityDigest(previous)
			if err != nil {
				return err
			}
			after, err := gatewaySecurityDigest(g)
			if err != nil {
				return err
			}
			if before != after || digest(baseProfiles) != digest(doc.Configuration.ProfileAssignments) {
				return zoneIssue("/gateways", "zone_resolution_required", "Changing security inputs of an assigned Gateway requires a new trusted resolution; only display names may be edited while retaining provenance")
			}
		}
		actual, e := configmodel.Digest(g.Spec.WAF)
		if e != nil {
			return e
		}
		z, e := loadZoneRecord(ctx, tx, a.zoneID)
		if e != nil {
			return e
		}
		if actual != a.bindingDigest || z.revision.SiteID != g.Metadata.SiteID || z.zone.Spec.PolicyRevisionID != g.Spec.WAF.PolicyRevisionID || z.zone.Spec.Mode != g.Spec.WAF.Mode {
			return zoneIssue("/gateways/spec/waf", "zone_change_required", "Changing an assigned WAF binding requires a trusted zone change")
		}
		if _, e = tx.Exec(ctx, `INSERT INTO config_revision_zone_assignments(revision_id,gateway_id,zone_revision_id,resolution_id,binding_digest) VALUES(?,?,?,?,?)`, id, gateway, a.zoneID, a.resolutionID, a.bindingDigest); e != nil {
			return e
		}
	}
	return nil
}

func (s *Service) zoneView(ctx context.Context, tx storage.IdentityTx, p *Principal, r *ZoneRevision) (*ZoneRevision, error) {
	out := *r
	publications, e := securitystate.Strings(ctx, tx, `SELECT id FROM config_zone_publications WHERE zone_revision_id=?`, r.ID)
	if e != nil {
		return nil, e
	}
	if len(publications) > 0 {
		out.State = "published"
		newer, e := securitystate.Strings(ctx, tx, `SELECT p.id FROM config_zone_publications p JOIN config_zone_revisions n ON n.id=p.zone_revision_id JOIN config_zone_revisions old ON old.id=? WHERE n.zone_id=old.zone_id AND n.revision_number>old.revision_number LIMIT 1`, r.ID)
		if e != nil {
			return nil, e
		}
		if len(newer) > 0 {
			out.State = "superseded"
		}
		return &out, nil
	}
	record, e := loadZoneRecord(ctx, tx, r.ID)
	if e != nil {
		return nil, e
	}
	ids, e := securitystate.Strings(ctx, tx, `SELECT id FROM config_zone_validations WHERE zone_revision_id=? ORDER BY created_at DESC,id DESC LIMIT 32`, r.ID)
	if e != nil {
		return nil, e
	}
	for _, id := range ids {
		v, e := loadZoneValidation(ctx, tx, id)
		if e != nil {
			return nil, e
		}
		if s.zoneValidationCurrent(ctx, tx, p, record, v) != nil {
			continue
		}
		out.State = "validated"
		approvals, e := securitystate.Strings(ctx, tx, `SELECT id FROM config_zone_approvals WHERE validation_id=? ORDER BY created_at DESC,id DESC LIMIT 32`, id)
		if e != nil {
			return nil, e
		}
		for _, approval := range approvals {
			if _, e = s.currentZoneApproval(ctx, tx, p, record, approval); e == nil {
				out.State = "approved"
				break
			}
		}
		break
	}
	return &out, nil
}

func (s *Service) publishedZone(ctx context.Context, tx storage.IdentityTx, p *Principal, id, site string, caches ...map[string]*publishedPolicyPin) (*zoneRecord, *publishedPolicyPin, string, error) {
	r, e := loadZoneRecord(ctx, tx, id)
	if e != nil {
		return nil, nil, "", e
	}
	if r.revision.SiteID != site {
		return nil, nil, "", storage.ErrNotFound
	}
	var publication, approval, content, dependency string
	var epoch int64
	e = securitystate.One(ctx, tx, `SELECT id,approval_id,authority_epoch,content_digest,dependency_digest FROM config_zone_publications WHERE zone_revision_id=?`, []any{id}, func(rows storage.IdentityRows) error {
		return rows.Scan(&publication, &approval, &epoch, &content, &dependency)
	})
	if e != nil {
		return nil, nil, "", e
	}
	a, e := readZoneApproval(ctx, tx, approval)
	if e != nil {
		return nil, nil, "", e
	}
	v, e := loadZoneValidation(ctx, tx, a.validationID)
	if e != nil {
		return nil, nil, "", e
	}
	policy, currentDependency, e := s.zoneDependency(ctx, tx, p, r, caches...)
	if e != nil {
		return nil, nil, "", e
	}
	if epoch != p.Epoch || a.epoch != p.Epoch || v.epoch != p.Epoch || a.revisionID != id || v.report.ZoneRevisionID != id || content != r.revision.ContentDigest || a.contentDigest != content || v.report.ContentDigest != content || dependency != a.qualificationDigest || dependency != v.report.DependencyDigest || dependency != currentDependency {
		return nil, nil, "", storage.ErrConflict
	}
	return r, policy, digest([]any{publication, dependency}), nil
}
