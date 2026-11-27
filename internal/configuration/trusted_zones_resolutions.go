package configuration

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type ZoneResolutionRequest struct {
	BaseRevisionID         string                              `json:"baseRevisionId"`
	CapacityProfile        string                              `json:"capacityProfile"`
	Action                 string                              `json:"action"`
	ReplacementAssignments []configmodel.ReplacementAssignment `json:"replacementAssignments,omitempty"`
}

func normalizeZoneResolutionRequest(in ZoneResolutionRequest) (ZoneResolutionRequest, error) {
	if !validID.MatchString(in.BaseRevisionID) || (in.CapacityProfile != "pilot-500" && in.CapacityProfile != "fleet-10k") || (in.Action != "reconcile" && in.Action != "retire") || len(in.ReplacementAssignments) > 10000 {
		return in, ErrInvalidRequest
	}
	in.ReplacementAssignments = append([]configmodel.ReplacementAssignment{}, in.ReplacementAssignments...)
	sort.Slice(in.ReplacementAssignments, func(i, j int) bool {
		return in.ReplacementAssignments[i].GatewayID < in.ReplacementAssignments[j].GatewayID
	})
	for i, r := range in.ReplacementAssignments {
		if !validID.MatchString(r.GatewayID) || !validID.MatchString(r.ZoneRevisionID) || (i > 0 && in.ReplacementAssignments[i-1].GatewayID == r.GatewayID) {
			return in, ErrInvalidRequest
		}
	}
	return in, nil
}

type trustedZoneClosure struct {
	document *configmodel.Document
	request  configmodel.ResolveRequest
	inputs   configmodel.TrustedZoneInputs
}

// buildTrustedZoneClosure uses only persisted canonical desired configuration,
// sealed provenance, immutable publications and a freshly checked server source.
// Caller supplied IDs choose exact objects; they never supply membership facts.
func (s *Service) buildTrustedZoneClosure(ctx context.Context, tx storage.IdentityTx, p *Principal, request configmodel.ResolveRequest) (*trustedZoneClosure, error) {
	if s.trustedInventory == nil {
		return nil, zoneIssue("/inventory", "trusted_inventory_required", "Current authenticated node inventory and component qualification are required")
	}
	head, _, e := readHead(ctx, tx)
	if e != nil {
		return nil, e
	}
	if head != request.BaseConfigRevisionID {
		return nil, ErrRevisionMismatch
	}
	doc, e := baseDocument(ctx, tx, request.BaseConfigRevisionID)
	if e != nil {
		return nil, e
	}
	if len(doc.Configuration.ProfileAssignments) > 0 {
		return nil, zoneIssue("/profileAssignments", "unsupported_profile_assignments", "Trusted zone materialization requires qualified policy-profile inheritance, which is not available yet")
	}
	if e = verifyOwnership(ctx, tx, doc); e != nil {
		return nil, e
	}
	owned, e := securitystate.Strings(ctx, tx, `SELECT gateway_id FROM config_gateway_ownership WHERE site_id=?`, request.SiteID)
	if e != nil {
		return nil, e
	}
	ownership := map[string]bool{}
	for _, id := range owned {
		ownership[id] = true
	}
	for _, g := range doc.Configuration.Gateways {
		if g.Metadata.SiteID == request.SiteID && !ownership[g.Metadata.ID] {
			return nil, zoneIssue("/gateways", "unsupported_gateway_onboarding", "Trusted resolution currently requires an existing immutable Gateway/Site ownership registration")
		}
	}
	if e = p.RequireSiteSnapshot(ctx, tx, "config.edit", request.BaseConfigRevisionID, request.SiteID); e != nil {
		return nil, e
	}
	assignments, e := readZoneAssignments(ctx, tx, request.BaseConfigRevisionID)
	if e != nil {
		return nil, e
	}
	current := map[string]string{}
	zoneIDs := map[string]bool{request.ZoneRevisionID: true}
	gateways := map[string]configmodel.Gateway{}
	for _, g := range doc.Configuration.Gateways {
		gateways[g.Metadata.ID] = g
		if a, ok := assignments[g.Metadata.ID]; ok {
			actual, e := configmodel.Digest(g.Spec.WAF)
			if e != nil {
				return nil, e
			}
			if actual != a.bindingDigest {
				return nil, storage.ErrConflict
			}
			current[g.Metadata.ID] = a.zoneID
			if g.Metadata.SiteID == request.SiteID {
				zoneIDs[a.zoneID] = true
			}
		}
	}
	for _, r := range request.ReplacementAssignments {
		g, ok := gateways[r.GatewayID]
		if !ok || g.Metadata.SiteID != request.SiteID {
			return nil, storage.ErrNotFound
		}
		zoneIDs[r.ZoneRevisionID] = true
	}
	request.CurrentAssignments = current
	request.AllowLegacyMigration = true // explicit authenticated migration of existing owned Gateways only
	request.ZoneRevisions = []configmodel.ZoneRevision{}
	policyCache := map[string]*publishedPolicyPin{}
	policies := map[string]configmodel.CatalogInput{}
	proofs := map[string]WAFQualification{}
	pins := []string{}
	ids := make([]string, 0, len(zoneIDs))
	for id := range zoneIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	zoneBytes := 0
	for _, id := range ids {
		zone, policy, pin, e := s.publishedZone(ctx, tx, p, id, request.SiteID, policyCache)
		if e != nil {
			return nil, e
		}
		if len(zone.revision.Content) > (64<<20)-zoneBytes {
			return nil, zoneIssue("/zoneRevisions", "zone_closure_byte_limit", "Published zone closure exceeds the 64 MiB document budget")
		}
		zoneBytes += len(zone.revision.Content)
		request.ZoneRevisions = append(request.ZoneRevisions, configmodel.ZoneRevision{ID: id, Digest: zone.revision.ContentDigest, Content: *zone.zone, Published: true})
		policies[policy.record.revision.ID] = configmodel.CatalogInput{Kind: "waf_policy", ID: policy.record.revision.ID, Digest: policy.record.revision.ContentDigest, SiteID: request.SiteID, State: "published", BaseExceptionCount: 0}
		proofs[digest(policy.proof)] = policy.proof
		pins = append(pins, pin)
	}
	// Original bindings are part of the security closure as well as destinations.
	for _, g := range doc.Configuration.Gateways {
		if g.Metadata.SiteID != request.SiteID {
			continue
		}
		policy, e := s.publishedZonePolicy(ctx, tx, p, g.Spec.WAF.PolicyRevisionID, request.SiteID, policyCache)
		if e != nil {
			return nil, e
		}
		if g.Spec.ComponentProfileRef.ID != policy.proof.ProfileID || g.Spec.ComponentProfileRef.Digest != policy.proof.ProfileDigest {
			return nil, zoneIssue("/gateways/spec/componentProfileRef", "native_profile_mismatch", "Gateway component profile must match its current signed native WAF qualification")
		}
		proofs[digest(policy.proof)] = policy.proof
		pins = append(pins, digest([]any{policy.publicationID, policy.record.revision.ContentDigest, policy.proof}))
		for _, route := range g.Spec.Routes {
			if len(route.WAFExceptionIDs) > 0 {
				return nil, zoneIssue("/gateways/spec/routes/wafExceptionIds", "unsupported_derivation", "Local exceptions require separately qualified lineage")
			}
		}
	}
	proofIDs := make([]string, 0, len(proofs))
	for id := range proofs {
		proofIDs = append(proofIDs, id)
	}
	sort.Strings(proofIDs)
	qualifications := make([]WAFQualification, 0, len(proofIDs))
	for _, id := range proofIDs {
		qualifications = append(qualifications, proofs[id])
	}
	observation, e := s.trustedInventory.Current(ctx, tx, securityjournal.UInt63(p.Epoch), request.SiteID, qualifications)
	if e != nil {
		return nil, e
	}
	if observation == nil || !configmodel.ValidDigest(observation.SourceDigest) {
		return nil, storage.ErrConflict
	}
	sort.Strings(pins)
	minimum := s.compiler.MinimumWAFMode
	if minimum == "" {
		minimum = "detection"
	}
	input := configmodel.TrustedZoneInputs{SourceDigest: digest([]any{"agp.trusted-zone-inputs/v1", p.Epoch, observation.SourceDigest, pins}), MinimumWAFMode: minimum, Nodes: observation.Nodes, Policies: []configmodel.CatalogInput{}}
	policyIDs := make([]string, 0, len(policies))
	for id := range policies {
		policyIDs = append(policyIDs, id)
	}
	sort.Strings(policyIDs)
	for _, id := range policyIDs {
		input.Policies = append(input.Policies, policies[id])
	}
	return &trustedZoneClosure{document: doc, request: request, inputs: input}, nil
}

type storedZoneResolution struct {
	report                                 configmodel.WafZoneResolution
	request                                configmodel.ResolveRequest
	epoch                                  int64
	author, authorFingerprint, operationID string
	created                                time.Time
}

func loadZoneResolution(ctx context.Context, tx storage.IdentityTx, id string) (*storedZoneResolution, error) {
	if !validID.MatchString(id) {
		return nil, ErrInvalidRequest
	}
	v := &storedZoneResolution{}
	var requestRaw, reportRaw, digest, zone, site, base string
	var expires time.Time
	e := securitystate.One(ctx, tx, `SELECT zone_revision_id,site_id,base_revision_id,authority_epoch,resolution_digest,request_json,report_json,created_by,author_fingerprint,operation_id,created_at,expires_at FROM config_zone_resolutions WHERE id=?`, []any{id}, func(rows storage.IdentityRows) error {
		return rows.Scan(&zone, &site, &base, &v.epoch, &digest, &requestRaw, &reportRaw, &v.author, &v.authorFingerprint, &v.operationID, &v.created, &expires)
	})
	if e != nil {
		return nil, e
	}
	if e = json.Unmarshal([]byte(requestRaw), &v.request); e != nil {
		return nil, e
	}
	if e = json.Unmarshal([]byte(reportRaw), &v.report); e != nil {
		return nil, e
	}
	actual, e := configmodel.ResolutionDigest(v.report)
	if e != nil {
		return nil, e
	}
	reportExpires, e := time.Parse(time.RFC3339Nano, v.report.ExpiresAt)
	if e != nil {
		return nil, e
	}
	if v.report.ID != id || actual != digest || v.report.ResolutionDigest != digest || v.report.ZoneRevisionID != zone || v.report.SiteID != site || v.report.BaseConfigRevisionID != base || v.request.ID != id || v.request.ZoneRevisionID != zone || v.request.SiteID != site || v.request.BaseConfigRevisionID != base || !v.request.CreatedAt.Truncate(time.Microsecond).Equal(v.created) || !reportExpires.Truncate(time.Microsecond).Equal(expires) {
		return nil, storage.ErrConflict
	}
	if e = configmodel.ValidateResolution(&v.report); e != nil {
		return nil, e
	}
	return v, nil
}
func (s *Service) recheckZoneResolution(ctx context.Context, tx storage.IdentityTx, p *Principal, v *storedZoneResolution) (*trustedZoneClosure, error) {
	expires, e := time.Parse(time.RFC3339Nano, v.report.ExpiresAt)
	if e != nil {
		return nil, e
	}
	if v.epoch != p.Epoch || !time.Now().Before(expires) || time.Now().Before(v.request.CreatedAt) {
		return nil, storage.ErrConflict
	}
	if e = wafSubjectPermission(ctx, tx, v.author, "config.edit", v.report.SiteID, p.head); e != nil {
		return nil, e
	}
	fp, e := subjectFingerprint(ctx, tx, v.author, p.head)
	if e != nil {
		return nil, e
	}
	if fp != v.authorFingerprint {
		return nil, storage.ErrConflict
	}
	closure, e := s.buildTrustedZoneClosure(ctx, tx, p, v.request)
	if e != nil {
		return nil, e
	}
	expected, e := configmodel.ResolveTrustedZones(ctx, closure.document.Configuration, closure.inputs, closure.request)
	if e != nil {
		return nil, e
	}
	if expected.ResolutionDigest != v.report.ResolutionDigest || expected.InventoryDigest != v.report.InventoryDigest {
		return nil, storage.ErrConflict
	}
	return closure, nil
}
func (s *Service) ResolveZone(ctx context.Context, a Actor, id, key string, in ZoneResolutionRequest) (out *configmodel.WafZoneResolution, err error) {
	if !validID.MatchString(id) {
		return nil, ErrInvalidRequest
	}
	in, err = normalizeZoneResolutionRequest(in)
	if err != nil {
		return nil, err
	}
	op, fp := "zone.resolve:"+id, digest(in)
	ctx, err = s.directorySubjectContext(ctx, a, true, directorySubjectSelection{Kind: "zone_resolve", ID: id, RevisionID: in.BaseRevisionID, ZoneRevisionIDs: replacementIDs(in.ReplacementAssignments)})
	if err != nil {
		return
	}
	err = s.transactScoped(ctx, a, true, func(tx storage.IdentityTx, p *Principal) error {
		target, e := loadZoneRecord(ctx, tx, id)
		if e != nil {
			return e
		}
		if p.Require("config.edit", target.revision.SiteID) != nil {
			return storage.ErrNotFound
		}
		h, e := request(ctx, tx, p.ID, op, key, fp)
		if e != nil {
			return e
		}
		if h != nil {
			v, e := loadZoneResolution(ctx, tx, h.id)
			if e != nil {
				return e
			}
			if _, e = s.recheckZoneResolution(ctx, tx, p, v); e != nil {
				return e
			}
			out = &v.report
			return nil
		}
		now := time.Now().UTC()
		request := configmodel.ResolveRequest{ID: securitystate.ID("zresolution"), SiteID: target.revision.SiteID, ZoneRevisionID: id, BaseConfigRevisionID: in.BaseRevisionID, Action: in.Action, CapacityProfile: in.CapacityProfile, CreatedAt: now, ReplacementAssignments: in.ReplacementAssignments}
		closure, e := s.buildTrustedZoneClosure(ctx, tx, p, request)
		if e != nil {
			return e
		}
		report, e := configmodel.ResolveTrustedZones(ctx, closure.document.Configuration, closure.inputs, closure.request)
		if e != nil {
			return e
		}
		requestRaw, e := json.Marshal(closure.request)
		if e != nil {
			return e
		}
		reportRaw, e := json.Marshal(report)
		if e != nil {
			return e
		}
		if len(reportRaw) > 64<<20 {
			return ErrUnavailable
		}
		author, e := subjectFingerprint(ctx, tx, p.ID, p.head)
		if e != nil {
			return e
		}
		operation := securitystate.ID("operation")
		if _, e = tx.Exec(ctx, `INSERT INTO config_zone_resolutions(id,zone_revision_id,site_id,base_revision_id,authority_epoch,resolution_digest,request_json,report_json,created_by,author_fingerprint,operation_id,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, report.ID, id, report.SiteID, in.BaseRevisionID, p.Epoch, report.ResolutionDigest, string(requestRaw), string(reportRaw), p.ID, author, operation, now.Truncate(time.Microsecond), now.Add(30*time.Minute).Truncate(time.Microsecond)); e != nil {
			return e
		}
		if e = remember(ctx, tx, p.ID, op, key, fp, responseHandle{"zone_resolution", report.ID, 0}); e != nil {
			return e
		}
		if e = securitystate.Audit(ctx, tx, "config.waf.zone.resolved", p.ID, map[string]any{"zoneRevisionId": id, "resolutionId": report.ID, "resolutionDigest": report.ResolutionDigest, "inventoryDigest": report.InventoryDigest, "memberCount": len(report.Members), "conflictCount": len(report.Conflicts), "apply": false}); e != nil {
			return e
		}
		out = report
		return nil
	})
	return
}
func (s *Service) ResolveZoneAccepted(ctx context.Context, a Actor, id, key string, in ZoneResolutionRequest) (out *AcceptedOperation, err error) {
	report, e := s.ResolveZone(ctx, a, id, key, in)
	if e != nil {
		return nil, e
	}
	err = s.transactScoped(ctx, a, false, func(tx storage.IdentityTx, p *Principal) error {
		v, e := loadZoneResolution(ctx, tx, report.ID)
		if e != nil {
			return e
		}
		if e = p.RequireSiteSnapshot(ctx, tx, "config.read", v.report.BaseConfigRevisionID, v.report.SiteID); e != nil {
			return e
		}
		out = &AcceptedOperation{OperationID: v.operationID, ResourceID: report.ID, StatusURL: "/api/v2/operations/" + v.operationID, SubmittedAt: v.created}
		return nil
	})
	return
}
func (s *Service) GetZoneResolution(ctx context.Context, a Actor, id string) (out *configmodel.WafZoneResolution, err error) {
	err = s.transactScoped(ctx, a, false, func(tx storage.IdentityTx, p *Principal) error {
		v, e := loadZoneResolution(ctx, tx, id)
		if e != nil {
			return e
		}
		if e = p.RequireSiteSnapshot(ctx, tx, "config.read", v.report.BaseConfigRevisionID, v.report.SiteID); e != nil {
			return storage.ErrNotFound
		}
		out = &v.report
		return nil
	})
	return
}

type ZoneChangeView struct {
	ID               string                    `json:"id"`
	Request          configmodel.WafZoneChange `json:"request"`
	RequestDigest    string                    `json:"requestDigest"`
	State            string                    `json:"state"`
	ResultRevisionID string                    `json:"resultRevisionId"`
	Revision         string                    `json:"revision"`
}

func loadZoneChange(ctx context.Context, tx storage.IdentityTx, id string) (*ZoneChangeView, string, time.Time, error) {
	if !validID.MatchString(id) {
		return nil, "", time.Time{}, ErrInvalidRequest
	}
	out := &ZoneChangeView{ID: id, State: "materialized", Revision: "0"}
	var raw, operation string
	var created time.Time
	e := securitystate.One(ctx, tx, `SELECT request_json,request_digest,result_revision_id,operation_id,created_at FROM config_zone_changes WHERE id=?`, []any{id}, func(rows storage.IdentityRows) error {
		return rows.Scan(&raw, &out.RequestDigest, &out.ResultRevisionID, &operation, &created)
	})
	if e != nil {
		return nil, "", time.Time{}, e
	}
	if e = json.Unmarshal([]byte(raw), &out.Request); e != nil {
		return nil, "", time.Time{}, e
	}
	d, e := configmodel.Digest(out.Request)
	if e != nil || d != out.RequestDigest {
		return nil, "", time.Time{}, storage.ErrConflict
	}
	return out, operation, created, nil
}
func (s *Service) materializeZone(ctx context.Context, a Actor, key string, in configmodel.WafZoneChange) (revision *Revision, view *ZoneChangeView, operation *AcceptedOperation, err error) {
	raw, e := json.Marshal(in)
	if e != nil {
		return nil, nil, nil, e
	}
	if _, e = configmodel.ParseZoneChange(bytes.NewReader(raw), configmodel.JSON); e != nil {
		return nil, nil, nil, e
	}
	op, fp := "zone.materialize", digest(in)
	ctx, err = s.directorySubjectContext(ctx, a, true, directorySubjectSelection{Kind: "zone_resolution", ID: in.ResolutionID})
	if err != nil {
		return
	}
	err = s.transactScoped(ctx, a, true, func(tx storage.IdentityTx, p *Principal) error {
		v, e := loadZoneResolution(ctx, tx, in.ResolutionID)
		if e != nil {
			return e
		}
		if p.RequireSiteSnapshot(ctx, tx, "config.edit", v.report.BaseConfigRevisionID, v.report.SiteID) != nil {
			return storage.ErrNotFound
		}
		if v.epoch != p.Epoch || in.BaseRevisionID != v.report.BaseConfigRevisionID || in.ZoneRevisionID != v.report.ZoneRevisionID || in.ResolutionDigest != v.report.ResolutionDigest {
			return storage.ErrConflict
		}
		h, e := request(ctx, tx, p.ID, op, key, fp)
		if e != nil {
			return e
		}
		if h != nil {
			// A successful exact retry returns the original immutable result after
			// current session/scope checks; it cannot issue a fresh resolution permit.
			saved, operationID, created, e := loadZoneChange(ctx, tx, h.id)
			if e != nil {
				return e
			}
			if saved.Request.ResolutionID != in.ResolutionID {
				return storage.ErrConflict
			}
			revision, e = readRevision(ctx, tx, saved.ResultRevisionID)
			if e != nil {
				return e
			}
			if p.Require("config.read", "") != nil {
				revision.Content = nil
				revision.ViewScope = "metadata"
			}
			view = saved
			operation = &AcceptedOperation{OperationID: operationID, ResourceID: saved.ID, StatusURL: "/api/v2/operations/" + operationID, SubmittedAt: created}
			return nil
		}
		closure, e := s.recheckZoneResolution(ctx, tx, p, v)
		if e != nil {
			return e
		}
		doc, e := configmodel.MaterializeWithTrustedInputs(ctx, closure.document.Configuration, closure.inputs, closure.request, v.report, time.Now().UTC())
		if e != nil {
			return e
		}
		overrides := map[string]zoneAssignment{}
		for _, member := range v.report.Members {
			if member.Disposition != "inherited" {
				return storage.ErrConflict
			}
			overrides[member.GatewayID] = zoneAssignment{zoneID: member.TargetZoneRevisionID, resolutionID: v.report.ID, bindingDigest: member.TargetBindingDigest}
		}
		revision, e = insertRevisionWithZones(ctx, tx, p.ID, in.BaseRevisionID, doc, overrides)
		if e != nil {
			return e
		}
		changeID, operationID, now := securitystate.ID("zchange"), securitystate.ID("operation"), time.Now().UTC()
		requestDigest, e := configmodel.Digest(in)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO config_zone_changes(id,resolution_id,request_json,request_digest,result_revision_id,operation_id,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)`, changeID, v.report.ID, string(raw), requestDigest, revision.ID, operationID, p.ID, now); e != nil {
			return e
		}
		if e = remember(ctx, tx, p.ID, op, key, fp, responseHandle{"zone_change", changeID, 0}); e != nil {
			return e
		}
		if e = securitystate.Audit(ctx, tx, "config.waf.zone.materialized", p.ID, map[string]any{"zoneChangeId": changeID, "resolutionId": v.report.ID, "resolutionDigest": v.report.ResolutionDigest, "baseRevisionId": in.BaseRevisionID, "resultRevisionId": revision.ID, "reason": in.Reason, "apply": false}); e != nil {
			return e
		}
		if p.Require("config.read", "") != nil {
			revision.Content = nil
			revision.ViewScope = "metadata"
		}
		view = &ZoneChangeView{ID: changeID, Request: in, RequestDigest: requestDigest, State: "materialized", ResultRevisionID: revision.ID, Revision: "0"}
		operation = &AcceptedOperation{OperationID: operationID, ResourceID: changeID, StatusURL: "/api/v2/operations/" + operationID, SubmittedAt: now}
		return nil
	})
	return
}
func (s *Service) MaterializeZone(ctx context.Context, a Actor, key string, in configmodel.WafZoneChange) (*Revision, error) {
	r, _, _, e := s.materializeZone(ctx, a, key, in)
	return r, e
}
func (s *Service) CreateZoneChange(ctx context.Context, a Actor, key string, in configmodel.WafZoneChange) (*AcceptedOperation, error) {
	_, _, op, e := s.materializeZone(ctx, a, key, in)
	return op, e
}
func (s *Service) GetZoneChange(ctx context.Context, a Actor, id string) (out *ZoneChangeView, err error) {
	err = s.transactScoped(ctx, a, false, func(tx storage.IdentityTx, p *Principal) error {
		v, _, _, e := loadZoneChange(ctx, tx, id)
		if e != nil {
			return e
		}
		resolution, e := loadZoneResolution(ctx, tx, v.Request.ResolutionID)
		if e != nil {
			return e
		}
		if e = p.RequireSiteSnapshot(ctx, tx, "config.read", resolution.report.BaseConfigRevisionID, resolution.report.SiteID); e != nil {
			return storage.ErrNotFound
		}
		out = v
		return nil
	})
	return
}
