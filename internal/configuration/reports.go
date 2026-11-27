package configuration

import (
	"context"
	"encoding/json"
	"time"

	"github.com/netwizd/agp/internal/compiler"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type Report struct {
	ID                string               `json:"id"`
	TargetKind        string               `json:"targetKind"`
	TargetID          string               `json:"targetId"`
	TargetRevision    string               `json:"targetRevision"`
	ConfigDigest      string               `json:"configDigest"`
	CatalogSnapshotID string               `json:"catalogSnapshotId,omitempty"`
	CatalogDigest     string               `json:"catalogDigest,omitempty"`
	CompilerDigest    string               `json:"compilerDigest"`
	AuthoringValid    bool                 `json:"authoringValid"`
	Deployable        bool                 `json:"deployable"`
	Issues            []configmodel.Issue  `json:"issues"`
	Diff              []configmodel.Change `json:"diff"`
	Preview           *compiler.Result     `json:"preview,omitempty"`
	CreatedAt         time.Time            `json:"createdAt"`
}

func readReport(ctx context.Context, tx storage.IdentityTx, id string) (*Report, error) {
	if !validID.MatchString(id) {
		return nil, ErrInvalidRequest
	}
	var raw string
	err := securitystate.One(ctx, tx, `SELECT report_json FROM config_reports WHERE id=?`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&raw) })
	if err != nil {
		return nil, err
	}
	var out Report
	if err = json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, err
	}
	return &out, nil
}
func (s *Service) GetReport(ctx context.Context, a Actor, id string) (out *Report, err error) {
	err = s.transact(ctx, a, false, func(tx storage.IdentityTx, _ string) error { out, err = readReport(ctx, tx, id); return err })
	return
}
func (s *Service) GetOperation(ctx context.Context, a Actor, id string) (out *Operation, err error) {
	if !validID.MatchString(id) {
		return nil, ErrInvalidRequest
	}
	out = &Operation{}
	err = s.transact(ctx, a, false, func(tx storage.IdentityTx, _ string) error {
		return securitystate.One(ctx, tx, `SELECT id,resource_id,state,created_at FROM config_operations WHERE id=?`, []any{id}, func(r storage.IdentityRows) error {
			return r.Scan(&out.ID, &out.ResourceID, &out.State, &out.CreatedAt)
		})
	})
	out.UpdatedAt = out.CreatedAt
	return
}
func compileReport(ctx context.Context, s *Service, kind, id, version string, doc *configmodel.Document, base *configmodel.Document, catalog *configmodel.CatalogDocument) (*Report, error) {
	compilerDigest, err := configmodel.Digest(s.compiler)
	if err != nil {
		return nil, err
	}
	out := &Report{ID: securitystate.ID("validation"), TargetKind: kind, TargetID: id, TargetRevision: version, ConfigDigest: doc.Digest, CompilerDigest: compilerDigest, Issues: []configmodel.Issue{}, Diff: []configmodel.Change{}, CreatedAt: time.Now().UTC()}
	if base != nil {
		out.Diff, err = configmodel.SemanticDiff(base.Configuration, doc.Configuration)
		if err != nil {
			return nil, err
		}
	}
	if catalog == nil {
		out.Issues = append(out.Issues, configmodel.Issue{Path: "", Code: "catalog_required", Message: "Import an immutable operator-declared input catalog before reference validation", Severity: "error"})
		return out, nil
	}
	out.CatalogSnapshotID = catalog.Catalog.ID
	out.CatalogDigest = catalog.Digest
	result, err := compiler.Preview(ctx, doc.Configuration, catalog.Catalog, s.compiler)
	if err != nil {
		return nil, err
	}
	out.Preview = result
	out.CompilerDigest = result.CompilerDigest
	out.Issues = result.Issues
	out.AuthoringValid = true
	for _, i := range out.Issues {
		if i.Severity != "error" {
			continue
		}
		switch i.Code {
		case "native_qualification_required", "capability_unqualified", "baseline_unavailable":
		default:
			out.AuthoringValid = false
		}
	}
	// Operator-declared provenance never becomes authority for apply.
	out.Deployable = false
	return out, nil
}
func saveReport(ctx context.Context, tx storage.IdentityTx, actor string, report *Report) error {
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	if len(raw) > 64<<20 {
		return &configmodel.ValidationError{Issues: []configmodel.Issue{{Path: "", Code: "preview_capacity_exceeded", Message: "Full preview exceeds the 64 MiB report envelope", Severity: "error"}}}
	}
	v, err := parseVersion(report.TargetRevision)
	if err != nil {
		return err
	}
	outcome := "failed"
	if report.Deployable {
		outcome = "passed"
	}
	_, err = tx.Exec(ctx, `INSERT INTO config_reports(id,target_kind,target_id,target_version,content_digest,catalog_id,report_json,outcome,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, report.ID, report.TargetKind, report.TargetID, v, report.ConfigDigest, nullable(report.CatalogSnapshotID), string(raw), outcome, actor, report.CreatedAt)
	if err != nil {
		return err
	}
	return securitystate.Audit(ctx, tx, "config.validation.completed", actor, map[string]any{"reportId": report.ID, "targetId": report.TargetID, "configDigest": report.ConfigDigest, "catalogDigest": report.CatalogDigest, "compilerDigest": report.CompilerDigest, "authoringValid": report.AuthoringValid, "deployable": false})
}
func baseDocument(ctx context.Context, tx storage.IdentityTx, base string) (*configmodel.Document, error) {
	if base == "" {
		return nil, nil
	}
	r, e := readRevision(ctx, tx, base)
	if e != nil {
		return nil, e
	}
	return parseContent(r.Content)
}
func (s *Service) PreviewDraft(ctx context.Context, a Actor, id, catalogID, key string) (out *Report, err error) {
	if catalogID != "" && !validID.MatchString(catalogID) {
		return nil, ErrInvalidRequest
	}
	op := "draft.preview:" + id
	fp := digest([]string{id, catalogID})
	var d *Draft
	var doc, base *configmodel.Document
	var catalog *configmodel.CatalogDocument
	err = s.transact(ctx, a, true, func(tx storage.IdentityTx, actor string) error {
		h, e := request(ctx, tx, actor, op, key, fp)
		if e != nil {
			return e
		}
		if h != nil {
			out, e = readReport(ctx, tx, h.id)
			return e
		}
		d, e = readDraft(ctx, tx, id, nil)
		if e != nil {
			return e
		}
		doc, e = parseContent(d.Content)
		if e != nil {
			return e
		}
		base, e = baseDocument(ctx, tx, d.BaseRevisionID)
		if e != nil {
			return e
		}
		catalog, e = loadCatalog(ctx, tx, catalogID)
		if e != nil {
			return e
		}
		if catalog != nil {
			return validateGroups(ctx, tx, catalog.Catalog)
		}
		return nil
	})
	if err != nil || out != nil {
		return out, err
	}
	out, err = compileReport(ctx, s, "draft", id, d.Revision, doc, base, catalog)
	if err != nil {
		return nil, err
	}
	err = s.transact(ctx, a, true, func(tx storage.IdentityTx, actor string) error {
		h, e := request(ctx, tx, actor, op, key, fp)
		if e != nil {
			return e
		}
		if h != nil {
			out, e = readReport(ctx, tx, h.id)
			return e
		}
		if catalog != nil {
			if e = validateGroups(ctx, tx, catalog.Catalog); e != nil {
				return e
			}
		}
		if e = saveReport(ctx, tx, actor, out); e != nil {
			return e
		}
		return remember(ctx, tx, actor, op, key, fp, responseHandle{"report", out.ID, 0})
	})
	return
}
func (s *Service) ValidateRevision(ctx context.Context, a Actor, id, key string) (out *AcceptedOperation, err error) {
	op := "revision.validate:" + id
	fp := digest([]string{id})
	var r *Revision
	var doc, base *configmodel.Document
	var catalog *configmodel.CatalogDocument
	readAccepted := func(ctx context.Context, tx storage.IdentityTx, operationID string) (*AcceptedOperation, error) {
		var reportID string
		var created time.Time
		e := securitystate.One(ctx, tx, `SELECT resource_id,created_at FROM config_operations WHERE id=?`, []any{operationID}, func(r storage.IdentityRows) error { return r.Scan(&reportID, &created) })
		if e != nil {
			return nil, e
		}
		return &AcceptedOperation{OperationID: operationID, ResourceID: reportID, StatusURL: "/api/v2/config/validations/" + reportID, SubmittedAt: created}, nil
	}
	err = s.transact(ctx, a, true, func(tx storage.IdentityTx, actor string) error {
		h, e := request(ctx, tx, actor, op, key, fp)
		if e != nil {
			return e
		}
		if h != nil {
			out, e = readAccepted(ctx, tx, h.id)
			return e
		}
		r, e = readRevision(ctx, tx, id)
		if e != nil {
			return e
		}
		doc, e = parseContent(r.Content)
		if e != nil {
			return e
		}
		base, e = baseDocument(ctx, tx, r.BaseRevisionID)
		if e != nil {
			return e
		}
		catalog, e = loadCatalog(ctx, tx, "")
		if e != nil {
			return e
		}
		if catalog != nil {
			return validateGroups(ctx, tx, catalog.Catalog)
		}
		return nil
	})
	if err != nil || out != nil {
		return out, err
	}
	report, err := compileReport(ctx, s, "revision", id, r.Revision, doc, base, catalog)
	if err != nil {
		return nil, err
	}
	err = s.transact(ctx, a, true, func(tx storage.IdentityTx, actor string) error {
		h, e := request(ctx, tx, actor, op, key, fp)
		if e != nil {
			return e
		}
		if h != nil {
			out, e = readAccepted(ctx, tx, h.id)
			return e
		}
		if catalog != nil {
			if e = validateGroups(ctx, tx, catalog.Catalog); e != nil {
				return e
			}
		}
		if e = saveReport(ctx, tx, actor, report); e != nil {
			return e
		}
		operationID := securitystate.ID("operation")
		now := time.Now().UTC()
		if _, e = tx.Exec(ctx, `INSERT INTO config_operations(id,resource_id,state,created_at) VALUES(?,?,'succeeded',?)`, operationID, report.ID, now); e != nil {
			return e
		}
		if e = remember(ctx, tx, actor, op, key, fp, responseHandle{"operation", operationID, 0}); e != nil {
			return e
		}
		out, e = readAccepted(ctx, tx, operationID)
		return e
	})
	return
}
