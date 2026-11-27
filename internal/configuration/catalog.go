package configuration

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func validateGroups(ctx context.Context, tx storage.IdentityTx, c configmodel.Catalog) error {
	rows, err := tx.Query(ctx, `SELECT id FROM groups`)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		known[id] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range c.Groups {
		if !known[id] {
			return &configmodel.ValidationError{Issues: []configmodel.Issue{{Path: "/groups", Code: "group_unavailable", Message: "Catalog groups must reference existing identity groups", Severity: "error"}}}
		}
	}
	return nil
}
func insertCatalog(ctx context.Context, tx storage.IdentityTx, doc *configmodel.CatalogDocument) (*CatalogSnapshot, error) {
	if err := validateGroups(ctx, tx, doc.Catalog); err != nil {
		return nil, err
	}
	var existing string
	err := securitystate.One(ctx, tx, `SELECT content_digest FROM config_catalog_snapshots WHERE id=?`, []any{doc.Catalog.ID}, func(r storage.IdentityRows) error { return r.Scan(&existing) })
	if err == nil {
		if existing != doc.Digest {
			return nil, storage.ErrConflict
		}
		return catalogMetadata(ctx, tx, doc.Catalog.ID)
	}
	if err != storage.ErrNotFound {
		return nil, err
	}
	now := time.Now().UTC()
	_, err = tx.Exec(ctx, `INSERT INTO config_catalog_snapshots(id,content_digest,canonical_json,source_kind,source_ref,recorded_at) VALUES(?,?,?,?,?,?)`, doc.Catalog.ID, doc.Digest, string(doc.Canonical), doc.Catalog.SourceKind, doc.Catalog.SourceRef, now)
	if err != nil {
		return nil, err
	}
	return catalogMetadata(ctx, tx, doc.Catalog.ID)
}
func catalogMetadata(ctx context.Context, tx storage.IdentityTx, id string) (out *CatalogSnapshot, err error) {
	out = &CatalogSnapshot{}
	err = securitystate.One(ctx, tx, `SELECT id,content_digest,source_kind,source_ref,recorded_at FROM config_catalog_snapshots WHERE id=?`, []any{id}, func(r storage.IdentityRows) error {
		return r.Scan(&out.ID, &out.ContentDigest, &out.SourceKind, &out.SourceRef, &out.RecordedAt)
	})
	return
}
func (s *Service) ImportCatalog(ctx context.Context, a Actor, key string, raw []byte, format configmodel.Format) (out *CatalogSnapshot, err error) {
	doc, err := configmodel.ParseCatalog(bytes.NewReader(raw), format)
	if err != nil {
		return nil, err
	}
	err = s.transactAdmin(ctx, a, true, func(tx storage.IdentityTx, actor string) error {
		h, e := request(ctx, tx, actor, "catalog.create", key, doc.Digest)
		if e != nil {
			return e
		}
		if h != nil {
			out, e = catalogMetadata(ctx, tx, h.id)
			return e
		}
		out, e = insertCatalog(ctx, tx, doc)
		if e != nil {
			return e
		}
		if e = remember(ctx, tx, actor, "catalog.create", key, doc.Digest, responseHandle{"catalog", out.ID, 0}); e != nil {
			return e
		}
		return securitystate.Audit(ctx, tx, "config.catalog.created", actor, map[string]any{"catalogSnapshotId": out.ID, "contentDigest": out.ContentDigest, "sourceKind": "operator_declared"})
	})
	return
}
func (s *Service) ListCatalogs(ctx context.Context, a Actor) (out []CatalogSnapshot, err error) {
	out = []CatalogSnapshot{}
	err = s.transact(ctx, a, false, func(tx storage.IdentityTx, _ string) error {
		rows, e := tx.Query(ctx, `SELECT id,content_digest,source_kind,source_ref,recorded_at FROM config_catalog_snapshots ORDER BY recorded_at DESC,id DESC LIMIT 200`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var c CatalogSnapshot
			if e = rows.Scan(&c.ID, &c.ContentDigest, &c.SourceKind, &c.SourceRef, &c.RecordedAt); e != nil {
				return e
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return
}
func loadCatalog(ctx context.Context, tx storage.IdentityTx, id string) (*configmodel.CatalogDocument, error) {
	q := `SELECT canonical_json,content_digest FROM config_catalog_snapshots WHERE id=?`
	args := []any{id}
	if id == "" {
		q = `SELECT canonical_json,content_digest FROM config_catalog_snapshots ORDER BY recorded_at DESC,id DESC LIMIT 1`
		args = nil
	}
	var raw, expected string
	err := securitystate.One(ctx, tx, q, args, func(r storage.IdentityRows) error { return r.Scan(&raw, &expected) })
	if err == storage.ErrNotFound && id == "" {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	doc, err := configmodel.ParseCatalog(bytes.NewBufferString(raw), configmodel.JSON)
	if err != nil {
		return nil, err
	}
	if doc.Digest != expected {
		return nil, fmt.Errorf("catalog integrity mismatch")
	}
	return doc, nil
}
