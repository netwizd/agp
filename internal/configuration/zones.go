package configuration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// ZoneCreate appends an immutable authored body. BaseRevisionID is the exact
// current authoring head of the stable zone, not a Configuration revision.
type ZoneCreate struct {
	BaseRevisionID string          `json:"baseRevisionId,omitempty"`
	Content        json.RawMessage `json:"content"`
}

// ZoneRevision is an immutable authoring body with separately derived lifecycle facts.
type ZoneRevision struct {
	ID             string          `json:"id"`
	BaseRevisionID string          `json:"baseRevisionId,omitempty"`
	ZoneID         string          `json:"zoneId"`
	SiteID         string          `json:"siteId"`
	OwnerID        string          `json:"ownerId"`
	ContentDigest  string          `json:"contentDigest"`
	Content        json.RawMessage `json:"content,omitempty"`
	State          string          `json:"state"`
	Revision       string          `json:"revision"`
}

type ZonePage struct {
	Items      []ZoneRevision `json:"items"`
	NextCursor string         `json:"nextCursor,omitempty"`
}

func zoneIssue(path, code, message string) error {
	return &configmodel.ValidationError{Issues: []configmodel.Issue{{Path: path, Code: code, Message: message, Severity: "error"}}}
}

func readZoneRevision(ctx context.Context, tx storage.IdentityTx, id string) (*ZoneRevision, error) {
	if !validID.MatchString(id) {
		return nil, ErrInvalidRequest
	}
	out := &ZoneRevision{State: "draft", Revision: "0"}
	var parent *string
	var raw string
	err := securitystate.One(ctx, tx, `SELECT id,parent_id,zone_id,site_id,owner_id,content_digest,canonical_json FROM config_zone_revisions WHERE id=?`, []any{id}, func(r storage.IdentityRows) error {
		return r.Scan(&out.ID, &parent, &out.ZoneID, &out.SiteID, &out.OwnerID, &out.ContentDigest, &raw)
	})
	if err != nil {
		return nil, err
	}
	if parent != nil {
		out.BaseRevisionID = *parent
	}
	zone, err := configmodel.ParseWafZone(bytes.NewBufferString(raw), configmodel.JSON)
	if err != nil {
		return nil, err
	}
	canonical, err := configmodel.CanonicalJSON(zone)
	if err != nil {
		return nil, err
	}
	d, err := configmodel.Digest(zone)
	if err != nil {
		return nil, err
	}
	if d != out.ContentDigest || string(canonical) != raw || zone.Metadata.ID != out.ZoneID || zone.Metadata.SiteID != out.SiteID || zone.Metadata.OwnerID != out.OwnerID {
		return nil, fmt.Errorf("zone revision integrity mismatch")
	}
	out.Content = json.RawMessage(raw)
	return out, nil
}

func validateZoneOwner(ctx context.Context, tx storage.IdentityTx, id string) error {
	var exists string
	err := securitystate.One(ctx, tx, `SELECT id FROM users WHERE id=? AND blocked_at IS NULL`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&exists) })
	if err == storage.ErrNotFound {
		return zoneIssue("/content/metadata/ownerId", "owner_unavailable", "Owner must be an existing unblocked principal")
	}
	return err
}

func (s *Service) CreateZoneRevision(ctx context.Context, a Actor, key string, in ZoneCreate) (out *ZoneRevision, err error) {
	zone, err := configmodel.ParseWafZone(bytes.NewReader(in.Content), configmodel.JSON)
	if err != nil {
		return nil, err
	}
	if in.BaseRevisionID != "" && !validID.MatchString(in.BaseRevisionID) {
		return nil, ErrInvalidRequest
	}
	canonical, err := configmodel.CanonicalJSON(zone)
	if err != nil {
		return nil, err
	}
	if len(canonical) > 2<<20 {
		return nil, zoneIssue("/content", "zone_capacity_exceeded", "Canonical authored zone exceeds 2 MiB")
	}
	contentDigest, err := configmodel.Digest(zone)
	if err != nil {
		return nil, err
	}
	fp := digest([]string{in.BaseRevisionID, contentDigest})
	err = s.transactScoped(ctx, a, true, func(tx storage.IdentityTx, p *Principal) error {
		actor := p.ID
		if e := p.Require("config.edit", zone.Metadata.SiteID); e != nil {
			return e
		}
		if e := validateZoneOwner(ctx, tx, zone.Metadata.OwnerID); e != nil {
			return e
		}
		h, e := request(ctx, tx, actor, "zone.create", key, fp)
		if e != nil {
			return e
		}
		if h != nil {
			out, e = readZoneRevision(ctx, tx, h.id)
			return e
		}
		var head, site, owner string
		var version int64
		e = securitystate.One(ctx, tx, `SELECT revision_id,site_id,owner_id,row_version FROM config_zone_heads WHERE zone_id=?`, []any{zone.Metadata.ID}, func(r storage.IdentityRows) error {
			return r.Scan(&head, &site, &owner, &version)
		})
		if e != nil && e != storage.ErrNotFound {
			return e
		}
		if head != "" {
			if e = p.Require("config.edit", site); e != nil {
				return storage.ErrNotFound
			}
		}
		if head != in.BaseRevisionID {
			return ErrRevisionMismatch
		}
		if head != "" && (site != zone.Metadata.SiteID || owner != zone.Metadata.OwnerID) {
			return zoneIssue("/content/metadata", "zone_identity_immutable", "Site and owner cannot be reassigned by creating a zone revision")
		}
		if version == int64(^uint64(0)>>1) {
			return ErrUnavailable
		}
		id := securitystate.ID("wzrev")
		now := time.Now().UTC()
		_, e = tx.Exec(ctx, `INSERT INTO config_zone_revisions(id,parent_id,zone_id,site_id,owner_id,revision_number,content_digest,canonical_json,canonical_size_bytes,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, id, nullable(head), zone.Metadata.ID, zone.Metadata.SiteID, zone.Metadata.OwnerID, version+1, contentDigest, string(canonical), len(canonical), actor, now)
		if e != nil {
			return e
		}
		if head == "" {
			_, e = tx.Exec(ctx, `INSERT INTO config_zone_heads(zone_id,site_id,owner_id,revision_id,row_version) VALUES(?,?,?,?,1)`, zone.Metadata.ID, zone.Metadata.SiteID, zone.Metadata.OwnerID, id)
		} else {
			var n int64
			n, e = tx.Exec(ctx, `UPDATE config_zone_heads SET revision_id=?,row_version=? WHERE zone_id=? AND revision_id=? AND row_version=?`, id, version+1, zone.Metadata.ID, head, version)
			if e == nil && n != 1 {
				return ErrRevisionMismatch
			}
		}
		if e != nil {
			return e
		}
		if e = remember(ctx, tx, actor, "zone.create", key, fp, responseHandle{"zone", id, 0}); e != nil {
			return e
		}
		if e = securitystate.Audit(ctx, tx, "config.zone.revision.created", actor, map[string]any{"zoneRevisionId": id, "zoneId": zone.Metadata.ID, "siteId": zone.Metadata.SiteID, "contentDigest": contentDigest, "state": "draft"}); e != nil {
			return e
		}
		out, e = readZoneRevision(ctx, tx, id)
		return e
	})
	return
}

func (s *Service) GetZoneRevision(ctx context.Context, a Actor, id string) (out *ZoneRevision, err error) {
	ctx, err = s.directorySubjectContext(ctx, a, false, directorySubjectSelection{Kind: "zone_view", ID: id})
	if err != nil {
		return
	}
	err = s.transactScoped(ctx, a, false, func(tx storage.IdentityTx, p *Principal) error {
		out, err = readZoneRevision(ctx, tx, id)
		if err != nil {
			return err
		}
		if e := p.Require("config.read", out.SiteID); e != nil {
			return storage.ErrNotFound
		}
		out, err = s.zoneView(ctx, tx, p, out)
		return err
	})
	return
}

func (s *Service) ListZones(ctx context.Context, a Actor, limit int, cursor, site string) (out ZonePage, err error) {
	out.Items = []ZoneRevision{}
	if limit < 1 || limit > 200 || (cursor != "" && !validID.MatchString(cursor)) || (site != "" && !validID.MatchString(site)) {
		return out, ErrInvalidRequest
	}
	ctx, err = s.directorySubjectContext(ctx, a, false, directorySubjectSelection{Kind: "zones_list", Limit: limit, Cursor: cursor, SiteID: site})
	if err != nil {
		return
	}
	err = s.transactScoped(ctx, a, false, func(tx storage.IdentityTx, p *Principal) error {
		q := `SELECT revision_id,zone_id FROM config_zone_heads WHERE zone_id>?`
		args := []any{cursor}
		if site != "" {
			if e := p.Require("config.read", site); e != nil {
				return e
			}
			q += ` AND site_id=?`
			args = append(args, site)
		} else if global, sites := p.ReadSites("config.read"); !global {
			if len(sites) == 0 {
				return storage.ErrPermissionDenied
			}
			q += ` AND site_id IN (` + strings.TrimSuffix(strings.Repeat("?,", len(sites)), ",") + `)`
			for _, id := range sites {
				args = append(args, id)
			}
		}
		q += ` ORDER BY zone_id LIMIT ?`
		args = append(args, limit+1)
		rows, e := tx.Query(ctx, q, args...)
		if e != nil {
			return e
		}
		type item struct{ id, zone string }
		items := []item{}
		for rows.Next() {
			var i item
			if e = rows.Scan(&i.id, &i.zone); e != nil {
				rows.Close()
				return e
			}
			items = append(items, i)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		if len(items) > limit {
			out.NextCursor = items[limit-1].zone
			items = items[:limit]
		}
		for _, i := range items {
			r, e := readZoneRevision(ctx, tx, i.id)
			if e != nil {
				return e
			}
			r, e = s.zoneView(ctx, tx, p, r)
			if e != nil {
				return e
			}
			r.Content = nil
			out.Items = append(out.Items, *r)
		}
		return nil
	})
	return
}

// zoneHeadRevisions freezes authoring inputs, not runtime assignments. The
// bounded result prevents an unbounded Site catalog from exhausting a preview.
func zoneHeadRevisions(ctx context.Context, tx storage.IdentityTx, site string) ([]*ZoneRevision, error) {
	rows, err := tx.Query(ctx, `SELECT revision_id FROM config_zone_heads WHERE site_id=? ORDER BY zone_id LIMIT 1001`, site)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(ids) > 1000 {
		return nil, zoneIssue("/siteId", "zone_preview_capacity_exceeded", "Authoring preview supports at most 1000 pinned zones in a Site")
	}
	out := make([]*ZoneRevision, 0, len(ids))
	totalBytes := 0
	for _, id := range ids {
		z, err := readZoneRevision(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		totalBytes += len(z.Content)
		if totalBytes > 64<<20 {
			return nil, zoneIssue("/siteId", "zone_preview_capacity_exceeded", "Complete pinned authoring inventory exceeds 64 MiB")
		}
		out = append(out, z)
	}
	return out, nil
}

// zoneHeadsDigest is the complete authoring Site head set. A new zone, even one
// absent from an old preview's pins, invalidates review of that old snapshot.
func zoneHeadsDigest(ctx context.Context, tx storage.IdentityTx, site string) (string, error) {
	rows, err := tx.Query(ctx, `SELECT zone_id,revision_id FROM config_zone_heads WHERE site_id=? ORDER BY zone_id LIMIT 1001`, site)
	if err != nil {
		return "", err
	}
	type pin struct {
		ZoneID     string `json:"zoneId"`
		RevisionID string `json:"revisionId"`
	}
	pins := []pin{}
	for rows.Next() {
		var p pin
		if err = rows.Scan(&p.ZoneID, &p.RevisionID); err != nil {
			rows.Close()
			return "", err
		}
		pins = append(pins, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", err
	}
	if len(pins) > 1000 {
		return "", zoneIssue("/siteId", "zone_preview_capacity_exceeded", "Authoring preview supports at most 1000 pinned zones in a Site")
	}
	return configmodel.Digest(pins)
}
