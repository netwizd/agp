package configuration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"time"

	"github.com/netwizd/agp/internal/compiler"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// Current is deliberately the same fenced admission used by secure identity.
type Current interface {
	Current(context.Context, func(storage.IdentityTx, securityjournal.Head) error) error
	Head(context.Context) (securityjournal.Head, error)
}
type Service struct {
	current           Current
	origin            string
	compiler          compiler.Options
	wafQualifier      WAFQualifier
	trustedInventory  TrustedInventory
	planSigning       planReviewSigning
	directorySubjects HistoricalSubjectResolver
}

func New(current Current, origin string, options compiler.Options) *Service {
	return &Service{current: current, origin: origin, compiler: options}
}

// WithWAFQualifier is configured once, before the service serves requests.
// An absent provider keeps native validation and publication closed.
func (s *Service) WithWAFQualifier(q WAFQualifier) *Service {
	s.wafQualifier = q
	return s
}

// HistoricalSubjectResolver supplies private volatile live observations. It is
// configured at startup; the final transaction checks every exact pin again.
type HistoricalSubjectResolver interface {
	WithCurrentHistoricalSubjects(context.Context, []string, func(context.Context) error) error
}

func (s *Service) WithDirectorySubjects(resolver HistoricalSubjectResolver) *Service {
	s.directorySubjects = resolver
	return s
}

var validKey = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
var validID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

func (s *Service) transact(ctx context.Context, a Actor, write bool, fn func(storage.IdentityTx, string) error) error {
	return s.transactScoped(ctx, a, write, func(tx storage.IdentityTx, p *Principal) error {
		permission := "config.read"
		if write {
			permission = "config.edit"
		}
		if e := p.Require(permission, ""); e != nil {
			return e
		}
		return fn(tx, p.ID)
	})
}
func (s *Service) transactAdmin(ctx context.Context, a Actor, write bool, fn func(storage.IdentityTx, string) error) error {
	return s.transactScoped(ctx, a, write, func(tx storage.IdentityTx, p *Principal) error {
		if !p.Admin {
			return storage.ErrPermissionDenied
		}
		return fn(tx, p.ID)
	})
}

func digest(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func parseContent(raw json.RawMessage) (*configmodel.Document, error) {
	return configmodel.ParseConfiguration(bytes.NewReader(raw), configmodel.JSON)
}
func parseVersion(raw string) (int64, error) {
	v, e := strconv.ParseInt(raw, 10, 64)
	if e != nil || v < 0 || strconv.FormatInt(v, 10) != raw {
		return 0, ErrInvalidRequest
	}
	return v, nil
}
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func readHead(ctx context.Context, tx storage.IdentityTx) (string, int64, error) {
	var head *string
	var version int64
	e := securitystate.One(ctx, tx, `SELECT revision_id,row_version FROM config_head WHERE id=1`, nil, func(r storage.IdentityRows) error { return r.Scan(&head, &version) })
	if head == nil {
		return "", version, e
	}
	return *head, version, e
}

type responseHandle struct {
	kind, id string
	version  int64
}

func request(ctx context.Context, tx storage.IdentityTx, actor, operation, key, fp string) (*responseHandle, error) {
	if !validKey.MatchString(key) {
		return nil, ErrInvalidRequest
	}
	var prior string
	h := responseHandle{}
	err := securitystate.One(ctx, tx, `SELECT fingerprint,resource_kind,resource_id,resource_version FROM config_requests WHERE actor_id=? AND operation=? AND request_key=?`, []any{actor, operation, key}, func(r storage.IdentityRows) error { return r.Scan(&prior, &h.kind, &h.id, &h.version) })
	if err == storage.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if prior != fp {
		return nil, ErrIdempotencyConflict
	}
	return &h, nil
}
func remember(ctx context.Context, tx storage.IdentityTx, actor, operation, key, fp string, h responseHandle) error {
	_, e := tx.Exec(ctx, `INSERT INTO config_requests(actor_id,operation,request_key,fingerprint,resource_kind,resource_id,resource_version,created_at) VALUES(?,?,?,?,?,?,?,?)`, actor, operation, key, fp, h.kind, h.id, h.version, time.Now().UTC())
	return e
}
func readRevision(ctx context.Context, tx storage.IdentityTx, id string) (*Revision, error) {
	if !validID.MatchString(id) {
		return nil, ErrInvalidRequest
	}
	r := &Revision{ViewScope: "global"}
	var base *string
	var canonical string
	var version int64
	e := securitystate.One(ctx, tx, `SELECT id,parent_id,content_digest,canonical_json,state,row_version FROM config_revisions WHERE id=?`, []any{id}, func(rows storage.IdentityRows) error {
		return rows.Scan(&r.ID, &base, &r.ContentDigest, &canonical, &r.State, &version)
	})
	if base != nil {
		r.BaseRevisionID = *base
	}
	r.Content = json.RawMessage(canonical)
	r.Revision = strconv.FormatInt(version, 10)
	return r, e
}
func readDraft(ctx context.Context, tx storage.IdentityTx, id string, version *int64) (*Draft, error) {
	if !validID.MatchString(id) {
		return nil, ErrInvalidRequest
	}
	d := &Draft{ID: id}
	var base *string
	var current int64
	err := securitystate.One(ctx, tx, `SELECT base_revision_id,current_version FROM config_drafts WHERE id=?`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&base, &current) })
	if err != nil {
		return nil, err
	}
	if version != nil {
		current = *version
	}
	var body string
	err = securitystate.One(ctx, tx, `SELECT content_digest,canonical_json FROM config_draft_versions WHERE draft_id=? AND version=?`, []any{id, current}, func(r storage.IdentityRows) error { return r.Scan(&d.ContentDigest, &body) })
	if base != nil {
		d.BaseRevisionID = *base
	}
	d.Revision = strconv.FormatInt(current, 10)
	d.Content = json.RawMessage(body)
	return d, err
}
func (s *Service) GetRevision(ctx context.Context, a Actor, id string) (out *Revision, err error) {
	err = s.transact(ctx, a, false, func(tx storage.IdentityTx, _ string) error { out, err = readRevision(ctx, tx, id); return err })
	return
}
func (s *Service) GetDraft(ctx context.Context, a Actor, id string) (out *Draft, err error) {
	err = s.transact(ctx, a, false, func(tx storage.IdentityTx, _ string) error { out, err = readDraft(ctx, tx, id, nil); return err })
	return
}
func (s *Service) ListRevisions(ctx context.Context, a Actor, limit int, cursor string) (out RevisionPage, err error) {
	if limit < 1 || limit > 200 {
		return out, ErrInvalidRequest
	}
	var before int64 = math.MaxInt64
	if cursor != "" {
		before, err = parseVersion(cursor)
		if err != nil {
			return out, err
		}
	}
	out.Items = []Revision{}
	err = s.transact(ctx, a, false, func(tx storage.IdentityTx, _ string) error {
		query := `SELECT id,revision_number FROM config_revisions ORDER BY revision_number DESC LIMIT ?`
		args := []any{limit + 1}
		if cursor != "" {
			query = `SELECT id,revision_number FROM config_revisions WHERE revision_number<? ORDER BY revision_number DESC LIMIT ?`
			args = []any{before, limit + 1}
		}
		rows, e := tx.Query(ctx, query, args...)
		if e != nil {
			return e
		}
		type item struct {
			id string
			n  int64
		}
		items := []item{}
		for rows.Next() {
			var i item
			if e = rows.Scan(&i.id, &i.n); e != nil {
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
			out.NextCursor = strconv.FormatInt(items[limit-1].n, 10)
			items = items[:limit]
		}
		for _, i := range items {
			r, e := readRevision(ctx, tx, i.id)
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
func (s *Service) CreateDraft(ctx context.Context, a Actor, key string, in CreateDraft) (out *Draft, err error) {
	doc, err := parseContent(in.Content)
	if err != nil {
		return nil, err
	}
	if in.BaseRevisionID != "" && !validID.MatchString(in.BaseRevisionID) {
		return nil, ErrInvalidRequest
	}
	fp := digest([]string{in.BaseRevisionID, doc.Digest})
	err = s.transact(ctx, a, true, func(tx storage.IdentityTx, actor string) error {
		h, e := request(ctx, tx, actor, "draft.create", key, fp)
		if e != nil {
			return e
		}
		if h != nil {
			out, e = readDraft(ctx, tx, h.id, &h.version)
			return e
		}
		head, _, e := readHead(ctx, tx)
		if e != nil {
			return e
		}
		if head != in.BaseRevisionID {
			return ErrRevisionMismatch
		}
		id := securitystate.ID("draft")
		now := time.Now().UTC()
		if _, e = tx.Exec(ctx, `INSERT INTO config_drafts(id,base_revision_id,current_version,created_by,created_at) VALUES(?,?,0,?,?)`, id, nullable(head), actor, now); e != nil {
			return e
		}
		if e = saveDraftVersion(ctx, tx, id, 0, doc, actor, now); e != nil {
			return e
		}
		if e = remember(ctx, tx, actor, "draft.create", key, fp, responseHandle{"draft", id, 0}); e != nil {
			return e
		}
		if e = securitystate.Audit(ctx, tx, "config.draft.created", actor, map[string]any{"draftId": id, "contentDigest": doc.Digest}); e != nil {
			return e
		}
		out, e = readDraft(ctx, tx, id, nil)
		return e
	})
	return
}
func saveDraftVersion(ctx context.Context, tx storage.IdentityTx, id string, v int64, doc *configmodel.Document, actor string, now time.Time) error {
	_, e := tx.Exec(ctx, `INSERT INTO config_draft_versions(draft_id,version,content_digest,canonical_json,canonical_size_bytes,created_by,created_at) VALUES(?,?,?,?,?,?,?)`, id, v, doc.Digest, string(doc.Canonical), len(doc.Canonical), actor, now)
	return e
}
func (s *Service) UpdateDraft(ctx context.Context, a Actor, id, version, key string, content json.RawMessage) (out *Draft, err error) {
	v, err := parseVersion(version)
	if err != nil || v == math.MaxInt64 {
		return nil, ErrInvalidRequest
	}
	doc, err := parseContent(content)
	if err != nil {
		return nil, err
	}
	fp := digest([]string{id, version, doc.Digest})
	op := "draft.update:" + id
	err = s.transact(ctx, a, true, func(tx storage.IdentityTx, actor string) error {
		h, e := request(ctx, tx, actor, op, key, fp)
		if e != nil {
			return e
		}
		if h != nil {
			out, e = readDraft(ctx, tx, h.id, &h.version)
			return e
		}
		n, e := tx.Exec(ctx, `UPDATE config_drafts SET current_version=? WHERE id=? AND current_version=?`, v+1, id, v)
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrRevisionMismatch
		}
		if e = saveDraftVersion(ctx, tx, id, v+1, doc, actor, time.Now().UTC()); e != nil {
			return e
		}
		if e = remember(ctx, tx, actor, op, key, fp, responseHandle{"draft", id, v + 1}); e != nil {
			return e
		}
		if e = securitystate.Audit(ctx, tx, "config.draft.updated", actor, map[string]any{"draftId": id, "version": strconv.FormatInt(v+1, 10), "contentDigest": doc.Digest}); e != nil {
			return e
		}
		out, e = readDraft(ctx, tx, id, nil)
		return e
	})
	return
}
func (s *Service) CreateRevision(ctx context.Context, a Actor, key string, in CreateRevision) (out *Revision, err error) {
	if in.ResourceChange != nil {
		return s.ChangeResource(ctx, a, key, in)
	}
	if in.WafZoneChange != nil {
		if len(in.Content) != 0 || in.GatewayChange != nil || in.BaseRevisionID != "" {
			return nil, ErrInvalidRequest
		}
		return s.MaterializeZone(ctx, a, key, *in.WafZoneChange)
	}

	if (len(in.Content) == 0) == (in.GatewayChange == nil) {
		return nil, ErrInvalidRequest
	}
	var doc *configmodel.Document
	var gateway *configmodel.Gateway
	if in.GatewayChange == nil {
		doc, err = parseContent(in.Content)
	} else {
		if in.BaseRevisionID == "" {
			return nil, ErrInvalidRequest
		}
		gateway, err = configmodel.ParseGateway(bytes.NewReader(in.GatewayChange.Content), configmodel.JSON)
		if err == nil && gateway.Metadata.ID != in.GatewayChange.GatewayID {
			return nil, ErrInvalidRequest
		}
	}
	if err != nil {
		return nil, err
	}
	var fp string
	if doc != nil {
		fp = digest([]string{in.BaseRevisionID, doc.Digest})
	} else {
		raw, e := configmodel.CanonicalJSON(gateway)
		if e != nil {
			return nil, e
		}
		fp = digest([]string{in.BaseRevisionID, gateway.Metadata.ID, string(raw)})
	}
	err = s.transact(ctx, a, true, func(tx storage.IdentityTx, actor string) error {
		h, e := request(ctx, tx, actor, "revision.create", key, fp)
		if e != nil {
			return e
		}
		if h != nil {
			out, e = readRevision(ctx, tx, h.id)
			return e
		}
		if gateway != nil {
			base, e := readRevision(ctx, tx, in.BaseRevisionID)
			if e != nil {
				return e
			}
			baseDoc, e := parseContent(base.Content)
			if e != nil {
				return e
			}
			found := false
			for i, g := range baseDoc.Configuration.Gateways {
				if g.Metadata.ID == gateway.Metadata.ID {
					baseDoc.Configuration.Gateways[i] = *gateway
					found = true
					break
				}
			}
			if !found {
				baseDoc.Configuration.Gateways = append(baseDoc.Configuration.Gateways, *gateway)
			}
			doc, e = configmodel.Canonicalize(baseDoc.Configuration)
			if e != nil {
				return e
			}
		}
		out, e = insertRevision(ctx, tx, actor, in.BaseRevisionID, doc)
		if e != nil {
			return e
		}
		return remember(ctx, tx, actor, "revision.create", key, fp, responseHandle{"revision", out.ID, 0})
	})
	return
}
func (s *Service) SealDraft(ctx context.Context, a Actor, id, version, key string) (out *Revision, err error) {
	v, err := parseVersion(version)
	if err != nil {
		return nil, err
	}
	fp := digest([]string{id, version})
	op := "draft.seal:" + id
	err = s.transact(ctx, a, true, func(tx storage.IdentityTx, actor string) error {
		h, e := request(ctx, tx, actor, op, key, fp)
		if e != nil {
			return e
		}
		if h != nil {
			out, e = readRevision(ctx, tx, h.id)
			return e
		}
		d, e := readDraft(ctx, tx, id, nil)
		if e != nil {
			return e
		}
		if d.Revision != version {
			return ErrRevisionMismatch
		}
		doc, e := parseContent(d.Content)
		if e != nil {
			return e
		}
		out, e = insertRevision(ctx, tx, actor, d.BaseRevisionID, doc)
		if e != nil {
			return e
		}
		return remember(ctx, tx, actor, op, key, fp, responseHandle{"revision", out.ID, v})
	})
	return
}
func insertRevision(ctx context.Context, tx storage.IdentityTx, actor, base string, doc *configmodel.Document) (*Revision, error) {
	return insertRevisionWithZones(ctx, tx, actor, base, doc, nil)
}

func insertRevisionWithZones(ctx context.Context, tx storage.IdentityTx, actor, base string, doc *configmodel.Document, overrides map[string]zoneAssignment) (*Revision, error) {
	if e := verifyOwnership(ctx, tx, doc); e != nil {
		return nil, e
	}
	head, version, err := readHead(ctx, tx)
	if err != nil {
		return nil, err
	}
	if head != base {
		return nil, ErrRevisionMismatch
	}
	if version == math.MaxInt64 {
		return nil, ErrUnavailable
	}
	id := securitystate.ID("cfg")
	now := time.Now().UTC()
	_, err = tx.Exec(ctx, `INSERT INTO config_revisions(id,revision_number,parent_id,schema_version,capacity_profile,canonical_size_bytes,content_digest,canonical_json,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, id, version+1, nullable(base), doc.Configuration.APIVersion, doc.Capacity.Profile, len(doc.Canonical), doc.Digest, string(doc.Canonical), actor, now)
	if err != nil {
		return nil, err
	}
	if err = insertProjections(ctx, tx, id, doc); err != nil {
		return nil, err
	}
	if err = insertZoneAssignments(ctx, tx, base, id, doc, overrides); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO config_revision_seals(revision_id,created_at) VALUES(?,?)`, id, now); err != nil {
		return nil, err
	}
	n, err := tx.Exec(ctx, `UPDATE config_head SET revision_id=?,row_version=? WHERE id=1 AND row_version=?`, id, version+1, version)
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, ErrRevisionMismatch
	}
	if err = securitystate.Audit(ctx, tx, "config.revision.created", actor, map[string]any{"revisionId": id, "baseRevisionId": base, "contentDigest": doc.Digest}); err != nil {
		return nil, err
	}
	return readRevision(ctx, tx, id)
}

func (s *Service) Profile(ctx context.Context, a Actor) (out Profile, err error) {
	err = s.transact(ctx, a, false, func(tx storage.IdentityTx, _ string) error { var e error; out, e = profile(ctx, tx); return e })
	return
}
func profile(ctx context.Context, tx storage.IdentityTx) (out Profile, err error) {
	err = securitystate.One(ctx, tx, `SELECT enabled FROM configuration_profile WHERE id=1`, nil, func(r storage.IdentityRows) error { return r.Scan(&out.Enabled) })
	if err == nil {
		out.HeadRevisionID, _, err = readHead(ctx, tx)
	}
	return
}

// CheckProfile prevents a current binary from silently reopening legacy writes.
func CheckProfile(ctx context.Context, store storage.Store, enabled bool) error {
	return store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		p, e := profile(ctx, tx)
		if e != nil {
			return e
		}
		if p.Enabled && !enabled {
			return fmt.Errorf("canonical configuration profile is active; AGP_CONFIGURATION_ENABLED cannot be disabled")
		}
		return nil
	})
}

// InspectProfile reads persisted metadata for the offline CLI preview.
func InspectProfile(ctx context.Context, store storage.Store) (out Profile, err error) {
	err = store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		out, err = profile(ctx, tx)
		return err
	})
	return
}

// Activate is an explicit offline CLI operation, fenced by the identity lease.
func (s *Service) Activate(ctx context.Context) error {
	if s.current == nil {
		return ErrUnavailable
	}
	return s.current.Current(ctx, func(tx storage.IdentityTx, _ securityjournal.Head) error {
		p, e := profile(ctx, tx)
		if e != nil {
			return e
		}
		if p.Enabled {
			return nil
		}
		if p.HeadRevisionID == "" {
			return fmt.Errorf("create an immutable configuration revision before activation")
		}
		if _, e = tx.Exec(ctx, `UPDATE configuration_profile SET enabled=?,activated_at=? WHERE id=1 AND enabled=?`, true, time.Now().UTC(), false); e != nil {
			return e
		}
		return securitystate.Audit(ctx, tx, "config.profile.activated", "cli", map[string]any{"headRevisionId": p.HeadRevisionID})
	})
}
