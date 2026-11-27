package securityjournal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/001_journal.sql
var migration string

type ApprovalKey struct {
	PrincipalID  string
	PublicKey    ed25519.PublicKey
	AllowedKinds []string
}

type StoreConfig struct {
	DSN, AuthorityID, KeyID string
	SigningKey              ed25519.PrivateKey
	// Approval keys are independently held by restore/lift approvers, not CP.
	ApprovalKeys map[string]ApprovalKey
}
type Store struct {
	pool *pgxpool.Pool
	cfg  StoreConfig
}

func Open(ctx context.Context, cfg StoreConfig) (*Store, error) {
	if !objectID.MatchString(cfg.AuthorityID) || !objectID.MatchString(cfg.KeyID) || len(cfg.SigningKey) != ed25519.PrivateKeySize {
		return nil, bad("journal configuration")
	}

	seenKeys := map[string]string{}
	for id, approval := range cfg.ApprovalKeys {
		if !objectID.MatchString(id) || !objectID.MatchString(approval.PrincipalID) || len(approval.PublicKey) != ed25519.PublicKeySize || len(approval.AllowedKinds) == 0 || bytes.Equal(approval.PublicKey, cfg.SigningKey.Public().(ed25519.PublicKey)) {
			return nil, bad("independent approver registry")
		}
		for _, kind := range approval.AllowedKinds {
			if !needsApproval(kind) {
				return nil, bad("approval role")
			}
		}
		encoded := string(approval.PublicKey)
		if principal, ok := seenKeys[encoded]; ok && principal != approval.PrincipalID {
			return nil, bad("approval key cannot alias principals")
		}
		seenKeys[encoded] = approval.PrincipalID
	}
	pc, e := pgxpool.ParseConfig(cfg.DSN)
	if e != nil {
		return nil, errors.New("invalid journal database configuration")
	}
	pc.MaxConns = 8
	pc.ConnConfig.RuntimeParams["synchronous_commit"] = "on"
	pc.ConnConfig.RuntimeParams["statement_timeout"] = "10000"
	pc.ConnConfig.RuntimeParams["lock_timeout"] = "5000"
	pool, e := pgxpool.NewWithConfig(ctx, pc)
	if e != nil {
		return nil, fmt.Errorf("open journal database: %w", e)
	}
	s := &Store{pool: pool, cfg: cfg}
	if e = pool.Ping(ctx); e != nil {
		pool.Close()
		return nil, fmt.Errorf("ping journal database: %w", e)
	}
	return s, nil
}
func (s *Store) Close() { s.pool.Close() }

// Migrate is explicit, for the journal owner account. The runtime role should
// have only SELECT/INSERT, authority head/floor UPDATE, no DDL or TRUNCATE.
func (s *Store) Migrate(ctx context.Context) error {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(381447921)`); e != nil {
		return e
	}
	var exists bool
	if e = tx.QueryRow(ctx, `SELECT to_regclass('agp_security_journal.schema_version') IS NOT NULL`).Scan(&exists); e != nil {
		return e
	}
	if !exists {
		if _, e = tx.Exec(ctx, migration); e != nil {
			return fmt.Errorf("journal migration: %w", e)
		}
	} else {
		var v int
		if e = tx.QueryRow(ctx, `SELECT version FROM agp_security_journal.schema_version`).Scan(&v); e != nil || v != 1 {
			return errors.New("unsupported journal schema")
		}
	}
	if _, e = tx.Exec(ctx, `INSERT INTO agp_security_journal.authorities(id,authority_epoch) VALUES($1,1) ON CONFLICT DO NOTHING`, s.cfg.AuthorityID); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *Store) Head(ctx context.Context) (Head, error) { return s.head(ctx, "") }
func (s *Store) head(ctx context.Context, challenge string) (Head, error) {
	h := Head{AuthorityID: s.cfg.AuthorityID, Challenge: challenge, RecordedAt: time.Now().UTC(), KeyID: s.cfg.KeyID}
	var epoch, seq int64
	var cutoff, release *time.Time
	e := s.pool.QueryRow(ctx, `SELECT authority_epoch,head_sequence,COALESCE(head_digest,''),restore_cutoff,release_after FROM agp_security_journal.authorities WHERE id=$1`, s.cfg.AuthorityID).Scan(&epoch, &seq, &h.Digest, &cutoff, &release)
	if e != nil {
		return h, e
	}
	h.Epoch = UInt63(epoch)
	h.Sequence = UInt63(seq)
	if cutoff != nil {
		h.RestoreCutoff = *cutoff
	}
	if release != nil {
		h.ReleaseAfter = *release
	}
	if h.Sequence > 0 {
		var body []byte
		if e = s.pool.QueryRow(ctx, `SELECT event_json FROM agp_security_journal.events WHERE authority_id=$1 AND sequence=$2`, s.cfg.AuthorityID, seq).Scan(&body); e != nil {
			return Head{}, e
		}
		tail, err := s.decodeEvent(body, nil)
		if err != nil || tail.Digest != h.Digest || tail.Sequence != h.Sequence || tail.Epoch != h.Epoch {
			return Head{}, bad("journal head inconsistent with signed tail")
		}
	}
	if h.Epoch == 1 {
		if cutoff != nil || release != nil {
			return Head{}, bad("unexpected restore metadata")
		}
	} else {
		var body []byte
		if e = s.pool.QueryRow(ctx, `SELECT event_json FROM agp_security_journal.events WHERE authority_id=$1 AND authority_epoch=$2 AND kind='advance_authority_epoch' ORDER BY sequence DESC LIMIT 1`, s.cfg.AuthorityID, epoch).Scan(&body); e != nil {
			return Head{}, bad("missing signed restore epoch")
		}
		restore, err := s.decodeEvent(body, nil)
		if err != nil || restore.Epoch != h.Epoch || restore.Request.Payload.NewEpoch != h.Epoch || restore.Sequence > h.Sequence || cutoff == nil || release == nil {
			return Head{}, bad("restore metadata signature")
		}
		p := restore.Request.Payload
		if cutoff.Sub(p.RestoreCutoff) > time.Microsecond || p.RestoreCutoff.Sub(*cutoff) > time.Microsecond || release.Sub(p.ReleaseAfter) > time.Microsecond || p.ReleaseAfter.Sub(*release) > time.Microsecond {
			return Head{}, bad("restore metadata projection differs from signed event")
		}
		h.RestoreCutoff = p.RestoreCutoff
		h.ReleaseAfter = p.ReleaseAfter
	}

	e = signHead(&h, s.cfg.SigningKey)
	return h, e
}
func (s *Store) Operation(ctx context.Context, id string) (Event, error) {
	if !objectID.MatchString(id) {
		return Event{}, bad("operation id")
	}
	var b []byte
	e := s.pool.QueryRow(ctx, `SELECT event_json FROM agp_security_journal.events WHERE authority_id=$1 AND operation_id=$2`, s.cfg.AuthorityID, id).Scan(&b)
	if errors.Is(e, pgx.ErrNoRows) {
		return Event{}, ErrNotFound
	}
	return s.decodeEvent(b, e)
}
func (s *Store) decodeEvent(b []byte, e error) (Event, error) {
	var ev Event
	if e != nil {
		return ev, e
	}
	if e = json.Unmarshal(b, &ev); e != nil {
		return ev, e
	}
	if e = VerifyEvent(ev, s.cfg.AuthorityID, s.cfg.KeyID, s.cfg.SigningKey.Public().(ed25519.PublicKey)); e != nil {
		return Event{}, e
	}
	return ev, nil
}
func (s *Store) Events(ctx context.Context, after UInt63, limit int) ([]Event, error) {
	if after > MaxUInt63 || limit < 1 || limit > 1000 {
		return nil, bad("event cursor/limit")
	}
	rows, e := s.pool.Query(ctx, `SELECT event_json FROM agp_security_journal.events WHERE authority_id=$1 AND sequence>$2 ORDER BY sequence LIMIT $3`, s.cfg.AuthorityID, int64(after), limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	events := []Event{}
	for rows.Next() {
		var b []byte
		if e = rows.Scan(&b); e != nil {
			return nil, e
		}
		ev, err := s.decodeEvent(b, nil)
		if err != nil {
			return nil, err
		}
		events = append(events, ev)
	}
	return events, rows.Err()
}
func (s *Store) Append(ctx context.Context, r AppendRequest) (Event, error) {
	if e := validateRequest(r); e != nil {
		return Event{}, e
	}
	rd, e := RequestDigest(r)
	if e != nil {
		return Event{}, e
	}
	tx, e := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return Event{}, e
	}
	defer tx.Rollback(ctx)
	var epoch, seq int64
	var prev string
	if e = tx.QueryRow(ctx, `SELECT authority_epoch,head_sequence,COALESCE(head_digest,'') FROM agp_security_journal.authorities WHERE id=$1 FOR UPDATE`, s.cfg.AuthorityID).Scan(&epoch, &seq, &prev); e != nil {
		return Event{}, e
	}
	// Lookup under the authority lock makes concurrent repeats return the same
	// committed receipt even after an epoch/head change.
	var b []byte
	e = tx.QueryRow(ctx, `SELECT event_json FROM agp_security_journal.events WHERE authority_id=$1 AND operation_id=$2`, s.cfg.AuthorityID, r.OperationID).Scan(&b)
	if e == nil {
		ev, err := s.decodeEvent(b, nil)
		if err != nil {
			return Event{}, err
		}
		if ev.RequestDigest != rd {
			return Event{}, ErrConflict
		}
		return ev, nil
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return Event{}, e
	}
	if r.ExpectedEpoch != UInt63(epoch) || r.ExpectedSequence != UInt63(seq) || r.ExpectedDigest != prev || UInt63(seq) == MaxUInt63 {
		return Event{}, ErrConflict
	}
	now := time.Now().UTC()
	if r.RecordedAt.After(now.Add(30 * time.Second)) {
		return Event{}, bad("operation time")
	}
	if needsApproval(r.Kind) {
		approval, ok := s.cfg.ApprovalKeys[r.ApprovalKeyID]
		allowedKind := false
		for _, kind := range approval.AllowedKinds {
			if kind == r.Kind {
				allowedKind = true
			}
		}
		key := approval.PublicKey
		sig, err := base64.RawURLEncoding.DecodeString(r.ApprovalSignature)
		d, _ := ApprovalDigest(r)
		if !ok || !allowedKind || approval.PrincipalID != r.ApproverID || r.RecordedAt.Before(now.Add(-5*time.Minute)) || len(key) != ed25519.PublicKeySize || r.ApproverID == r.ActorID || !objectID.MatchString(r.ApproverID) || err != nil || !ed25519.Verify(key, []byte("AGP-JOURNAL-APPROVAL-v1\n"+d), sig) {
			return Event{}, bad("independent approval required")
		}
	}
	if r.Kind == "advance_authority_epoch" {
		if r.TargetID != s.cfg.AuthorityID || r.Payload.RestoreCutoff.After(now.Add(5*time.Second)) || r.Payload.RestoreCutoff.Before(now.Add(-5*time.Minute)) {
			return Event{}, bad("trusted restore cutoff")
		}
	}
	if r.Payload.OriginalEventID != "" {
		var kind, target, typ string
		e = tx.QueryRow(ctx, `SELECT kind,event_json->'request'->>'targetId',event_json->'request'->>'targetType' FROM agp_security_journal.events WHERE authority_id=$1 AND id=$2`, s.cfg.AuthorityID, r.Payload.OriginalEventID).Scan(&kind, &target, &typ)
		pairs := map[string]string{"unblock_principal": "block_principal", "enable_resource": "disable_resource", "clear_route_deny": "deny_route"}
		if e != nil || kind != pairs[r.Kind] || target != r.TargetID || typ != r.TargetType {
			return Event{}, bad("lift original deny")
		}
		var latestID string
		e = tx.QueryRow(ctx, `SELECT id FROM agp_security_journal.events WHERE authority_id=$1 AND event_json->'request'->>'targetId'=$2 AND event_json->'request'->>'targetType'=$3 AND kind IN ($4,$5) ORDER BY sequence DESC LIMIT 1`, s.cfg.AuthorityID, r.TargetID, r.TargetType, kind, r.Kind).Scan(&latestID)
		if e != nil || latestID != r.Payload.OriginalEventID {
			return Event{}, bad("lift must reference current deny")
		}

	}
	if r.Kind == "bump_authenticator_floor" || r.Kind == "revoke_secret" {
		var floor int64
		e = tx.QueryRow(ctx, `SELECT minimum_version FROM agp_security_journal.authenticator_floors WHERE authority_id=$1 AND principal_id=$2 AND authenticator_id=$3`, s.cfg.AuthorityID, r.Payload.PrincipalID, r.Payload.AuthenticatorID).Scan(&floor)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return Event{}, e
		}
		if r.Payload.MinimumVersion <= UInt63(floor) {
			return Event{}, ErrConflict
		}
	}
	id, e := randomID("evt_")
	if e != nil {
		return Event{}, e
	}
	newEpoch := UInt63(epoch)
	if r.Kind == "advance_authority_epoch" {
		newEpoch = r.Payload.NewEpoch
	}
	ev := Event{AuthorityID: s.cfg.AuthorityID, ID: id, Epoch: newEpoch, Sequence: UInt63(seq + 1), Request: r, RequestDigest: rd, PreviousDigest: prev, RecordedAt: now, KeyID: s.cfg.KeyID}
	if e = signEvent(&ev, s.cfg.SigningKey); e != nil {
		return Event{}, e
	}
	body, e := json.Marshal(ev)
	if e != nil {
		return Event{}, e
	}
	payload, e := json.Marshal(r.Payload)
	if e != nil {
		return Event{}, e
	}
	pd, e := hash(r.Payload)
	if e != nil {
		return Event{}, e
	}
	sig, _ := base64.RawURLEncoding.DecodeString(ev.Signature)
	if _, e = tx.Exec(ctx, `INSERT INTO agp_security_journal.operations(id,authority_id,request_digest,expected_authority_epoch,expected_head_sequence,actor_id,authorization_digest,accepted_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, r.OperationID, s.cfg.AuthorityID, rd, epoch, seq, r.ActorID, r.AuthorizationDigest, now); e != nil {
		return Event{}, e
	}
	var previous any
	if prev != "" {
		previous = prev
	}
	if _, e = tx.Exec(ctx, `INSERT INTO agp_security_journal.events(id,authority_id,sequence,authority_epoch,operation_id,kind,payload_json,payload_digest,previous_digest,event_digest,signing_key_id,receipt_signature,event_json,accepted_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, ev.ID, s.cfg.AuthorityID, seq+1, int64(newEpoch), r.OperationID, r.Kind, payload, pd, previous, ev.Digest, s.cfg.KeyID, sig, body, now); e != nil {
		return Event{}, e
	}
	if r.Kind == "bump_authenticator_floor" || r.Kind == "revoke_secret" {
		if _, e = tx.Exec(ctx, `INSERT INTO agp_security_journal.authenticator_floors(authority_id,principal_id,authenticator_id,minimum_version,source_sequence) VALUES($1,$2,$3,$4,$5) ON CONFLICT(authority_id,principal_id,authenticator_id) DO UPDATE SET minimum_version=EXCLUDED.minimum_version,source_sequence=EXCLUDED.source_sequence`, s.cfg.AuthorityID, r.Payload.PrincipalID, r.Payload.AuthenticatorID, int64(r.Payload.MinimumVersion), seq+1); e != nil {
			return Event{}, e
		}
	}
	if r.Kind == "advance_authority_epoch" {
		_, e = tx.Exec(ctx, `UPDATE agp_security_journal.authorities SET authority_epoch=$2,head_sequence=$3,head_digest=$4,restore_cutoff=$5,release_after=$6,row_version=row_version+1 WHERE id=$1`, s.cfg.AuthorityID, int64(newEpoch), seq+1, ev.Digest, r.Payload.RestoreCutoff, r.Payload.ReleaseAfter)
	} else {
		_, e = tx.Exec(ctx, `UPDATE agp_security_journal.authorities SET head_sequence=$2,head_digest=$3,row_version=row_version+1 WHERE id=$1`, s.cfg.AuthorityID, seq+1, ev.Digest)
	}
	if e != nil {
		return Event{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return Event{}, e
	}
	return ev, nil
}

// ValidateChain verifies the full retained journal before serving. It detects
// missing/mutated facts; independent retention is still needed against rolling
// back the journal itself together with the CP.
func (s *Store) ValidateChain(ctx context.Context) error {
	head, e := s.Head(ctx)
	if e != nil {
		return e
	}
	var seq UInt63
	prev := ""
	epoch := UInt63(1)
	for seq < head.Sequence {
		events, e := s.Events(ctx, seq, 1000)
		if e != nil {
			return e
		}
		if len(events) == 0 {
			return bad("journal gap")
		}
		for _, ev := range events {
			if ev.Sequence != seq+1 || ev.PreviousDigest != prev || ev.Request.ExpectedEpoch != epoch || ev.Request.ExpectedSequence != seq || ev.Request.ExpectedDigest != prev {
				return bad("broken journal chain")
			}
			if ev.Request.Kind == "advance_authority_epoch" {
				epoch = ev.Request.Payload.NewEpoch
			}
			if ev.Epoch != epoch {
				return bad("event epoch")
			}
			seq = ev.Sequence
			prev = ev.Digest
		}
	}
	if seq != head.Sequence || prev != head.Digest || epoch != head.Epoch {
		return bad("head/chain mismatch")
	}
	return nil
}

// DecodePublicKey accepts the documented hex-encoded Ed25519 public key.
func DecodePublicKey(value string) (ed25519.PublicKey, error) {
	b, e := hex.DecodeString(value)
	if e != nil || len(b) != ed25519.PublicKeySize {
		return nil, bad("Ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
}
