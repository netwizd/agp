// Package securitystate coordinates the CP writer with the independent deny
// authority. Durable pending operations are a global fail-closed S0 barrier.
package securitystate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

var ErrUnavailable = errors.New("security state unavailable")
var ErrBarrier = errors.New("security mutation pending")

type Repository interface {
	WriteIdentity(context.Context, func(storage.IdentityTx) error) error
}
type Materializer func(context.Context, storage.IdentityTx, json.RawMessage) error
type Intent struct {
	Epoch            securityjournal.UInt63 `json:"epoch"`
	PreparedSequence securityjournal.UInt63 `json:"preparedSequence"`
	Kind             string                 `json:"kind"`
	Data             json.RawMessage        `json:"data"`
}
type Coordinator struct {
	sessionGuard        ManagementSessionGuard
	sessionResolver     ManagementSessionResolver
	identityTargetGuard ProtectedIdentityTargetGuard
	Store               Repository
	Authority           securityjournal.Authority
	handlers            map[string]Materializer
	finishMu            sync.Mutex
}

func New(store Repository, authority securityjournal.Authority) *Coordinator {
	return &Coordinator{Store: store, Authority: authority, handlers: make(map[string]Materializer)}
}

// Register is startup-only, before the service accepts requests.
func (c *Coordinator) Register(kind string, fn Materializer) { c.handlers[kind] = fn }
func ID(prefix string) string {
	token, _, err := auth.NewToken()
	if err != nil {
		panic(err)
	}
	return prefix + "_" + token
}
func Digest(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func One(ctx context.Context, tx storage.IdentityTx, q string, args []any, scan func(storage.IdentityRows) error) error {
	rows, err := tx.Query(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		return storage.ErrNotFound
	}
	return scan(rows)
}
func Strings(ctx context.Context, tx storage.IdentityTx, q string, args ...any) ([]string, error) {
	rows, err := tx.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func state(ctx context.Context, tx storage.IdentityTx) (securityjournal.Head, error) {
	var h securityjournal.Head
	var epoch, seq int64
	var enabled bool
	err := One(ctx, tx, `SELECT authority_id,epoch,sequence,digest,enabled FROM security_state WHERE id=1`, nil, func(r storage.IdentityRows) error { return r.Scan(&h.AuthorityID, &epoch, &seq, &h.Digest, &enabled) })
	if err != nil {
		return h, err
	}
	if !enabled || epoch <= 0 || seq < 0 {
		return h, ErrUnavailable
	}
	h.Epoch = securityjournal.UInt63(epoch)
	h.Sequence = securityjournal.UInt63(seq)
	return h, nil
}
func sameProjection(a, b securityjournal.Head) bool {
	return a.AuthorityID == b.AuthorityID && a.Epoch == b.Epoch && a.Sequence == b.Sequence && a.Digest == b.Digest
}

// Head reads independently authenticated authority time and state. It does not
// authorize a transaction; callers must retain their surrounding Current fence.
func (c *Coordinator) Head(ctx context.Context) (securityjournal.Head, error) {
	if c == nil || c.Authority == nil {
		return securityjournal.Head{}, ErrUnavailable
	}
	return c.Authority.Head(ctx)
}

func pending(ctx context.Context, tx storage.IdentityTx) error {
	ids, err := Strings(ctx, tx, `SELECT id FROM security_operations WHERE status='pending'`)
	if err != nil {
		return err
	}
	if len(ids) > 0 {
		return ErrBarrier
	}
	return nil
}
func (c *Coordinator) Current(ctx context.Context, fn func(storage.IdentityTx, securityjournal.Head) error) error {
	before, err := c.Authority.Head(ctx)
	if err != nil {
		return fmt.Errorf("%w: head", ErrUnavailable)
	}
	if time.Now().UTC().Before(before.ReleaseAfter) {
		return ErrBarrier
	}
	return c.Store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		local, err := state(ctx, tx)
		if err != nil || !sameProjection(local, before) {
			return ErrUnavailable
		}
		if err := pending(ctx, tx); err != nil {
			return err
		}
		if err := fn(tx, before); err != nil {
			return err
		}
		after, err := c.Authority.Head(ctx)
		if err != nil || !before.SameState(after) {
			return ErrUnavailable
		}
		return nil
	})
}
func (c *Coordinator) Ready(ctx context.Context) error {
	return c.Current(ctx, func(storage.IdentityTx, securityjournal.Head) error { return nil })
}
func (c *Coordinator) Activate(ctx context.Context) error { return c.ActivateProfile(ctx, nil) }

// ActivateProfile atomically activates the origin/session profile, independent
// authority projection and initial grant incarnations. Existing sessions die
// in the same transaction; a failed activation cannot expose a half profile.
func (c *Coordinator) ActivateProfile(ctx context.Context, profile *domain.SessionProfile) error {
	h, err := c.Authority.Head(ctx)
	if err != nil {
		return err
	}
	if time.Now().Before(h.ReleaseAfter) {
		return ErrBarrier
	}
	return c.Store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		ids, err := Strings(ctx, tx, `SELECT authority_id FROM security_state WHERE id=1`)
		if err != nil {
			return err
		}
		if len(ids) > 0 {
			return errors.New("security state already initialized; reconcile or perform supervised restore")
		}
		if h.Sequence != 0 {
			return errors.New("new CP activation requires empty journal; existing authority requires explicit restore/recovery")
		}
		if profile != nil {
			if !profile.SecureProfile {
				return errors.New("secure activation requires secure profile")
			}
			if _, err := storage.ExecuteSessionProfileReset(ctx, tx, *profile); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO security_state(id,authority_id,epoch,sequence,digest,enabled) VALUES(1,?,?,?,?,?)`, h.AuthorityID, int64(h.Epoch), int64(h.Sequence), h.Digest, true); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at=? WHERE revoked_at IS NULL`, time.Now().UTC()); err != nil {
			return err
		}
		if err := SyncGrants(ctx, tx); err != nil {
			return err
		}
		after, err := c.Authority.Head(ctx)
		if err != nil || !h.SameState(after) {
			return ErrUnavailable
		}
		return Audit(ctx, tx, "identity.profile.activated", "cli", map[string]any{"authority": h.AuthorityID, "epoch": h.Epoch})
	})
}

// Execute first commits an intent/barrier. Only then can it contact the journal.
// prepare authorizes against the live CP state and returns restrictive events.
func (c *Coordinator) Execute(ctx context.Context, intent Intent, prepare func(storage.IdentityTx, securityjournal.Head) ([]securityjournal.AppendRequest, error)) error {
	return c.ExecuteDynamic(ctx, intent.Kind, func(tx storage.IdentityTx, h securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error) {
		requests, err := prepare(tx, h)
		return intent.Data, requests, err
	})
}

// ExecuteDynamic lets preparation derive an exact, immutable intent from the
// locked current state before committing the fail-closed barrier.
func (c *Coordinator) ExecuteDynamic(ctx context.Context, kind string, prepare func(storage.IdentityTx, securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error)) error {
	op := ID("op")
	err := c.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		data, requests, err := prepare(tx, h)
		intent := Intent{Epoch: h.Epoch, PreparedSequence: h.Sequence, Kind: kind, Data: data}
		if err != nil {
			return err
		}
		for i := range requests {
			requests[i].OperationID = fmt.Sprintf("%s_%d", op, i)
			requests[i].ExpectedEpoch = h.Epoch
			requests[i].ExpectedSequence = h.Sequence
			requests[i].ExpectedDigest = h.Digest
			requests[i].RecordedAt = time.Now().UTC()
			requests[i].AuthorizationDigest = Digest(intent)
		}
		raw, err := json.Marshal(requests)
		if err != nil {
			return err
		}
		intentJSON, err := json.Marshal(intent)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO security_operations(id,requests_json,intent_json,status,actor_id) VALUES(?,?,?,'pending',?)`, op, string(raw), string(intentJSON), "cp")
		return err
	})
	if err != nil {
		return err
	}
	if err := c.finish(ctx, op); err != nil {
		return err
	}
	var final string
	if err := c.Store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		return One(ctx, tx, `SELECT status FROM security_operations WHERE id=?`, []any{op}, func(r storage.IdentityRows) error { return r.Scan(&final) })
	}); err != nil {
		return err
	}
	if final != "applied" {
		return ErrBarrier
	}
	return nil
}
func (c *Coordinator) finish(ctx context.Context, op string) error {
	c.finishMu.Lock()
	defer c.finishMu.Unlock()
	var requests []securityjournal.AppendRequest
	var intent Intent
	var status string
	if err := c.Store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		var raw, data string
		err := One(ctx, tx, `SELECT requests_json,intent_json,status FROM security_operations WHERE id=?`, []any{op}, func(r storage.IdentityRows) error { return r.Scan(&raw, &data, &status) })
		if err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(raw), &requests); err != nil {
			return err
		}
		return json.Unmarshal([]byte(data), &intent)
	}); err != nil {
		return err
	}
	if status == "applied" || status == "aborted" {
		return nil
	}
	currentHead, err := c.Authority.Head(ctx)
	if err != nil {
		return err
	}
	if intent.Epoch != currentHead.Epoch {
		return c.Store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
			_, err := tx.Exec(ctx, `UPDATE security_operations SET status='aborted' WHERE id=?`, op)
			return err
		})
	}
	for i := range requests {
		accepted := false
		for attempt := 0; attempt < 4; attempt++ {
			request := requests[i]
			found, lookupErr := c.Authority.Operation(ctx, request.OperationID)
			if lookupErr == nil {
				digest, _ := securityjournal.RequestDigest(request)
				if found.RequestDigest != digest {
					return ErrUnavailable
				}
				accepted = true
				break
			}
			if !errors.Is(lookupErr, securityjournal.ErrNotFound) {
				return lookupErr
			}
			h, e := c.Authority.Head(ctx)
			if e != nil {
				return e
			}
			if h.Epoch != intent.Epoch {
				return ErrBarrier
			}
			foreign, err := c.foreignEvents(ctx, intent, requests, h)
			if err != nil {
				return err
			}
			if foreign {
				if err := c.Replay(ctx); err != nil {
					return err
				}
				return c.Store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
					_, err := tx.Exec(ctx, `UPDATE security_operations SET status='aborted' WHERE id=?`, op)
					return err
				})
			}

			if request.ExpectedSequence != h.Sequence || request.ExpectedDigest != h.Digest {
				// Approval signatures bind the exact expected head. They cannot be
				// silently retargeted after conflict or an ambiguous append response.
				if request.ApprovalSignature != "" {
					return securityjournal.ErrConflict
				}
				request.ExpectedEpoch = h.Epoch
				request.ExpectedSequence = h.Sequence
				request.ExpectedDigest = h.Digest
				requests[i] = request
				raw, _ := json.Marshal(requests)
				if e = c.Store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
					_, e := tx.Exec(ctx, `UPDATE security_operations SET requests_json=? WHERE id=? AND status='pending'`, string(raw), op)
					return e
				}); e != nil {
					return e
				}
			}
			receipt, appendErr := c.Authority.Append(ctx, request)
			if appendErr == nil {
				digest, _ := securityjournal.RequestDigest(request)
				if receipt.RequestDigest != digest {
					return ErrUnavailable
				}
				accepted = true
				break
			}
			// Lookup must precede any rewrite of this persisted request, including
			// when Append returned a conflict after an unknown transport outcome.
			receipt, lookupErr = c.Authority.Operation(ctx, request.OperationID)
			if lookupErr == nil {
				digest, _ := securityjournal.RequestDigest(request)
				if receipt.RequestDigest != digest {
					return ErrUnavailable
				}
				accepted = true
				break
			}
			if !errors.Is(lookupErr, securityjournal.ErrNotFound) {
				return lookupErr
			}
			if !errors.Is(appendErr, securityjournal.ErrConflict) {
				return appendErr
			}
		}
		if !accepted {
			return securityjournal.ErrConflict
		}
	}
	if err := c.Replay(ctx); err != nil {
		return err
	}
	handler, ok := c.handlers[intent.Kind]
	if !ok {
		return fmt.Errorf("unknown pending intent %q", intent.Kind)
	}
	return c.Store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		var latestStatus string
		if err := One(ctx, tx, `SELECT status FROM security_operations WHERE id=?`, []any{op}, func(r storage.IdentityRows) error { return r.Scan(&latestStatus) }); err != nil {
			return err
		}
		if latestStatus == "applied" || latestStatus == "aborted" {
			return nil
		}
		h, err := c.Authority.Head(ctx)
		if err != nil {
			return err
		}
		local, err := state(ctx, tx)
		if err != nil || !sameProjection(local, h) || intent.Epoch != h.Epoch {
			return ErrUnavailable
		}
		// A concurrent independently authorized restriction invalidates this
		// old positive intent. Replay the restriction, retire the barrier, and
		// require a fresh caller authorization instead of resurrecting grants.
		own := make(map[string]bool, len(requests))
		for _, request := range requests {
			own[request.OperationID] = true
		}
		events, err := Strings(ctx, tx, `SELECT event_json FROM security_events WHERE sequence>?`, int64(intent.PreparedSequence))
		if err != nil {
			return err
		}
		for _, raw := range events {
			var event securityjournal.Event
			if err := json.Unmarshal([]byte(raw), &event); err != nil {
				return err
			}
			if !own[event.Request.OperationID] {
				_, err := tx.Exec(ctx, `UPDATE security_operations SET status='aborted' WHERE id=?`, op)
				return err
			}
		}
		if err := handler(ctx, tx, intent.Data); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE security_operations SET status='applied' WHERE id=?`, op); err != nil {
			return err
		}
		if err := SyncGrants(ctx, tx); err != nil {
			return err
		}
		after, err := c.Authority.Head(ctx)
		if err != nil || !h.SameState(after) {
			return ErrUnavailable
		}
		return nil
	})
}
func (c *Coordinator) Recover(ctx context.Context) error {
	if err := c.Replay(ctx); err != nil {
		return err
	}
	var ops []string
	if err := c.Store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		var err error
		ops, err = Strings(ctx, tx, `SELECT id FROM security_operations WHERE status='pending' ORDER BY created_at,id`)
		return err
	}); err != nil {
		return err
	}
	for _, op := range ops {
		if err := c.finish(ctx, op); err != nil {
			return err
		}
	}
	return nil
}
func (c *Coordinator) Replay(ctx context.Context) error {
	h, err := c.Authority.Head(ctx)
	if err != nil {
		return err
	}
	var local securityjournal.Head
	if err := c.Store.WriteIdentity(ctx, func(tx storage.IdentityTx) error { var err error; local, err = state(ctx, tx); return err }); err != nil {
		return err
	}
	if local.AuthorityID != h.AuthorityID || local.Sequence > h.Sequence {
		return ErrUnavailable
	}
	for local.Sequence < h.Sequence {
		events, err := c.Authority.Events(ctx, local.Sequence, 100)
		if err != nil {
			return err
		}
		if len(events) == 0 {
			return ErrUnavailable
		}
		for _, event := range events {
			if event.Sequence > h.Sequence {
				break
			}
			if event.Sequence != local.Sequence+1 || event.PreviousDigest != local.Digest {
				return ErrUnavailable
			}
			if err := c.Store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
				current, err := state(ctx, tx)
				if err != nil {
					return err
				}
				if current.Sequence >= event.Sequence {
					return nil
				}
				if current.Sequence+1 != event.Sequence || current.Digest != event.PreviousDigest {
					return ErrUnavailable
				}
				if err := MaterializeEvent(ctx, tx, event); err != nil {
					return err
				}
				raw, _ := json.Marshal(event)
				if _, err := tx.Exec(ctx, `INSERT INTO security_events(sequence,event_id,event_json) VALUES(?,?,?)`, int64(event.Sequence), event.ID, string(raw)); err != nil {
					return err
				}
				_, err = tx.Exec(ctx, `UPDATE security_state SET epoch=?,sequence=?,digest=? WHERE id=1`, int64(event.Epoch), int64(event.Sequence), event.Digest)
				return err
			}); err != nil {
				return err
			}
			local.Epoch = event.Epoch
			local.Sequence = event.Sequence
			local.Digest = event.Digest
		}
	}
	if !sameProjection(local, h) {
		return ErrUnavailable
	}
	return nil
}
func Floor(ctx context.Context, tx storage.IdentityTx, principal, authenticator string) (uint64, error) {
	var v int64
	err := One(ctx, tx, `SELECT minimum_version FROM authenticator_floors WHERE principal_id=? AND authenticator_id=?`, []any{principal, authenticator}, func(r storage.IdentityRows) error { return r.Scan(&v) })
	if errors.Is(err, storage.ErrNotFound) {
		return 0, nil
	}
	return uint64(v), err
}
func FloorRequest(actor, principal, authenticator string, version uint64) securityjournal.AppendRequest {
	return securityjournal.AppendRequest{Kind: "bump_authenticator_floor", TargetType: "authenticator", TargetID: authenticator, ActorID: actor, Payload: securityjournal.Payload{PrincipalID: principal, AuthenticatorID: authenticator, MinimumVersion: securityjournal.UInt63(version)}}
}

// foreignEvents is checked before retargeting a not-yet-committed request. A
// higher independently published floor can make its payload permanently stale;
// it must retire the old positive intent instead of leaving an endless barrier.
func (c *Coordinator) foreignEvents(ctx context.Context, intent Intent, requests []securityjournal.AppendRequest, h securityjournal.Head) (bool, error) {
	own := make(map[string]bool, len(requests))
	for _, r := range requests {
		own[r.OperationID] = true
	}
	after := intent.PreparedSequence
	for after < h.Sequence {
		events, err := c.Authority.Events(ctx, after, 100)
		if err != nil {
			return false, err
		}
		if len(events) == 0 {
			return false, ErrUnavailable
		}
		previous := after
		for _, event := range events {
			if event.Sequence > h.Sequence {
				break
			}
			if event.Sequence != after+1 {
				return false, ErrUnavailable
			}
			after = event.Sequence
			if !own[event.Request.OperationID] {
				return true, nil
			}
		}
		if after == previous {
			return false, ErrUnavailable
		}
	}
	return false, nil
}
