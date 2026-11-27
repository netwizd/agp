package inventory

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type Service struct {
	current      Current
	authority    Authority
	registryPath string
	provider     RegistryProvider
}

func New(current Current, authority Authority, registryPath string) (*Service, error) {
	if current == nil || authority == nil || !filepath.IsAbs(registryPath) || filepath.Clean(registryPath) != registryPath {
		return nil, ErrUnavailable
	}
	if _, e := loadRegistry(registryPath); e != nil {
		return nil, e
	}
	return &Service{current: current, authority: authority, registryPath: registryPath}, nil
}
func nonce() (string, error) {
	var b [32]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
func (s *Service) admitted(ctx context.Context, tx storage.IdentityTx, peer *tls.ConnectionState, h securityjournal.Head) (*registryEntry, error) {
	r, e := s.loadRegistry(ctx, h)
	if e != nil {
		return nil, e
	}
	n, e := r.peer(peer, h)
	if e != nil {
		return nil, e
	}
	if e = notRevoked(ctx, tx, n.NodeID); e != nil {
		return nil, e
	}
	return n, nil
}
func (s *Service) registrationUnchanged(ctx context.Context, n *registryEntry, h securityjournal.Head) error {
	r, e := s.loadRegistry(ctx, h)
	if e != nil {
		return e
	}
	if r.authority != h.AuthorityID {
		return ErrIdentity
	}
	for _, next := range r.entries {
		if next.NodeID == n.NodeID && next.digest == n.digest {
			return nil
		}
	}
	return ErrIdentity
}
func notRevoked(ctx context.Context, tx storage.IdentityTx, node string) error {
	ids, e := securitystate.Strings(ctx, tx, `SELECT node_id FROM security_node_revocations WHERE node_id=?`, node)
	if e != nil {
		return e
	}
	if len(ids) != 0 {
		return ErrIdentity
	}
	return nil
}
func (s *Service) Challenge(ctx context.Context, peer *tls.ConnectionState) (out *Challenge, err error) {
	err = s.current.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		n, e := s.admitted(ctx, tx, peer, h)
		if e != nil {
			return e
		}
		now := h.RecordedAt.UTC().Truncate(time.Microsecond)
		var active, recent int64
		e = securitystate.One(ctx, tx, `SELECT COUNT(*) FROM fleet_inventory_challenges WHERE identity_digest=? AND consumed_request_id IS NULL AND expires_at>?`, []any{n.digest, now}, func(r storage.IdentityRows) error { return r.Scan(&active) })
		if e != nil {
			return e
		}
		e = securitystate.One(ctx, tx, `SELECT COUNT(*) FROM fleet_inventory_challenges WHERE node_id=? AND created_at>?`, []any{n.NodeID, now.Add(-time.Minute)}, func(r storage.IdentityRows) error { return r.Scan(&recent) })
		if e != nil {
			return e
		}
		if active >= 4 || recent >= 30 {
			return ErrConflict
		}
		token, e := nonce()
		if e != nil {
			return e
		}
		id, e := nonce()
		if e != nil {
			return e
		}
		out = &Challenge{ID: "ich_" + id, Challenge: token, ExpiresAt: now.Add(ChallengeTTL)}
		_, e = tx.Exec(ctx, `INSERT INTO fleet_inventory_challenges(id,node_id,identity_digest,authority_epoch,token_hash,created_at,expires_at) VALUES(?,?,?,?,?,?,?)`, out.ID, n.NodeID, n.digest, int64(h.Epoch), hash([]byte(token)), now, out.ExpiresAt)
		if e != nil {
			return e
		}
		return s.registrationUnchanged(ctx, n, h)
	})
	return
}
func (s *Service) Submit(ctx context.Context, peer *tls.ConnectionState, in Submission) (out *Receipt, err error) {
	if !idPattern.MatchString(in.RequestID) || !idPattern.MatchString(in.ChallengeID) || !tokenPattern.MatchString(in.Challenge) {
		return nil, ErrInvalid
	}
	_, facts, observation, e := normalizeObservation(in.Observation)
	if e != nil {
		return nil, e
	}
	// Canonicalize the normalized set before comparing idempotent requests.
	if e = decodeBounded(bytes.NewReader(observation), &in.Observation, MaxObservationBytes); e != nil {
		return nil, e
	}
	fp, e := Digest(in)
	if e != nil {
		return nil, e
	}
	capDigest, obsDigest := hash(facts), hash(observation)
	err = s.current.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		n, e := s.admitted(ctx, tx, peer, h)
		if e != nil {
			return e
		}
		now := h.RecordedAt.UTC().Truncate(time.Microsecond)
		var priorFP, priorJSON string
		e = securitystate.One(ctx, tx, `SELECT request_fingerprint,receipt_json FROM fleet_inventory_receipts WHERE node_id=? AND identity_digest=? AND request_id=?`, []any{n.NodeID, n.digest, in.RequestID}, func(r storage.IdentityRows) error { return r.Scan(&priorFP, &priorJSON) })
		if e == nil {
			if priorFP != fp {
				return ErrConflict
			}
			var old Receipt
			if decodeBounded(bytes.NewBufferString(priorJSON), &old, 8192) != nil {
				return ErrUnavailable
			}
			out = &old
			return s.registrationUnchanged(ctx, n, h)
		}
		if e != storage.ErrNotFound {
			return e
		}
		var challengeNode, identity, tokenHash string
		var latestSequence int64
		var latestTime time.Time
		e = securitystate.One(ctx, tx, `SELECT receipt_sequence,received_at FROM fleet_inventory_receipts WHERE node_id=? ORDER BY receipt_sequence DESC LIMIT 1`, []any{n.NodeID}, func(r storage.IdentityRows) error { return r.Scan(&latestSequence, &latestTime) })
		if e != nil && e != storage.ErrNotFound {
			return e
		}
		if latestSequence == int64(securityjournal.MaxUInt63) || now.Before(latestTime) {
			return ErrNotFresh
		}
		var epoch int64
		var expires time.Time
		var consumed *string
		e = securitystate.One(ctx, tx, `SELECT node_id,identity_digest,authority_epoch,token_hash,expires_at,consumed_request_id FROM fleet_inventory_challenges WHERE id=?`, []any{in.ChallengeID}, func(r storage.IdentityRows) error {
			return r.Scan(&challengeNode, &identity, &epoch, &tokenHash, &expires, &consumed)
		})
		if e == storage.ErrNotFound {
			return ErrChallenge
		}
		if e != nil {
			return e
		}
		if challengeNode != n.NodeID || identity != n.digest || epoch != int64(h.Epoch) || consumed != nil || !now.Before(expires) || subtle.ConstantTimeCompare([]byte(hash([]byte(in.Challenge))), []byte(tokenHash)) != 1 {
			return ErrChallenge
		}
		changed, e := tx.Exec(ctx, `UPDATE fleet_inventory_challenges SET consumed_request_id=? WHERE id=? AND consumed_request_id IS NULL`, in.RequestID, in.ChallengeID)
		if e != nil {
			return e
		}
		if changed != 1 {
			return ErrChallenge
		}
		var existing string
		e = securitystate.One(ctx, tx, `SELECT canonical_json FROM fleet_capability_snapshots WHERE node_id=? AND digest=?`, []any{n.NodeID, capDigest}, func(r storage.IdentityRows) error { return r.Scan(&existing) })
		if e == storage.ErrNotFound {
			_, e = tx.Exec(ctx, `INSERT INTO fleet_capability_snapshots(node_id,digest,canonical_json,created_at) VALUES(?,?,?,?)`, n.NodeID, capDigest, string(facts), now)
		} else if e == nil && existing != string(facts) {
			return ErrUnavailable
		}
		if e != nil {
			return e
		}
		id, e := nonce()
		if e != nil {
			return e
		}
		out = &Receipt{ID: "irc_" + id, Sequence: securityjournal.UInt63(latestSequence + 1), RequestID: in.RequestID, NodeID: n.NodeID, CapabilityDigest: capDigest, ObservationDigest: obsDigest, ReceivedAt: now, ExpiresAt: now.Add(Freshness)}
		raw, e := canonical(out)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO fleet_inventory_receipts(id,node_id,receipt_sequence,identity_digest,authority_epoch,request_id,request_fingerprint,capability_digest,observation_digest,observation_json,receipt_json,received_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, out.ID, n.NodeID, int64(out.Sequence), n.digest, int64(h.Epoch), in.RequestID, fp, capDigest, obsDigest, string(observation), string(raw), now, out.ExpiresAt)
		if e != nil {
			return e
		}
		return s.registrationUnchanged(ctx, n, h)
	})
	return
}

func currentReceipt(ctx context.Context, tx storage.IdentityTx, n registryEntry, epoch securityjournal.UInt63, now time.Time) (*Node, error) {
	var raw, identity, capDigest, obsDigest, obsJSON string
	var storedEpoch, storedSequence int64
	e := securitystate.One(ctx, tx, `SELECT receipt_json,identity_digest,authority_epoch,capability_digest,observation_digest,observation_json,receipt_sequence FROM fleet_inventory_receipts WHERE node_id=? ORDER BY receipt_sequence DESC LIMIT 1`, []any{n.NodeID}, func(r storage.IdentityRows) error {
		return r.Scan(&raw, &identity, &storedEpoch, &capDigest, &obsDigest, &obsJSON, &storedSequence)
	})
	if e == storage.ErrNotFound {
		return nil, ErrNotFresh
	}
	if e != nil {
		return nil, e
	}
	var receipt Receipt
	var observation Observation
	if decodeBounded(bytes.NewBufferString(raw), &receipt, 8192) != nil || Decode(bytes.NewBufferString(obsJSON), &observation) != nil {
		return nil, ErrUnavailable
	}
	_, facts, normalized, e := normalizeObservation(observation)
	if e != nil || storedSequence <= 0 || receipt.Sequence != securityjournal.UInt63(storedSequence) || hash(facts) != capDigest || hash(normalized) != obsDigest || receipt.NodeID != n.NodeID || receipt.CapabilityDigest != capDigest || receipt.ObservationDigest != obsDigest || receipt.ExpiresAt.Sub(receipt.ReceivedAt) != Freshness {
		return nil, ErrUnavailable
	}
	if identity != n.digest || storedEpoch != int64(epoch) || !now.Before(receipt.ExpiresAt) || now.Before(receipt.ReceivedAt) {
		return nil, ErrNotFresh
	}
	var storedFacts string
	if e = securitystate.One(ctx, tx, `SELECT canonical_json FROM fleet_capability_snapshots WHERE node_id=? AND digest=?`, []any{n.NodeID, capDigest}, func(r storage.IdentityRows) error { return r.Scan(&storedFacts) }); e != nil {
		return nil, e
	}
	if storedFacts != string(facts) {
		return nil, ErrUnavailable
	}
	return &Node{ID: n.NodeID, SiteID: n.SiteID, Name: n.Name, Labels: n.Labels, GroupIDs: n.GroupIDs, IdentityDigest: n.digest, CapabilityDigest: capDigest, Capabilities: observation.Capabilities, ReceiptID: receipt.ID, ReceivedAt: receipt.ReceivedAt, ExpiresAt: receipt.ExpiresAt}, nil
}

// CurrentNodes runs in the caller's already fenced writer transaction. It never
// opens a nested transaction and obtains a new signed authority clock itself.
// Any matching registered node without current evidence rejects the full view.
func (s *Service) CurrentNodes(ctx context.Context, tx storage.IdentityTx, epoch securityjournal.UInt63, site string) ([]Node, error) {
	if s == nil || tx == nil || !idPattern.MatchString(site) {
		return nil, ErrInvalid
	}
	h, e := s.authority.Head(ctx)
	if e != nil || h.RecordedAt.IsZero() || h.Epoch != epoch {
		return nil, ErrUnavailable
	}
	r, e := s.loadRegistry(ctx, h)
	if e != nil {
		return nil, e
	}
	if r.authority != h.AuthorityID {
		return nil, ErrIdentity
	}
	if e = s.completeSite(ctx, tx, h, r, site); e != nil {
		return nil, e
	}
	out := []Node{}
	for _, n := range r.entries {
		if n.SiteID != site || n.AcceptUntil != nil {
			continue
		}
		if n.Revoked || n.IssuanceEpoch != epoch || !validAt(n.leaf, h.RecordedAt) {
			return nil, ErrIdentity
		}
		if e = notRevoked(ctx, tx, n.NodeID); e != nil {
			return nil, e
		}
		node, e := currentReceipt(ctx, tx, n, epoch, h.RecordedAt)
		if e != nil {
			return nil, e
		}
		out = append(out, *node)
	}
	return out, nil
}

// ListForAdmin preserves the management boundary and filters the inventory by
// explicit nodes.read scopes. Config editing alone grants no node permission.
func (s *Service) ListForAdmin(ctx context.Context, tokenHash, origin string) (out []NodeView, err error) {
	out = []NodeView{}
	if tokenHash == "" || origin == "" {
		return nil, storage.ErrPermissionDenied
	}
	err = s.current.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		access, e := ReadNodeAccess(ctx, tx, h, s.current, tokenHash, origin, "nodes.read", false)
		if e != nil {
			return e
		}
		if e = access.Resolve(ctx, tx); e != nil {
			return e
		}
		r, e := s.loadRegistry(ctx, h)
		if e != nil {
			return e
		}
		if r.authority != h.AuthorityID {
			return ErrIdentity
		}
		for _, n := range r.entries {
			if n.AcceptUntil != nil {
				continue
			}
			allowed, e := access.AllowsNode(ctx, tx, n.NodeID)
			if e != nil {
				return e
			}
			if !allowed {
				continue
			}
			v := NodeView{ID: n.NodeID, SiteID: n.SiteID, Name: n.Name, Labels: n.Labels, GroupIDs: n.GroupIDs, Connectivity: "unknown", IdentityState: "active"}
			if n.Revoked {
				v.IdentityState = "revoked"
			} else if n.IssuanceEpoch != h.Epoch || !validAt(n.leaf, h.RecordedAt) {
				v.IdentityState = "expired"
			} else if e = notRevoked(ctx, tx, n.NodeID); e == ErrIdentity {
				v.IdentityState = "revoked"
			} else if e != nil {
				return e
			}
			if v.IdentityState == "active" {
				node, e := currentReceipt(ctx, tx, n, h.Epoch, h.RecordedAt)
				if e == nil {
					v.Connectivity = "online"
					v.CapabilityDigest = node.CapabilityDigest
					t := node.ReceivedAt
					v.LastSeenAt = &t
				} else if e == ErrNotFresh {
					v.Connectivity = "offline"
				} else {
					return e
				}
			}
			out = append(out, v)
		}
		return access.Finish(ctx, tx, s.current, tokenHash, origin, false)
	})
	if err != nil {
		out = nil
	}
	return
}

// Encode uses ordinary JSON for transport; digest calculation always uses JCS.
func Encode(v any) ([]byte, error) { return json.Marshal(v) }
