package nodeidentity

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

// RegisterRecovery must run before Coordinator.Recover at process startup, even
// when optional enrollment listeners have not yet been constructed.
func RegisterRecovery(c *securitystate.Coordinator) { c.Register("node_revoke", materializeRevoke) }

type RevokeNodeRequest struct {
	Reason string `json:"reason"`
}
type NodeOperation struct {
	ID     string `json:"id"`
	NodeID string `json:"nodeId"`
	Kind   string `json:"kind"`
	State  string `json:"state"`
}
type revokeIntent struct {
	Actor, Key, Fingerprint, Reason, AccessFingerprint string
	Epoch                                              securityjournal.UInt63
	Operation                                          NodeOperation
}

func (s *Service) RevokeNode(ctx context.Context, a Actor, nodeID, key string, in RevokeNodeRequest) (out NodeOperation, err error) {
	if !idPattern.MatchString(nodeID) || !idPattern.MatchString(key) || len(strings.TrimSpace(in.Reason)) == 0 || len(in.Reason) > 512 || strings.ContainsAny(in.Reason, "\x00\r\n") {
		return out, ErrInvalid
	}
	c, ok := s.current.(*securitystate.Coordinator)
	if !ok {
		return out, ErrUnavailable
	}
	fp := digest(struct{ Node, Reason string }{nodeID, in.Reason})
	var intent revokeIntent
	err = s.withAccess(ctx, a, "nodes.revoke", true, func(tx storage.IdentityTx, h securityjournal.Head, access *inventory.NodeAccess) error {
		if e := requireNode(ctx, tx, access, nodeID); e != nil {
			return e
		}
		actor := access.ID
		done, e := replay(ctx, tx, actor, "node_revoke", key, fp, h.Epoch, &out)
		if e != nil {
			return e
		}
		if done {
			return nil
		}
		if _, e = loadNode(ctx, tx, nodeID); e != nil {
			return e
		}
		intent = revokeIntent{AccessFingerprint: access.Fingerprint(), Actor: actor, Key: key, Fingerprint: fp, Reason: in.Reason, Epoch: h.Epoch, Operation: NodeOperation{ID: "nrev_" + strings.TrimPrefix(digest([]string{actor, key, nodeID}), "sha256:"), NodeID: nodeID, Kind: "revoke_node", State: "completed"}}
		return nil
	})
	if err != nil || out.ID != "" {
		return
	}
	replayed := errors.New("completed node revoke")
	err = c.ExecuteDynamic(ctx, "node_revoke", func(tx storage.IdentityTx, h securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error) {
		if a.Origin != s.origin {
			return nil, nil, storage.ErrPermissionDenied
		}
		access, e := inventory.ReadNodeAccess(ctx, tx, h, s.current, a.TokenHash, a.Origin, "nodes.revoke", true)
		if e != nil {
			return nil, nil, e
		}
		if e = requireNode(ctx, tx, access, nodeID); e != nil {
			return nil, nil, e
		}
		actor := access.ID
		if actor != intent.Actor || h.Epoch != intent.Epoch || access.Fingerprint() != intent.AccessFingerprint {
			return nil, nil, storage.ErrPermissionDenied
		}
		done, e := replay(ctx, tx, actor, "node_revoke", key, fp, h.Epoch, &out)
		if e != nil {
			return nil, nil, e
		}
		if done {
			return nil, nil, replayed
		}
		if _, e = loadNode(ctx, tx, nodeID); e != nil {
			return nil, nil, e
		}
		if e = access.Finish(ctx, tx, s.current, a.TokenHash, a.Origin, true); e != nil {
			return nil, nil, e
		}
		raw, e := json.Marshal(intent)
		return raw, []securityjournal.AppendRequest{{Kind: "revoke_node", TargetType: "node", TargetID: nodeID, ActorID: actor, Payload: securityjournal.Payload{NodeID: nodeID}}}, e
	})
	if errors.Is(err, replayed) {
		err = nil
		return
	}
	if err == nil {
		out = intent.Operation
	}
	return
}
func materializeRevoke(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
	var in revokeIntent
	if decodeJSON(string(raw), &in) != nil {
		return ErrUnavailable
	}
	if e := remember(ctx, tx, in.Actor, "node_revoke", in.Key, in.Fingerprint, in.Epoch, in.Operation); e != nil {
		return e
	}
	return securitystate.Audit(ctx, tx, "node.revoked", in.Actor, map[string]string{"nodeId": in.Operation.NodeID, "reason": in.Reason})
}
func (s *Service) GetOperation(ctx context.Context, a Actor, id string) (out NodeOperation, err error) {
	err = s.withAccess(ctx, a, "nodes.revoke", false, func(tx storage.IdentityTx, h securityjournal.Head, access *inventory.NodeAccess) error {
		actor := access.ID
		rows, e := tx.Query(ctx, `SELECT result_json FROM node_identity_requests WHERE actor_id=? AND operation='node_revoke' AND authority_epoch=?`, actor, int64(h.Epoch))
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var raw string
			var op NodeOperation
			if rows.Scan(&raw) != nil || decodeJSON(raw, &op) != nil {
				return ErrUnavailable
			}
			if op.ID == id {
				rows.Close()
				if e = requireNode(ctx, tx, access, op.NodeID); e != nil {
					return e
				}
				out = op
				return nil
			}
		}
		if e = rows.Err(); e != nil {
			return e
		}
		return storage.ErrNotFound
	})
	return
}
