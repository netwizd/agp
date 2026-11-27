package securitystate

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

func MaterializeEvent(ctx context.Context, tx storage.IdentityTx, event securityjournal.Event) error {
	r := event.Request
	p := r.Payload
	now := event.RecordedAt
	switch r.Kind {
	case "bump_authenticator_floor", "revoke_secret", "raise_security_floor":
		id := p.AuthenticatorID
		if r.Kind == "raise_security_floor" {
			id = "principal_" + p.PrincipalID
		}
		if _, err := tx.Exec(ctx, `INSERT INTO authenticator_floors(principal_id,authenticator_id,minimum_version) VALUES(?,?,?) ON CONFLICT(principal_id,authenticator_id) DO UPDATE SET minimum_version=CASE WHEN authenticator_floors.minimum_version<excluded.minimum_version THEN excluded.minimum_version ELSE authenticator_floors.minimum_version END`, p.PrincipalID, id, int64(p.MinimumVersion)); err != nil {
			return err
		}
		if strings.HasPrefix(p.AuthenticatorID, "totp_replay_") {
			return nil
		}
		_, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`, now, p.PrincipalID)
		return err
	case "block_principal":
		_, err := tx.Exec(ctx, `UPDATE users SET blocked_at=COALESCE(blocked_at,?) WHERE id=?`, now, p.PrincipalID)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`, now, p.PrincipalID)
		return err
	case "unblock_principal":
		_, err := tx.Exec(ctx, `UPDATE users SET blocked_at=NULL WHERE id=?`, p.PrincipalID)
		return err
	case "revoke_session":
		_, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at=? WHERE (id=? OR source_session_id=?) AND revoked_at IS NULL`, now, p.SessionID, p.SessionID)
		return err
	case "disable_resource", "deny_route":
		_, err := tx.Exec(ctx, `UPDATE resources SET enabled=? WHERE id=?`, false, p.ResourceID)
		return err
	case "enable_resource", "clear_route_deny":
		_, err := tx.Exec(ctx, `UPDATE resources SET enabled=? WHERE id=?`, true, p.ResourceID)
		return err
	case "remove_membership", "revoke_role_binding":
		if r.Kind == "revoke_role_binding" && strings.HasPrefix(p.GrantID, "rbinding_") {
			return materializeRoleBindingRevocation(ctx, tx, event)
		}
		if r.Kind == "revoke_role_binding" && strings.HasPrefix(p.GrantID, "cgrant_") {
			_, err := tx.Exec(ctx, `UPDATE config_scope_grants SET revoked=TRUE WHERE id=?`, p.GrantID)
			return err
		}
		var kind, subject, object string
		var active bool
		err := One(ctx, tx, `SELECT kind,subject_id,object_id,active FROM security_grants WHERE id=?`, []any{p.GrantID}, func(r storage.IdentityRows) error { return r.Scan(&kind, &subject, &object, &active) })
		if err == storage.ErrNotFound {
			return nil
		}
		if err != nil {
			return err
		}
		if !active {
			return nil
		}
		var q string
		switch kind {
		case "membership":
			q = `DELETE FROM user_groups WHERE user_id=? AND group_id=?`
		case "permission":
			q = `DELETE FROM group_permissions WHERE group_id=? AND permission_id=?`
		case "resource":
			q = `DELETE FROM resource_groups WHERE resource_id=? AND group_id=?`
		case "superadmin":
			if _, err := tx.Exec(ctx, `UPDATE users SET is_admin=? WHERE id=?`, false, subject); err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `UPDATE security_grants SET active=? WHERE id=?`, false, p.GrantID)
			return err
		default:
			return fmt.Errorf("unknown grant kind %s", kind)
		}
		if _, err := tx.Exec(ctx, q, subject, object); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE security_grants SET active=? WHERE id=?`, false, p.GrantID)
		return err
	case "advance_authority_epoch":
		if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at=? WHERE revoked_at IS NULL`, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE identity_flows SET state='cancelled',next_step='none' WHERE state<>'completed'`); err != nil {
			return err
		}
		return nil
	case "revoke_node":
		if _, err := tx.Exec(ctx, `INSERT INTO security_node_revocations(node_id,event_id) VALUES(?,?) ON CONFLICT(node_id) DO NOTHING`, p.NodeID, event.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE gateways SET enabled=? WHERE node_id=?`, false, p.NodeID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at=? WHERE node_id=? AND revoked_at IS NULL`, now, p.NodeID)
		return err
	default:
		return fmt.Errorf("unsupported restrictive event %q", r.Kind)
	}
}
func SyncGrants(ctx context.Context, tx storage.IdentityTx) error {
	for _, kind := range []string{"membership", "permission", "resource", "superadmin"} {
		q := map[string]string{"membership": `SELECT user_id,group_id FROM user_groups`, "permission": `SELECT group_id,permission_id FROM group_permissions`, "resource": `SELECT resource_id,group_id FROM resource_groups`, "superadmin": `SELECT id,'' FROM users WHERE is_admin=true`}[kind]
		rows, err := tx.Query(ctx, q)
		if err != nil {
			return err
		}
		var pairs [][2]string
		for rows.Next() {
			var pair [2]string
			if err := rows.Scan(&pair[0], &pair[1]); err != nil {
				rows.Close()
				return err
			}
			pairs = append(pairs, pair)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, pair := range pairs {
			ids, err := Strings(ctx, tx, `SELECT id FROM security_grants WHERE kind=? AND subject_id=? AND object_id=? AND active=?`, kind, pair[0], pair[1], true)
			if err != nil {
				return err
			}
			if len(ids) == 0 {
				if _, err := tx.Exec(ctx, `INSERT INTO security_grants(id,kind,subject_id,object_id,active) VALUES(?,?,?,?,?)`, ID("grant"), kind, pair[0], pair[1], true); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func Audit(ctx context.Context, tx storage.IdentityTx, event, actor string, data any) error {
	raw, _ := json.Marshal(data)
	_, err := tx.Exec(ctx, `INSERT INTO audit_events(event_type,subject_user_id,outcome,metadata_json,created_at) VALUES(?,?,'success',?,?)`, event, actor, string(raw), time.Now().UTC())
	return err
}
