package securitystate

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

type resourceCommand struct {
	Actor, Kind, ID string
	Input           domain.ResourceInput
	Update          domain.ResourceUpdate
	ForceDisabled   bool
}

func (s *protectedStore) CreateResource(ctx context.Context, input domain.ResourceInput) (*domain.ResourceDetail, error) {
	cmd := resourceCommand{Kind: "create", ID: ID("res"), Input: input}
	if err := s.resourceMutation(ctx, &cmd); err != nil {
		return nil, err
	}
	return s.Store.FindResourceByID(ctx, cmd.ID)
}
func (s *protectedStore) UpdateResource(ctx context.Context, id string, u domain.ResourceUpdate) (*domain.ResourceDetail, error) {
	cmd := resourceCommand{Kind: "update", ID: id, Update: u}
	if err := s.resourceMutation(ctx, &cmd); err != nil {
		return nil, err
	}
	return s.Store.FindResourceByID(ctx, id)
}
func (s *protectedStore) DeleteResource(ctx context.Context, id string) error {
	return s.resourceMutation(ctx, &resourceCommand{Kind: "delete", ID: id})
}
func (s *protectedStore) resourceMutation(ctx context.Context, cmd *resourceCommand) error {
	hash, _ := ctx.Value(actorKey{}).(string)
	return s.c.ExecuteDynamic(ctx, "v1_resource", func(tx storage.IdentityTx, h securityjournal.Head) (json.RawMessage, []securityjournal.AppendRequest, error) {
		if err := storage.RequireLegacyResourceWrites(ctx, tx); err != nil {
			return nil, nil, err
		}
		if err := s.c.CheckManagementSession(ctx, tx, h, hash); err != nil {
			return nil, nil, err
		}
		principal, err := managementActor(ctx, tx, h, hash, authz.PermResourcesManage)
		if err != nil {
			return nil, nil, err
		}
		actor := principal.ID
		cmd.Actor = actor
		if err = SyncGrants(ctx, tx); err != nil {
			return nil, nil, err
		}
		before, err := grants(ctx, tx)
		if err != nil {
			return nil, nil, err
		}
		requests := []securityjournal.AppendRequest{}
		if cmd.Kind == "create" && !cmd.Input.Enabled {
			requests = append(requests, securityjournal.AppendRequest{Kind: "disable_resource", TargetType: "resource", TargetID: cmd.ID, ActorID: actor, Payload: securityjournal.Payload{ResourceID: cmd.ID}})
		}
		if cmd.Kind != "create" {
			var enabled bool
			if err = One(ctx, tx, `SELECT enabled FROM resources WHERE id=?`, []any{cmd.ID}, func(r storage.IdentityRows) error { return r.Scan(&enabled) }); err != nil {
				return nil, nil, err
			}
			if cmd.Kind == "update" && cmd.Update.Enabled != nil && *cmd.Update.Enabled && !enabled {
				return nil, nil, storage.ErrPermissionDenied
			}
			// Route and network-policy replacement invalidates the old stable route.
			// Re-enabling it requires the independent two-person journal lift.
			cmd.ForceDisabled = cmd.Kind == "delete" || (cmd.Update.Enabled != nil && !*cmd.Update.Enabled) || cmd.Update.InternalURL != nil || cmd.Update.PublicHost != nil || cmd.Update.PublicPath != nil || cmd.Update.UpdateAllowCIDRs
			if cmd.ForceDisabled {
				requests = append(requests, securityjournal.AppendRequest{Kind: "disable_resource", TargetType: "resource", TargetID: cmd.ID, ActorID: actor, Payload: securityjournal.Payload{ResourceID: cmd.ID}})
			}
		}
		if _, err = tx.Exec(ctx, `SAVEPOINT authorize_resource`); err != nil {
			return nil, nil, err
		}
		if err = applyResource(ctx, tx, *cmd); err != nil {
			return nil, nil, err
		}
		removed, err := removedGrants(ctx, tx, before)
		if err != nil {
			return nil, nil, err
		}
		if _, err = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT authorize_resource`); err != nil {
			return nil, nil, err
		}
		if _, err = tx.Exec(ctx, `RELEASE SAVEPOINT authorize_resource`); err != nil {
			return nil, nil, err
		}
		requests = append(requests, grantRequests(actor, removed)...)
		raw, err := json.Marshal(cmd)
		if err != nil {
			return nil, nil, err
		}
		if err = s.finalIdentityAuthority(ctx, tx, h, hash, &identityAuthorityWitness{actor: principal}); err != nil {
			return nil, nil, err
		}
		return raw, requests, nil
	})
}
func (s *protectedStore) materializeResource(ctx context.Context, tx storage.IdentityTx, raw json.RawMessage) error {
	var cmd resourceCommand
	if err := json.Unmarshal(raw, &cmd); err != nil {
		return err
	}
	if err := applyResource(ctx, tx, cmd); err != nil {
		return err
	}
	return Audit(ctx, tx, "identity.resource.mutation", cmd.Actor, map[string]any{"kind": cmd.Kind, "target": cmd.ID})
}
func applyResource(ctx context.Context, tx storage.IdentityTx, cmd resourceCommand) error {
	now := time.Now().UTC()
	switch cmd.Kind {
	case "create":
		i := cmd.Input
		if err := storage.CheckResourceProfile(ctx, tx, i.PublicHost); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO resources(id,name,description,category,icon,internal_url,public_host,public_path,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, cmd.ID, i.Name, i.Description, i.Category, i.Icon, i.InternalURL, i.PublicHost, i.PublicPath, i.Enabled, now, now); err != nil {
			return err
		}
		if err := replaceResourceRelations(ctx, tx, cmd.ID, "resource_groups", "group_id", i.GroupIDs); err != nil {
			return err
		}
		return replaceResourceRelations(ctx, tx, cmd.ID, "resource_ip_allowlists", "cidr", i.AllowCIDRs)
	case "delete":
		n, err := tx.Exec(ctx, `DELETE FROM resources WHERE id=?`, cmd.ID)
		if err == nil && n != 1 {
			return storage.ErrNotFound
		}
		return err
	case "update":
		u := cmd.Update
		if err := storage.CheckResourceUpdateProfile(ctx, tx, cmd.ID, u.PublicHost); err != nil {
			return err
		}
		fields := []struct {
			name string
			v    *string
		}{{"name", u.Name}, {"description", u.Description}, {"category", u.Category}, {"icon", u.Icon}, {"internal_url", u.InternalURL}, {"public_host", u.PublicHost}, {"public_path", u.PublicPath}}
		for _, f := range fields {
			if f.v != nil {
				if _, err := tx.Exec(ctx, `UPDATE resources SET `+f.name+`=?,updated_at=? WHERE id=?`, *f.v, now, cmd.ID); err != nil {
					return err
				}
			}
		}
		if cmd.ForceDisabled {
			v := false
			u.Enabled = &v
		}
		if u.Enabled != nil {
			if _, err := tx.Exec(ctx, `UPDATE resources SET enabled=?,updated_at=? WHERE id=?`, *u.Enabled, now, cmd.ID); err != nil {
				return err
			}
		}
		if u.UpdateGroups {
			if err := replaceResourceRelations(ctx, tx, cmd.ID, "resource_groups", "group_id", u.GroupIDs); err != nil {
				return err
			}
		}
		if u.UpdateAllowCIDRs {
			return replaceResourceRelations(ctx, tx, cmd.ID, "resource_ip_allowlists", "cidr", u.AllowCIDRs)
		}
		return nil
	default:
		return errors.New("unknown resource command")
	}
}
func replaceResourceRelations(ctx context.Context, tx storage.IdentityTx, id, table, column string, values []string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE resource_id=?`, id); err != nil {
		return err
	}
	for _, v := range values {
		if _, err := tx.Exec(ctx, `INSERT INTO `+table+`(resource_id,`+column+`) VALUES(?,?)`, id, v); err != nil {
			return err
		}
	}
	return nil
}
