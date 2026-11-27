package configuration

import (
	"context"
	"errors"
	"sort"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/rolescope"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type gatewayScopeWitness struct {
	gateway configmodel.Gateway
	digest  string
}

func concealedGatewayError(err error) error {
	if errors.Is(err, storage.ErrPermissionDenied) || errors.Is(err, storage.ErrNotFound) {
		return storage.ErrNotFound
	}
	return err
}

func gatewayPermissionMatches(grant, requested string) bool {
	return grant == requested || requested == "config.read" && grant == "config.edit"
}

// This only admits the object workflow. It never authorizes a particular
// Gateway, a whole snapshot, a Site, or an approval.
func (p *Principal) hasGatewayPermission(permission string) bool {
	if p.Require(permission, "") == nil {
		return true
	}
	for _, grant := range p.grants {
		if !gatewayPermissionMatches(grant.Permission, permission) {
			continue
		}
		switch grant.ScopeType {
		case "site", "node_group", "node":
			return true
		}
	}
	return false
}

func (s *Service) AuthorizeGateway(ctx context.Context, a Actor, write bool) error {
	permission := "config.read"
	if write {
		permission = "config.edit"
	}
	return s.transactScoped(ctx, a, write, func(_ storage.IdentityTx, p *Principal) error {
		if !p.hasGatewayPermission(permission) {
			return storage.ErrPermissionDenied
		}
		return nil
	})
}

func (p *Principal) requireGatewayRecipients(ctx context.Context, tx storage.IdentityTx, permission string, gateway configmodel.Gateway) error {
	hasRecipientGrant := false
	for _, grant := range p.grants {
		if (grant.ScopeType == "node" || grant.ScopeType == "node_group") && gatewayPermissionMatches(grant.Permission, permission) {
			hasRecipientGrant = true
			break
		}
	}
	if !hasRecipientGrant {
		return storage.ErrPermissionDenied
	}
	recipients, err := p.currentGatewayRecipients(ctx, tx, gateway)
	if err != nil {
		return subjectFailure(tx, err)
	}
	if len(recipients.Nodes) == 0 {
		return storage.ErrPermissionDenied
	}
	for _, node := range recipients.Nodes {
		covered := false
		for _, grant := range p.grants {
			if !gatewayPermissionMatches(grant.Permission, permission) {
				continue
			}
			switch grant.ScopeType {
			case "global":
				covered = true
			case "site":
				covered = grant.ScopeID == node.SiteID
			case "node":
				covered = grant.ScopeID == node.NodeID
			case "node_group":
				for _, group := range node.GroupIDs {
					if group == grant.ScopeID {
						covered = true
						break
					}
				}
			}
			if covered {
				break
			}
		}
		if !covered {
			return storage.ErrPermissionDenied
		}
	}
	p.rememberGatewayRecipients(gateway, recipients)
	return nil
}

func (p *Principal) currentGatewayRecipients(ctx context.Context, tx storage.IdentityTx, gateway configmodel.Gateway) (rolescope.GatewayRecipients, error) {
	key := digest([]any{"gateway-scope/v1", gateway.Metadata.ID, gateway.Metadata.SiteID, gateway.Spec.NodeSelector})
	if snapshot, ok := p.gatewaySnapshots[key]; ok {
		return snapshot, nil
	}
	if p.gatewayResolver == nil {
		var err error
		p.gatewayResolver, err = rolescope.NewGatewayRecipientResolver(ctx, tx, p.head)
		if err != nil {
			return rolescope.GatewayRecipients{}, subjectFailure(tx, err)
		}
	}
	recipients, err := p.gatewayResolver.Resolve(gateway)
	if err != nil {
		return recipients, subjectFailure(tx, err)
	}
	if p.gatewaySnapshots == nil {
		p.gatewaySnapshots = map[string]rolescope.GatewayRecipients{}
	}
	p.gatewaySnapshots[key] = recipients
	return recipients, nil
}

func (p *Principal) rememberGatewayRecipients(gateway configmodel.Gateway, recipients rolescope.GatewayRecipients) {
	if p.gatewayEvidence == nil {
		p.gatewayEvidence = map[string]gatewayScopeWitness{}
	}
	// Only selector/identity participate in authority, and the saved selector
	// must not alias a caller's subsequently edited slice or map.
	frozen := gateway
	frozen.Spec.NodeSelector.NodeIDs = append([]string(nil), gateway.Spec.NodeSelector.NodeIDs...)
	if labels := gateway.Spec.NodeSelector.MatchLabels; labels != nil {
		copyLabels := configmodel.Labels{}
		for key, value := range *labels {
			copyLabels[key] = value
		}
		frozen.Spec.NodeSelector.MatchLabels = &copyLabels
	}
	p.gatewayEvidence[recipients.Digest] = gatewayScopeWitness{gateway: frozen, digest: recipients.Digest}
}

func (p *Principal) revalidateGatewayEvidence(ctx context.Context, tx storage.IdentityTx, head securityjournal.Head) error {
	owners := make([]string, 0, len(p.gatewayOwners))
	for id := range p.gatewayOwners {
		owners = append(owners, id)
	}
	sort.Strings(owners)
	for _, id := range owners {
		var site string
		err := securitystate.One(ctx, tx, `SELECT site_id FROM config_gateway_ownership WHERE gateway_id=?`, []any{id}, func(row storage.IdentityRows) error { return row.Scan(&site) })
		if errors.Is(err, storage.ErrNotFound) || err == nil && site != p.gatewayOwners[id] {
			return storage.ErrPermissionDenied
		}
		if err != nil {
			return err
		}
	}
	if len(p.gatewayEvidence) == 0 {
		return nil
	}
	resolver, err := rolescope.NewGatewayRecipientResolver(ctx, tx, head)
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(p.gatewayEvidence))
	for key := range p.gatewayEvidence {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		previous := p.gatewayEvidence[key]
		current, err := resolver.Resolve(previous.gateway)
		if err != nil {
			return err
		}
		if current.Digest != previous.digest {
			return storage.ErrPermissionDenied
		}
	}
	return nil
}
