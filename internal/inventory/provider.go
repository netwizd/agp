package inventory

import (
	"context"
	"crypto/tls"

	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

// RegistryProvider obtains public identity state from a separate durable issuer
// authority. It must independently fence restores and return current state;
// CP database rows alone are not an identity registry.
type RegistryProvider interface {
	Registry(context.Context, securityjournal.Head) (Registry, error)
}

// DeclaredNode is an operator-owned member of the complete managed Site,
// including pending nodes which do not have a certificate yet.
type DeclaredNode struct {
	NodeID, SiteID, Name string
	Labels               map[string]string
	GroupIDs             []string
}
type CompleteRegistryProvider interface {
	RegistryProvider
	DeclaredNodes(context.Context, storage.IdentityTx, securityjournal.Head, string) ([]DeclaredNode, error)
}

func (s *Service) completeSite(ctx context.Context, tx storage.IdentityTx, h securityjournal.Head, r *registry, site string) error {
	if s.provider == nil {
		return nil
	}
	provider, ok := s.provider.(CompleteRegistryProvider)
	if !ok {
		return ErrUnavailable
	}
	declared, e := provider.DeclaredNodes(ctx, tx, h, site)
	if e != nil {
		return e
	}
	expected := map[string]string{}
	for _, n := range declared {
		if n.SiteID != site || expected[n.NodeID] != "" {
			return ErrUnavailable
		}
		d, e := Digest(n)
		if e != nil {
			return e
		}
		expected[n.NodeID] = d
	}
	seen := map[string]bool{}
	for _, n := range r.entries {
		if n.SiteID != site || n.AcceptUntil != nil {
			continue
		}
		d, e := Digest(DeclaredNode{n.NodeID, n.SiteID, n.Name, n.Labels, n.GroupIDs})
		if e != nil {
			return e
		}
		if expected[n.NodeID] != d {
			return ErrIdentity
		}
		seen[n.NodeID] = true
	}
	if len(seen) != len(expected) {
		return ErrIdentity
	}
	return nil
}

func NewWithRegistry(current Current, authority Authority, provider RegistryProvider) (*Service, error) {
	if current == nil || authority == nil || provider == nil {
		return nil, ErrUnavailable
	}
	return &Service{current: current, authority: authority, provider: provider}, nil
}

func (s *Service) loadRegistry(ctx context.Context, h securityjournal.Head) (*registry, error) {
	if s.provider == nil {
		return loadRegistry(s.registryPath)
	}
	r, e := s.provider.Registry(ctx, h)
	if e != nil {
		return nil, ErrUnavailable
	}
	return validateRegistry(r, true)
}

// WithIdentity runs an authenticated agent action in the same fenced writer
// transaction, then checks the identity again after the action's I/O.
func (s *Service) WithIdentity(ctx context.Context, peer *tls.ConnectionState, fn func(storage.IdentityTx, securityjournal.Head, Registration) error) error {
	return s.current.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		n, e := s.admitted(ctx, tx, peer, h)
		if e != nil {
			return e
		}
		if e = fn(tx, h, n.Registration); e != nil {
			return e
		}
		return s.registrationUnchanged(ctx, n, h)
	})
}

func (s *Service) WithFreshAgent(ctx context.Context, peer *tls.ConnectionState, fn func(storage.IdentityTx, securityjournal.Head, Node) error) error {
	return s.WithIdentity(ctx, peer, func(tx storage.IdentityTx, h securityjournal.Head, r Registration) error {
		d, e := Digest(r)
		if e != nil {
			return e
		}
		n, e := currentReceipt(ctx, tx, registryEntry{Registration: r, digest: d}, h.Epoch, h.RecordedAt)
		if e != nil {
			return e
		}
		return fn(tx, h, *n)
	})
}
