package helper

import (
	"context"
	"errors"

	"github.com/netwizd/agp/internal/ownedtree"
)

var ErrOwnedTree = errors.New("helper_owned_tree_unavailable")

// NewGateWithOwnedTree adds a concrete local filesystem check to the admission
// foundation. The caller retains ownership of tree and must close it after the
// gate is no longer used. Paths never come from a task or control response.
// This does not establish Nginx runtime qualification or authorize execution.
func NewGateWithOwnedTree(s *Store, trust Trust, sources Sources, tree *ownedtree.Tree) (*Gate, error) {
	if s == nil || tree == nil {
		return nil, ErrInvalid
	}
	b := tree.Binding()
	if b.NodeID != s.installation.NodeID || b.SiteID != s.installation.SiteID || b.ManifestDigest != s.installation.OwnershipDigest {
		return nil, ErrInvalid
	}
	g, err := NewGate(s, trust, sources)
	if err != nil {
		return nil, err
	}
	g.tree = tree
	return g, nil
}

func (g *Gate) checkOwnedTree(ctx context.Context) error {
	if g.tree == nil {
		// The legacy constructor is retained only for the existing admission
		// foundation. Neither constructor exposes an executor.
		return nil
	}
	observation, err := g.tree.Verify(ctx)
	if err != nil || observation == nil {
		return ErrOwnedTree
	}
	return nil
}
