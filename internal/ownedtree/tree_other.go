//go:build !linux

package ownedtree

import "context"

// Tree is unavailable without Linux mount identity proofs.
type Tree struct{}

func Open(Manifest, string) (*Tree, error)                 { return nil, ErrUnsupported }
func Load(string, string) (*Tree, error)                   { return nil, ErrUnsupported }
func (*Tree) Binding() Binding                             { return Binding{} }
func (*Tree) Verify(context.Context) (*Observation, error) { return nil, ErrUnsupported }
func (*Tree) inspect(context.Context, map[string][]byte) (*Observation, error) {
	return nil, ErrUnsupported
}
func (*Tree) Close() error { return nil }
