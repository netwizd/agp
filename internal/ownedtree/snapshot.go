package ownedtree

import (
	"context"
	"sync"
)

// Snapshot is a bounded, volatile copy of manifest-approved bytes read through
// the tree's pinned descriptors. It is not a durable backup or active baseline.
// File contents can contain secrets: callers must keep them local and private,
// close the snapshot after staging, and never log or serialize those bytes.
type Snapshot struct {
	mu          sync.Mutex
	observation Observation
	files       map[string][]byte
	closed      bool
}

// Capture hashes exactly the bytes it copies and returns nothing after any
// filesystem or cancellation failure. It uses the same checks as Verify.
func (t *Tree) Capture(ctx context.Context) (*Snapshot, error) {
	files := make(map[string][]byte)
	observation, err := t.inspect(ctx, files)
	if err != nil {
		return nil, err
	}
	return &Snapshot{observation: *observation, files: files}, nil
}

func (s *Snapshot) Observation() (*Observation, error) {
	if s == nil {
		return nil, ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	out := s.observation
	out.Entries = append([]ObservedEntry(nil), out.Entries...)
	return &out, nil
}

// File returns a private copy. The caller owns and must dispose of that copy.
func (s *Snapshot) File(name string) ([]byte, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, false
	}
	b, ok := s.files[name]
	return append([]byte(nil), b...), ok
}

func (s *Snapshot) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	for _, data := range s.files {
		clear(data)
	}
	clear(s.files)
	s.observation = Observation{}
	return nil
}

// MarshalJSON prevents accidental use of volatile snapshot contents as a wire
// artifact. Metadata-only observations have their own explicit contract.
func (*Snapshot) MarshalJSON() ([]byte, error) { return nil, ErrManifest }
