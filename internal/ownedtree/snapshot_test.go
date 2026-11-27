//go:build linux

package ownedtree

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestSnapshotCopiesApprovedBytesAndDetaches(t *testing.T) {
	f := treeFixture(t)
	tr := mustOpen(t, f)
	s, err := tr.Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	b, ok := s.File("nginx.conf")
	if !ok || !bytes.Equal(b, []byte("http {}\n")) {
		t.Fatal("captured bytes differ")
	}
	b[0] = 'X'
	again, _ := s.File("nginx.conf")
	if !bytes.Equal(again, []byte("http {}\n")) {
		t.Fatal("caller mutated private snapshot")
	}
	view, err := s.Observation()
	if err != nil || view.ManifestDigest != f.digest || !view.NoExecution || view.RuntimeValidated {
		t.Fatal("snapshot gained runtime authority")
	}
	view.Entries[0].Path = "outside"
	view2, _ := s.Observation()
	if view2.Entries[0].Path == "outside" {
		t.Fatal("metadata aliases snapshot")
	}
	if raw, err := json.Marshal(s); err == nil || len(raw) != 0 {
		t.Fatal("snapshot serialized as a wire artifact")
	}
	if b, ok := s.File("../outside"); ok || b != nil {
		t.Fatal("snapshot selected unapproved path")
	}
	if err := os.WriteFile(filepath.Join(f.root, "nginx.conf"), []byte("httpX{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := tr.Verify(context.Background()); err == nil || got != nil {
		t.Fatal("live drift became current evidence")
	}
	again, _ = s.File("nginx.conf")
	if !bytes.Equal(again, []byte("http {}\n")) {
		t.Fatal("snapshot changed with live bytes")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Observation(); err != ErrClosed {
		t.Fatal("closed snapshot remains readable")
	}
	if b, ok := s.File("nginx.conf"); ok || b != nil {
		t.Fatal("closed snapshot retained readable contents")
	}
}

func TestSnapshotFailureNeverReturnsPartialContents(t *testing.T) {
	for _, action := range []string{"drift", "cancel"} {
		t.Run(action, func(t *testing.T) {
			f := treeFixture(t)
			tr := mustOpen(t, f)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fired := false
			tr.checkpoint = func(point string) {
				if fired || point != "entry:conf.d/site.conf" {
					return
				}
				fired = true
				if action == "cancel" {
					cancel()
				} else if err := os.WriteFile(filepath.Join(f.root, "nginx.conf"), []byte("httpX{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if s, err := tr.Capture(ctx); err == nil || s != nil || !fired {
				t.Fatalf("partial snapshot returned after %s: %v", action, err)
			}
			if action == "cancel" {
				tr.checkpoint = nil
				s, err := tr.Capture(context.Background())
				if err != nil {
					t.Fatal("cancellation poisoned a stable tree")
				}
				_ = s.Close()
			}
		})
	}
}

func TestSnapshotConcurrentReadAndClose(t *testing.T) {
	f := treeFixture(t)
	tr := mustOpen(t, f)
	s, err := tr.Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_, _ = s.File("nginx.conf")
				_, _ = s.Observation()
			}
		}()
	}
	_ = s.Close()
	wg.Wait()
	if s.files != nil && len(s.files) != 0 {
		t.Fatal("closed snapshot retained file buffers")
	}
}
