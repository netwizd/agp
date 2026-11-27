//go:build linux

package nativeactivation

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/netwizd/agp/internal/helper"
)

// These exercise actual fresh Unix HTTP exchanges. They do not replace the
// separate root/Nginx/SIGHUP integration qualification on the target host.
func TestFunctionalProbeRequiresGenerationFreshChallengeAndSecurityOutcome(t *testing.T) {
	for _, mode := range []string{"correct", "wrong-generation", "cached-challenge", "auth-bypass", "waf-bypass", "wrong-body", "redirect", "world-socket"} {
		t.Run(mode, func(t *testing.T) {
			root, e := os.MkdirTemp("/tmp", "agp-native-probe-test-")
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { os.RemoveAll(root) })
			socket := filepath.Join(root, "probe.sock")
			listener, e := net.Listen("unix", socket)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.Chmod(socket, 0600); e != nil {
				t.Fatal(e)
			}
			if mode == "world-socket" {
				os.Chmod(socket, 0666)
			}
			var mu sync.Mutex
			seen := map[string]bool{}
			duplicate := false
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				challenge := r.Header.Get("X-AGP-Probe-Challenge")
				mu.Lock()
				if challenge == "" || seen[challenge] {
					duplicate = true
				}
				seen[challenge] = true
				mu.Unlock()
				generation := "generation-a"
				if mode == "wrong-generation" {
					generation = "generation-old"
				}
				if mode == "cached-challenge" {
					challenge = "old-challenge"
				}
				w.Header().Set("X-AGP-Generation", generation)
				w.Header().Set("X-AGP-Probe-Challenge", challenge)
				if mode == "redirect" {
					w.Header().Set("Location", "http://example.invalid/")
					w.WriteHeader(302)
					return
				}
				switch r.URL.Path {
				case "/route":
					w.WriteHeader(200)
					if mode == "wrong-body" {
						w.Write([]byte("unrelated backend 200"))
					} else {
						w.Write([]byte("routed"))
					}
				case "/auth":
					if mode == "auth-bypass" {
						w.WriteHeader(200)
					} else {
						w.WriteHeader(401)
					}
					w.Write([]byte("unauthorized"))
				case "/waf":
					if mode == "waf-bypass" {
						w.WriteHeader(200)
					} else {
						w.WriteHeader(403)
					}
					w.Write([]byte("blocked"))
				default:
					w.WriteHeader(404)
				}
			})}
			go server.Serve(listener)
			t.Cleanup(func() { server.Close(); listener.Close() })
			bundle := testBundle("generation-a", "revision-a")
			g := helper.ExecutionGeneration{GenerationID: bundle.GenerationID}
			e = verifyProbes(context.Background(), Config{ProbeSocket: socket}, g, bundle.Probes, uint32(os.Geteuid()))
			if (mode == "correct") != (e == nil) {
				t.Fatalf("mode %s result %v", mode, e)
			}
			if mode == "correct" {
				if e = verifyProbes(context.Background(), Config{ProbeSocket: socket}, g, bundle.Probes, uint32(os.Geteuid())); e != nil {
					t.Fatal(e)
				}
				mu.Lock()
				defer mu.Unlock()
				if duplicate || len(seen) != 6 {
					t.Fatalf("freshness not proved: %d duplicate=%v", len(seen), duplicate)
				}
			}
		})
	}
}

func TestRootIdentityParserAndClosedProcessStat(t *testing.T) {
	if !rootProcess([]byte("Name:\tnginx\nUid:\t0\t0\t0\t0\n")) {
		t.Fatal("root identity rejected")
	}
	for _, b := range []string{"Uid:\t0\t1001\t0\t0\n", "Uid:\t0\t0\t0\n", "Uid:\t1001\t1001\t1001\t1001\n"} {
		if rootProcess([]byte(b)) {
			t.Fatal("non-root identity accepted")
		}
	}
	start, e := processStart(os.Getpid())
	if e != nil || start == "" {
		t.Fatal("could not read process identity")
	}
}
