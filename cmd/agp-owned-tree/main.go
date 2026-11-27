// agp-owned-tree checks an installation-selected tree without modifying it.
// Its output is local filesystem observation, never a verified runtime baseline.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/ownedtree"
)

var (
	errArguments = errors.New("owned_tree_invalid_local_arguments")
	errRoot      = errors.New("owned_tree_local_root_required")
	errObserve   = errors.New("owned_tree_observation_unavailable")
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("agp-owned-tree", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var manifest, digest string
	flags.StringVar(&manifest, "manifest", "", "Protected local installation manifest")
	flags.StringVar(&digest, "ownership-digest", "", "Separately trusted canonical ownership digest")
	parseErr := flags.Parse(args)
	if errors.Is(parseErr, flag.ErrHelp) {
		if out == nil {
			return errArguments
		}
		_, err := io.WriteString(out, "Usage: agp-owned-tree -manifest /protected/manifest.json -ownership-digest sha256:<trusted-digest>\nRead-only filesystem observation; requires root. Does not validate Nginx runtime or authorize apply.\n")
		return err
	}
	if parseErr != nil || flags.NArg() != 0 || manifest == "" || !configmodel.ValidDigest(digest) {
		return errArguments
	}
	// Production ownership is root-owned. The package's self-owned test fixtures
	// exercise the reader; they do not qualify a privileged installation.
	if os.Geteuid() != 0 {
		return errRoot
	}
	return observe(ctx, manifest, digest, out)
}

func observe(ctx context.Context, manifest, digest string, out io.Writer) error {
	if ctx == nil || out == nil || ctx.Err() != nil {
		return errObserve
	}
	tree, err := ownedtree.Load(manifest, digest)
	if err != nil {
		return errObserve
	}
	defer tree.Close()
	observation, err := tree.Verify(ctx)
	if err != nil || observation == nil || ctx.Err() != nil {
		return errObserve
	}
	raw, err := json.Marshal(observation)
	if err != nil || len(raw) > 4<<20 || ctx.Err() != nil {
		return errObserve
	}
	raw = append(raw, '\n')
	if n, err := out.Write(raw); err != nil || n != len(raw) {
		return errObserve
	}
	return nil
}
