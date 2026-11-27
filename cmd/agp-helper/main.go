//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/netwizd/agp/internal/helperruntime"
)

func main() {
	if run(os.Args[1:]) != nil {
		fmt.Fprintln(os.Stderr, "helper startup or execution unavailable")
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) < 1 {
		return errors.New("expected stage-initial, initialize or run")
	}
	mode := args[0]
	f := flag.NewFlagSet("agp-helper", flag.ContinueOnError)
	var path string
	f.StringVar(&path, "config", "", "Root-owned private installer configuration")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 || path == "" {
		return helperruntime.ErrRuntime
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if mode == "stage-initial" {
		return helperruntime.StageInitial(ctx, path)
	}
	if mode == "initialize" {
		return helperruntime.Initialize(ctx, path)
	}
	if mode != "run" {
		return helperruntime.ErrRuntime
	}
	r, e := helperruntime.Open(path)
	if e != nil {
		return e
	}
	defer r.Close()
	return r.Run(ctx)
}
