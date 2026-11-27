package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/netwizd/agp/internal/repository"
	"github.com/netwizd/agp/internal/runtime"
	"github.com/netwizd/agp/internal/wafnative"
)

func wafRender(args []string) error {
	flags := flag.NewFlagSet("waf-render", flag.ContinueOnError)
	policyFile := flags.String("policy", "", "typed JSON policy file")
	bundle := flags.String("bundle", "", "native candidate bundle (render only)")
	work := flags.String("work", "", "private native scratch directory")
	mode := flags.String("mode", "detection", "off, detection or blocking")
	if e := flags.Parse(args); e != nil {
		return e
	}
	if flags.NArg() != 0 || *policyFile == "" || !filepath.IsAbs(*bundle) || !filepath.IsAbs(*work) {
		return fmt.Errorf("policy, absolute bundle and work paths are required")
	}
	f, e := os.Open(*policyFile)
	if e != nil {
		return e
	}
	defer f.Close()
	p, e := wafnative.ReadPolicy(f)
	if e != nil {
		return e
	}
	out, e := wafnative.Render(*p, *mode, *bundle, *work)
	if e != nil {
		return e
	}
	_, e = fmt.Print(out)
	return e
}
func wafRepository(args []string) error {
	flags := flag.NewFlagSet("waf-repository", flag.ContinueOnError)
	anchor := flags.String("trust-config", "", "independent public trust configuration")
	dir := flags.String("store", "", "existing private independent trust directory")
	bundle := flags.String("import-bundle", "", "offline TUF/manifest/CAS bundle to verify and import")
	if e := flags.Parse(args); e != nil {
		return e
	}
	if flags.NArg() != 0 || !filepath.IsAbs(*anchor) || !filepath.IsAbs(*dir) || !filepath.IsAbs(*bundle) {
		return fmt.Errorf("absolute trust-config, store and import-bundle paths are required")
	}
	client, e := runtime.OpenJournalClient()
	if e != nil {
		return e
	}
	defer client.CloseIdleConnections()
	head, e := client.Head(context.Background())
	if e != nil {
		return e
	}
	v, e := (repository.Store{Dir: *dir, AnchorPath: *anchor}).Import(context.Background(), *bundle, head.RecordedAt)
	if e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"imported": true, "releaseId": v.Manifest.Signed.ReleaseID, "manifestDigest": v.ManifestDigest, "profileDigest": v.Manifest.Signed.CompatibilityProfile.Digest, "expiresAt": v.ExpiresAt})
}
