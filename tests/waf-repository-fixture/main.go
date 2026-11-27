// waf-repository-fixture creates ephemeral TEST-ONLY trust for the isolated
// acceptance lab. It is not shipped as an administrative or release command.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/netwizd/agp/internal/repository"
	"github.com/netwizd/agp/internal/repository/repotest"
)

func run() error {
	var in repotest.NativeInput
	var output string
	flag.StringVar(&in.BundlePath, "bundle", "", "absolute path to the frozen actual native bundle")
	flag.StringVar(&in.EvidencePath, "evidence", "", "absolute path to the actual successful native corpus report")
	flag.StringVar(&in.RendererPath, "renderer", "", "absolute path to the agpctl renderer exercised by the native corpus")
	flag.StringVar(&output, "output", "", "absolute path to a new private TEST-ONLY repository directory")
	flag.Parse()
	if flag.NArg() != 0 || !filepath.IsAbs(output) || filepath.Clean(output) != output {
		return fmt.Errorf("--bundle, --evidence, --renderer and --output require clean absolute paths; run from repository root")
	}
	for _, name := range []string{in.BundlePath, in.EvidencePath, in.RendererPath} {
		if !filepath.IsAbs(name) || filepath.Clean(name) != name {
			return fmt.Errorf("all input paths must be clean and absolute")
		}
	}
	var e error
	in.HarnessPath, e = filepath.Abs("tests/native-waf/qualification.py")
	if e != nil {
		return e
	}
	in.CorpusPath, e = filepath.Abs("tests/native-waf/corpus.json")
	if e != nil {
		return e
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(output))
	if e != nil {
		return e
	}
	if parent != filepath.Dir(output) {
		return fmt.Errorf("output parent must not contain symlinks")
	}
	if e = os.Mkdir(output, 0700); e != nil {
		return e
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(output)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	f, e := repotest.Native(ctx, in)
	if e != nil {
		return e
	}
	bundle := f.Build(1)
	anchorPath, e := f.Write(output, bundle)
	if e != nil {
		return e
	}
	// Validate the written bytes through the same disk readers the real import
	// CLI will use, including all CAS bytes and the independent public anchor.
	anchor, e := repository.ReadAnchor(anchorPath)
	if e != nil {
		return e
	}
	input, e := repository.ReadBundle(output)
	if e != nil {
		return e
	}
	now := time.Now().UTC()
	verified, e := repository.Verify(ctx, anchor, nil, input, now)
	if e != nil {
		return e
	}
	profile, e := verified.QualifiedProfile(now)
	if e != nil {
		return e
	}
	if e = json.NewEncoder(os.Stdout).Encode(struct {
		Bundle           string `json:"bundle"`
		Anchor           string `json:"anchor"`
		ManifestPath     string `json:"manifestPath"`
		ProfileID        string `json:"profileId"`
		RulesetVersionID string `json:"rulesetVersionId"`
	}{output, anchorPath, bundle.ManifestPath, profile.Profile.ID, profile.Profile.RulesetVersionID}); e != nil {
		return e
	}
	success = true
	return nil
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "TEST-ONLY WAF repository fixture:", e)
		os.Exit(1)
	}
}
