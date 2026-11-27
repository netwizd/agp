package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/netwizd/agp/internal/compiler"
	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/repository"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/wafnative"
)

func OpenWAFProvider(client *securityjournal.Client, options compiler.Options) (*wafnative.Provider, error) {
	anchor, dir := os.Getenv("AGP_WAF_TRUST_CONFIG"), os.Getenv("AGP_WAF_REPOSITORY_DIR")
	if anchor == "" && dir == "" {
		return nil, nil
	}
	if client == nil || !filepath.IsAbs(anchor) || !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("WAF requires an independent trust config, repository directory and verified journal client")
	}
	digest, e := configmodel.Digest(struct {
		Compiler compiler.Options `json:"compiler"`
		Renderer string           `json:"renderer"`
	}{options, wafnative.RendererVersion})
	if e != nil {
		return nil, e
	}
	return &wafnative.Provider{Store: repository.Store{Dir: dir, AnchorPath: anchor}, CompilerDigest: digest, TempDir: os.Getenv("AGP_WAF_TEMP_DIR"), Clock: func(ctx context.Context) (time.Time, error) {
		head, err := client.Head(ctx)
		if err != nil {
			return time.Time{}, err
		}
		return head.RecordedAt, nil
	}}, nil
}
