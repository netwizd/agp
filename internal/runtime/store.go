package runtime

import (
	"context"
	"fmt"

	"github.com/netwizd/agp/internal/config"
	"github.com/netwizd/agp/internal/storage"
	"github.com/netwizd/agp/internal/storage/postgres"
	"github.com/netwizd/agp/internal/storage/sqlite"
)

func OpenStore(ctx context.Context, cfg config.Config) (storage.Store, error) {
	switch cfg.DatabaseDriver {
	case "postgres":
		return postgres.Open(ctx, cfg.DatabaseDSN)
	case "sqlite":
		return sqlite.Open(cfg.DatabasePath)
	default:
		return nil, fmt.Errorf("unsupported database driver %q", cfg.DatabaseDriver)
	}
}
