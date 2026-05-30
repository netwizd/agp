package storage

import (
	"context"

	"github.com/netwizd/agp/internal/domain"
)

var ErrNotFound = errString("not found")

type errString string

func (e errString) Error() string { return string(e) }

type Store interface {
	Close() error
	Migrate(ctx context.Context) error
	FindUserByUsername(ctx context.Context, username string) (*domain.UserWithPassword, error)
	CreateSession(ctx context.Context, session domain.Session) error
	FindSessionByTokenHash(ctx context.Context, tokenHash string) (*domain.SessionContext, error)
	DeleteSession(ctx context.Context, tokenHash string) error
	ListResourcesForUser(ctx context.Context, userID string) ([]domain.Resource, error)
	FindResourceByPublicHost(ctx context.Context, host string) (*domain.Resource, error)
	UserHasResourceAccess(ctx context.Context, userID string, resourceID string) (bool, error)
	ListResourceAllowCIDRs(ctx context.Context, resourceID string) ([]string, error)
	AppendAudit(ctx context.Context, event domain.AuditEvent) error
}
