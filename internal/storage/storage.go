package storage

import (
	"context"
	"time"

	"github.com/netwizd/agp/internal/domain"
)

var (
	ErrNotFound = errString("not found")
	ErrConflict = errString("conflict")
)

type errString string

func (e errString) Error() string { return string(e) }

type Store interface {
	Close() error
	Migrate(ctx context.Context) error
	Ping(ctx context.Context) error
	ApplyRetention(ctx context.Context, now time.Time, auditRetention time.Duration, sessionRetention time.Duration) error
	FindUserByUsername(ctx context.Context, username string) (*domain.UserWithPassword, error)
	CreateSession(ctx context.Context, session domain.Session) error
	FindSessionByTokenHash(ctx context.Context, tokenHash string) (*domain.SessionContext, error)
	DeleteSession(ctx context.Context, tokenHash string) error
	ListResourcesForUser(ctx context.Context, userID string) ([]domain.Resource, error)
	FindResourceByPublicHost(ctx context.Context, host string) (*domain.Resource, error)
	FindResourceByPublicRoute(ctx context.Context, host string, path string) (*domain.Resource, error)
	UserHasResourceAccess(ctx context.Context, userID string, resourceID string) (bool, error)
	ListResourceAllowCIDRs(ctx context.Context, resourceID string) ([]string, error)
	ListPublicDownloads(ctx context.Context, includeDisabled bool) ([]domain.PublicDownload, error)
	FindPublicDownloadByID(ctx context.Context, id string) (*domain.PublicDownload, error)
	AppendAudit(ctx context.Context, event domain.AuditEvent) error
	AppendResourceDiagnostics(ctx context.Context, run domain.ResourceDiagnosticsRun) error
	GetPortalSettings(ctx context.Context) (*domain.PortalSettings, error)
	DashboardStats(ctx context.Context) (*domain.DashboardStats, error)
	ListUsers(ctx context.Context) ([]domain.User, error)
	CreateUser(ctx context.Context, input domain.UserInput) (*domain.User, error)
	UpdateUser(ctx context.Context, id string, update domain.UserUpdate) (*domain.User, error)
	DeleteUser(ctx context.Context, id string) error
	ListGroups(ctx context.Context) ([]domain.Group, error)
	CreateGroup(ctx context.Context, input domain.GroupInput) (*domain.Group, error)
	UpdateGroup(ctx context.Context, id string, input domain.GroupInput) (*domain.Group, error)
	DeleteGroup(ctx context.Context, id string) error
	ListResources(ctx context.Context) ([]domain.ResourceDetail, error)
	FindResourceByID(ctx context.Context, id string) (*domain.ResourceDetail, error)
	CreateResource(ctx context.Context, input domain.ResourceInput) (*domain.ResourceDetail, error)
	UpdateResource(ctx context.Context, id string, update domain.ResourceUpdate) (*domain.ResourceDetail, error)
	DeleteResource(ctx context.Context, id string) error
	CreatePublicDownload(ctx context.Context, input domain.PublicDownloadInput) (*domain.PublicDownload, error)
	UpdatePublicDownload(ctx context.Context, id string, update domain.PublicDownloadUpdate) (*domain.PublicDownload, error)
	DeletePublicDownload(ctx context.Context, id string) error
	UpdatePortalSettings(ctx context.Context, settings domain.PortalSettings) (*domain.PortalSettings, error)
	ListActiveSessions(ctx context.Context) ([]domain.ActiveSession, error)
	RevokeSession(ctx context.Context, id string) error
	ListAuditEvents(ctx context.Context, filter domain.AuditFilter) ([]domain.AuditEvent, error)
	ListResourceDiagnostics(ctx context.Context, resourceID string, limit int) ([]domain.ResourceDiagnosticsRun, error)
}
