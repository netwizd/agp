package domain

import "time"

type User struct {
	ID          string
	Username    string
	DisplayName string
	IsAdmin     bool
	BlockedAt   *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type UserWithPassword struct {
	User
	PasswordHash string
}

type Group struct {
	ID            string
	Name          string
	Description   string
	PermissionIDs []string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type Resource struct {
	ID          string
	Name        string
	Description string
	Icon        string
	InternalURL string
	PublicHost  string
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type ResourceDetail struct {
	Resource
	GroupIDs     []string
	AllowCIDRs   []string
	NginxSnippet string
}

type Session struct {
	ID        string
	UserID    string
	TokenHash string
	CSRFHash  string
	IP        string
	UserAgent string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type SessionContext struct {
	Session
	User        User
	Groups      []string
	Permissions []string
}

type ActiveSession struct {
	ID        string
	UserID    string
	Username  string
	IP        string
	UserAgent string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type AuditEvent struct {
	Type          string
	SubjectUserID string
	Username      string
	ResourceID    string
	IP            string
	UserAgent     string
	Outcome       string
	Reason        string
	MetadataJSON  string
	CreatedAt     time.Time
}

type DashboardStats struct {
	UsersCount           int
	BlockedUsersCount    int
	ActiveSessionsCount  int
	ResourcesCount       int
	PublicDownloadsCount int
	AuditEventsCount     int
	RecentEvents         []AuditEvent
}

type PublicDownload struct {
	ID          string
	Title       string
	Description string
	FileName    string
	StoredName  string
	ContentType string
	SizeBytes   int64
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type PublicDownloadInput struct {
	Title       string
	Description string
	FileName    string
	StoredName  string
	ContentType string
	SizeBytes   int64
	Enabled     bool
}

type PublicDownloadUpdate struct {
	Title       *string
	Description *string
	Enabled     *bool
}

type PortalSettings struct {
	BrandName      string
	LogoText       string
	PortalTitle    string
	PortalSubtitle string
	WelcomeTitle   string
	WelcomeBody    string
	FooterText     string
	SupportText    string
	SupportURL     string
	UpdatedAt      time.Time
}

type UserInput struct {
	Username     string
	PasswordHash string
	DisplayName  string
	IsAdmin      bool
	GroupIDs     []string
}

type UserUpdate struct {
	DisplayName  *string
	IsAdmin      *bool
	Blocked      *bool
	PasswordHash *string
	GroupIDs     []string
	UpdateGroups bool
}

type GroupInput struct {
	Name          string
	Description   string
	PermissionIDs []string
}

type ResourceInput struct {
	Name        string
	Description string
	Icon        string
	InternalURL string
	PublicHost  string
	Enabled     bool
	GroupIDs    []string
	AllowCIDRs  []string
}

type ResourceUpdate struct {
	Name             *string
	Description      *string
	Icon             *string
	InternalURL      *string
	PublicHost       *string
	Enabled          *bool
	GroupIDs         []string
	UpdateGroups     bool
	AllowCIDRs       []string
	UpdateAllowCIDRs bool
}

type ResourceDiagnostics struct {
	ResourceID    string        `json:"resource_id"`
	InternalURL   string        `json:"internal_url"`
	DNS           CheckResult   `json:"dns"`
	TCP           CheckResult   `json:"tcp"`
	HTTP          CheckResult   `json:"http"`
	TotalDuration time.Duration `json:"total_duration"`
}

type CheckResult struct {
	OK       bool          `json:"ok"`
	Target   string        `json:"target"`
	Detail   string        `json:"detail"`
	Duration time.Duration `json:"duration"`
}
