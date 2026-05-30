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
	ID          string
	Name        string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
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
	User   User
	Groups []string
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
	UsersCount          int
	BlockedUsersCount   int
	ActiveSessionsCount int
	ResourcesCount      int
	AuditEventsCount    int
	RecentEvents        []AuditEvent
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
	Name        string
	Description string
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
