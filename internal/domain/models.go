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
