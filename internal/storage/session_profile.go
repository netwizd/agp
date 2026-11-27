package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/origin"
)

var ErrSessionProfile = errString("session profile does not match; preview and explicitly apply session-profile with session revocation")

func ReadSessionProfile(ctx context.Context, tx IdentityTx) (*domain.SessionProfile, error) {
	rows, err := tx.Query(ctx, `SELECT fingerprint, portal_host, management_origin, session_cookie_name, csrf_cookie_name,login_origin,secure_profile FROM session_profiles WHERE id = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	p := &domain.SessionProfile{}
	var fingerprint string
	if err := rows.Scan(&fingerprint, &p.PortalHost, &p.ManagementOrigin, &p.SessionCookieName, &p.CSRFCookieName, &p.LoginOrigin, &p.SecureProfile); err != nil {
		return nil, err
	}
	if fingerprint != p.Fingerprint() {
		return nil, ErrSessionProfile
	}
	return p, nil
}

func MatchSessionProfile(current *domain.SessionProfile, expected domain.SessionProfile) error {
	if current == nil {
		if expected.ManagementOrigin == "" {
			return nil
		}
		return ErrSessionProfile
	}
	if current.Fingerprint() != expected.Fingerprint() {
		return ErrSessionProfile
	}
	return nil
}

func ValidateProfileResources(ctx context.Context, tx IdentityTx, p domain.SessionProfile) error {
	if p.ManagementOrigin == "" {
		return nil
	}
	if _, err := origin.HTTPS(p.ManagementOrigin); err != nil {
		return err
	}
	managementHost, _ := origin.Hostname(strings.TrimPrefix(p.ManagementOrigin, "https://"))
	loginHost, _ := origin.Hostname(strings.TrimPrefix(p.LoginOrigin, "https://"))
	portalHost, err := origin.Hostname(p.PortalHost)
	if err != nil {
		return err
	}
	if managementHost == portalHost || (p.SecureProfile && (loginHost == portalHost || loginHost == managementHost)) {
		return fmt.Errorf("management and portal hostnames collide: %w", ErrConflict)
	}
	hosts, err := identityStrings(ctx, tx, `SELECT public_host FROM resources`)
	if err != nil {
		return err
	}
	for _, host := range hosts {
		hostname, err := origin.Hostname(host)
		if err != nil {
			return fmt.Errorf("invalid existing resource host %q: %w", host, err)
		}
		if hostname == managementHost || (p.SecureProfile && hostname == loginHost) {
			return fmt.Errorf("resource host %q collides with management: %w", host, ErrConflict)
		}
	}
	return nil
}

func CheckResourceProfile(ctx context.Context, tx IdentityTx, host string) error {
	p, err := ReadSessionProfile(ctx, tx)
	if err != nil {
		return err
	}
	if p == nil || p.ManagementOrigin == "" {
		return nil
	}
	managementHost, _ := origin.Hostname(strings.TrimPrefix(p.ManagementOrigin, "https://"))
	loginHost, _ := origin.Hostname(strings.TrimPrefix(p.LoginOrigin, "https://"))
	resourceHost, err := origin.Hostname(host)
	if err != nil {
		return fmt.Errorf("invalid resource host: %w", ErrConflict)
	}
	if resourceHost == managementHost || (p.SecureProfile && resourceHost == loginHost) {
		return fmt.Errorf("resource host is reserved for management: %w", ErrConflict)
	}
	return nil
}

func CheckResourceUpdateProfile(ctx context.Context, tx IdentityTx, id string, host *string) error {
	if host != nil {
		return CheckResourceProfile(ctx, tx, *host)
	}
	hosts, err := identityStrings(ctx, tx, `SELECT public_host FROM resources WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if len(hosts) != 1 {
		return ErrNotFound
	}
	return CheckResourceProfile(ctx, tx, hosts[0])
}

// ExecuteSessionProfileReset must share the identity writer lock with session
// issuance and resource writes. Profile, revocation and audit commit together.
func ExecuteSessionProfileReset(ctx context.Context, tx IdentityTx, p domain.SessionProfile) (int64, error) {
	rows, err := tx.Query(ctx, `SELECT enabled FROM security_state WHERE id=1`)
	if err != nil {
		return 0, err
	}
	active := rows.Next()
	rows.Close()
	if active {
		return 0, fmt.Errorf("secure authority is activated; legacy profile reset is forbidden")
	}

	if err := ValidateProfileResources(ctx, tx, p); err != nil {
		return 0, err
	}
	current, err := ReadSessionProfile(ctx, tx)
	if err != nil {
		return 0, err
	}
	if current != nil && current.Fingerprint() == p.Fingerprint() {
		return 0, nil
	}
	now := time.Now().UTC()
	revoked, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = ? WHERE revoked_at IS NULL`, now)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO session_profiles(id, fingerprint, portal_host, management_origin, session_cookie_name, csrf_cookie_name, updated_at,login_origin,secure_profile)
 VALUES (1, ?, ?, ?, ?, ?, ?,?,?)
 ON CONFLICT(id) DO UPDATE SET fingerprint = excluded.fingerprint, portal_host = excluded.portal_host, management_origin = excluded.management_origin, session_cookie_name = excluded.session_cookie_name, csrf_cookie_name = excluded.csrf_cookie_name, updated_at = excluded.updated_at,login_origin=excluded.login_origin,secure_profile=excluded.secure_profile`, p.Fingerprint(), p.PortalHost, p.ManagementOrigin, p.SessionCookieName, p.CSRFCookieName, now, p.LoginOrigin, p.SecureProfile); err != nil {
		return 0, err
	}
	metadata, _ := json.Marshal(map[string]any{"profile": p, "fingerprint": p.Fingerprint(), "revoked_sessions": revoked})
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events(event_type, username, outcome, reason, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?)`, "session.profile.changed", "agpctl", "success", "explicit_session_reset", string(metadata), now); err != nil {
		return 0, err
	}
	return revoked, nil
}

func NormalizeSessionAudience(session domain.Session) (domain.Session, error) {
	if session.Audience == "" {
		session.Audience = domain.SessionAudienceLegacy
	}
	if session.Audience == domain.SessionAudienceLegacy && session.AudienceOrigin == "" {
		return session, nil
	}
	if session.Audience == domain.SessionAudienceManagement && session.AudienceOrigin != "" {
		if _, err := origin.HTTPS(session.AudienceOrigin); err == nil {
			return session, nil
		}
	}
	return session, ErrPermissionDenied
}

func AuthorizeSessionCreation(ctx context.Context, tx IdentityTx, session domain.Session, expected domain.SessionProfile) error {
	current, err := ReadSessionProfile(ctx, tx)
	if err != nil {
		return err
	}
	if err := MatchSessionProfile(current, expected); err != nil {
		return err
	}
	if session.Audience == domain.SessionAudienceLegacy && session.AudienceOrigin == "" {
		return nil
	}
	if current == nil || current.ManagementOrigin == "" || session.Audience != domain.SessionAudienceManagement || session.AudienceOrigin != current.ManagementOrigin {
		return ErrPermissionDenied
	}
	_, permissions, err := identityUser(ctx, tx, session.UserID)
	if err != nil {
		return err
	}
	for _, permission := range authz.AllPermissions() {
		if authz.HasPermission(permissions, permission) {
			return nil
		}
	}
	return ErrPermissionDenied
}
