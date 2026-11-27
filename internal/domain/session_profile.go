package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

const (
	SessionAudienceLegacy       = "legacy"
	SessionAudienceManagement   = "management"
	SessionAudienceLogin        = "login"
	SessionAudienceGateway      = "gateway"
	LoginSessionCookieName      = "__Host-agp_login"
	LoginCSRFCookieName         = "__Host-agp_login_csrf"
	ManagementSessionCookieName = "__Host-agp_management"
	ManagementCSRFCookieName    = "__Host-agp_management_csrf"
)

type SessionProfile struct {
	LoginOrigin       string `json:"login_origin,omitempty"`
	SecureProfile     bool   `json:"secure_profile,omitempty"`
	PortalHost        string `json:"portal_host"`
	ManagementOrigin  string `json:"management_origin"`
	SessionCookieName string `json:"session_cookie_name"`
	CSRFCookieName    string `json:"csrf_cookie_name"`
}

func (p SessionProfile) Fingerprint() string {
	raw, _ := json.Marshal(p)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
