package domain

import (
	"encoding/json"
	"github.com/netwizd/agp/internal/securityjournal"
	"time"
)

type HandoffRedeemRequest struct {
	Code         string `json:"code"`
	GatewayID    string `json:"gatewayId"`
	RedirectURI  string `json:"redirectUri"`
	CodeVerifier string `json:"codeVerifier"`
}
type HandoffRedeemResponse struct {
	SessionToken string    `json:"sessionToken"`
	SessionID    string    `json:"sessionId"`
	ExpiresAt    time.Time `json:"expiresAt"`
	UserID       string    `json:"userId"`
}
type EdgeDecisionRequest struct {
	GatewayID            string `json:"gatewayId"`
	RouteID              string `json:"routeId"`
	DeploymentGeneration string `json:"deploymentGeneration"`
	SessionToken         string `json:"sessionToken"`
	ClientIP             string `json:"clientIp"`
	Method               string `json:"method"`
	Path                 string `json:"path"`
}
type EdgeDecision struct {
	Decision         string                 `json:"decision"`
	ReasonCode       string                 `json:"reasonCode"`
	SecuritySequence securityjournal.UInt63 `json:"securitySequence"`
	UserID           string                 `json:"userId,omitempty"`
	GroupIDs         []string               `json:"groupIds,omitempty"`
}
type EdgeLogoutRequest struct {
	GatewayID    string `json:"gatewayId"`
	SessionToken string `json:"sessionToken"`
}
type GatewayRegistration struct {
	ID         string `json:"id"`
	NodeID     string `json:"nodeId"`
	Origin     string `json:"origin"`
	Callback   string `json:"callback"`
	ResourceID string `json:"resourceId"`
	Generation string `json:"generation"`
}

func (d EdgeDecision) MarshalJSON() ([]byte, error) {
	out := map[string]any{"decision": d.Decision, "reasonCode": d.ReasonCode, "securitySequence": d.SecuritySequence}
	if d.Decision == "allow" {
		groups := d.GroupIDs
		if groups == nil {
			groups = []string{}
		}
		out["userId"] = d.UserID
		out["groupIds"] = groups
	}
	return json.Marshal(out)
}
