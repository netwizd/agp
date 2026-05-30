package nginx

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"strings"
	"text/template"

	"github.com/netwizd/agp/internal/domain"
)

type Recommendation struct {
	ResourceID string   `json:"resource_id"`
	PublicHost string   `json:"public_host"`
	Snippet    string   `json:"snippet"`
	Warnings   []string `json:"warnings"`
}

func GenerateResourceServer(resource domain.ResourceDetail, portalHost string) (*Recommendation, error) {
	warnings := make([]string, 0)
	publicHost, err := normalizeHost(resource.PublicHost)
	if err != nil {
		return nil, err
	}
	internalURL, err := normalizeProxyURL(resource.InternalURL)
	if err != nil {
		return nil, err
	}
	if portalHost == "" {
		portalHost = "portal.company.ru"
		warnings = append(warnings, "portal host is not configured; placeholder portal.company.ru is used")
	}
	if len(resource.GroupIDs) == 0 {
		warnings = append(warnings, "resource has no group mapping; AGP will deny access until at least one group is assigned")
	}
	if len(resource.AllowCIDRs) == 0 {
		warnings = append(warnings, "resource has no IP allowlist; access is controlled by session and group only")
	}
	for _, cidr := range resource.AllowCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return nil, fmt.Errorf("invalid allowlist cidr %q: %w", cidr, err)
		}
	}

	var out bytes.Buffer
	if err := resourceServerTemplate.Execute(&out, map[string]any{
		"PublicHost":  publicHost,
		"InternalURL": internalURL,
		"PortalHost":  portalHost,
	}); err != nil {
		return nil, fmt.Errorf("render nginx recommendation: %w", err)
	}
	return &Recommendation{
		ResourceID: resource.ID,
		PublicHost: publicHost,
		Snippet:    strings.TrimSpace(out.String()) + "\n",
		Warnings:   warnings,
	}, nil
}

func normalizeHost(host string) (string, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return "", fmt.Errorf("public host is required")
	}
	if strings.Contains(host, "/") || strings.ContainsAny(host, " \t\r\n;{}") {
		return "", fmt.Errorf("public host contains invalid nginx characters")
	}
	if strings.Contains(host, ":") {
		parsed, _, err := net.SplitHostPort(host)
		if err != nil {
			return "", fmt.Errorf("invalid public host: %w", err)
		}
		host = parsed
	}
	return host, nil
}

func normalizeProxyURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse internal url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("internal url must use http or https")
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("internal url host is required")
	}
	if strings.ContainsAny(raw, " \t\r\n;{}") {
		return "", fmt.Errorf("internal url contains invalid nginx characters")
	}
	return parsed.String(), nil
}

var resourceServerTemplate = template.Must(template.New("resource-server").Parse(`
server {
    listen 443 ssl http2;
    server_name {{ .PublicHost }};

    ssl_certificate /etc/letsencrypt/live/{{ .PublicHost }}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{{ .PublicHost }}/privkey.pem;

    access_log /var/log/nginx/agp.resources.access.log;
    error_log /var/log/nginx/agp.resources.error.log warn;

    auth_request /_agp_auth;
    auth_request_set $agp_user $upstream_http_x_agp_user;
    auth_request_set $agp_user_id $upstream_http_x_agp_user_id;
    auth_request_set $agp_groups $upstream_http_x_agp_groups;

    proxy_set_header X-AGP-User $agp_user;
    proxy_set_header X-AGP-User-ID $agp_user_id;
    proxy_set_header X-AGP-Groups $agp_groups;

    error_page 401 =302 https://{{ .PortalHost }}/login;
    error_page 403 /403.html;

    location = /_agp_auth {
        internal;
        proxy_pass http://agp_backend/auth/request;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Cookie $http_cookie;
    }

    location = /403.html {
        root /opt/agp/errors;
        internal;
    }

    location / {
        proxy_pass {{ .InternalURL }};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
    }
}
`))
