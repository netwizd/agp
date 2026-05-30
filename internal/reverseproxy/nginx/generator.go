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

type Bundle struct {
	PortalHost string   `json:"portal_host"`
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

func GenerateBundle(resources []domain.ResourceDetail, portalHost string) (*Bundle, error) {
	warnings := make([]string, 0)
	portalHost, err := normalizeHost(portalHost)
	if err != nil {
		return nil, fmt.Errorf("invalid portal host: %w", err)
	}

	var out bytes.Buffer
	if err := bundleHeaderTemplate.Execute(&out, map[string]any{"PortalHost": portalHost}); err != nil {
		return nil, fmt.Errorf("render nginx portal server: %w", err)
	}
	for _, resource := range resources {
		recommendation, err := GenerateResourceServer(resource, portalHost)
		if err != nil {
			return nil, fmt.Errorf("render resource %s: %w", resource.ID, err)
		}
		if len(recommendation.Warnings) > 0 {
			for _, warning := range recommendation.Warnings {
				warnings = append(warnings, fmt.Sprintf("%s: %s", resource.PublicHost, warning))
			}
		}
		out.WriteString("\n\n")
		out.WriteString(recommendation.Snippet)
	}
	return &Bundle{
		PortalHost: portalHost,
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

var bundleHeaderTemplate = template.Must(template.New("bundle-header").Parse(`
upstream agp_backend {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name {{ .PortalHost }};

    ssl_certificate /etc/letsencrypt/live/{{ .PortalHost }}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{{ .PortalHost }}/privkey.pem;

    access_log /var/log/nginx/agp.portal.access.log;
    error_log /var/log/nginx/agp.portal.error.log warn;

    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer always;
    add_header Content-Security-Policy "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        proxy_pass http://agp_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
    }
}
`))

var resourceServerTemplate = template.Must(template.New("resource-server").Parse(`
server {
    listen 443 ssl http2;
    server_name {{ .PublicHost }};

    ssl_certificate /etc/letsencrypt/live/{{ .PublicHost }}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{{ .PublicHost }}/privkey.pem;

    access_log /var/log/nginx/agp.resources.access.log;
    error_log /var/log/nginx/agp.resources.error.log warn;

    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    auth_request /_agp_auth;
    auth_request_set $agp_user $upstream_http_x_agp_user;
    auth_request_set $agp_user_id $upstream_http_x_agp_user_id;
    auth_request_set $agp_groups $upstream_http_x_agp_groups;

    proxy_set_header X-AGP-User $agp_user;
    proxy_set_header X-AGP-User-ID $agp_user_id;
    proxy_set_header X-AGP-Groups $agp_groups;

    error_page 401 =302 https://{{ .PortalHost }}/login;
    error_page 403 =302 https://{{ .PortalHost }}/access-denied;

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
