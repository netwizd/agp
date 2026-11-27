package nginx

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/netwizd/agp/internal/origin"
)

var edgeSocketPath = regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`)

// GenerateEdgeGatewayServer provisions a dedicated host. All application bytes
// pass through EdgeAuth's Go proxy because auth_request cannot filter response
// cookies. The private adapter translates validated JSON decisions into status.
func GenerateEdgeGatewayServer(gatewayOrigin, socketPath string) (string, error) {
	return GenerateEdgeGatewayServerWithTLS(gatewayOrigin, socketPath, "/etc/nginx/ssl/gateway/cert.pem", "/etc/nginx/ssl/gateway/private.key")
}

// GenerateEdgeGatewayServerWithTLS uses explicit operator-selected material;
// the generator neither chooses a CA issuer nor starts certificate automation.
func GenerateEdgeGatewayServerWithTLS(gatewayOrigin, socketPath, certificateFile, keyFile string) (string, error) {
	for _, file := range []string{certificateFile, keyFile} {
		if !edgeSocketPath.MatchString(file) || filepath.Clean(file) != file || len(file) > 4096 {
			return "", fmt.Errorf("invalid explicit TLS file path")
		}
	}

	if _, err := origin.HTTPS(gatewayOrigin); err != nil {
		return "", err
	}
	if !edgeSocketPath.MatchString(socketPath) || filepath.Clean(socketPath) != socketPath || len(socketPath) > 100 {
		return "", fmt.Errorf("invalid private EdgeAuth Unix socket")
	}
	u, _ := url.Parse(gatewayOrigin)
	port := u.Port()
	if port == "" {
		port = "443"
	}
	common := `        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-AGP-Client-IP $remote_addr;
        proxy_set_header X-AGP-Start "";
        proxy_set_header X-AGP-Original-URI $request_uri;
        proxy_set_header X-AGP-Original-Method $agp_original_method;
        proxy_http_version 1.1;
`
	var b strings.Builder
	fmt.Fprintf(&b, `# EdgeAuth runs as a separate service account. Grant only Nginx access to this socket.
upstream agp_edge_auth { server unix:%s; }
map $http_upgrade $agp_edge_connection { default upgrade; '' close; }
server {
    listen %s ssl;
    http2 on;
    server_name %s;
    ssl_certificate %s;
    ssl_certificate_key %s;
    if ($http_host != "%s") { return 421; }
    set $agp_original_method $request_method;
    location = /_agp/authorize {
        internal;
        proxy_pass http://agp_edge_auth/_agp/authorize;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
%s    }
`, socketPath, port, u.Hostname(), certificateFile, keyFile, u.Host, common)
	for _, p := range []string{"/_agp/start", "/_agp/callback", "/_agp/logout"} {
		fmt.Fprintf(&b, "    location = %s {\n        access_log off;\n        proxy_pass http://agp_edge_auth;\n%s    }\n", p, common)
	}
	fmt.Fprintf(&b, `    location /_agp { return 404; }
    location @agp_start {
        proxy_pass http://agp_edge_auth;
%s        proxy_set_header X-AGP-Start "1";
    }
    location @agp_auth_unavailable { return 503; }
    location / {
        auth_request /_agp/authorize;
        error_page 401 = @agp_start;
        error_page 500 = @agp_auth_unavailable;
        proxy_pass http://agp_edge_auth;
%s        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $agp_edge_connection;
        proxy_read_timeout 310s;
        proxy_send_timeout 30s;
    }
}
`, strings.Replace(common, "        proxy_set_header X-AGP-Start \"\";\n", "", 1), common)
	sum := sha256.Sum256([]byte(gatewayOrigin + "\x00" + socketPath))
	suffix := hex.EncodeToString(sum[:12])
	return strings.NewReplacer("agp_edge_auth", "agp_edge_auth_"+suffix, "agp_edge_connection", "agp_ec_"+suffix).Replace(b.String()), nil
}
