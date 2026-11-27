// Package origin validates browser origins and HTTP host authorities without
// trusting forwarded request headers.
package origin

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func Authority(raw string) (string, error) {
	if raw == "" || strings.ContainsAny(raw, " /\\\t\r\n?#@%") {
		return "", fmt.Errorf("invalid host authority")
	}
	u, err := url.Parse("https://" + raw)
	if err != nil || u.Host != raw || u.Hostname() == "" {
		return "", fmt.Errorf("invalid host authority")
	}
	host := strings.ToLower(u.Hostname())
	if strings.HasSuffix(host, ".") {
		return "", fmt.Errorf("trailing DNS dot is not permitted")
	}
	if net.ParseIP(host) == nil {
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", fmt.Errorf("invalid hostname")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return "", fmt.Errorf("invalid hostname")
				}
			}
		}
		if len(host) > 253 {
			return "", fmt.Errorf("invalid hostname")
		}
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", fmt.Errorf("invalid port")
		}
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" && port != "443" {
		host = net.JoinHostPort(strings.Trim(host, "[]"), port)
	}
	return host, nil
}

func Hostname(authority string) (string, error) {
	canonical, err := Authority(authority)
	if err != nil {
		return "", err
	}
	u, _ := url.Parse("https://" + canonical)
	return u.Hostname(), nil
}

func HTTPS(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", fmt.Errorf("expected canonical HTTPS origin without path, credentials, query or fragment")
	}
	authority, err := Authority(u.Host)
	if err != nil {
		return "", err
	}
	canonical := "https://" + authority
	if canonical != raw {
		return "", fmt.Errorf("origin must be canonical: %s", canonical)
	}
	return canonical, nil
}
