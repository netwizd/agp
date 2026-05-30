package diagnostics

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/netwizd/agp/internal/domain"
)

type Prober struct {
	Timeout time.Duration
}

func (p Prober) ProbeResource(ctx context.Context, resource domain.ResourceDetail) (*domain.ResourceDiagnostics, error) {
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	parsed, err := url.Parse(resource.InternalURL)
	if err != nil {
		return nil, fmt.Errorf("parse resource internal url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("unsupported resource scheme %q", parsed.Scheme)
	}
	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("resource internal url host is required")
	}
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	result := &domain.ResourceDiagnostics{
		ResourceID:  resource.ID,
		InternalURL: resource.InternalURL,
	}

	result.DNS = checkDNS(ctx, host)
	result.TCP = checkTCP(ctx, net.JoinHostPort(host, port), timeout)
	if result.TCP.OK {
		result.HTTP = checkHTTP(ctx, parsed.String(), timeout)
	} else {
		result.HTTP = domain.CheckResult{
			OK:     false,
			Target: parsed.String(),
			Detail: "skipped because TCP check failed",
		}
	}
	result.TotalDuration = time.Since(start)
	return result, nil
}

func checkDNS(ctx context.Context, host string) domain.CheckResult {
	start := time.Now()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return domain.CheckResult{
			OK:       false,
			Target:   host,
			Detail:   err.Error(),
			Duration: time.Since(start),
		}
	}
	return domain.CheckResult{
		OK:       true,
		Target:   host,
		Detail:   fmt.Sprintf("%d address(es): %v", len(addrs), addrs),
		Duration: time.Since(start),
	}
}

func checkTCP(ctx context.Context, address string, timeout time.Duration) domain.CheckResult {
	start := time.Now()
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return domain.CheckResult{
			OK:       false,
			Target:   address,
			Detail:   err.Error(),
			Duration: time.Since(start),
		}
	}
	_ = conn.Close()
	return domain.CheckResult{
		OK:       true,
		Target:   address,
		Detail:   "tcp connection established",
		Duration: time.Since(start),
	}
}

func checkHTTP(ctx context.Context, rawURL string, timeout time.Duration) domain.CheckResult {
	start := time.Now()
	client := http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	if err != nil {
		return domain.CheckResult{
			OK:       false,
			Target:   rawURL,
			Detail:   err.Error(),
			Duration: time.Since(start),
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return domain.CheckResult{
			OK:       false,
			Target:   rawURL,
			Detail:   err.Error(),
			Duration: time.Since(start),
		}
	}
	defer resp.Body.Close()

	ok := resp.StatusCode >= 200 && resp.StatusCode < 500
	return domain.CheckResult{
		OK:       ok,
		Target:   rawURL,
		Detail:   "status " + strconv.Itoa(resp.StatusCode),
		Duration: time.Since(start),
	}
}
