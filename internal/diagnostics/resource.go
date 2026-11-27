package diagnostics

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/domain"
)

type Prober struct {
	Timeout     time.Duration
	Policy      NetworkPolicy
	lookupHost  func(context.Context, string) ([]string, error)
	dialContext func(context.Context, string, string) (net.Conn, error)
}

type NetworkPolicy struct {
	AllowCIDRs []*net.IPNet
	DenyCIDRs  []*net.IPNet
}

func NewNetworkPolicy(allowCIDRs []string, denyCIDRs []string) (NetworkPolicy, error) {
	allow, err := parseCIDRs(allowCIDRs)
	if err != nil {
		return NetworkPolicy{}, err
	}
	deny, err := parseCIDRs(denyCIDRs)
	if err != nil {
		return NetworkPolicy{}, err
	}
	return NetworkPolicy{AllowCIDRs: allow, DenyCIDRs: deny}, nil
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

	lookup := p.lookupHost
	if lookup == nil {
		lookup = net.DefaultResolver.LookupHost
	}
	ips, dnsResult := resolveHostWith(ctx, host, lookup)
	result.DNS = dnsResult
	policyErr := p.Policy.Allows(ips)
	if !dnsResult.OK || policyErr != nil {
		detail := "skipped because DNS resolution failed"
		if dnsResult.OK {
			detail = policyErr.Error()
		}
		result.TCP = domain.CheckResult{Target: net.JoinHostPort(host, port), Detail: detail}
		result.HTTP = domain.CheckResult{Target: parsed.String(), Detail: "skipped because DNS or diagnostics network policy blocked the target"}
		result.TotalDuration = time.Since(start)
		return result, nil
	}

	dial := p.dialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: timeout}).DialContext
	}
	// Both probes use only this validated resolution. Keep the URL authority intact
	// so HTTP Host and HTTPS certificate verification/SNI still use the hostname.
	pinnedDial := func(ctx context.Context, network, address string) (net.Conn, error) {
		dialHost, dialPort, err := net.SplitHostPort(address)
		if err != nil || !strings.EqualFold(dialHost, host) || dialPort != port {
			return nil, fmt.Errorf("diagnostics dial target differs from validated authority")
		}
		var lastErr error
		for _, ip := range ips {
			conn, err := dial(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
			if ctx.Err() != nil {
				break
			}
		}
		return nil, lastErr
	}
	result.TCP = checkTCP(ctx, net.JoinHostPort(host, port), pinnedDial)
	if result.TCP.OK {
		result.HTTP = checkHTTP(ctx, parsed.String(), timeout, pinnedDial)
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
	_, result := resolveHost(ctx, host)
	return result
}

func resolveHost(ctx context.Context, host string) ([]net.IP, domain.CheckResult) {
	return resolveHostWith(ctx, host, net.DefaultResolver.LookupHost)
}

func resolveHostWith(ctx context.Context, host string, lookup func(context.Context, string) ([]string, error)) ([]net.IP, domain.CheckResult) {
	start := time.Now()
	addrs, err := lookup(ctx, host)
	if err != nil {
		return nil, domain.CheckResult{
			OK:       false,
			Target:   host,
			Detail:   err.Error(),
			Duration: time.Since(start),
		}
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips, domain.CheckResult{
		OK:       len(ips) > 0,
		Target:   host,
		Detail:   fmt.Sprintf("%d address(es): %v", len(addrs), addrs),
		Duration: time.Since(start),
	}
}

func (p NetworkPolicy) Allows(ips []net.IP) error {
	if len(ips) == 0 {
		return fmt.Errorf("diagnostics target did not resolve to an IP address")
	}
	if len(p.AllowCIDRs) > 0 {
		for _, ip := range ips {
			if !cidrsContain(p.AllowCIDRs, ip) {
				return fmt.Errorf("diagnostics target IP %s is outside AGP_DIAGNOSTICS_ALLOW_CIDRS", ip)
			}
		}
		return nil
	}
	for _, ip := range ips {
		if cidrsContain(p.DenyCIDRs, ip) {
			return fmt.Errorf("diagnostics target IP %s is blocked by AGP_DIAGNOSTICS_DENY_CIDRS", ip)
		}
	}
	return nil
}

func parseCIDRs(values []string) ([]*net.IPNet, error) {
	networks := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("parse diagnostics cidr %q: %w", value, err)
		}
		networks = append(networks, network)
	}
	return networks, nil
}

func cidrsContain(networks []*net.IPNet, ip net.IP) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func checkTCP(ctx context.Context, address string, dial func(context.Context, string, string) (net.Conn, error)) domain.CheckResult {
	start := time.Now()
	conn, err := dial(ctx, "tcp", address)
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

func checkHTTP(ctx context.Context, rawURL string, timeout time.Duration, dial func(context.Context, string, string) (net.Conn, error)) domain.CheckResult {
	start := time.Now()
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dial,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     true,
	}
	defer transport.CloseIdleConnections()
	client := http.Client{
		Timeout:   timeout,
		Transport: transport,
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
