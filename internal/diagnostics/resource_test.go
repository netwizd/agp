package diagnostics

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/domain"
)

func TestProbePinsResolutionAndPreservesHost(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Setenv("HTTP_PROXY", "http://proxy.invalid:8888")
			t.Setenv("HTTPS_PROXY", "http://proxy.invalid:8888")
			t.Setenv("NO_PROXY", "")
			lookups, dials := 0, 0
			requests := make(chan *http.Request, 1)
			prober := Prober{
				Timeout: time.Second,
				lookupHost: func(_ context.Context, host string) ([]string, error) {
					lookups++
					if host != "app.example" {
						t.Errorf("unexpected DNS authority %q", host)
					}
					if lookups > 1 {
						return []string{"127.0.0.1"}, nil // DNS rebinding must never be used.
					}
					return []string{"192.0.2.10"}, nil
				},
				dialContext: func(_ context.Context, network, address string) (net.Conn, error) {
					dials++
					if network != "tcp" || address != "192.0.2.10:8080" {
						t.Fatalf("unvalidated dial %s %s", network, address)
					}
					client, server := net.Pipe()
					if dials == 1 {
						_ = server.Close() // TCP probe; no HTTP exchange.
					} else {
						go func() {
							defer server.Close()
							_ = server.SetDeadline(time.Now().Add(time.Second))
							req, err := http.ReadRequest(bufio.NewReader(server))
							if err != nil {
								return
							}
							requests <- req
							_, _ = fmt.Fprintf(server, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nLocation: http://127.0.0.1/private\r\nConnection: close\r\n\r\n", status, http.StatusText(status))
						}()
					}
					return client, nil
				},
			}
			result, err := prober.ProbeResource(context.Background(), diagnosticResource("http://app.example:8080/health"))
			if err != nil || !result.DNS.OK || !result.TCP.OK || !result.HTTP.OK {
				t.Fatalf("probe failed: %#v, %v", result, err)
			}
			if lookups != 1 || dials != 2 {
				t.Fatalf("resolution reused or redirect followed: lookups=%d, dials=%d", lookups, dials)
			}
			select {
			case req := <-requests:
				if req.Host != "app.example:8080" || req.Method != http.MethodHead || req.URL.Path != "/health" {
					t.Fatalf("original HTTP authority not preserved: %#v", req)
				}
			default:
				t.Fatal("upstream did not receive HTTP request")
			}
		})
	}
}

func TestProbeRejectsDNSAndPolicyFailuresWithoutDial(t *testing.T) {
	policy, err := NewNetworkPolicy(nil, []string{"127.0.0.0/8", "::1/128"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		ips  []string
		err  error
	}{
		{"dns_failure", nil, errors.New("DNS failed")},
		{"partial_dns_failure", []string{"192.0.2.10"}, errors.New("incomplete DNS")},
		{"empty_dns", nil, nil},
		{"blocked_ipv4", []string{"127.0.0.1"}, nil},
		{"mixed_ipv4_ipv6", []string{"192.0.2.10", "::1"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prober := Prober{
				Policy:     policy,
				lookupHost: func(context.Context, string) ([]string, error) { return tc.ips, tc.err },
				dialContext: func(context.Context, string, string) (net.Conn, error) {
					t.Fatal("dial attempted before complete DNS/policy validation")
					return nil, errors.New("unexpected dial")
				},
			}
			result, err := prober.ProbeResource(context.Background(), diagnosticResource("http://app.example"))
			if err != nil || result.TCP.OK || result.HTTP.OK {
				t.Fatalf("expected fail-closed result: %#v, %v", result, err)
			}
		})
	}
}

func TestProbeHTTPSKeepsHostnameForSNI(t *testing.T) {
	sni := make(chan string, 1)
	dials := 0
	prober := Prober{
		Timeout:    time.Second,
		lookupHost: func(context.Context, string) ([]string, error) { return []string{"2001:db8::10"}, nil },
		dialContext: func(_ context.Context, _, address string) (net.Conn, error) {
			dials++
			if address != "[2001:db8::10]:443" {
				t.Fatalf("unexpected HTTPS dial %q", address)
			}
			client, server := net.Pipe()
			if dials == 1 {
				_ = server.Close()
			} else {
				go func() {
					defer server.Close()
					_ = server.SetDeadline(time.Now().Add(time.Second))
					conn := tls.Server(server, &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
						sni <- hello.ServerName
						return nil, errors.New("stop after checking SNI")
					}})
					_ = conn.Handshake()
				}()
			}
			return client, nil
		},
	}
	result, err := prober.ProbeResource(context.Background(), diagnosticResource("https://app.example/health"))
	if err != nil || !result.TCP.OK || result.HTTP.OK {
		t.Fatalf("expected TLS rejection after TCP: %#v, %v", result, err)
	}
	select {
	case host := <-sni:
		if host != "app.example" {
			t.Fatalf("TLS SNI uses pinned IP instead of hostname: %q", host)
		}
	default:
		t.Fatal("TLS handshake did not send SNI")
	}
}

func TestProbeTriesOnlyApprovedAddresses(t *testing.T) {
	var addresses []string
	prober := Prober{
		lookupHost: func(context.Context, string) ([]string, error) { return []string{"192.0.2.10", "2001:db8::10"}, nil },
		dialContext: func(_ context.Context, _, address string) (net.Conn, error) {
			addresses = append(addresses, address)
			return nil, errors.New("unavailable")
		},
	}
	result, err := prober.ProbeResource(context.Background(), diagnosticResource("http://app.example"))
	if err != nil || result.TCP.OK || result.HTTP.OK || strings.Join(addresses, ",") != "192.0.2.10:80,[2001:db8::10]:80" {
		t.Fatalf("unexpected fallback: addresses=%v result=%#v err=%v", addresses, result, err)
	}
}

func diagnosticResource(rawURL string) domain.ResourceDetail {
	return domain.ResourceDetail{Resource: domain.Resource{ID: "res_test", InternalURL: rawURL}}
}
