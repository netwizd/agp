package nginx

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/edgeauth"
)

type nativeEdgeAuthority struct {
	unavailable atomic.Bool
	methods     chan string
}

func (a *nativeEdgeAuthority) Redeem(context.Context, edgeauth.RedeemRequest) (edgeauth.RedeemResponse, error) {
	return edgeauth.RedeemResponse{}, fmt.Errorf("not used")
}
func (a *nativeEdgeAuthority) Logout(context.Context, string, string) error { return nil }
func (a *nativeEdgeAuthority) Decide(_ context.Context, r edgeauth.DecisionRequest) (edgeauth.Decision, error) {
	if a.unavailable.Load() {
		return edgeauth.Decision{}, fmt.Errorf("journal unavailable")
	}
	a.methods <- r.Method + " " + r.Path
	if r.SessionToken == "" {
		return edgeauth.Decision{Decision: "deny", ReasonCode: "authentication_required", SecuritySequence: 3}, nil
	}
	return edgeauth.Decision{Decision: "allow", ReasonCode: "allowed", UserID: "usr_checked", GroupIDs: []string{"grp_checked"}, SecuritySequence: 3}, nil
}

func TestNativeEdgeAuthIsolation(t *testing.T) {
	binary := os.Getenv("AGP_TEST_NGINX_BIN")
	if binary == "" {
		t.Skip("AGP_TEST_NGINX_BIN is not set; native EdgeAuth test was not run")
	}
	dir, e := os.MkdirTemp("", "agp-edge-nginx-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "app_sid=application; Path=/; Secure")
		w.Header().Add("Set-Cookie", "__Host-agp_gateway=attacker; Path=/; Secure")
		w.Header().Add("Set-Cookie", "app_sid=parent; Domain=example; Path=/")
		_ = json.NewEncoder(w).Encode(r.Header)
	}))
	defer app.Close()
	port, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := port.Addr().String()
	_, number, _ := net.SplitHostPort(address)
	_ = port.Close()
	host := "app.example:" + number
	state, e := edgeauth.OpenStateStore(context.Background(), filepath.Join(dir, "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	authority := &nativeEdgeAuthority{methods: make(chan string, 32)}
	socket := filepath.Join(dir, "edge.sock")
	cfg := edgeauth.Config{NodeID: "node_one", GatewayID: "gw_one", Origin: "https://" + host, LoginOrigin: "https://login.example", CentralOrigin: "https://central.example", DeploymentGeneration: "1", Routes: []edgeauth.Route{{ID: "route_one", PathPrefix: "/", Upstream: app.URL, ApplicationCookies: []string{"app_sid"}}}}
	edge, e := edgeauth.NewServer(cfg, state, authority)
	if e != nil {
		t.Fatal(e)
	}
	defer edge.Close()
	listener, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	server := &http.Server{Handler: edge.Handler(), ReadHeaderTimeout: time.Second}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	snippet, e := GenerateEdgeGatewayServer(cfg.Origin, socket)
	if e != nil {
		t.Fatal(e)
	}

	// Multiple gateways must compose in one Nginx http{} without duplicate
	// upstream/map identifiers, even when they share the same private socket.
	second, e := GenerateEdgeGatewayServer("https://second.example:"+number, socket)
	if e != nil {
		t.Fatal(e)
	}
	snippet += "\n" + second
	var lines []string
	for _, line := range strings.Split(snippet, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "ssl_certificate") || strings.HasPrefix(trim, "http2 ") {
			continue
		}
		lines = append(lines, strings.ReplaceAll(line, "listen "+number+" ssl;", "listen "+address+";"))
	}
	config := "pid nginx.pid;\nerror_log stderr;\nevents {}\nhttp {\naccess_log off;\nclient_body_temp_path body; proxy_temp_path proxy; fastcgi_temp_path fastcgi; uwsgi_temp_path uwsgi; scgi_temp_path scgi;\n" + strings.Join(lines, "\n") + "\n}\n"
	filename := filepath.Join(dir, "nginx.conf")
	if e = os.WriteFile(filename, []byte(config), 0600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "-e", "stderr", "-p", dir+"/", "-c", filename, "-g", "daemon off;")
	var log bytes.Buffer
	command.Stdout = &log
	command.Stderr = &log
	if e = command.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		_ = command.Process.Signal(os.Interrupt)
		_ = command.Wait()
		if t.Failed() {
			t.Log(log.String())
		}
	}()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	request := func(method, path, authorityHost string, cookie bool) (*http.Response, []byte, error) {
		r, e := http.NewRequest(method, "http://"+address+path, nil)
		if e != nil {
			return nil, nil, e
		}
		r.Host = authorityHost
		r.Header.Set("X-AGP-User-ID", "usr_attacker")
		r.Header.Set("X-AGP-Evil", "attacker")
		r.Header.Set("X-AGP-Start", "1")
		if cookie {
			r.AddCookie(&http.Cookie{Name: edgeauth.GatewayCookie, Value: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))})
			r.AddCookie(&http.Cookie{Name: "__Host-agp_management", Value: "management_secret"})
			r.AddCookie(&http.Cookie{Name: "app_sid", Value: "application"})
		}
		resp, e := client.Do(r)
		if e != nil {
			return nil, nil, e
		}
		body, e := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp, body, e
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, _, e := request("GET", "/health", host, true)
		if e == nil {
			if resp.StatusCode != 200 {
				t.Fatalf("Nginx EdgeAuth startup status%d", resp.StatusCode)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Nginx did not start: %v", e)
		}
		time.Sleep(20 * time.Millisecond)
	}
	resp, body, e := request("POST", "/dashboard?one=two", host, true)
	if e != nil || resp.StatusCode != 200 {
		t.Fatalf("protected proxy: status=%v error=%v body=%s", resp, e, body)
	}
	var headers http.Header
	if e = json.Unmarshal(body, &headers); e != nil {
		t.Fatal(e)
	}
	if headers.Get("X-AGP-User-ID") != "usr_checked" || headers.Get("X-AGP-Groups") != "grp_checked" || headers.Get("X-AGP-Evil") != "" || headers.Get("Cookie") != "app_sid=application" {
		t.Fatalf("Nginx bypassed header/cookie filtering: %v", headers)
	}
	if cookies := resp.Cookies(); len(cookies) != 1 || cookies[0].Name != "app_sid" || cookies[0].Domain != "" {
		t.Fatal("Nginx allowed response cookie injection")
	}
	seenPost := 0
	for len(authority.methods) > 0 {
		if <-authority.methods == "POST /dashboard?one=two" {
			seenPost++
		}
	}
	if seenPost != 2 {
		t.Fatalf("adapter/proxy lost original method/path: count%d", seenPost)
	}
	resp, body, e = request("GET", "/dashboard?one=two", host, false)
	if e != nil || resp.StatusCode != 303 {
		t.Fatalf("handoff did not start: %+v %v %s", resp, e, body)
	}
	location, _ := url.Parse(resp.Header.Get("Location"))
	if location.Host != "login.example" || location.Path != "/auth/v2/authorize" {
		t.Fatalf("unsafe authorize destination %s", location)
	}
	if resp, _, e = request("GET", edgeauth.AuthorizePath, host, true); e != nil || resp.StatusCode != 404 {
		t.Fatal("private status adapter reachable externally")
	}
	if resp, _, e = request("GET", "/dashboard", "unknown.example", true); e != nil || resp.StatusCode != 421 {
		t.Fatal("unknown host accepted")
	}
	authority.unavailable.Store(true)
	if resp, body, e = request("GET", "/dashboard", host, true); e != nil || resp.StatusCode != 503 {
		t.Fatalf("unavailable authority did not fail closed503: %+v %v %s", resp, e, body)
	}
}

func TestEdgeGeneratorRejectsInjection(t *testing.T) {
	for _, socket := range []string{"/tmp/edge.sock;return 200;", "/tmp/../edge.sock", "relative.sock", "/tmp/edge\n.sock"} {
		if _, e := GenerateEdgeGatewayServer("https://app.example", socket); e == nil {
			t.Errorf("accepted socket %q", socket)
		}
	}
	if _, e := GenerateEdgeGatewayServer("https://app.example/evil", "/tmp/edge.sock"); e == nil {
		t.Fatal("accepted origin path")
	}
}
