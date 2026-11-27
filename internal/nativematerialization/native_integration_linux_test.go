//go:build linux

package nativematerialization

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/edgeauth"
)

// This is a native integration test of the unsigned candidate, not signed
// qualification. It uses real Nginx, TLS, ModSecurity/CRS, EdgeAuth and an HTTP
// upstream. Central Auth's decision interface is a controlled test dependency;
// corporate authentication, mTLS and the installation lifecycle are not claimed.
func TestNativeServiceCandidate(t *testing.T) {
	runtimeRoot := os.Getenv("AGP_TEST_SERVICE_RUNTIME")
	if runtimeRoot == "" {
		t.Skip("AGP_TEST_SERVICE_RUNTIME not set; real service candidate runtime was not exercised")
	}
	if !filepath.IsAbs(runtimeRoot) {
		t.Fatal("AGP_TEST_SERVICE_RUNTIME must be absolute")
	}
	work, err := os.MkdirTemp("", "agp-service-candidate-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(work) })
	c, policies, opts := candidateFixture(t)
	opts.RuntimeRoot = runtimeRoot
	opts.GenerationRoot, opts.RunDir, opts.StateDir, opts.SecretDir = work+"/generation", work+"/run", work+"/state", work+"/secrets"
	for _, dir := range []string{opts.GenerationRoot, opts.RunDir, opts.StateDir, opts.SecretDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	opts.ListenAddress = listener.Addr().String()
	_ = listener.Close()
	var hits atomic.Int64
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Set-Cookie", "__Host-agp_gateway=attacker; Path=/; Secure")
		_ = json.NewEncoder(w).Encode(r.Header)
	}))
	defer app.Close()
	c.Gateways[0].Spec.Routes[0].Upstream.URL = app.URL
	c.Gateways[0].Spec.WAF.Mode = "blocking"
	second := c.Gateways[0]
	second.Metadata.ID = "gateway_detection"
	second.Spec.Routes = append([]configmodel.Route(nil), second.Spec.Routes...)
	second.Spec.Routes[0].ID = "route_detection"
	second.Spec.Routes[0].Hostname = "detection.example.net"
	second.Spec.WAF.Mode = "detection"
	c.Gateways = append(c.Gateways, second)
	candidate, err := Compile(context.Background(), c, policies, opts)
	if err != nil {
		t.Fatal(err)
	}
	rootCA := installTestCertificate(t, opts.SecretDir+"/"+c.Gateways[0].Spec.TLS.CertificateVersionID, []string{c.Gateways[0].Spec.Routes[0].Hostname, "detection.example.net"})
	for _, artifact := range candidate.Artifacts {
		filename := filepath.Join(opts.GenerationRoot, filepath.FromSlash(artifact.Path))
		if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(artifact.Content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	authority := &candidateAuthority{}
	for _, gateway := range candidate.Gateways {
		serveTestEdge(t, gateway.Edge, authority)
	}
	loader := runtimeRoot + "/lib/ld-linux-x86-64.so.2"
	binary := runtimeRoot + "/bin/nginx"
	nginxArgs := []string{"--library-path", runtimeRoot + "/lib", binary, "-e", "stderr", "-p", work + "/", "-c", opts.GenerationRoot + "/nginx.conf"}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	syntax := exec.CommandContext(ctx, loader, append(append([]string(nil), nginxArgs...), "-t")...)
	syntax.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	if out, err := syntax.CombinedOutput(); err != nil || !bytes.Contains(out, []byte("test is successful")) {
		t.Fatalf("actual candidate nginx -t failed: %v\n%s", err, out)
	}
	badName := opts.GenerationRoot + "/bad.conf"
	config, err := os.ReadFile(opts.GenerationRoot + "/nginx.conf")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(badName, append(config, []byte("\nnot_a_valid_nginx_directive;\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	badArgs := append([]string(nil), nginxArgs...)
	badArgs[len(badArgs)-1] = badName
	invalid := exec.CommandContext(ctx, loader, append(badArgs, "-t")...)
	invalid.Env = syntax.Env
	if out, err := invalid.CombinedOutput(); err == nil || !bytes.Contains(out, []byte("unknown directive")) {
		t.Fatalf("real nginx failed to reject invalid config: %v\n%s", err, out)
	}
	log, err := os.OpenFile(work+"/nginx.log", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	command := exec.Command(loader, append(nginxArgs, "-g", "daemon off;")...)
	command.Env = syntax.Env
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = command.Wait(); close(done) }()
	defer func() {
		_ = command.Process.Signal(syscall.SIGQUIT)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			<-done
		}
		if t.Failed() {
			raw, _ := os.ReadFile(work + "/nginx.log")
			t.Logf("actual Nginx diagnostic:\n%s", raw)
		}
	}()
	_, port, _ := net.SplitHostPort(opts.ListenAddress)
	appHost := c.Gateways[0].Spec.Routes[0].Hostname
	client := candidateClient(t, rootCA, appHost)
	detectionClient := candidateClient(t, rootCA, "detection.example.net")
	request := func(client *http.Client, host, method, path, body, contentType string, cookie bool) (*http.Response, []byte, error) {
		r, err := http.NewRequest(method, "https://"+opts.ListenAddress+path, strings.NewReader(body))
		if err != nil {
			return nil, nil, err
		}
		r.Host = host + ":" + port
		r.Header.Set("X-AGP-User-ID", "forged_user")
		r.Header.Set("X-AGP-Evil", "forged")
		r.Header.Set("X-AGP-Start", "1")
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		if cookie {
			r.AddCookie(&http.Cookie{Name: edgeauth.GatewayCookie, Value: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))})
			r.AddCookie(&http.Cookie{Name: "__Host-agp_management", Value: "must_not_reach_upstream"})
		}
		response, err := client.Do(r)
		if err != nil {
			return nil, nil, err
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(response.Body, 128<<10))
		return response, raw, err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		response, _, err := request(client, appHost, "GET", "/", "", "", true)
		if err == nil && response.StatusCode == 200 {
			break
		}
		select {
		case <-done:
			t.Fatal("actual Nginx exited before serving")
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("native service did not start: response=%v error=%v", response, err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	response, body, err := request(client, appHost, "GET", "/dashboard?normal=one", "", "", true)
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("real route failed: response=%v error=%v body=%s", response, err, body)
	}
	var headers http.Header
	if err := json.Unmarshal(body, &headers); err != nil {
		t.Fatal(err)
	}
	if headers.Get("X-AGP-User-ID") != "checked_user" || headers.Get("X-AGP-Groups") != "checked_group" || headers.Get("X-AGP-Evil") != "" || headers.Get("Cookie") != "" || len(response.Cookies()) != 0 {
		t.Fatalf("native service bypassed identity/cookie filtering: %v", headers)
	}
	t.Log("actual TLS route and EdgeAuth identity/cookie isolation: PASS")
	before := hits.Load()
	response, body, err = request(client, appHost, "GET", "/dashboard", "", "", false)
	if err != nil || response.StatusCode != 303 || !strings.HasPrefix(response.Header.Get("Location"), opts.LoginOrigin+"/auth/v2/authorize?") || hits.Load() != before {
		t.Fatalf("anonymous request reached app or unsafe handoff: response=%v error=%v body=%s", response, err, body)
	}
	response, _, err = request(client, appHost, "GET", edgeauth.AuthorizePath, "", "", true)
	if err != nil || response.StatusCode != 404 {
		t.Fatal("private auth adapter was exposed")
	}
	response, _, err = request(client, "unknown.example.net", "GET", "/", "", "", true)
	if err != nil || response.StatusCode != 421 {
		t.Fatalf("unknown authority accepted: response=%v error=%v", response, err)
	}
	authority.unavailable.Store(true)
	response, _, err = request(client, appHost, "GET", "/dashboard", "", "", true)
	if err != nil || response.StatusCode != 503 || hits.Load() != before {
		t.Fatalf("authority failure did not fail closed: response=%v error=%v", response, err)
	}
	authority.unavailable.Store(false)
	t.Log("anonymous handoff, private auth endpoint, host boundary and unavailable authority: PASS")
	attack := "/?q=" + url.QueryEscape("<script>alert(1)</script>")
	response, body, err = request(client, appHost, "GET", attack, "", "", true)
	if err != nil || response.StatusCode != 403 || hits.Load() != before {
		t.Fatalf("actual CRS did not block before app: response=%v error=%v body=%s", response, err, body)
	}
	response, body, err = request(client, appHost, "POST", "/", "{broken", "application/json", true)
	if err != nil || response.StatusCode != 400 || hits.Load() != before {
		t.Fatalf("malformed JSON reached app: response=%v error=%v body=%s", response, err, body)
	}
	response, body, err = request(detectionClient, "detection.example.net", "GET", attack, "", "", true)
	if err != nil || response.StatusCode != 200 || hits.Load() != before+1 {
		t.Fatalf("detection Gateway inherited blocking state: response=%v error=%v body=%s", response, err, body)
	}
	if candidate.Deployable || candidate.APIVersion != CandidateVersion {
		t.Fatal("native exercise promoted candidate to deployable")
	}
	t.Log("real CRS blocking and malformed-body rejection before upstream; detection neighbour allows: PASS")
}

type candidateAuthority struct{ unavailable atomic.Bool }

func (a *candidateAuthority) Redeem(context.Context, edgeauth.RedeemRequest) (edgeauth.RedeemResponse, error) {
	return edgeauth.RedeemResponse{}, errors.New("not used in this test")
}
func (a *candidateAuthority) Logout(context.Context, string, string) error { return nil }
func (a *candidateAuthority) Decide(_ context.Context, r edgeauth.DecisionRequest) (edgeauth.Decision, error) {
	if a.unavailable.Load() {
		return edgeauth.Decision{}, errors.New("controlled authority unavailable")
	}
	if r.SessionToken == "" {
		return edgeauth.Decision{Decision: "deny", ReasonCode: "authentication_required", SecuritySequence: 1}, nil
	}
	return edgeauth.Decision{Decision: "allow", ReasonCode: "allowed", UserID: "checked_user", GroupIDs: []string{"checked_group"}, SecuritySequence: 1}, nil
}

func serveTestEdge(t *testing.T, cfg edgeauth.Config, authority edgeauth.Central) {
	t.Helper()
	state, err := edgeauth.OpenStateStore(context.Background(), cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	edge, err := edgeauth.NewServer(cfg, state, authority)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(edge.Close)
	listener, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: edge.Handler(), ReadHeaderTimeout: time.Second}
	done := make(chan struct{})
	go func() { _ = server.Serve(listener); close(done) }()
	t.Cleanup(func() { _ = server.Close(); <-done })
}

func candidateClient(t *testing.T, roots *x509.CertPool, host string) *http.Client {
	t.Helper()
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: host}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func installTestCertificate(t *testing.T, dir string, hosts []string) *x509.CertPool {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "AGP native candidate test only"}, DNSNames: hosts, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(dir+"/certificate.pem", certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/private.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal(fmt.Errorf("test certificate could not be parsed"))
	}
	return pool
}
