package inventory

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/deploymentplan"
	"github.com/netwizd/agp/internal/helper"
)

func executionClientFixture(t *testing.T, handler http.Handler) (*Client, ClientConfig) {
	t.Helper()
	dir := privateTestDir(t)
	now := time.Now().UTC()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(51), Subject: pkix.Name{CommonName: "execution-test-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	ca := createCert(t, tmpl, tmpl, pub, key)
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0644); err != nil {
		t.Fatal(err)
	}
	clientPub, clientKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("spiffe://agp/agent/node_one")
	leaf := createCert(t, &x509.Certificate{SerialNumber: big.NewInt(52), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}, ca, clientPub, key)
	_, certPath, keyPath := writePair(t, dir, "client", leaf, clientKey)
	serverPub, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverLeaf := createCert(t, &x509.Certificate{SerialNumber: big.NewInt(53), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}, ca, serverPub, key)
	serverPair, _, _ := writePair(t, dir, "server", serverLeaf, serverKey)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.VerifiedChains) != 1 || len(r.TLS.PeerCertificates) != 1 || !bytes.Equal(r.TLS.PeerCertificates[0].Raw, leaf.Raw) || r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Accept-Encoding") != "identity" || r.URL.RawQuery != "" {
			t.Error("execution transport lost pinned mTLS identity or fixed request profile")
			w.WriteHeader(403)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverPair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	server.StartTLS()
	t.Cleanup(server.Close)
	cfg := ClientConfig{URL: server.URL, CAFile: caPath, CAFingerprint: hash(ca.Raw), CertificateFile: certPath, KeyFile: keyPath}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client, cfg
}

func executionClientRequest(t *testing.T, node string) helper.Request {
	t.Helper()
	d := "sha256:" + strings.Repeat("1", 64)
	now := time.Now().UTC().Truncate(time.Second)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	r := helper.Request{Task: helper.Task{APIVersion: "agp.task/v1alpha1", ID: "task_one", NodeID: node, Kind: "apply_config", IdempotencyKey: "abcdefghijklmnop", AuthorityEpoch: 1, WriterEpoch: 1, NodeDeploymentSequence: 8, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), PlanID: "plan_one", Preconditions: helper.Preconditions{BaseRevisionID: "base", ExpectedNodeDeploymentSequence: 7, CapabilityDigest: d}, Payload: helper.Payload{TargetRevisionID: "target", DeploymentGeneration: "generation", BundleDigest: d, SecretVersionIDs: []string{}, RecoveryBaseBundleDigest: d}}, Permit: helper.Permit{APIVersion: helper.PermitVersion, KeyID: "permit_key", InstallationDigest: d, IdentityDigest: d, OwnershipDigest: d, ComponentProfileDigest: d, ReleaseManifestDigest: d, TupleDigest: d, CompilerDigest: d, Approval: helper.Approval{SiteID: "site_one", CreatedBy: "author", ApprovedBy: "reviewer", ApprovalDigest: d}, Recovery: helper.Recovery{BaseRevisionID: "base", BaseBundleDigest: d, OwnershipDigest: d}}}
	plan, err := deploymentplan.Sign(deploymentplan.Plan{APIVersion: deploymentplan.Version1, ID: r.Task.PlanID, Kind: r.Task.Kind, SiteID: "site_one", RevisionID: "target", CreatedBy: "author", CreatedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ExpiresAt: now.Add(2 * time.Minute).Format(time.RFC3339Nano), Targets: []deploymentplan.Target{{NodeID: node, BaseRevisionID: "base", ExpectedNodeDeploymentSequence: 7, CapabilityDigest: d, BundleDigest: d, SecretVersionIDs: []string{}, BaseBundleDigest: d}}, RolloutPolicy: deploymentplan.RolloutPolicy{CanaryNodeIDs: []string{node}, MaxParallel: 1, ObservationSeconds: 60, FailureAction: "pause"}, CompilerVersion: "transport-test/1", Reason: "Controlled transport fixture", ResolvedInputs: []deploymentplan.ResolvedInput{{Kind: "component_profile", ID: "profile", Digest: d}}, AuthorityEpoch: 1}, "permit_key", key)
	if err != nil {
		t.Fatal(err)
	}
	r.SignedPlan, r.Task.PlanDigest = plan, plan.Plan.PlanDigest
	r.Permit.TaskDigest, _ = helper.TaskDigest(r.Task)
	digest, _ := configmodel.Digest(r.Permit)
	r.Permit.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte("AGP-HELPER-PERMIT-v1\n"+digest)))
	r.Task.PermitDigest, _ = helper.PermitDigest(r.Permit)
	return r
}

func executionClientQuery() helper.StartQuery {
	d := "sha256:" + strings.Repeat("1", 64)
	return helper.StartQuery{APIVersion: helper.StartVersion, Challenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), RequestDigest: d, InstallationDigest: d, Head: helper.HeadPin{AuthorityID: "journal_one", Epoch: 1}}
}

func executionClientProof(q helper.StartQuery) helper.StartProof {
	now := time.Now().UTC().Truncate(time.Second)
	return helper.StartProof{Query: q, KeyID: "control_key", WriterEpoch: 1, CheckedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Second).Format(time.RFC3339Nano), Signature: base64.RawURLEncoding.EncodeToString(make([]byte, 64))}
}

func executionClientReceipt() helper.ExecutionReceipt {
	return helper.ExecutionReceipt{APIVersion: helper.ExecutionReceiptVersion, Purpose: "local_execution_outcome", ReceiptID: "receipt_one", NodeID: "node_one", TaskID: "task_one", RequestDigest: "sha256:" + strings.Repeat("1", 64), KeyID: "root_receipt", Signature: base64.RawURLEncoding.EncodeToString(make([]byte, 64))}
}

func executionClientBaselineChallenge() helper.BaselineChallenge {
	now := time.Now().UTC().Truncate(time.Second)
	return helper.BaselineChallenge{APIVersion: helper.BaselineChallengeVersion, ID: "baseline_challenge", Challenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), NodeID: "node_one", AnchorDigest: "sha256:" + strings.Repeat("1", 64), AuthorityID: "journal_one", AuthorityEpoch: 1, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)}
}

func TestExecutionClientBaselineCaptureTransport(t *testing.T) {
	query := executionClientBaselineChallenge()
	capture := helper.BaselineCapture{APIVersion: helper.BaselineCaptureVersion, Purpose: "verified_baseline_capture", Query: query, KeyID: "root_receipt", Signature: base64.RawURLEncoding.EncodeToString(make([]byte, 64))}
	var mu sync.Mutex
	response := query
	var baselineStatus = http.StatusNoContent
	var submitted []helper.BaselineCapture
	client, _ := executionClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/agent/v1/execution/baseline-challenges":
			var in struct{}
			if Decode(r.Body, &in) != nil {
				t.Error("challenge request is not closed empty JSON")
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(response)
		case "/agent/v1/execution/baselines":
			var got helper.BaselineCapture
			if Decode(r.Body, &got) != nil {
				t.Error("capture changed on transport")
			}
			submitted = append(submitted, got)
			w.WriteHeader(baselineStatus)
		default:
			t.Error("unexpected baseline route")
			w.WriteHeader(404)
		}
	}))
	got, err := client.ExecutionBaselineChallenge(context.Background())
	if err != nil || got == nil || *got != query {
		t.Fatalf("challenge binding lost: %#v %v", got, err)
	}
	if err := client.ExecutionCapture(context.Background(), capture); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(submitted) != 1 || !reflect.DeepEqual(submitted[0], capture) {
		t.Error("capture fields changed")
	}
	response.NodeID = "node_foreign"
	mu.Unlock()
	if got, err := client.ExecutionBaselineChallenge(context.Background()); got != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("foreign challenge accepted")
	}
	mu.Lock()
	response = query
	issued, _ := time.Parse(time.RFC3339Nano, query.IssuedAt)
	response.ExpiresAt = issued.Add(3 * time.Minute).Format(time.RFC3339Nano)
	mu.Unlock()
	if got, err := client.ExecutionBaselineChallenge(context.Background()); got != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("excessive challenge TTL accepted")
	}
	mu.Lock()
	baselineStatus = http.StatusOK
	mu.Unlock()
	if err := client.ExecutionCapture(context.Background(), capture); !errors.Is(err, ErrUnavailable) {
		t.Fatal("capture acknowledged without 204")
	}
	capture.Query.NodeID = "node_foreign"
	if err := client.ExecutionCapture(context.Background(), capture); !errors.Is(err, ErrInvalid) {
		t.Fatal("foreign capture submitted")
	}
}

func TestExecutionClientRealMTLSAndExactDelivery(t *testing.T) {
	request := executionClientRequest(t, "node_one")
	query := executionClientQuery()
	proof := executionClientProof(query)
	receipt := executionClientReceipt()
	var mu sync.Mutex
	var deliveries [][]byte
	client, cfg := executionClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		switch r.URL.Path {
		case "/agent/v1/execution/tasks":
			var in struct{}
			if Decode(r.Body, &in) != nil {
				t.Error("pending request is not an empty closed document")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []helper.Request{request}})
		case "/agent/v1/execution/start-proofs":
			var got helper.StartQuery
			if Decode(r.Body, &got) != nil || got != query {
				t.Error("start challenge changed")
			}
			_ = json.NewEncoder(w).Encode(proof)
		case "/agent/v1/execution/receipts":
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			deliveries = append(deliveries, body)
			first := len(deliveries) == 1
			mu.Unlock()
			if first {
				// The control plane committed the receipt, but the reply was lost.
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_ = conn.Close()
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("caller selected unexpected path: %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	items, err := client.ExecutionPending(context.Background())
	if err != nil || len(items) != 1 || !reflect.DeepEqual(items[0], request) {
		t.Fatalf("pending binding lost: %#v %v", items, err)
	}
	raw, err := client.ExecutionAuthorize(context.Background(), query)
	var got helper.StartProof
	if err != nil || json.Unmarshal(raw, &got) != nil || got != proof {
		t.Fatalf("proof binding lost: %s %v", raw, err)
	}
	if err := client.ExecutionRecord(context.Background(), receipt); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("lost reply acknowledged: %v", err)
	}
	if err := client.ExecutionRecord(context.Background(), receipt); err != nil {
		t.Fatalf("exact receipt retry rejected: %v", err)
	}
	mu.Lock()
	if len(deliveries) != 2 || !bytes.Equal(deliveries[0], deliveries[1]) {
		t.Error("delivery retry changed immutable receipt")
	}
	mu.Unlock()
	cfg.CAFingerprint = "sha256:" + strings.Repeat("0", 64)
	if _, err := NewClient(cfg); !errors.Is(err, ErrIdentity) {
		t.Fatalf("wrong CA pin accepted: %v", err)
	}
}

func TestExecutionClientRejectsMalformedResponses(t *testing.T) {
	request := executionClientRequest(t, "node_one")
	foreign := executionClientRequest(t, "node_foreign")
	encode := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	valid := encode(map[string]any{"items": []helper.Request{request}})
	query := executionClientQuery()
	wrongProof := executionClientProof(query)
	wrongProof.Query.Challenge = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	longProof := executionClientProof(query)
	checked, _ := time.Parse(time.RFC3339Nano, longProof.CheckedAt)
	longProof.ExpiresAt = checked.Add(time.Minute).Format(time.RFC3339Nano)
	var mu sync.Mutex
	content, payload, status := "application/json", `{"items":[]}`, http.StatusOK
	client, _ := executionClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", content)
		if status == http.StatusTemporaryRedirect {
			w.Header().Set("Location", "/must-never-follow")
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, payload)
	}))
	set := func(c, p string, s int) { mu.Lock(); content, payload, status = c, p, s; mu.Unlock() }
	for _, tc := range []struct {
		name, body, content string
		status              int
	}{
		{"wrong_node", encode(map[string]any{"items": []helper.Request{foreign}}), "application/json", 200},
		{"multiple_tasks", encode(map[string]any{"items": []helper.Request{request, request}}), "application/json", 200},
		{"missing_items", `{}`, "application/json", 200},
		{"null_items", `{"items":null}`, "application/json", 200},
		{"unknown_field", `{"items":[],"secret":"private"}`, "application/json", 200},
		{"duplicate_field", `{"items":[],"items":[]}`, "application/json", 200},
		{"nested_duplicate", strings.Replace(valid, `"nodeId":"node_one"`, `"nodeId":"node_one","nodeId":"node_foreign"`, 1), "application/json", 200},
		{"signed_plan_presence", strings.Replace(valid, `"plan":{"apiVersion":`, `"plan":{"capacityProfile":"","apiVersion":`, 1), "application/json", 200},
		{"trailing_document", valid + `{}`, "application/json", 200},
		{"oversized", strings.Repeat(" ", executionResponseLimit+1), "application/json", 200},
		{"wrong_content_type", valid, "text/plain", 200},
		{"wrong_charset", valid, "application/json; charset=iso-8859-1", 200},
		{"wrong_status", valid, "application/json", 201},
		{"redirect", valid, "application/json", 307},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set(tc.content, tc.body, tc.status)
			if got, err := client.ExecutionPending(context.Background()); err == nil || got != nil {
				t.Fatalf("malformed pending accepted: %#v %v", got, err)
			}
		})
	}
	for _, tc := range []struct{ name, body string }{
		{"wrong_query", encode(wrongProof)},
		{"long_interval", encode(longProof)},
		{"unknown_proof_field", strings.TrimSuffix(encode(executionClientProof(query)), "}") + `,"token":"secret"}`},
		{"duplicate_proof_field", strings.TrimSuffix(encode(executionClientProof(query)), "}") + `,"keyId":"control_key"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set("application/json", tc.body, 200)
			if got, err := client.ExecutionAuthorize(context.Background(), query); err == nil || got != nil {
				t.Fatal("malformed proof accepted")
			}
		})
	}
	for _, code := range []int{200, 201, 202, 400} {
		set("application/json", `{}`, code)
		if err := client.ExecutionRecord(context.Background(), executionClientReceipt()); err == nil {
			t.Fatalf("receipt acknowledged status %d", code)
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.ExecutionPending(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

type executionRoundTripFunc func(*http.Request) (*http.Response, error)

func (f executionRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestExecutionReceiptRequiresEmpty204(t *testing.T) {
	for _, response := range []*http.Response{
		{StatusCode: 204, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{}"))},
		{StatusCode: 204, Header: http.Header{"Content-Length": []string{"2"}}, Body: http.NoBody},
		{StatusCode: 204, Header: http.Header{}, TransferEncoding: []string{"chunked"}, Body: http.NoBody},
	} {
		client := &Client{http: &http.Client{Transport: executionRoundTripFunc(func(*http.Request) (*http.Response, error) { return response, nil })}, base: "https://installed.invalid", node: "node_one"}
		if err := client.ExecutionRecord(context.Background(), executionClientReceipt()); !errors.Is(err, ErrInvalid) {
			t.Fatalf("nonempty 204 acknowledged: %v", err)
		}
	}
}
