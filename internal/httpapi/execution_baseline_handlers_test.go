package httpapi

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/netwizd/agp/internal/config"
	"github.com/netwizd/agp/internal/executionsources"
	"github.com/netwizd/agp/internal/helper"
	"github.com/netwizd/agp/internal/inventory"
)

type baselineRouteSource struct {
	calls   int
	peer    *tls.ConnectionState
	err     error
	capture helper.BaselineCapture
}

func (b *baselineRouteSource) ChallengePeer(_ context.Context, p *tls.ConnectionState) (*helper.BaselineChallenge, error) {
	b.calls++
	b.peer = p
	return &helper.BaselineChallenge{ID: "challenge_one"}, b.err
}
func (b *baselineRouteSource) CapturePeer(_ context.Context, p *tls.ConnectionState, c helper.BaselineCapture) error {
	b.calls++
	b.peer = p
	b.capture = c
	return b.err
}

// Transport binding only: cryptographic identity and baseline admission are
// separately tested by inventory and executionsources on SQLite/PostgreSQL.
func TestExecutionBaselineHTTPTransport(t *testing.T) {
	s := NewServer(config.Config{SecureProfile: true, ConfigurationEnabled: true}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetInventory(new(inventory.Service))
	source := &baselineRouteSource{}
	s.SetExecutionBaselines(source)
	peer := &tls.ConnectionState{}
	request := func(path, body, header string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://agent.test/agent/v1/execution/"+path, strings.NewReader(body))
		r.TLS = peer
		r.Header.Set("Content-Type", "application/json")
		if header != "" {
			r.Header.Set(header, "forbidden")
		}
		w := httptest.NewRecorder()
		s.AgentHandler().ServeHTTP(w, r)
		return w
	}
	if w := request("baseline-challenges", `{}`, ""); w.Code != 201 || source.calls != 1 || source.peer != peer {
		t.Fatal("actual TLS state not passed", w.Code, w.Body.String())
	}
	if w := request("baselines", `{"signature":"signed_result"}`, ""); w.Code != 204 || w.Body.Len() != 0 || source.capture.Signature != "signed_result" {
		t.Fatal("capture acknowledgement", w.Code, w.Body.String())
	}
	for _, tc := range []struct{ path, body, header string }{{"baseline-challenges", `{"nodeId":"chosen_node"}`, ""}, {"baseline-challenges", `{"x":1,"x":2}`, ""}, {"baseline-challenges", `{}`, "Origin"}, {"baselines", `{}`, "Cookie"}, {"baselines?nodeId=other", `{}`, ""}, {"baselines", `{"unknown":true}`, ""}} {
		before := source.calls
		if w := request(tc.path, tc.body, tc.header); w.Code < 400 || source.calls != before {
			t.Fatal("invalid agent transport reached source", tc, w.Code)
		}
	}
	source.err = executionsources.ErrCapture
	if w := request("baselines", `{}`, ""); w.Code != 409 {
		t.Fatal("stale capture status", w.Code)
	}
	source.err = errors.New("private path should not escape")
	if w := request("baselines", `{}`, ""); w.Code < 400 || strings.Contains(w.Body.String(), "private path") {
		t.Fatal("raw error exposed", w.Code, w.Body.String())
	}
	s.SetExecutionBaselines(nil)
	if w := request("baseline-challenges", `{}`, ""); w.Code != 503 {
		t.Fatal("default runtime did not fail closed", w.Code)
	}
	for _, path := range []string{"baseline-challenges", "baselines"} {
		r := httptest.NewRequest("POST", "https://management.test/agent/v1/execution/"+path, strings.NewReader(`{}`))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code < 400 {
			t.Fatal("browser listener exposed baseline endpoint", path)
		}
	}
}
