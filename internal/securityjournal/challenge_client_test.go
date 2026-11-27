package securityjournal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestHeadWithChallengePreservesCallerNonceOverMTLS(t *testing.T) {
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	serverTLS, clientTLS := testPKI(t)
	var wrong atomic.Bool
	observed := make(chan string, 4)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			t.Error("mTLS peer missing")
			w.WriteHeader(403)
			return
		}
		nonce := r.URL.Query().Get("challenge")
		observed <- nonce
		if wrong.Load() {
			nonce = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		}
		h := Head{AuthorityID: "journal_one", KeyID: "journal_key", Epoch: 1, Challenge: nonce, RecordedAt: time.Now().UTC()}
		if err := signHead(&h, key); err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(h)
	}))
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()
	c, err := NewClient(ClientConfig{URL: server.URL, AuthorityID: "journal_one", KeyID: "journal_key", PublicKey: public, TLSConfig: clientTLS})
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseIdleConnections()
	bytes := make([]byte, 32)
	rand.Read(bytes)
	nonce := base64.RawURLEncoding.EncodeToString(bytes)
	h, err := c.HeadWithChallenge(context.Background(), nonce)
	if err != nil || h.Challenge != nonce || <-observed != nonce {
		t.Fatal("caller challenge replaced", err)
	}
	wrong.Store(true)
	if _, err = c.HeadWithChallenge(context.Background(), nonce); err == nil {
		t.Fatal("valid signature for another challenge accepted")
	}
	<-observed
	for _, bad := range []string{"", nonce + "=", "not_a_32_byte_nonce"} {
		if _, err = c.HeadWithChallenge(context.Background(), bad); err == nil {
			t.Fatal("invalid caller nonce admitted")
		}
	}
	select {
	case <-observed:
		t.Fatal("invalid nonce reached journal")
	default:
	}
	pin := c.SigningPublicKey()
	pin[0] ^= 1
	if c.SigningPublicKey()[0] != public[0] {
		t.Fatal("public key accessor exposed mutable trust")
	}
}
