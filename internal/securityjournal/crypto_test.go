package securityjournal

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func fixtureRequest(t *testing.T, head Head, kind string) AppendRequest {
	t.Helper()
	id, e := randomID("op_")
	if e != nil {
		t.Fatal(e)
	}
	return AppendRequest{OperationID: id, ExpectedEpoch: head.Epoch, ExpectedSequence: head.Sequence, ExpectedDigest: head.Digest, Kind: kind, TargetType: "principal", TargetID: "usr_test", ActorID: "usr_admin", AuthorizationDigest: "sha256:" + strings.Repeat("a", 64), RecordedAt: time.Now().UTC(), Payload: Payload{PrincipalID: "usr_test"}}
}
func TestUInt63Wire(t *testing.T) {
	for _, s := range []string{`0`, `1`, `"01"`, `"-1"`, `"9223372036854775808"`, `"1.0"`, `null`, `"+1"`} {
		var v UInt63
		if json.Unmarshal([]byte(s), &v) == nil {
			t.Errorf("accepted %s", s)
		}
	}
	for _, v := range []UInt63{0, 1, 9007199254740993, MaxUInt63} {
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		var actual UInt63
		if e = json.Unmarshal(b, &actual); e != nil || actual != v {
			t.Fatalf("lost value: %s", b)
		}
	}
}
func TestSignedHeadChallengeAndFreshness(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	h := Head{AuthorityID: "test", Epoch: 1, Challenge: "fresh", RecordedAt: now, KeyID: "signer"}
	if e := signHead(&h, key); e != nil {
		t.Fatal(e)
	}
	if e := VerifyHead(h, "fresh", "test", "signer", pub, now); e != nil {
		t.Fatal(e)
	}
	for _, test := range []struct {
		name      string
		h         Head
		challenge string
		now       time.Time
	}{{"replayed challenge", h, "other", now}, {"stale", h, "fresh", now.Add(time.Minute)}, {"future", h, "fresh", now.Add(-time.Minute)}} {
		t.Run(test.name, func(t *testing.T) {
			if VerifyHead(test.h, test.challenge, "test", "signer", pub, test.now) == nil {
				t.Fatal("invalid signed head accepted")
			}
		})
	}
	h.Epoch = 2
	if VerifyHead(h, "fresh", "test", "signer", pub, now) == nil {
		t.Fatal("tampered head accepted")
	}
}
func TestTypedEventsAndSignatures(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	r := fixtureRequest(t, Head{Epoch: 1}, "block_principal")
	if e := validateRequest(r); e != nil {
		t.Fatal(e)
	}
	rd, _ := RequestDigest(r)
	e := Event{AuthorityID: "test", ID: "evt_test", Epoch: 1, Sequence: 1, Request: r, RequestDigest: rd, RecordedAt: time.Now().UTC(), KeyID: "signer"}
	if err := signEvent(&e, key); err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvent(e, "test", "signer", pub); err != nil {
		t.Fatal(err)
	}
	e.Request.Payload.PrincipalID = "other"
	if VerifyEvent(e, "test", "signer", pub) == nil {
		t.Fatal("tampered receipt accepted")
	}
	r.Payload.SessionID = "extra"
	if validateRequest(r) == nil {
		t.Fatal("ambiguous union accepted")
	}
	r.Payload.SessionID = ""
	r.Kind = "grant_admin"
	if validateRequest(r) == nil {
		t.Fatal("positive grant accepted")
	}
}
