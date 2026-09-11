package serving

// P2-2 parser fuzzing: VerifyRevocationList consumes a network-supplied JSON document — a hostile
// controller-impersonator must not be able to crash a node with a crafted CRL. And the heartbeat
// decoder is the Link's front door.

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"dani.local/agent/internal/ca"
	"dani.local/agent/internal/kms"
)

func FuzzVerifyRevocationList(f *testing.F) {
	f.Add(`{"seq":1,"revoked":["a"],"issuedBy":"ctrl","sig":"aGk=","chain":["aGk="]}`)
	f.Add(`{"seq":-1,"revoked":null,"sig":"","chain":[]}`)
	f.Add(`{"chain":["%%%"]}`)
	f.Add(`{}`)
	f.Add(`{"seq":9223372036854775807,"revoked":["` + strings.Repeat("x", 500) + `"]}`)
	f.Fuzz(func(t *testing.T, doc string) {
		var rl RevocationList
		if json.Unmarshal([]byte(doc), &rl) != nil {
			return
		}
		auth := fuzzAuthority(t)
		set, err := VerifyRevocationList(rl, auth)
		if err == nil && set == nil {
			t.Fatal("verify returned ok with a nil set")
		}
		// fuzzed docs are never signed by our CA — they must ALL be rejected
		if err == nil {
			t.Fatalf("unsigned fuzz doc verified: %q", doc)
		}
	})
}

// fuzzAuthority caches one CA root per fuzz process (a genesis ceremony per exec would dominate).
var (
	fuzzOnce   sync.Once
	fuzzCARoot *x509.Certificate
)

func fuzzAuthority(t *testing.T) *x509.Certificate {
	t.Helper()
	fuzzOnce.Do(func() {
		ks, err := kms.NewSoftware()
		if err != nil {
			return
		}
		if a, err := ca.Genesis(context.Background(), ks, "FuzzOrg"); err == nil {
			fuzzCARoot = a.Root
		}
	})
	if fuzzCARoot == nil {
		t.Skip("ca genesis unavailable")
	}
	return fuzzCARoot
}

func FuzzHeartbeatDecode(f *testing.F) {
	f.Add(`{"node_uuid":"w1","dispatch_addr":"1.2.3.4:9443","health":"healthy","max_concurrent":4}`)
	f.Add(`{"node_uuid":""}`)
	f.Add(`{"loaded":["a","b"],"queued":-5,"ema_service_ms":9999999999}`)
	f.Add(`[]`)
	f.Add(`{"max_concurrent":"four"}`)
	f.Fuzz(func(t *testing.T, body string) {
		p := &Plane{workers: map[string]*workerState{}, inflight: map[string]int{},
			drained: map[string]bool{}, revoked: map[string]bool{}, stale: time.Minute}
		req := httptest.NewRequest("POST", "/link/heartbeat", strings.NewReader(body))
		rec := httptest.NewRecorder()
		p.handleHeartbeat(rec, req) // must never panic; bad bodies 400
		if rec.Code != 204 && rec.Code != 400 && rec.Code != 403 {
			t.Fatalf("unexpected status %d for %q", rec.Code, body)
		}
	})
}
