package serving

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"dani.local/agent/internal/openid"
)

func admitPlane(t *testing.T) *Plane {
	t.Helper()
	return &Plane{workers: map[string]*workerState{}, inflight: map[string]int{}, drained: map[string]bool{},
		revoked: map[string]bool{}, stale: time.Minute}
}

func TestParsePoW(t *testing.T) {
	if b, n, ok := parsePoW("42.1000"); !ok || b != 42 || n != 1000 {
		t.Fatalf("parse: %d %d %v", b, n, ok)
	}
	for _, bad := range []string{"", "nodot", "42.", ".5", "x.5", "42.y"} {
		if _, _, ok := parsePoW(bad); ok {
			t.Fatalf("%q should not parse", bad)
		}
	}
}

func TestPromptOf(t *testing.T) {
	body := []byte(`{"messages":[{"role":"system","content":"sys"},{"role":"user","content":"the real prompt"}]}`)
	if got := promptOf(body); got != "the real prompt" {
		t.Fatalf("promptOf: %q", got)
	}
	if promptOf([]byte("not json")) != "" {
		t.Fatal("bad json -> empty")
	}
}

func TestModerationGate(t *testing.T) {
	p := admitPlane(t)
	p.EnableModeration([]string{"BadWord", " weapons "}, func(s string) (string, bool) {
		if strings.Contains(s, "classifier-trip") {
			return "classifier", true
		}
		return "", false
	})
	body := func(prompt string) []byte {
		return []byte(`{"messages":[{"role":"user","content":"` + prompt + `"}]}`)
	}
	// clean prompt passes
	rw := httptest.NewRecorder()
	if !p.admitRequest(rw, httptest.NewRequest("POST", "/v1/chat/completions", nil), body("hello there")) {
		t.Fatal("clean prompt must pass")
	}
	// denylist hit (case-insensitive) refused 403
	rw = httptest.NewRecorder()
	if p.admitRequest(rw, httptest.NewRequest("POST", "/", nil), body("contains badword yes")) {
		t.Fatal("denylisted prompt must be refused")
	}
	if rw.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rw.Code)
	}
	// classifier hook hit
	rw = httptest.NewRecorder()
	if p.admitRequest(rw, httptest.NewRequest("POST", "/", nil), body("classifier-trip")) {
		t.Fatal("classifier hook must refuse")
	}
}

// the NAT story: a request with NO proof-of-work is refused with a solvable challenge; solving it
// (bound to THIS body + the current time bucket) lets the request through.
func TestRequestPoWAdmission(t *testing.T) {
	p := admitPlane(t)
	p.EnableRequestPoW(10, 30)
	body := []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`)

	// no header -> 429 with challenge params
	rw := httptest.NewRecorder()
	if p.admitRequest(rw, httptest.NewRequest("POST", "/", nil), body) {
		t.Fatal("missing PoW must be refused")
	}
	if rw.Code != http.StatusTooManyRequests || rw.Header().Get("X-Dani-PoW-Bits") != "10" {
		t.Fatalf("expected 429 + challenge, got %d bits=%q", rw.Code, rw.Header().Get("X-Dani-PoW-Bits"))
	}
	bucket, _ := strconv.ParseInt(rw.Header().Get("X-Dani-PoW-Bucket"), 10, 64)

	// solve it for this body + bucket, resend -> passes
	nonce, ok := openid.SolveRequest(bucket, openid.BodyHash(body), 10, 1<<22)
	if !ok {
		t.Fatal("solve failed")
	}
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("X-Dani-PoW", strconv.FormatInt(bucket, 10)+"."+strconv.FormatUint(nonce, 10))
	rw2 := httptest.NewRecorder()
	if !p.admitRequest(rw2, r, body) {
		t.Fatalf("a solved PoW must pass (code %d)", rw2.Code)
	}

	// the SAME nonce for a DIFFERENT body is rejected (bound to the body — no replay)
	r2 := httptest.NewRequest("POST", "/", nil)
	r2.Header.Set("X-Dani-PoW", strconv.FormatInt(bucket, 10)+"."+strconv.FormatUint(nonce, 10))
	if p.admitRequest(httptest.NewRecorder(), r2, []byte(`{"model":"m","messages":[{"role":"user","content":"DIFFERENT"}]}`)) {
		t.Fatal("a PoW bound to one body must not admit another (replay blocked)")
	}
}

// off by default: no PoW, no moderation -> everything admitted (enterprise unaffected).
func TestAdmissionOffByDefault(t *testing.T) {
	p := admitPlane(t)
	if !p.admitRequest(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil), []byte(`{}`)) {
		t.Fatal("with nothing enabled, all requests are admitted")
	}
}
