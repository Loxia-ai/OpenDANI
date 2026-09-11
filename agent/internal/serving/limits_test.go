package serving

// P2-1 tests: body caps (Content-Length 413 + chunked MaxBytesReader backstop), the per-IP token
// bucket (limit, refill, isolation between IPs, GC), live re-configuration, and the edge metrics.

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func limitsPlane(t *testing.T) *Plane {
	t.Helper()
	p := &Plane{workers: map[string]*workerState{}, inflight: map[string]int{}, stale: time.Minute, limits: newLimits()}
	return p
}

// echoOK reads the whole body; a MaxBytesReader overrun surfaces as a read error -> 400.
func echoOK() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(rw, "body too large", http.StatusBadRequest)
			return
		}
		rw.WriteHeader(http.StatusOK)
	})
}

func TestBodyCap(t *testing.T) {
	p := limitsPlane(t)
	p.EnableMetrics()
	p.ApplyGatewayConfig(map[string]string{"gateway.max-body-bytes": "1024"})
	h := p.limitsHandler(echoOK())

	// small body passes
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader("small"))
	req.RemoteAddr = "10.0.0.1:1"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("small body: %d", rec.Code)
	}
	// Content-Length over the cap -> clean 413 before reading
	big := strings.Repeat("x", 2048)
	req = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(big))
	req.RemoteAddr = "10.0.0.1:1"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize body: %d (want 413)", rec.Code)
	}
	// chunked (unknown length) oversize -> MaxBytesReader backstop stops the read
	req = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(big))
	req.ContentLength = -1 // chunked
	req.RemoteAddr = "10.0.0.1:1"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("chunked oversize: %d (want 400 from the read backstop)", rec.Code)
	}
	// GET is never body-capped
	req = httptest.NewRequest(http.MethodGet, "/dani/fleet", nil)
	req.RemoteAddr = "10.0.0.1:1"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: %d", rec.Code)
	}
	if p.metrics.edgeRefused.Value("body") != 1 {
		t.Fatalf("edge metric body: %v", p.metrics.edgeRefused.Value("body"))
	}
}

func TestPerIPRateLimit(t *testing.T) {
	p := limitsPlane(t)
	p.EnableMetrics()
	now := time.Now()
	p.limits.nowFn = func() time.Time { return now }
	p.ApplyGatewayConfig(map[string]string{"gateway.rate-per-ip": "3"})
	h := p.limitsHandler(echoOK())
	hit := func(ip string) int {
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		req.RemoteAddr = ip + ":12345"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 0; i < 3; i++ {
		if c := hit("10.0.0.7"); c != http.StatusOK {
			t.Fatalf("request %d refused early: %d", i, c)
		}
	}
	// 4th from the same IP -> 429 with Retry-After
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.RemoteAddr = "10.0.0.7:12345"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("4th request: %d retry=%q", rec.Code, rec.Header().Get("Retry-After"))
	}
	// a DIFFERENT client is unaffected
	if c := hit("10.0.0.8"); c != http.StatusOK {
		t.Fatalf("other IP refused: %d", c)
	}
	// tokens refill with time
	now = now.Add(time.Minute)
	if c := hit("10.0.0.7"); c != http.StatusOK {
		t.Fatalf("post-refill refused: %d", c)
	}
	// live re-config to off restores service instantly
	p.ApplyGatewayConfig(map[string]string{"gateway.rate-per-ip": "0"})
	for i := 0; i < 10; i++ {
		if c := hit("10.0.0.7"); c != http.StatusOK {
			t.Fatalf("limiter off but refused: %d", c)
		}
	}
	if p.metrics.edgeRefused.Value("rate") != 1 {
		t.Fatalf("edge metric rate: %v", p.metrics.edgeRefused.Value("rate"))
	}
}

func TestBucketGCAndClientIP(t *testing.T) {
	p := limitsPlane(t)
	now := time.Now()
	p.limits.nowFn = func() time.Time { return now }
	p.ApplyGatewayConfig(map[string]string{"gateway.rate-per-ip": "100"})
	for i := 0; i < 5000; i++ {
		p.limits.allow(fmt.Sprintf("10.%d.%d.%d", i/65536, i/256%256, i%256))
	}
	// idle past the refill horizon -> the next allow() sweeps them all
	now = now.Add(2 * time.Minute)
	p.limits.allow("10.99.99.99")
	p.limits.mu.Lock()
	n := len(p.limits.buckets)
	p.limits.mu.Unlock()
	if n > 2 {
		t.Fatalf("bucket GC never ran: %d buckets", n)
	}
	// clientIP: host:port and bare forms
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.168.1.5:9999"
	if clientIP(r) != "192.168.1.5" {
		t.Fatalf("clientIP host:port: %q", clientIP(r))
	}
	r.RemoteAddr = "no-port-here"
	if clientIP(r) != "no-port-here" {
		t.Fatalf("clientIP bare: %q", clientIP(r))
	}
}

func TestApplyGatewayConfigGuards(t *testing.T) {
	p := limitsPlane(t)
	p.ApplyGatewayConfig(map[string]string{
		"gateway.max-body-bytes": "banana", // ignored
		"gateway.rate-per-ip":    "-3",     // ignored
	})
	if got := p.limits.maxBodyBytes; got != defaultMaxBodyBytes {
		t.Fatalf("junk body cap applied: %d", got)
	}
	if got := p.limits.ratePerMin; got != 0 {
		t.Fatalf("junk rate applied: %d", got)
	}
	// absent keys leave state untouched
	p.ApplyGatewayConfig(map[string]string{"gateway.max-body-bytes": "8192"})
	p.ApplyGatewayConfig(map[string]string{})
	if p.limits.maxBodyBytes != 8192 {
		t.Fatalf("absent key reset the cap: %d", p.limits.maxBodyBytes)
	}
}
