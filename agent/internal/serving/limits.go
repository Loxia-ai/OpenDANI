package serving

// Edge protection (PRODUCTION-READINESS P2-1): the public gateway gets request-BODY CAPS (a client
// cannot stream an unbounded body into JSON decoders — 413 with a clear message) and an optional
// per-IP token-bucket RATE LIMIT (pre-auth abuse control for the login + API surface — 429 with
// Retry-After). Both knobs are governed by the §6.20 config store and LIVE-APPLIED: an operator can
// tighten the edge during an incident without restarting anything.
//
//	gateway.max-body-bytes  int, default 10 MiB  (4 KiB .. 1 GiB)
//	gateway.rate-per-ip     requests/min per client IP, default 0 = off
//
// The per-PRINCIPAL quota (policy.rate-max) stays in the Policy Engine — that is the tenant quota;
// this is the network edge in front of it.

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const defaultMaxBodyBytes = 10 << 20 // 10 MiB

// limitsState is the gateway's live edge-protection state.
type limitsState struct {
	maxBodyBytes int64 // atomic
	ratePerMin   int64 // atomic; 0 = off

	mu      sync.Mutex
	buckets map[string]*ipBucket
	nowFn   func() time.Time // test seam
}

type ipBucket struct {
	tokens float64
	last   time.Time
}

func newLimits() *limitsState {
	return &limitsState{maxBodyBytes: defaultMaxBodyBytes, buckets: map[string]*ipBucket{}, nowFn: time.Now}
}

// allow implements a token bucket per client IP: capacity = ratePerMin, refill = ratePerMin/minute.
// Returns ok plus a suggested retry delay when refused.
func (l *limitsState) allow(ip string) (bool, time.Duration) {
	rate := atomic.LoadInt64(&l.ratePerMin)
	if rate <= 0 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.nowFn()
	b, ok := l.buckets[ip]
	if !ok {
		b = &ipBucket{tokens: float64(rate), last: now}
		l.buckets[ip] = b
	}
	// refill
	b.tokens += now.Sub(b.last).Minutes() * float64(rate)
	if b.tokens > float64(rate) {
		b.tokens = float64(rate)
	}
	b.last = now
	// opportunistic GC: a bucket idle past the refill horizon (1 minute) is fully refilled and
	// therefore indistinguishable from an absent one — safe to drop.
	if len(l.buckets) > 4096 {
		for k, v := range l.buckets {
			if now.Sub(v.last) > time.Minute && k != ip {
				delete(l.buckets, k)
			}
		}
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	retry := time.Duration((1 - b.tokens) / float64(rate) * float64(time.Minute))
	if retry < time.Second {
		retry = time.Second
	}
	return false, retry
}

// clientIP extracts the remote IP (the direct peer — DANI terminates its own TLS, so there is no
// trusted proxy header by default; behind an ingress the operator disables this limiter and uses
// the ingress's own).
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// limitsHandler wraps the gateway with both protections. The body cap uses a Content-Length
// pre-check (clean 413 before reading) plus MaxBytesReader as the backstop for chunked bodies —
// a decoder mid-handler then errors instead of buffering without bound.
func (p *Plane) limitsHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if ok, retry := p.limits.allow(clientIP(r)); !ok {
			if p.metrics != nil {
				p.metrics.edgeRefused.Inc("rate")
			}
			rw.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds()+0.5)))
			http.Error(rw, "rate limit exceeded for this client address", http.StatusTooManyRequests)
			return
		}
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			max := atomic.LoadInt64(&p.limits.maxBodyBytes)
			if max > 0 {
				if r.ContentLength > max {
					if p.metrics != nil {
						p.metrics.edgeRefused.Inc("body")
					}
					http.Error(rw, fmt.Sprintf("request body %d bytes exceeds the %d-byte limit (gateway.max-body-bytes)", r.ContentLength, max), http.StatusRequestEntityTooLarge)
					return
				}
				r.Body = http.MaxBytesReader(rw, r.Body, max)
			}
		}
		next.ServeHTTP(rw, r)
	})
}

// ApplyGatewayConfig live-applies the edge keys from an effective config map (controller watcher).
func (p *Plane) ApplyGatewayConfig(eff map[string]string) {
	if v, ok := eff["gateway.max-body-bytes"]; ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			if n != atomic.SwapInt64(&p.limits.maxBodyBytes, n) {
				log.Printf("gateway: config applied gateway.max-body-bytes=%d", n)
			}
		}
	}
	if v, ok := eff["gateway.rate-per-ip"]; ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			if n != atomic.SwapInt64(&p.limits.ratePerMin, n) {
				log.Printf("gateway: config applied gateway.rate-per-ip=%d/min", n)
			}
		}
	}
}
