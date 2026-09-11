package serving

// Open-DANI public admission control (OPEN-DANI-LAUNCH.md §Admission). Per-IP rate limiting is the
// wrong tool behind NAT — shared-IP users throttle each other while an attacker rotates IPs cheaply.
// So the public gateway prices each request in CPU via a PROOF-OF-WORK the client attaches per
// request (NAT-agnostic, IP-rotation-proof), plus a content-moderation gate. Both are Open-DANI-only
// (nil unless enabled) and sit in front of the normal per-IP limiter, which stays as a cheap
// complementary signal.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"dani.local/agent/internal/openid"
)

type powConfig struct {
	bits      int
	windowSec int64
}

// moderationConfig gates prompts/outputs. deny is the always-on floor; fn is an optional pluggable
// classifier (returns a non-empty reason to refuse).
type moderationConfig struct {
	deny []string
	fn   func(text string) (reason string, blocked bool)
}

// EnableRequestPoW turns on NAT-agnostic per-request proof-of-work admission (Open-DANI).
func (p *Plane) EnableRequestPoW(bits int, windowSec int64) {
	if bits <= 0 {
		bits = 16
	}
	if windowSec <= 0 {
		windowSec = 30
	}
	p.mu.Lock()
	p.pow = &powConfig{bits: bits, windowSec: windowSec}
	p.mu.Unlock()
}

// EnableModeration turns on the content gate. denylist terms are matched case-insensitively; fn is
// an optional classifier hook (nil = denylist only).
func (p *Plane) EnableModeration(denylist []string, fn func(string) (string, bool)) {
	low := make([]string, 0, len(denylist))
	for _, d := range denylist {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			low = append(low, d)
		}
	}
	p.mu.Lock()
	p.moderation = &moderationConfig{deny: low, fn: fn}
	p.mu.Unlock()
}

// admitRequest enforces PoW + moderation. Returns true to proceed; on refusal it writes the response
// (429 with a solvable challenge, or 403) and returns false.
func (p *Plane) admitRequest(rw http.ResponseWriter, r *http.Request, body []byte) bool {
	p.mu.RLock()
	pow, mod := p.pow, p.moderation
	p.mu.RUnlock()

	if pow != nil && !p.checkPoW(rw, r, body, pow) {
		return false
	}
	if mod != nil {
		if reason, blocked := mod.check(promptOf(body)); blocked {
			if p.metrics != nil {
				p.metrics.edgeRefused.Inc("moderation")
			}
			http.Error(rw, "request refused by content policy: "+reason, http.StatusForbidden)
			return false
		}
	}
	return true
}

// checkPoW validates the X-Dani-PoW header ("bucket.nonce") against the body hash + difficulty,
// accepting the current or previous time window (clock-skew tolerance). On failure it emits a
// 429 carrying the challenge parameters so a client can solve and retry.
func (p *Plane) checkPoW(rw http.ResponseWriter, r *http.Request, body []byte, pow *powConfig) bool {
	now := timeNow().Unix()
	cur := openid.TimeBucket(now, pow.windowSec)
	bh := openid.BodyHash(body)
	if hdr := r.Header.Get("X-Dani-PoW"); hdr != "" {
		if bucket, nonce, ok := parsePoW(hdr); ok && (bucket == cur || bucket == cur-1) {
			if openid.VerifyRequest(bucket, bh, nonce, pow.bits) {
				return true
			}
		}
	}
	if p.metrics != nil {
		p.metrics.edgeRefused.Inc("pow")
	}
	rw.Header().Set("X-Dani-PoW-Bits", strconv.Itoa(pow.bits))
	rw.Header().Set("X-Dani-PoW-Bucket", strconv.FormatInt(cur, 10))
	rw.Header().Set("X-Dani-PoW-Window", strconv.FormatInt(pow.windowSec, 10))
	rw.Header().Set("Retry-After", "1")
	http.Error(rw, "proof-of-work required: solve sha256(bucket||sha256(body)||nonce) with the given leading-zero bits and resend as 'X-Dani-PoW: bucket.nonce'", http.StatusTooManyRequests)
	return false
}

func parsePoW(hdr string) (bucket int64, nonce uint64, ok bool) {
	dot := strings.IndexByte(hdr, '.')
	if dot <= 0 {
		return 0, 0, false
	}
	b, err1 := strconv.ParseInt(hdr[:dot], 10, 64)
	n, err2 := strconv.ParseUint(hdr[dot+1:], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return b, n, true
}

func (m *moderationConfig) check(text string) (string, bool) {
	low := strings.ToLower(text)
	for _, d := range m.deny {
		if strings.Contains(low, d) {
			return "blocked term", true
		}
	}
	if m.fn != nil {
		if reason, blocked := m.fn(text); blocked {
			return reason, true
		}
	}
	return "", false
}

// promptOf pulls the last user message out of an OpenAI chat body (best-effort; "" if not found).
func promptOf(body []byte) string {
	var req struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if json.Unmarshal(body, &req) != nil {
		return ""
	}
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" {
			return req.Messages[i].Content
		}
	}
	return ""
}
