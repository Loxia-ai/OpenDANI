// Package policy is the Policy & Governance Engine (Architecture §6.21 #6, §7) — the LIVE,
// per-request authority (DP13/DL-R11-07): cert bearer claims are advisory, but every request is
// checked here against the current policy. Centralizes what was inlined in the request path:
// AuthZ (signed role), content classification, the D-09 flow rule, plus a banned-content scan and
// per-principal rate limiting.
//
// IMPORTANT divergence from the simulator (logged as D-13): the sim stamps
// classification = max(clearance, content) — the F-02 FLOOR that Daniel REJECTED in D-09. This
// engine implements the D-09 decision instead: classification = CONTENT ONLY, and clearance is the
// authorization CEILING (deny if content > clearance), never a floor.
package policy

import (
	"regexp"
	"sync"
	"time"
)

var classRank = map[string]int{"unrestricted": 0, "internal": 1, "restricted": 2, "secret": 3}

func rank(c string) int {
	if r, ok := classRank[c]; ok {
		return r
	}
	return 1 // unknown treated as internal (fail-closed-ish)
}

// keywordClass bumps content classification (stand-in for the D40 detectors). Highest match wins.
var keywordClass = []struct {
	re  *regexp.Regexp
	cls string
}{
	{regexp.MustCompile(`(?i)\b(secret|classified|ts/sci|top.?secret)\b`), "secret"},
	{regexp.MustCompile(`(?i)\b(patient|diagnosis|account number|ssn|teudat|revenue|capital|risk)\b`), "restricted"},
	{regexp.MustCompile(`(?i)\b(internal|confidential|proprietary)\b`), "internal"},
}

// nowFn is a clock seam for the rate limiter (production: time.Now).
var nowFn = time.Now

// Principal is the resolved caller (from the Identity Bridge).
type Principal struct {
	Sub       string
	Clearance string
	Roles     []string
}

// Decision is the engine's verdict for one request.
type Decision struct {
	Allow          bool
	Reason         string // set when !Allow
	Classification string // D-09: content classification (drives routing); "" when denied
	ContentClass   string
}

// Engine is the live policy authority. Zero rate limits (RateMax<=0) disable rate limiting.
type Engine struct {
	mu         sync.Mutex
	rate       map[string][]time.Time
	RateMax    int
	RateWindow time.Duration
	detector   Detector // PII + prompt-injection detection (default PatternDetector; swappable)
}

// New builds a Policy Engine. rateMax<=0 disables rate limiting.
func New(rateMax int, rateWindow time.Duration) *Engine {
	if rateWindow <= 0 {
		rateWindow = time.Minute
	}
	return &Engine{rate: map[string][]time.Time{}, RateMax: rateMax, RateWindow: rateWindow, detector: PatternDetector{}}
}

// WithDetector swaps the PII/injection detector (e.g. a managed service or an LLM classifier).
// Returns the engine for chaining. A nil detector resets to the deterministic PatternDetector.
func (e *Engine) WithDetector(d Detector) *Engine {
	if d == nil {
		d = PatternDetector{}
	}
	e.mu.Lock()
	e.detector = d
	e.mu.Unlock()
	return e
}

// classify returns the content classification: the max of the keyword classifier and any PII the
// detector finds (a credit-card/SSN → restricted, a secret/key → secret, an email/phone/IP → internal).
func (e *Engine) classify(text string) string {
	c := ClassifyContent(text)
	for _, f := range e.detector.Scan(text) {
		if rank(f.Class) > rank(c) {
			c = f.Class
		}
	}
	return c
}

// injected reports whether the detector flags the text as a prompt-injection / jailbreak attempt.
func (e *Engine) injected(text string) bool {
	for _, f := range e.detector.Scan(text) {
		if f.Kind == "injection" {
			return true
		}
	}
	return false
}

// ClassifyContent returns a prompt/response's content classification (highest keyword match).
func ClassifyContent(text string) string {
	c := "unrestricted"
	for _, k := range keywordClass {
		if rank(k.cls) > rank(c) && k.re.MatchString(text) {
			c = k.cls
		}
	}
	return c
}

// CheckPrompt is the §6.17.1-step-4 live gate: AuthZ role, banned-content, rate limit, and the D-09
// flow rule (content classification is the routing label; clearance is the ceiling).
func (e *Engine) CheckPrompt(p Principal, prompt string) Decision {
	if !hasRole(p.Roles, "user") && !hasRole(p.Roles, "admin") {
		return deny("principal lacks a chat role")
	}
	if e.injected(prompt) {
		return deny("prompt flagged as a prompt-injection / policy-bypass attempt")
	}
	if !e.rateOK(p.Sub) {
		return deny("rate limit exceeded")
	}
	content := e.classify(prompt)
	if rank(content) > rank(p.Clearance) {
		return deny("prompt content is " + content + ", above " + p.Sub + "'s clearance " + p.Clearance + " (D-09 ceiling)")
	}
	return Decision{Allow: true, Classification: content, ContentClass: content}
}

// LabelResponse classifies a response = max(prompt classification, response content) — a response
// can only be MORE sensitive than the prompt, never less (§6.17.1 step 10).
func (e *Engine) LabelResponse(promptClass, responseText string) string {
	rc := e.classify(responseText)
	if rank(rc) > rank(promptClass) {
		return rc
	}
	return promptClass
}

// rateOK records a hit for sub and reports whether it is within the window budget.
// SetRate live-updates the per-principal quota (config store key policy.rate-max, P2-1).
func (e *Engine) SetRate(max int) {
	e.mu.Lock()
	e.RateMax = max
	e.mu.Unlock()
}

func (e *Engine) rateOK(sub string) bool {
	now := nowFn()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.RateMax <= 0 {
		return true
	}
	var kept []time.Time
	for _, t := range e.rate[sub] {
		if now.Sub(t) < e.RateWindow {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	e.rate[sub] = kept
	return len(kept) <= e.RateMax
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

func deny(reason string) Decision { return Decision{Allow: false, Reason: reason} }
