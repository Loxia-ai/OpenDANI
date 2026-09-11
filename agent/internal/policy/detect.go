package policy

// Real PII + prompt-injection detection (ROADMAP §3 — replaces the keyword-only stand-in). The
// default PatternDetector uses recognizer-plus-validation (the approach production PII scrubbers such
// as Presidio use): candidate regexes narrowed by real checks — Luhn for card numbers, area/group/
// serial rules for SSNs — plus a broad prompt-injection heuristic set. Detector is a seam so a managed
// service or an LLM classifier (RemoteDetector) can back it without touching the Policy Engine.

import (
	"regexp"
	"strings"
)

// Finding is one detected sensitive/adversarial span.
type Finding struct {
	Kind  string // pii-ssn | pii-credit-card | pii-email | pii-phone | pii-ip | secret | injection
	Class string // the content classification this finding implies (unrestricted..secret)
	Match string // the matched text (callers may redact)
}

// Detector scans text for PII and prompt-injection. Implementations must be safe for concurrent use.
type Detector interface {
	Scan(text string) []Finding
}

// PatternDetector is the deterministic, dependency-free default detector.
type PatternDetector struct{}

var (
	reCardCandidate = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)
	reSSNCandidate  = regexp.MustCompile(`\b\d{3}[- ]?\d{2}[- ]?\d{4}\b`)
	reEmail         = regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`)
	rePhone         = regexp.MustCompile(`\b(?:\+?1[ .\-]?)?\(?\d{3}\)?[ .\-]\d{3}[ .\-]\d{4}\b`)
	reIPv4          = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	reAWSKey        = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	rePrivateKey    = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)
	reSecretAssign  = regexp.MustCompile(`(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|password|passwd|bearer)\b\s*[:=]\s*\S{8,}`)
)

// injectionPatterns cover the common prompt-injection / jailbreak families (instruction override,
// system-prompt exfiltration, role-play jailbreaks, mode toggles, filter bypass) plus the original
// data-abuse phrases. Any match flags the prompt as adversarial (blocked by the Policy Engine).
var injectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|preceding|earlier)\s+(?:instructions?|prompts?|rules?|messages?)`),
	regexp.MustCompile(`(?i)\bdisregard\s+(?:your|all|the|any)\s+(?:instructions?|rules?|guidelines?|system\s+prompt)`),
	regexp.MustCompile(`(?i)\b(?:reveal|show|print|repeat|display|leak)\s+(?:me\s+)?(?:your|the)\s+(?:system\s+prompt|instructions?|initial\s+prompt|prompt|rules)`),
	regexp.MustCompile(`(?i)\byou\s+are\s+(?:now\s+)?(?:a\s+|an\s+)?(?:dan\b|developer\s+mode|jailbroken|unrestricted|unfiltered)`),
	regexp.MustCompile(`(?i)\b(?:enable|activate|enter|turn\s+on)\s+(?:developer|god|dan|debug|jailbreak)\s+mode`),
	regexp.MustCompile(`(?i)\bdo\s+anything\s+now\b`),
	regexp.MustCompile(`(?i)\bpretend\s+(?:you\s+are|to\s+be|that\s+you)`),
	regexp.MustCompile(`(?i)\bbypass\s+(?:your\s+|the\s+)?(?:safety|content|policy|guard|filter|restrictions?)`),
	regexp.MustCompile(`(?i)\bact\s+as\s+(?:if\s+)?(?:you\s+(?:are|were)\s+)?(?:an?\s+)?(?:unrestricted|uncensored|evil|jailbroken)`),
	regexp.MustCompile(`(?i)\b(?:exfiltrate|bypass\s+policy|disable\s+audit)\b`),
}

// piiRules pairs a validated recognizer with the classification it implies. Order is high→low so the
// first match on a span sets its class; classification takes the max across all findings anyway.
var piiRules = []struct {
	re    *regexp.Regexp
	kind  string
	class string
	valid func(string) bool
}{
	{rePrivateKey, "secret", "secret", nil},
	{reAWSKey, "secret", "secret", nil},
	{reSecretAssign, "secret", "secret", nil},
	{reCardCandidate, "pii-credit-card", "restricted", func(s string) bool { return luhnValid(onlyDigits(s)) }},
	{reSSNCandidate, "pii-ssn", "restricted", validSSN},
	{reEmail, "pii-email", "internal", nil},
	{rePhone, "pii-phone", "internal", nil},
	{reIPv4, "pii-ip", "internal", nil},
}

// Scan returns all PII + injection findings in text.
func (PatternDetector) Scan(text string) []Finding {
	var out []Finding
	for _, r := range piiRules {
		for _, m := range r.re.FindAllString(text, -1) {
			if r.valid != nil && !r.valid(m) {
				continue
			}
			out = append(out, Finding{Kind: r.kind, Class: r.class, Match: m})
		}
	}
	for _, re := range injectionPatterns {
		if m := re.FindString(text); m != "" {
			out = append(out, Finding{Kind: "injection", Class: "", Match: m})
			break // one injection finding is enough to block
		}
	}
	return out
}

// luhnValid checks the Luhn checksum (and a sane card length) so a random 16-digit string is not a
// false-positive card number.
func luhnValid(digits string) bool {
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum, alt := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// validSSN applies the US SSA allocation rules: area != 000/666/900-999, group != 00, serial != 0000.
func validSSN(s string) bool {
	d := onlyDigits(s)
	if len(d) != 9 {
		return false
	}
	area, group, serial := d[:3], d[3:5], d[5:]
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	if group == "00" || serial == "0000" {
		return false
	}
	return true
}

func onlyDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteByte(byte(r))
		}
	}
	return b.String()
}
