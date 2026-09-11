package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// RemoteDetector delegates PII + injection detection to an EXTERNAL classifier — a managed content-
// safety service or an LLM behind an OpenAI-compatible endpoint (the production "real ML" backend that
// replaces the deterministic PatternDetector). It POSTs the text and expects a JSON verdict:
//
//	{"findings":[{"kind":"pii-ssn","class":"restricted"},{"kind":"injection"}]}
//
// Fail-open to the local PatternDetector on any transport/decode error: a detector outage must not
// take the request path down, and the local recognizers still provide a floor of protection.
type RemoteDetector struct {
	Client   *http.Client
	URL      string   // classifier endpoint (POST {"text": "..."} -> {"findings":[...]})
	Fallback Detector // used on error; defaults to PatternDetector
}

func (d RemoteDetector) client() *http.Client {
	if d.Client != nil {
		return d.Client
	}
	return http.DefaultClient
}

func (d RemoteDetector) fallback() Detector {
	if d.Fallback != nil {
		return d.Fallback
	}
	return PatternDetector{}
}

// Scan calls the remote classifier, falling back to local pattern detection on any failure.
func (d RemoteDetector) Scan(text string) []Finding {
	body, _ := json.Marshal(map[string]string{"text": text})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, strings.TrimRight(d.URL, "/")+"/scan", bytes.NewReader(body))
	if err != nil {
		return d.fallback().Scan(text)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client().Do(req)
	if err != nil {
		return d.fallback().Scan(text)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return d.fallback().Scan(text)
	}
	var out struct {
		Findings []Finding `json:"findings"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return d.fallback().Scan(text)
	}
	return out.Findings
}
