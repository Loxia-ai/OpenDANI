package serving

// Translator is the client for the in-perimeter MT sidecar (NLLB via ctranslate2, localhost-only
// next to the gateway). The multilingual bridge: a non-English question is translated to English
// for the full-strength hybrid pipeline (BM25 needs English keywords), FUSED with a native dense
// leg on the original text (immune to term-of-art translation drift), answered in English (the
// small model's strong suit), grounding-verified in English, and the final answer translated back.
// Citations and § anchors pass through translation untouched — they are the ground truth either way.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Translator posts to the sidecar's /translate. Nil means the bridge is off (English-only).
type Translator struct {
	Base   string // e.g. http://127.0.0.1:9500
	Client *http.Client
}

// Translate converts text between NLLB FLORES codes ("heb_Hebr" → "eng_Latn").
func (t *Translator) Translate(text, src, tgt string) (string, error) {
	body, _ := json.Marshal(map[string]string{"text": text, "src": src, "tgt": tgt})
	client := t.Client
	if client == nil {
		client = &http.Client{Timeout: 90 * time.Second}
	}
	resp, err := client.Post(t.Base+"/translate", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("translate sidecar HTTP %d", resp.StatusCode)
	}
	var parsed struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", err
	}
	return parsed.Text, nil
}

// translateToEnglish bridges a detected non-English query; empty lang/nil translator no-op.
func (t *TrainingAPI) translateToEnglish(text, lang string) (string, bool) {
	if t.Translate == nil || lang == "" || lang == "en" {
		return text, false
	}
	src, ok := nllbCodes[lang]
	if !ok {
		return text, false
	}
	en, err := t.Translate.Translate(text, src, "eng_Latn")
	if err != nil || en == "" {
		return text, false // bridge failure degrades to the original query — never blocks the request
	}
	return en, true
}

// translateFromEnglish renders the final English answer in the user's language; failure returns
// the English answer (an English fallback beats an error).
func (t *TrainingAPI) translateFromEnglish(text, lang string) string {
	if t.Translate == nil || lang == "" || lang == "en" {
		return text
	}
	tgt, ok := nllbCodes[lang]
	if !ok {
		return text
	}
	out, err := t.Translate.Translate(text, "eng_Latn", tgt)
	if err != nil || out == "" {
		return text
	}
	return out
}
