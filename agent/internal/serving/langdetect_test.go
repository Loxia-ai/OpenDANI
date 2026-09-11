package serving

// Deterministic language detection + the MT sidecar client.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetectLang(t *testing.T) {
	cases := map[string]string{
		"מה הדרישות לבקרות ביקורת עבור מידע בריאותי מוגן?":       "he",
		"ما هي متطلبات ضوابط التدقيق للمعلومات الصحية؟":          "ar",
		"Каковы требования к аудиту защищенной информации?":      "ru",
		"¿Qué exige la norma para los controles de auditoría?":   "es",
		"Quelle section exige des garanties administratives?":    "fr",
		"Welche Vorschrift verlangt die Prüfkontrollen im Land?": "de",
		"What does the rule require for audit controls?":         "en",
		"CFR45-164.312":                                          "en", // no signal → safe default
		"":                                                       "en",
	}
	for in, want := range cases {
		if got := detectLang(in); got != want {
			t.Fatalf("detectLang(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTranslatorClientAndFallbacks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["src"] == "heb_Hebr" {
			_ = json.NewEncoder(rw).Encode(map[string]string{"text": "what are the audit control requirements?"})
			return
		}
		_ = json.NewEncoder(rw).Encode(map[string]string{"text": "תשובה מתורגמת"})
	}))
	defer srv.Close()
	api := &TrainingAPI{Translate: &Translator{Base: srv.URL}}
	en, bridged := api.translateToEnglish("מה הדרישות?", "he")
	if !bridged || en != "what are the audit control requirements?" {
		t.Fatalf("bridge failed: %q %v", en, bridged)
	}
	if back := api.translateFromEnglish("translated answer", "he"); back != "תשובה מתורגמת" {
		t.Fatalf("back-translation failed: %q", back)
	}
	// nil translator and English are no-ops
	none := &TrainingAPI{}
	if q, b := none.translateToEnglish("hola", "es"); b || q != "hola" {
		t.Fatal("nil translator must no-op")
	}
	if q, b := api.translateToEnglish("hello", "en"); b || q != "hello" {
		t.Fatal("English must not bridge")
	}
	// sidecar failure degrades to the original query, never blocks
	bad := &TrainingAPI{Translate: &Translator{Base: "http://127.0.0.1:1"}}
	if q, b := bad.translateToEnglish("שאלה", "he"); b || q != "שאלה" {
		t.Fatal("sidecar failure must degrade to the original")
	}
	if a := bad.translateFromEnglish("answer", "he"); a != "answer" {
		t.Fatal("answer translation failure must return English")
	}
}
