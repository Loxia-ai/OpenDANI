package serving

// Deterministic language detection for the multilingual bridge — no model, no network, microseconds.
// Script-based detection is EXACT for Hebrew/Arabic/Cyrillic/CJK (the script IS the signal);
// Latin-script languages (es/fr/de vs en) are separated by stopword voting — the 20 most frequent
// function words of a language appear in essentially every real sentence of it.

import (
	"strings"
	"unicode"
)

var latinStopwords = map[string][]string{
	"es": {"el", "la", "los", "las", "de", "del", "que", "para", "por", "con", "una", "es", "en", "se", "cuál", "qué", "cómo", "más", "según", "sobre"},
	"fr": {"le", "la", "les", "des", "du", "que", "pour", "par", "avec", "une", "est", "dans", "se", "quel", "quelle", "comment", "plus", "selon", "sur", "aux"},
	"de": {"der", "die", "das", "den", "und", "für", "mit", "eine", "ist", "im", "nach", "welche", "welcher", "wie", "über", "bei", "vom", "zur", "nicht", "sind"},
	"en": {"the", "of", "and", "to", "in", "is", "for", "what", "which", "how", "does", "are", "that", "with", "under", "must", "shall", "a", "an", "on"},
}

// nllbCodes maps detected languages to NLLB FLORES-200 codes.
var nllbCodes = map[string]string{
	"he": "heb_Hebr", "ar": "arb_Arab", "ru": "rus_Cyrl", "zh": "zho_Hans", "ja": "jpn_Jpan",
	"es": "spa_Latn", "fr": "fra_Latn", "de": "deu_Latn", "en": "eng_Latn",
}

// detectLang returns a language code ("he", "es", …, "en"). Unknown/ambiguous input returns "en" —
// the bridge then simply does nothing, which is always safe.
func detectLang(s string) string {
	var heb, arab, cyr, cjk, latin int
	for _, r := range s {
		switch {
		case unicode.Is(unicode.Hebrew, r):
			heb++
		case unicode.Is(unicode.Arabic, r):
			arab++
		case unicode.Is(unicode.Cyrillic, r):
			cyr++
		case unicode.Is(unicode.Han, r) || unicode.Is(unicode.Hiragana, r) || unicode.Is(unicode.Katakana, r):
			cjk++
		case unicode.IsLetter(r) && r < 0x250:
			latin++
		}
	}
	total := heb + arab + cyr + cjk + latin
	if total == 0 {
		return "en"
	}
	// script majorities are decisive
	switch {
	case heb*2 > total:
		return "he"
	case arab*2 > total:
		return "ar"
	case cyr*2 > total:
		return "ru"
	case cjk*2 > total:
		return "zh"
	}
	// Latin script: stopword vote
	words := strings.Fields(strings.ToLower(s))
	best, bestScore := "en", 0
	for lang, stops := range latinStopwords {
		set := make(map[string]bool, len(stops))
		for _, w := range stops {
			set[w] = true
		}
		score := 0
		for _, w := range words {
			if set[strings.Trim(w, ".,;:?!¿¡()\"'")] {
				score++
			}
		}
		// deterministic tie-break: English wins ties (the do-nothing bridge is the safe default)
		if score > bestScore || (score == bestScore && lang == "en" && best != "en" && score > 0) {
			if score > bestScore {
				best, bestScore = lang, score
			}
		}
	}
	if bestScore == 0 {
		return "en"
	}
	return best
}
