package serving

// The RAG request path (RAG-DESIGN.md; §6.17.2 step 4.5.2, M9) — and the implementation of the
// D-09 classification decisions: a prompt's classification comes from its CONTENT (F-02), the
// caller's clearance is only the authorization CEILING, retrieval sees only chunks <= clearance,
// and the augmented request routes at max(content, retrieved chunks) under dominance (F-01).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"dani.local/agent/internal/ingest"
	"dani.local/agent/internal/modelreg"
	"dani.local/agent/internal/policy"
)

// ragOutcome is a prepared, augmented chat request ready for normal routing.
type ragOutcome struct {
	body           []byte       // rewritten OpenAI request (model = base, retrieval context injected)
	baseModel      string       // route to this model
	classification string       // routing classification = max(content, retrieved chunks)
	hits           []ingest.Hit // citations (lineage travels with the answer)
	user, clear    string

	// agentic map-reduce (N≥5 multi-document questions — ragagentic.go): handleGateway hands the
	// request to serveAgenticRag instead of the single-dispatch path.
	agentic    bool
	subqs      []string
	collection string
	origQuery  string
	maxTokens  int

	ceiling       string // effective retrieval ceiling = min(clearance, fleet max class)
	ceilingCapped bool   // true when the fleet's clearance (not the caller's) is the binding cap

	userLang string // detected question language ("he", "es", …); "" or "en" = no bridge
	bridged  bool   // the query crossed the MT bridge (translated to English for the pipeline)
}

// chatMsg mirrors the OpenAI message shape.
type chatMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// buildRagChat authorizes and augments a chat request aimed at a RAG-compound alias. Returns the
// HTTP status + error for denials (403 AuthZ ceiling, 404 unknown user/collection, 400 malformed).
func (t *TrainingAPI) buildRagChat(raw []byte, alias modelreg.RagAlias, user, fleetMaxClass string) (*ragOutcome, int, error) {
	principal, err := t.Ident.Resolve(user)
	if err != nil {
		return nil, 404, err
	}
	// Retrieval ceiling = min(caller clearance, fleet max class): the caller retrieves only what
	// they may SEE, and only what some live worker is cleared to PROCESS — excerpts above every
	// worker's clearance cannot be served (dominance), so they are excluded and the cap reported.
	ceiling := principal.Clearance
	capped := false
	if fleetMaxClass != "" && rank(fleetMaxClass) < rank(ceiling) {
		ceiling = fleetMaxClass
		capped = true
	}
	var req struct {
		Messages   []chatMsg `json:"messages"`
		MaxTokens  int       `json:"max_tokens"`
		Subqueries []string  `json:"subqueries,omitempty"` // agent-provided decomposition override
		Agentic    *bool     `json:"agentic,omitempty"`    // true = force map-reduce; false = force single-shot; nil = auto
	}
	if err := json.Unmarshal(raw, &req); err != nil || len(req.Messages) == 0 {
		return nil, 400, fmt.Errorf("rag: malformed chat request")
	}
	query := ""
	for _, m := range req.Messages { // retrieval query = the LAST user message
		if m.Role == "user" {
			query = m.Content
		}
	}

	// The LIVE Policy Engine is the DP13 authority (AuthZ role, banned-content, rate limit, and the
	// D-09 flow rule: content classification is the label, clearance is the ceiling).
	dec := t.Policy.CheckPrompt(policy.Principal{Sub: principal.Sub, Clearance: principal.Clearance, Roles: principal.Roles}, query)
	if !dec.Allow {
		t.emit("policy.deny", map[string]any{"user": user, "reason": dec.Reason, "alias": alias.Alias})
		return nil, 403, fmt.Errorf("policy: %s", dec.Reason)
	}
	contentClass := dec.Classification
	// MULTILINGUAL BRIDGE: a non-English question is translated to English so the full-strength
	// hybrid pipeline (BM25 included) and the English-tuned small model both operate at their
	// measured quality. The ORIGINAL question is kept — its native dense ranking (bge-m3 embeds all
	// languages into one space) fuses with the translated retrieval, so a term-of-art
	// mistranslation cannot lose a document. The answer is translated back at the end.
	userLang := detectLang(query)
	origQuery := query
	bridged := false
	if userLang != "en" {
		if en, ok := t.translateToEnglish(query, userLang); ok {
			query = en
			bridged = true
		}
	}
	// Agentic map-reduce path: at N≥5 entities the single context window physically cannot seat
	// every document — fan the entities out across the fleet instead (ragagentic.go).
	subqsForAgentic := req.Subqueries
	if len(subqsForAgentic) == 0 {
		subqsForAgentic = decomposeQuery(query)
	}
	agentic := len(subqsForAgentic) >= agenticMinSubqs && len(subqsForAgentic) >= 2
	if req.Agentic != nil {
		agentic = *req.Agentic && len(subqsForAgentic) >= 2
	}
	if agentic {
		return &ragOutcome{agentic: true, subqs: subqsForAgentic, collection: alias.Collection,
			origQuery: query, maxTokens: req.MaxTokens, baseModel: alias.BaseModelID,
			classification: contentClass, user: user, clear: principal.Clearance,
			ceiling: ceiling, ceilingCapped: capped, userLang: userLang, bridged: bridged}, 0, nil
	}
	// Retrieval ceiling = clearance: the caller retrieves only what they may see. The multi-doc
	// pipeline (ragpack.go) retrieves deep, decomposes comparison/enumeration questions into
	// per-entity sub-queries, and packs a document-DIVERSE context under the token budget — an
	// N-document question gets all N documents represented instead of the top one eating the budget.
	var aux [][]ingest.Hit
	if bridged { // native-language dense leg — immune to translation drift
		if nh, nerr := t.Ingest.RetrieveMode(alias.Collection, origQuery, ragSubqK, ceiling, "dense"); nerr == nil {
			aux = append(aux, nh)
		}
	}
	hits, _, err := t.retrievePacked(alias.Collection, query, ceiling, req.Subqueries, false, false, aux...)
	if err != nil {
		return nil, 404, err
	}
	// Augmented classification = max(content, retrieved chunks): retrieval raises the routing
	// requirement; dominance (F-01) picks a worker cleared >= it.
	augClass := contentClass
	var ctx strings.Builder
	for i, h := range hits {
		if rank(h.Classification) > rank(augClass) {
			augClass = h.Classification
		}
		anchor := h.DocID
		if h.Section != "" {
			anchor += " · " + h.Section
		}
		fmt.Fprintf(&ctx, "[%d] (%s, %s) %s\n", i+1, anchor, h.Classification, h.Text)
	}
	system := chatMsg{Role: "system", Content: fmt.Sprintf(
		"Answer using ONLY the following in-perimeter excerpts from the '%s' collection "+
			"(classification-filtered for this caller). If they do not contain the answer, say so.\n%s",
		alias.Collection, ctx.String())}
	if len(hits) == 0 {
		system.Content = fmt.Sprintf("No excerpts from the '%s' collection are visible at this caller's "+
			"clearance. Say that no in-perimeter sources are available to answer.", alias.Collection)
	}
	outMsgs := append([]chatMsg{system}, req.Messages...)
	if bridged { // the model answers in English (its strong suit); the bridge translates back
		for i := range outMsgs {
			if outMsgs[i].Role == "user" && outMsgs[i].Content == origQuery {
				outMsgs[i].Content = query
			}
		}
	}
	body, _ := json.Marshal(map[string]any{
		"model":      alias.BaseModelID,
		"messages":   outMsgs,
		"max_tokens": req.MaxTokens,
	})
	return &ragOutcome{body: body, baseModel: alias.BaseModelID, classification: augClass,
		hits: hits, user: user, clear: principal.Clearance, ceiling: ceiling, ceilingCapped: capped,
		userLang: userLang, bridged: bridged}, 0, nil
}

// citationsJSON renders the compact citations header value.
func citationsJSON(hits []ingest.Hit) string {
	type c struct {
		ID      string  `json:"id"`
		Doc     string  `json:"doc"`
		Section string  `json:"section,omitempty"` // pinpoint anchor within the document
		Class   string  `json:"class"`
		Score   float32 `json:"score"`
	}
	cs := make([]c, len(hits))
	for i, h := range hits {
		cs[i] = c{ID: h.ID, Doc: h.DocID, Section: h.Section, Class: h.Classification, Score: h.Score}
	}
	b, _ := json.Marshal(cs)
	return string(b)
}

// handleRagSearch is the read-only retrieval probe (eval harnesses, ablations, future console
// search): the exact classification-filtered Retrieve the RAG chat path uses, without generation.
// The caller's clearance is the ceiling, same as chat — this endpoint cannot see more than a chat can.
func (t *TrainingAPI) handleRagSearch(rw http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	collection, query, user := q.Get("collection"), q.Get("q"), q.Get("user")
	if collection == "" || query == "" || user == "" {
		http.Error(rw, "collection, q and user query parameters required", http.StatusBadRequest)
		return
	}
	principal, err := t.Ident.Resolve(user)
	if err != nil {
		writeErr(rw, http.StatusNotFound, err)
		return
	}
	k := 3
	if n, aerr := strconv.Atoi(q.Get("k")); aerr == nil && n > 0 && n <= 50 {
		k = n
	}
	mode := q.Get("mode") // dense | sparse | hybrid ("" = hybrid) — the ablation surface
	if mode == "" {
		mode = "hybrid"
	}
	if q.Get("bridge") == "1" {
		// the multilingual bridge's retrieval, without generation: detect -> translate -> full
		// hybrid on the English query FUSED with a native-language dense leg (eval surface)
		lang := detectLang(query)
		enQuery, bridged := t.translateToEnglish(query, lang)
		var aux [][]ingest.Hit
		if bridged {
			if nh, nerr := t.Ingest.RetrieveMode(collection, query, ragSubqK, principal.Clearance, "dense"); nerr == nil {
				aux = append(aux, nh)
			}
		}
		hits, _, err := t.retrievePacked(collection, enQuery, principal.Clearance, nil, false, false, aux...)
		if err != nil {
			writeErr(rw, http.StatusNotFound, err)
			return
		}
		writeJSON(rw, http.StatusOK, map[string]any{"hits": hits, "user": user, "lang": lang,
			"bridged": bridged, "en": enQuery})
		return
	}
	if q.Get("pack") == "1" {
		// the CHAT path's packed context, without generation: pack=1 [&classic=1 old packer]
		// [&decomp=0 no decomposition] — the eval/ablation surface for multi-doc questions
		hits, subqs, err := t.retrievePacked(collection, query, principal.Clearance, nil,
			q.Get("decomp") == "0", q.Get("classic") == "1")
		if err != nil {
			writeErr(rw, http.StatusNotFound, err)
			return
		}
		writeJSON(rw, http.StatusOK, map[string]any{"hits": hits, "user": user,
			"clearance": principal.Clearance, "packed": true, "subqueries": subqs})
		return
	}
	hits, err := t.Ingest.RetrieveMode(collection, query, k, principal.Clearance, mode)
	if err != nil {
		writeErr(rw, http.StatusNotFound, err)
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"hits": hits, "user": user, "clearance": principal.Clearance, "mode": mode})
}

// handleRagAlias registers a RAG-compound alias: POST {"base","collection"}. The collection must be
// ingested — an alias is only meaningful over indexed, classified chunks. GET lists the registered
// aliases (the console's RAG panel reads it).
func (t *TrainingAPI) handleRagAlias(rw http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(rw, http.StatusOK, map[string]any{"aliases": t.Models.RagAliases()})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(rw, "GET or POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Base       string `json:"base"`
		Collection string `json:"collection"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Base == "" || req.Collection == "" {
		http.Error(rw, "bad request body (need base + collection)", http.StatusBadRequest)
		return
	}
	if _, ok := t.Ingest.Collection(req.Collection); !ok {
		writeErr(rw, http.StatusNotFound, fmt.Errorf("collection %q not ingested", req.Collection))
		return
	}
	a := t.Models.RegisterRagAlias(req.Base, req.Collection)
	writeJSON(rw, http.StatusOK, a)
}
