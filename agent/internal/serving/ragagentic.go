package serving

// Agentic map-reduce retrieval — how questions spanning MANY documents (N ≥ 5) escape the context
// window entirely. Single-shot packing hits a physical wall: N documents must share one ~820-word
// excerpt budget inside a 2048-token engine slot. Map-reduce removes the wall:
//
//   MAP     one sub-question per entity, each retrieving with a FULL excerpt budget and dispatched
//           to a worker through the normal reserve/dispatch routing — the maps run IN PARALLEL
//           across the fleet, so an N=8 question costs ~one generation of latency, not eight.
//   REDUCE  the per-entity findings (compact, ~50 words each) synthesize into the final answer in
//           one last generation — findings are small, so N can grow far beyond what raw excerpts
//           ever allowed.
//
// Engages automatically when decomposition finds ≥ agenticMinSubqs entities, or explicitly with
// "agentic": true in the chat body ("agentic": false forces single-shot — the eval/ablation lever).
// Every map answer is attributed (which node served it), the union of map excerpts travels as
// citations, and the final answer is grounding-verified against those excerpts like any RAG answer.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"dani.local/agent/internal/ingest"
)

const (
	agenticMinSubqs   = 5   // auto-engage at N≥5 — single-shot packing measured strong through N=4
	agenticMapK       = 6   // retrieval depth per map step
	agenticMapWords   = 500 // excerpt budget per map step (each entity gets its own window)
	agenticMapTokens  = 120 // map answers are compact findings, not essays
	agenticMapTimeout = 90 * time.Second
	agenticMaxCite    = 16 // citations header cap (union of map excerpts)
)

// agenticFinding is one map step's outcome.
type agenticFinding struct {
	entity  string
	answer  string
	node    string
	hits    []ingest.Hit
	failure string // non-empty when this entity's map step degraded
}

// agenticChatBody builds a minimal OpenAI chat request for an internal (map/reduce) call.
func agenticChatBody(model, system, user string, maxTokens int) []byte {
	b, _ := json.Marshal(map[string]any{
		"model":       model,
		"messages":    []chatMsg{{Role: "system", Content: system}, {Role: "user", Content: user}},
		"max_tokens":  maxTokens,
		"temperature": 0,
	})
	return b
}

// chatOnFleet runs one internal completion through the SAME reserve/dispatch routing user traffic
// takes (classification dominance, load balancing, back-pressure retries) and returns the answer
// text + the node that served it.
func (p *Plane) chatOnFleet(ctx context.Context, model, classification string, body []byte) (string, string, error) {
	tried := map[string]bool{}
	for attempt := 0; attempt < 4; attempt++ {
		c, ok := p.reserve(model, classification, "", tried)
		if !ok {
			return "", "", fmt.Errorf("no worker for %s/%s", model, classification)
		}
		resp, err := p.dispatch(ctx, c, body, "")
		if err != nil || resp.StatusCode == http.StatusTooManyRequests {
			if resp != nil {
				resp.Body.Close()
			}
			p.release(c.uuid)
			tried[c.uuid] = true
			continue
		}
		var parsed struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		derr := json.NewDecoder(resp.Body).Decode(&parsed)
		resp.Body.Close()
		p.release(c.uuid)
		if derr != nil || len(parsed.Choices) == 0 {
			return "", c.uuid, fmt.Errorf("bad completion from %s", c.uuid)
		}
		return parsed.Choices[0].Message.Content, c.uuid, nil
	}
	return "", "", fmt.Errorf("all candidates busy")
}

// serveAgenticRag answers a decomposed multi-document question via parallel map + one reduce.
func (p *Plane) serveAgenticRag(rw http.ResponseWriter, r *http.Request, rag *ragOutcome) {
	t := p.training
	query, subqs := rag.origQuery, rag.subqs

	// MAP: per-entity retrieval + compact extraction, in parallel across the fleet.
	findings := make([]agenticFinding, len(subqs))
	var wg sync.WaitGroup
	for i, sq := range subqs {
		wg.Add(1)
		go func(i int, sq string) {
			defer wg.Done()
			entity := sq
			if j := strings.Index(sq, " — "); j > 0 {
				entity = sq[:j]
			}
			f := agenticFinding{entity: entity}
			defer func() { findings[i] = f }()
			hits, err := t.Ingest.Retrieve(rag.collection, sq, agenticMapK, rag.ceiling)
			if err != nil || len(hits) == 0 {
				f.failure = "no visible sources"
				return
			}
			// pack this entity's OWN excerpt window
			var ctxB strings.Builder
			budget := agenticMapWords
			class := rag.classification
			for _, h := range hits {
				w := len(strings.Fields(h.Text))
				if w > budget && ctxB.Len() > 0 {
					break
				}
				anchor := h.DocID
				if h.Section != "" {
					anchor += " · " + h.Section
				}
				fmt.Fprintf(&ctxB, "(%s) %s\n", anchor, h.Text)
				f.hits = append(f.hits, h)
				budget -= w
				if rank(h.Classification) > rank(class) {
					class = h.Classification
				}
				if budget <= 0 {
					break
				}
			}
			body := agenticChatBody(rag.baseModel,
				"Extract facts from the excerpts. Answer in at most 50 words. Name the document identifiers (in parentheses) you used. If the excerpts do not contain the answer, reply exactly: not found",
				fmt.Sprintf("Question: %s\nFocus on: %s\nExcerpts:\n%s", query, entity, ctxB.String()),
				agenticMapTokens)
			mctx, cancel := context.WithTimeout(r.Context(), agenticMapTimeout)
			defer cancel()
			answer, node, err := p.chatOnFleet(mctx, rag.baseModel, class, body)
			if err != nil {
				f.failure = "generation unavailable"
				return
			}
			f.answer, f.node = strings.TrimSpace(answer), node
		}(i, sq)
	}
	wg.Wait()

	// REDUCE: synthesize the findings — compact per-entity facts, so N no longer fights the window.
	var fb strings.Builder
	nodes := map[string]bool{}
	var allHits []ingest.Hit
	reduceClass := rag.classification
	for _, f := range findings {
		if f.failure != "" {
			fmt.Fprintf(&fb, "- %s: (%s)\n", f.entity, f.failure)
			continue
		}
		fmt.Fprintf(&fb, "- %s: %s\n", f.entity, f.answer)
		nodes[f.node] = true
		for _, h := range f.hits {
			allHits = append(allHits, h)
			if rank(h.Classification) > rank(reduceClass) {
				reduceClass = h.Classification
			}
		}
	}
	maxTok := rag.maxTokens
	if maxTok <= 0 {
		maxTok = 256
	}
	body := agenticChatBody(rag.baseModel,
		"You are synthesizing findings gathered from separate documents by parallel workers. Use ONLY the findings. Keep the document identifiers they cite.",
		fmt.Sprintf("Question: %s\nFindings:\n%s", query, fb.String()), maxTok)
	answer, reduceNode, err := p.chatOnFleet(r.Context(), rag.baseModel, reduceClass, body)
	if err != nil {
		http.Error(rw, "agentic reduce: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	// dedupe citations (union of map excerpts), verify grounding of the final answer against them
	seen := map[string]bool{}
	var cites []ingest.Hit
	var excerpts []string
	for _, h := range allHits {
		if !seen[h.ID] {
			seen[h.ID] = true
			excerpts = append(excerpts, h.Text)
			if len(cites) < agenticMaxCite {
				cites = append(cites, h)
			}
		}
	}
	g := verifyGrounding(answer, excerpts) // grounding on the ENGLISH answer, before back-translation
	if rag.bridged && t != nil {
		if back := t.translateFromEnglish(answer, rag.userLang); back != answer {
			answer = back
			rw.Header().Set("X-Dani-Rag-Language", rag.userLang)
			rw.Header().Set("X-Dani-Rag-Translated", "query,answer")
			t.emit("rag.translated", map[string]any{"user": rag.user, "lang": rag.userLang, "agentic": true})
		}
	}

	nodeList := make([]string, 0, len(nodes))
	for n := range nodes {
		nodeList = append(nodeList, n)
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("X-Dani-Served-By", reduceNode)
	rw.Header().Set("X-Dani-Agentic", fmt.Sprintf("map-reduce entities=%d map-nodes=%d", len(subqs), len(nodes)))
	rw.Header().Set("X-Dani-Agentic-Nodes", strings.Join(nodeList, ","))
	rw.Header().Set("X-Dani-Rag-Chunks", citationsJSON(cites))
	rw.Header().Set("X-Dani-Rag-User", rag.user+"/"+rag.clear)
	if rag.ceilingCapped {
		rw.Header().Set("X-Dani-Rag-Ceiling", rag.ceiling+" (fleet clearance)")
	}
	rw.Header().Set("X-Dani-Classification", reduceClass)
	rw.Header().Set("X-Dani-Rag-Grounding", fmt.Sprintf("%.2f", g.Score))
	rw.Header().Set("X-Dani-Rag-Grounding-Checked", fmt.Sprintf("%d", g.Checked))
	if len(g.Unsupported) > 0 {
		detail := strings.Join(g.Unsupported, "; ")
		if len(detail) > 220 {
			detail = detail[:220]
		}
		rw.Header().Set("X-Dani-Rag-Ungrounded", detail)
	}
	if t != nil {
		t.emit("rag.agentic", map[string]any{"user": rag.user, "entities": len(subqs),
			"mapNodes": nodeList, "reduceNode": reduceNode, "grounding": g.Score})
	}
	out, _ := json.Marshal(map[string]any{
		"id": "agentic-" + reduceNode, "object": "chat.completion", "model": rag.baseModel,
		"choices": []map[string]any{{"index": 0, "finish_reason": "stop",
			"message": map[string]any{"role": "assistant", "content": answer}}},
	})
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write(out)
}
