// Package ingest is the Ingest Subsystem slice the Training Subsystem needs (Architecture §6.21 #14,
// §6.17.9 steps 1-6): crawl a source, CLASSIFY AT INGEST (source-mapped class + content scan),
// chunk, and record chunk→source lineage. The result is a named collection of classified chunks —
// exactly what training consumes for dataset classification and lineage.
//
// Ported from the sim's ingest.js, including its synthetic corpora (legal/hr/finance) so the DEMO
// trains on real, meaningful text. OUT of this slice (deferred with RAG, its own Matrix item):
// embeddings and retrieval — §6.17.9 steps 7-8. No AI is mocked here; classification is the same
// deterministic source+content rule the sim verified.
package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

var classRank = map[string]int{"unrestricted": 0, "internal": 1, "restricted": 2, "secret": 3}

func rank(c string) int {
	if r, ok := classRank[c]; ok {
		return r
	}
	return 1
}

// Chunk is one classified unit of an ingested document, with lineage back to its source.
//
// A chunk is either PLAIN TEXT (Format "text" / empty — completion-style continued pretraining) or a
// STRUCTURED example (Format "chat") carrying an OpenAI-shaped `messages` array (and optional `tools`
// schema). That one shape covers instruction/Q&A, multi-turn conversations, and tool-calling —
// exactly what you fine-tune an assistant/agent on. Messages/Tools are opaque JSON passed straight
// through to the trainer (which applies the model's chat template); `Text` is always the FLATTENED
// rendering used for classification-at-ingest, RAG embedding, and text-only trainers.
type Chunk struct {
	ID             string          `json:"id"`
	DocID          string          `json:"docId"`
	Section        string          `json:"section,omitempty"` // pinpoint anchor: the heading this chunk falls under
	Text           string          `json:"text"`
	Classification string          `json:"classification"`
	Source         string          `json:"source"`             // connector name
	Format         string          `json:"format,omitempty"`   // "" / "text" | "chat"
	Messages       json.RawMessage `json:"messages,omitempty"` // OpenAI messages (chat/tool examples)
	Tools          json.RawMessage `json:"tools,omitempty"`    // OpenAI tool schemas (agentic)
	Vec            []float32       `json:"-"`                  // embedding (§6.17.9 step 7; not serialized)
}

// Collection is a named set of classified chunks produced by one ingest run.
type Collection struct {
	Name      string  `json:"name"`
	Connector string  `json:"connector"`
	Chunks    []Chunk `json:"chunks"`
}

// corpus is a synthetic source: a connector flavor (D29), a source-mapped classification, and docs.
// examples is non-nil for operator uploads that were parsed into structured/plain training examples
// (one example per entry, no sentence-splitting — a Q&A pair or conversation is one unit).
type corpus struct {
	connector string
	srcClass  string
	docs      []string
	examples  []example
}

// example is one parsed training unit: plain text, or a structured chat/tool example. text is always
// set (the flattened rendering used for classification + embedding); messages/tools carry the raw
// OpenAI JSON for structured examples.
type example struct {
	text     string
	format   string // "text" | "chat"
	messages json.RawMessage
	tools    json.RawMessage
}

// chatTurn is the minimal OpenAI message shape we parse for RENDERING + validation; the raw JSON is
// preserved verbatim for the trainer, so any extra fields (names, ids, refusals) pass through.
type chatTurn struct {
	Role       string         `json:"role"`
	Content    string         `json:"content,omitempty"`
	Name       string         `json:"name,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
	ToolCalls  []chatToolCall `json:"tool_calls,omitempty"`
	Refusal    string         `json:"refusal,omitempty"`
}
type chatToolCall struct {
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// parseExample turns ONE uploaded line into a training example. It accepts three shapes so a
// non-expert and a power user both "just work":
//   - plain text                       -> completion-style example
//   - {"prompt":"…","completion":"…"}  -> a Q&A pair (converted to user/assistant messages)
//   - {"messages":[…],"tools":[…]}     -> a chat / multi-turn / tool-calling example (OpenAI shape)
//
// A line that starts with '{' but doesn't parse as a known object falls back to plain text (forgiving).
func parseExample(line string) (example, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return example{}, false
	}
	if !strings.HasPrefix(line, "{") {
		return example{text: line, format: "text"}, true
	}
	// {"text":"…"} — the simplest JSONL text form
	var textOnly struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal([]byte(line), &textOnly); err == nil && textOnly.Text != "" {
		var probe map[string]json.RawMessage
		_ = json.Unmarshal([]byte(line), &probe)
		if _, hasMsgs := probe["messages"]; !hasMsgs {
			if _, hasPrompt := probe["prompt"]; !hasPrompt {
				return example{text: textOnly.Text, format: "text"}, true
			}
		}
	}
	// {"prompt","completion"} — Q&A shorthand -> messages
	var qa struct {
		Prompt, Completion, System string
	}
	if err := json.Unmarshal([]byte(line), &qa); err == nil && qa.Prompt != "" && qa.Completion != "" {
		msgs := []map[string]string{}
		if qa.System != "" {
			msgs = append(msgs, map[string]string{"role": "system", "content": qa.System})
		}
		msgs = append(msgs, map[string]string{"role": "user", "content": qa.Prompt}, map[string]string{"role": "assistant", "content": qa.Completion})
		raw, _ := json.Marshal(msgs)
		return example{text: renderTurns(qa.System + "\n" + qa.Prompt + "\n" + qa.Completion), format: "chat", messages: raw}, true
	}
	// {"messages":[…], "tools":[…]} — full OpenAI shape
	var chat struct {
		Messages json.RawMessage `json:"messages"`
		Tools    json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal([]byte(line), &chat); err == nil && len(chat.Messages) > 0 {
		var turns []chatTurn
		if json.Unmarshal(chat.Messages, &turns) != nil {
			return example{text: line, format: "text"}, true // malformed messages -> treat raw as text
		}
		var sb strings.Builder
		for _, t := range turns {
			sb.WriteString(t.Content)
			sb.WriteByte('\n')
			for _, tc := range t.ToolCalls {
				sb.WriteString(tc.Function.Name)
				sb.WriteByte(' ')
				sb.WriteString(tc.Function.Arguments)
				sb.WriteByte('\n')
			}
		}
		// tool SCHEMAS carry names/descriptions that should also be classified
		sb.Write(chat.Tools)
		return example{text: renderTurns(sb.String()), format: "chat", messages: chat.Messages, tools: chat.Tools}, true
	}
	return example{text: line, format: "text"}, true
}

// renderTurns collapses whitespace so the flattened text is a clean classification/embedding input.
func renderTurns(s string) string {
	return strings.TrimSpace(strings.Join(strings.Fields(s), " "))
}

// corpora are the sim's synthetic sources — real sentences so a DEMO fine-tune has actual content.
var corpora = map[string]corpus{
	"legal": {connector: "confluence", srcClass: "restricted", docs: []string{
		"Master services agreement governs liability caps and indemnification between the parties.",
		"Data processing addendum requires all customer data to remain within the perimeter and be encrypted at rest.",
		"The non-disclosure agreement covers confidential information shared during the evaluation period.",
		"Regulatory filing obligations under BoI 357 require quarterly risk disclosures to the board.",
	}},
	"hr": {connector: "sharepoint", srcClass: "internal", docs: []string{
		"The employee handbook describes the remote work policy and equipment reimbursement process.",
		"Annual performance reviews are conducted in Q4 with calibration across managers.",
		"Parental leave policy provides up to 26 weeks of paid leave per applicable regulation.",
		"The onboarding checklist covers identity provisioning, security training, and equipment.",
	}},
	"finance": {connector: "jdbc", srcClass: "restricted", docs: []string{
		"Q3 revenue grew 14 percent driven by the regulated-sector pipeline and renewals.",
		"The risk report flags concentration in three large banking accounts as a material exposure.",
		"Capital adequacy under BoI 361 remained above the regulatory minimum throughout the quarter.",
		"Operating expenses included one-time costs for the air-gapped deployment lab.",
	}},
}

var (
	reSecret     = regexp.MustCompile(`(?i)\b(secret|classified)\b`)
	reRestricted = regexp.MustCompile(`(?i)\b(risk|revenue|capital|account)\b`)
	// "trade secret(s)" is a legal term of art in contract boilerplate, not a classification
	// marker — without this carve-out every real-world confidentiality clause raised to secret
	// (and on a fleet with no secret-cleared workers, became unroutable).
	reTradeSecret = regexp.MustCompile(`(?i)\btrade\s+secrets?\b`)
)

// ClassifyContent is the content-scan classifier on its own (no source mapping) — the F-02/D-09
// prompt classifier: a prompt's classification comes from its CONTENT, and the caller's clearance
// is only the authorization ceiling.
func ClassifyContent(text string) string {
	return classify(text, "unrestricted")
}

// classify implements classification-at-ingest (§6.17.9 step 5): max(source-mapped, content-scan).
func classify(text, srcClass string) string {
	c := srcClass
	scan := reTradeSecret.ReplaceAllString(text, "")
	if reSecret.MatchString(scan) && rank("secret") > rank(c) {
		c = "secret"
	}
	if reRestricted.MatchString(text) && rank("restricted") > rank(c) {
		c = "restricted"
	}
	return c
}

// Subsystem holds ingested collections.
type Subsystem struct {
	mu          sync.Mutex
	embedder    Embedder
	collections map[string]Collection
	custom      map[string]corpus          // operator-uploaded corpora (connector "upload")
	connectors  map[string]*connectorEntry // connector-backed collections (P1-6)
	store       *Store                     // nil = in-memory (tests/CI); set = durable write-through (P1-1)
	bm25        bm25Cache                  // lazy per-collection sparse index (hybrid retrieval)

	// console-connected sources ("Connect a source"): defs + their sync-loop lifecycles
	defs         map[string]ConnectorDef
	syncCancel   map[string]context.CancelFunc
	gitCacheRoot string // controller state dir for git working clones
}

// New builds an Ingest subsystem with the deterministic BoW embedder (CI/DEMO default).
func New() *Subsystem {
	return &Subsystem{embedder: BoWEmbedder{}, collections: map[string]Collection{},
		custom: map[string]corpus{}, connectors: map[string]*connectorEntry{}}
}

// AddCustom registers an operator-uploaded corpus (the console's dataset-upload path). The docs are
// classified at ingest exactly like connector corpora: srcClass is the SOURCE floor, and content
// classification can only raise it (D-09 direction). Returns the effective source class.
func (s *Subsystem) AddCustom(name string, docs []string, srcClass string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("ingest: custom corpus needs a name")
	}
	if len(docs) == 0 {
		return "", fmt.Errorf("ingest: custom corpus %q has no documents", name)
	}
	if _, builtin := corpora[name]; builtin {
		return "", fmt.Errorf("ingest: %q is a built-in corpus — pick another name", name)
	}
	if s.HasConnector(name) {
		return "", fmt.Errorf("ingest: %q is a connector-backed collection — pick another name", name)
	}
	if srcClass == "" {
		srcClass = "internal" // uploads default to internal: an operator moved them here on purpose
	}
	if _, ok := classRank[srcClass]; !ok {
		return "", fmt.Errorf("ingest: unknown classification %q", srcClass)
	}
	exs := make([]example, 0, len(docs))
	for _, d := range docs {
		if e, ok := parseExample(d); ok {
			exs = append(exs, e)
		}
	}
	if len(exs) == 0 {
		return "", fmt.Errorf("ingest: custom corpus %q has only empty documents", name)
	}
	c := corpus{connector: "upload", srcClass: srcClass, examples: exs}
	s.mu.Lock()
	st := s.store
	s.mu.Unlock()
	// durable-first: an upload that can't be persisted is refused (silently keeping it in-memory
	// would look saved and then vanish on restart — the exact failure P1-1 exists to remove).
	if st != nil {
		if err := st.saveCustom(context.Background(), name, c); err != nil {
			return "", err
		}
	}
	s.mu.Lock()
	s.custom[name] = c
	s.mu.Unlock()
	return srcClass, nil
}

// AvailableCorpora lists every source an operator can ingest: the built-in corpora, uploaded ones,
// and connector-backed collections.
func (s *Subsystem) AvailableCorpora() []string {
	names := Corpora()
	s.mu.Lock()
	for n := range s.custom {
		names = append(names, n)
	}
	for n := range s.connectors {
		names = append(names, n)
	}
	s.mu.Unlock()
	sort.Strings(names)
	return names
}

// WithEmbedder swaps in a real embedder (OpenAIEmbedder against Ollama/llama.cpp) and returns s.
func (s *Subsystem) WithEmbedder(e Embedder) *Subsystem {
	s.embedder = e
	return s
}

// WithStore makes the subsystem durable (P1-1): every ingest + upload writes through to the store,
// and everything previously persisted — collections WITH their embeddings, and uploaded corpora — is
// rehydrated right now, so datasets and RAG indexes survive a controller restart. Persisted vectors
// are restored byte-identical (no re-embed: a different embedder version would silently change
// retrieval ranking).
func (s *Subsystem) WithStore(ctx context.Context, st *Store) (*Subsystem, error) {
	cols, customs, err := st.loadAll(ctx)
	if err != nil {
		return nil, err
	}
	conns, err := st.loadConnectors(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.store = st
	for name, c := range cols {
		s.collections[name] = c
	}
	for name, c := range customs {
		s.custom[name] = c
	}
	for name, e := range conns {
		// docs + cursor come back; the live Connector arrives via RegisterConnector at boot
		// (secret material is flag/secret-store config, never persisted here).
		s.connectors[name] = e
	}
	s.mu.Unlock()
	return s, nil
}

// Ingest crawls a corpus into a classified, lineage-recorded, EMBEDDED collection (§6.17.9 steps
// 1-7: crawl -> classify -> chunk -> embed -> index). A connector-backed collection routes to its
// INCREMENTAL sync (P1-6) — the console's "Ingest" action just works for real sources too.
func (s *Subsystem) Ingest(name string) (Collection, error) {
	if s.HasConnector(name) {
		_, _, col, err := s.SyncConnector(context.Background(), name)
		return col, err
	}
	c, ok := corpora[name]
	if !ok {
		s.mu.Lock()
		c, ok = s.custom[name] // operator-uploaded corpora ingest identically
		s.mu.Unlock()
	}
	if !ok {
		return Collection{}, fmt.Errorf("ingest: no corpus for %q", name)
	}
	col := Collection{Name: name, Connector: c.connector}
	chunkID := 0
	// Structured/uploaded corpora: one chunk per parsed example (a Q&A pair or conversation is a
	// single training unit — do NOT sentence-split it). Classification scans the flattened text.
	for i, ex := range c.examples {
		chunkID++
		col.Chunks = append(col.Chunks, Chunk{
			ID: fmt.Sprintf("%s#%d", name, chunkID), DocID: fmt.Sprintf("%s/ex-%d", name, i+1),
			Text: ex.text, Classification: classify(ex.text, c.srcClass), Source: c.connector,
			Format: ex.format, Messages: ex.messages, Tools: ex.tools,
		})
	}
	// Built-in text corpora: structure-aware chunking (token-bounded, overlapped, §-labelled).
	for di, doc := range c.docs {
		docID := fmt.Sprintf("%s/doc-%d", name, di+1)
		class := classify(doc, c.srcClass)
		for _, dc := range chunkDoc(fmt.Sprintf("doc-%d", di+1), doc) {
			chunkID++
			col.Chunks = append(col.Chunks, Chunk{
				ID: fmt.Sprintf("%s#%d", name, chunkID), DocID: docID, Section: dc.Section, Text: dc.Text,
				Classification: class, Source: c.connector, Format: "text",
			})
		}
	}
	// embed (step 7) — incremental: a re-ingest reuses vectors for unchanged chunks
	s.mu.Lock()
	prev := s.collections[name]
	s.mu.Unlock()
	if err := s.embedChunks(prev, &col); err != nil {
		return Collection{}, fmt.Errorf("ingest: embed %q: %w", name, err)
	}
	s.mu.Lock()
	st := s.store
	s.mu.Unlock()
	// durable-first (same contract as AddCustom): the collection only becomes visible once persisted.
	if st != nil {
		if err := st.saveCollection(context.Background(), col); err != nil {
			return Collection{}, fmt.Errorf("ingest: persist %q: %w", name, err)
		}
	}
	s.mu.Lock()
	s.collections[name] = col
	s.mu.Unlock()
	return col, nil
}

// embedChunks fills vectors for col's chunks INCREMENTALLY: a chunk whose text is unchanged from
// prev reuses its vector (identical text ⇒ identical embedding, by definition). With a real
// embedding model this is the difference between a sync costing seconds and costing the whole
// collection — the old whole-collection re-embed was only affordable with the in-process BoW.
// A dimension guard invalidates reuse after an embedder swap (e.g. BoW 32-dim → bge 384-dim):
// stale-dim vectors are re-embedded so a collection is never silently unsearchable.
func (s *Subsystem) embedChunks(prev Collection, col *Collection) error {
	if len(col.Chunks) == 0 {
		return nil
	}
	// background-priority path when the embedder supports it: bulk (re-)embeds must never starve
	// interactive retrieval — the ONE lesson of the 51-second query embed.
	embed := s.embedder.Embed
	if be, ok := s.embedder.(interface {
		EmbedBackground([]string) ([][]float32, error)
	}); ok {
		embed = be.EmbedBackground
	}
	oldVec := make(map[string][]float32, len(prev.Chunks))
	for _, ch := range prev.Chunks {
		// an all-zero vector is the resilience ladder's degraded fallback, not knowledge — never
		// reuse it, so an interrupted embed run SELF-HEALS on the next background sync
		if len(ch.Vec) > 0 && !isZeroVec(ch.Vec) {
			oldVec[ch.Text] = ch.Vec
		}
	}
	var missIdx []int
	var missTexts []string
	for i := range col.Chunks {
		if v, ok := oldVec[col.Chunks[i].Text]; ok {
			col.Chunks[i].Vec = v
		} else {
			missIdx = append(missIdx, i)
			missTexts = append(missTexts, col.Chunks[i].Text)
		}
	}
	dim := 0
	if len(missTexts) > 0 {
		vecs, err := embed(missTexts)
		if err != nil {
			return err
		}
		for j, i := range missIdx {
			col.Chunks[i].Vec = vecs[j]
		}
		if len(vecs) > 0 {
			dim = len(vecs[0])
		}
	} else { // everything reused — probe once so an embedder swap can't hide behind unchanged text
		probe, err := s.embedder.Embed([]string{col.Chunks[0].Text})
		if err != nil {
			return err
		}
		dim = len(probe[0])
		col.Chunks[0].Vec = probe[0]
	}
	var staleIdx []int
	var staleTexts []string
	for i := range col.Chunks {
		if len(col.Chunks[i].Vec) != dim {
			staleIdx = append(staleIdx, i)
			staleTexts = append(staleTexts, col.Chunks[i].Text)
		}
	}
	if len(staleTexts) > 0 { // reused vectors from a previous embedder — re-embed at the live dim
		vecs, err := embed(staleTexts)
		if err != nil {
			return err
		}
		for j, i := range staleIdx {
			col.Chunks[i].Vec = vecs[j]
		}
	}
	return nil
}

// isZeroVec reports a degraded-fallback embedding (all zeros — dense-invisible by construction).
func isZeroVec(v []float32) bool {
	for _, x := range v {
		if x != 0 {
			return false
		}
	}
	return true
}

// Hit is one retrieved chunk with its relevance score — lineage travels with the answer.
type Hit struct {
	ID             string  `json:"id"`
	DocID          string  `json:"docId"`
	Section        string  `json:"section,omitempty"` // pinpoint anchor (heading) within the document
	Text           string  `json:"text"`
	Classification string  `json:"classification"`
	Source         string  `json:"source"`
	Score          float32 `json:"score"`
}

// Retrieve is classification-filtered top-K retrieval (§6.17.2 step 4.5.2): only chunks classified
// <= ceiling are searchable (D-09/F-02: the ceiling is the caller's clearance — you retrieve only
// what you may see). Default mode is HYBRID: dense (cosine) and sparse (BM25) rankings fused with
// RRF — legal/technical queries are half exact-lookup (section numbers, defined terms, party
// names) where lexical match beats embeddings, and half paraphrase where embeddings win.
func (s *Subsystem) Retrieve(collection, query string, topK int, ceiling string) ([]Hit, error) {
	return s.RetrieveMode(collection, query, topK, ceiling, "hybrid")
}

// RetrieveMode exposes the ranking mode (dense | sparse | hybrid) — the eval/ablation surface.
func (s *Subsystem) RetrieveMode(collection, query string, topK int, ceiling, mode string) ([]Hit, error) {
	s.mu.Lock()
	col, ok := s.collections[collection]
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("ingest: collection %q not ingested", collection)
	}
	if topK <= 0 {
		topK = 3
	}
	max := rank(ceiling)
	eligible := make([]int, 0, len(col.Chunks))
	for i, ch := range col.Chunks {
		if rank(ch.Classification) <= max { // above the caller's clearance — invisible
			eligible = append(eligible, i)
		}
	}

	var rankings [][]int
	if mode != "sparse" { // dense ranking
		qv, err := s.embedder.Embed([]string{query})
		if err != nil {
			return nil, fmt.Errorf("ingest: embed query: %w", err)
		}
		dense := make([]float64, len(col.Chunks))
		for _, i := range eligible {
			dense[i] = float64(cosine(qv[0], col.Chunks[i].Vec))
		}
		rankings = append(rankings, rankDesc(dense, eligible))
	}
	if mode != "dense" { // sparse (BM25) ranking
		sparse := s.bm25.index(col).scores(query)
		rankings = append(rankings, rankDesc(sparse, eligible))
	}

	fused := fuseRRF(len(col.Chunks), rankings...)
	order := rankDesc(fused, eligible)
	if len(order) > topK {
		order = order[:topK]
	}
	hits := make([]Hit, 0, len(order))
	for _, i := range order {
		ch := col.Chunks[i]
		hits = append(hits, Hit{ID: ch.ID, DocID: ch.DocID, Section: ch.Section, Text: ch.Text,
			Classification: ch.Classification, Source: ch.Source, Score: float32(fused[i])})
	}
	return hits, nil
}

// Collection returns an ingested collection by name.
func (s *Subsystem) Collection(name string) (Collection, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.collections[name]
	return c, ok
}

// List summarizes ingested collections (name order — deterministic for the console).
func (s *Subsystem) List() []Collection {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Collection, 0, len(s.collections))
	for _, c := range s.collections {
		out = append(out, c)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Name < out[j-1].Name; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// Corpora lists the available synthetic sources.
func Corpora() []string {
	names := make([]string, 0, len(corpora))
	for n := range corpora {
		names = append(names, n)
	}
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j-1], names[j] = names[j], names[j-1]
		}
	}
	return names
}

// splitSentences splits on sentence-ending periods (mirrors the sim's lookbehind split).
func splitSentences(doc string) []string {
	var out []string
	for _, part := range strings.SplitAfter(doc, ". ") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
