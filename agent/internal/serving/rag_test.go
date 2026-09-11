package serving

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func ragAPI(t *testing.T) *TrainingAPI {
	t.Helper()
	api := newTrainingAPI(t, "trainer-1")
	if _, err := api.Ingest.Ingest("legal"); err != nil { // restricted chunks
		t.Fatal(err)
	}
	if _, err := api.Ingest.Ingest("hr"); err != nil { // internal chunks
		t.Fatal(err)
	}
	api.Models.RegisterRagAlias("qwen2.5-0.5b", "legal")
	api.Models.RegisterRagAlias("qwen2.5-0.5b", "hr")
	return api
}

func chatBody(t *testing.T, model, q string) []byte {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"model": model,
		"messages": []map[string]string{{"role": "user", "content": q}}, "max_tokens": 64})
	return b
}

func TestBuildRagChatHappyPath(t *testing.T) {
	api := ragAPI(t)
	alias, _ := api.Models.ResolveRag("qwen2.5-0.5b-rag-legal")
	// alice: restricted clearance — sees the legal chunks
	out, status, err := api.buildRagChat(chatBody(t, alias.Alias, "what does the data processing addendum require?"), alias, "alice", "secret")
	if err != nil {
		t.Fatalf("status=%d err=%v", status, err)
	}
	if out.baseModel != "qwen2.5-0.5b" || len(out.hits) == 0 {
		t.Fatalf("outcome wrong: base=%s hits=%d", out.baseModel, len(out.hits))
	}
	// retrieval raised the routing classification to the chunks' level (restricted)
	if out.classification != "restricted" {
		t.Fatalf("augmented classification should be restricted, got %s", out.classification)
	}
	// the rewritten body targets the base model and injects the excerpts as a system message
	var rew struct {
		Model    string    `json:"model"`
		Messages []chatMsg `json:"messages"`
	}
	json.Unmarshal(out.body, &rew)
	if rew.Model != "qwen2.5-0.5b" || rew.Messages[0].Role != "system" ||
		!strings.Contains(rew.Messages[0].Content, "Data processing addendum") {
		t.Fatalf("augmentation wrong: %+v", rew.Messages[0])
	}
	if rew.Messages[len(rew.Messages)-1].Role != "user" {
		t.Fatal("original messages must follow the system context")
	}
}

func TestBuildRagChatClearanceFiltersRetrieval(t *testing.T) {
	api := ragAPI(t)
	alias, _ := api.Models.ResolveRag("qwen2.5-0.5b-rag-legal")
	// carol: internal clearance — the restricted legal chunks are INVISIBLE (D-09 ceiling)
	out, _, err := api.buildRagChat(chatBody(t, alias.Alias, "what does the addendum say?"), alias, "carol", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.hits) != 0 {
		t.Fatalf("carol must see no restricted chunks, got %d", len(out.hits))
	}
	var rew struct {
		Messages []chatMsg `json:"messages"`
	}
	json.Unmarshal(out.body, &rew)
	if !strings.Contains(rew.Messages[0].Content, "No excerpts") {
		t.Fatal("empty retrieval must instruct the model to say no sources are available")
	}
	// same question on hr (internal) IS visible to carol
	aliasHR, _ := api.Models.ResolveRag("qwen2.5-0.5b-rag-hr")
	out2, _, err := api.buildRagChat(chatBody(t, aliasHR.Alias, "what does the parental leave policy provide?"), aliasHR, "carol", "secret")
	if err != nil || len(out2.hits) == 0 {
		t.Fatalf("carol should retrieve from hr: %v %d", err, len(out2.hits))
	}
}

func TestBuildRagChatDenialsAndErrors(t *testing.T) {
	api := ragAPI(t)
	alias, _ := api.Models.ResolveRag("qwen2.5-0.5b-rag-hr")
	// F-02 ceiling: carol (internal) asks about restricted-scanning content -> 403
	_, status, err := api.buildRagChat(chatBody(t, alias.Alias, "summarize our revenue and capital risk exposure"), alias, "carol", "secret")
	if err == nil || status != 403 || !strings.Contains(err.Error(), "policy") {
		t.Fatalf("expected 403 ceiling denial, got %d %v", status, err)
	}
	// guest (unrestricted) is denied even on internal-scanning content? No — content scan drives it:
	// benign content passes for guest on an internal collection (retrieval just filters chunks).
	out, _, err := api.buildRagChat(chatBody(t, alias.Alias, "hello there"), alias, "guest", "secret")
	if err != nil || len(out.hits) != 0 {
		t.Fatalf("guest benign prompt: err=%v hits=%d (internal chunks invisible)", err, len(out.hits))
	}
	// unknown user -> 404
	if _, status, err := api.buildRagChat(chatBody(t, alias.Alias, "q"), alias, "mallory", "secret"); err == nil || status != 404 {
		t.Fatal("unknown user must 404")
	}
	// malformed body -> 400
	if _, status, err := api.buildRagChat([]byte("{"), alias, "alice", "secret"); err == nil || status != 400 {
		t.Fatal("malformed body must 400")
	}
	// alias over a collection that later disappears -> 404 from Retrieve
	ghost := api.Models.RegisterRagAlias("qwen2.5-0.5b", "never-ingested")
	if _, status, err := api.buildRagChat(chatBody(t, ghost.Alias, "q"), ghost, "alice", "secret"); err == nil || status != 404 {
		t.Fatal("un-ingested collection must 404")
	}
}

func TestHandleRagAlias(t *testing.T) {
	api := ragAPI(t)
	mux := serveTraining(api)
	// GET lists registered aliases (the fixture pre-registers some)
	var aliases struct {
		Aliases []struct{ Alias string } `json:"aliases"`
	}
	if rec := getJSON(t, mux, "/dani/rag/alias", &aliases); rec.Code != http.StatusOK {
		t.Fatalf("GET must list aliases: %d", rec.Code)
	}
	baseline := len(aliases.Aliases)
	if rec := postJSON(t, mux, "/dani/rag/alias", map[string]string{"base": "m"}); rec.Code != http.StatusBadRequest {
		t.Fatal("missing collection must 400")
	}
	if rec := postJSON(t, mux, "/dani/rag/alias", map[string]string{"base": "m", "collection": "ghost"}); rec.Code != http.StatusNotFound {
		t.Fatal("un-ingested collection must 404")
	}
	rec := postJSON(t, mux, "/dani/rag/alias", map[string]string{"base": "m", "collection": "legal"})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "m-rag-legal") {
		t.Fatalf("alias register failed: %d %s", rec.Code, rec.Body)
	}
	if _, ok := api.Models.ResolveRag("m-rag-legal"); !ok {
		t.Fatal("alias must resolve after registration")
	}
	// GET now includes the newly registered alias
	if rec := getJSON(t, mux, "/dani/rag/alias", &aliases); rec.Code != http.StatusOK || len(aliases.Aliases) != baseline+1 {
		t.Fatalf("GET must list the new alias: %d %+v", rec.Code, aliases)
	}
	found := false
	for _, a := range aliases.Aliases {
		if a.Alias == "m-rag-legal" {
			found = true
		}
	}
	if !found {
		t.Fatalf("m-rag-legal missing from alias list: %+v", aliases.Aliases)
	}
}

func TestGatewayRagDenialPath(t *testing.T) {
	// the denial happens BEFORE routing, so no workers are needed
	api := ragAPI(t)
	p := newTestPlane("site-hq")
	p.EnableTraining(api)
	alias, _ := api.Models.ResolveRag("qwen2.5-0.5b-rag-hr")
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(string(chatBody(t, alias.Alias, "revenue and capital risk report"))))
	req.Header.Set("X-Dani-User", "carol")
	rec := httptest.NewRecorder()
	p.handleGateway(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "policy") {
		t.Fatalf("gateway must surface the D-09 denial, got %d %s", rec.Code, rec.Body)
	}
}

func TestCitationsJSON(t *testing.T) {
	api := ragAPI(t)
	alias, _ := api.Models.ResolveRag("qwen2.5-0.5b-rag-legal")
	out, _, err := api.buildRagChat(chatBody(t, alias.Alias, "data processing addendum"), alias, "alice", "secret")
	if err != nil {
		t.Fatal(err)
	}
	s := citationsJSON(out.hits)
	if !strings.Contains(s, `"doc":"legal/doc-`) || !strings.Contains(s, `"class":"restricted"`) {
		t.Fatalf("citations JSON wrong: %s", s)
	}
	if citationsJSON(nil) != "[]" {
		t.Fatal("empty citations must be []")
	}
}
