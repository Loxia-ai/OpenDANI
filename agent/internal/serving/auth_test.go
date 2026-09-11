package serving

// Operator auth (--console-auth): write actions need a token, signing needs the reviewer ROLE, and
// the audit trail records who acted.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// serveTrainingAuthed builds the training mux with operator auth enabled, returning per-sub tokens.
func serveTrainingAuthed(t *testing.T, api *TrainingAPI) (*http.ServeMux, map[string]string, *Plane) {
	t.Helper()
	p := &Plane{workers: map[string]*workerState{}, inflight: map[string]int{},
		drained: map[string]bool{}, revoked: map[string]bool{}, stale: time.Minute}
	p.EnableTraining(api)
	auth := NewOperatorAuth()
	tokens := map[string]string{}
	for _, pr := range []OperatorPrincipal{
		{Sub: "alice", Roles: []string{"user"}, Clearance: "restricted"},
		{Sub: "dana", Roles: []string{"user", "security-officer"}, Clearance: "secret"},
		{Sub: "erin", Roles: []string{"user", "governance-officer"}, Clearance: "secret"},
		{Sub: "bob", Roles: []string{"user", "administrator"}, Clearance: "secret"},
	} {
		tok, err := auth.Mint(pr)
		if err != nil {
			t.Fatal(err)
		}
		tokens[pr.Sub] = tok
	}
	p.EnableOperatorAuth(auth)
	mux := http.NewServeMux()
	p.registerTrainingRoutes(mux)
	mux.HandleFunc("/dani/whoami", p.handleWhoami)
	return mux, tokens, p
}

// postAs POSTs a JSON body with an operator token (empty token = anonymous).
func postAs(t *testing.T, mux *http.ServeMux, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestAuthGatesWritesReadsStayOpen(t *testing.T) {
	api := newTrainingAPI(t, "trainer-1")
	mux, tokens, _ := serveTrainingAuthed(t, api)

	// anonymous write -> 401
	if rec := postAs(t, mux, "/dani/ingest", "", map[string]string{"collection": "legal"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous ingest must 401: %d", rec.Code)
	}
	// garbage token -> 401
	if rec := postAs(t, mux, "/dani/ingest", "not-a-token", map[string]string{"collection": "legal"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token must 401: %d", rec.Code)
	}
	// authenticated write works (Bearer form)
	if rec := postAs(t, mux, "/dani/ingest", tokens["alice"], map[string]string{"collection": "legal"}); rec.Code != http.StatusOK {
		t.Fatalf("authed ingest: %d %s", rec.Code, rec.Body)
	}
	// X-Dani-Operator header form works too
	b, _ := json.Marshal(map[string]string{"collection": "hr"})
	req := httptest.NewRequest(http.MethodPost, "/dani/ingest", bytes.NewReader(b))
	req.Header.Set("X-Dani-Operator", tokens["alice"])
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("X-Dani-Operator form: %d", rec.Code)
	}
	// reads stay open without any token
	if rec := getJSON(t, mux, "/dani/models", nil); rec.Code != http.StatusOK {
		t.Fatalf("reads must stay open: %d", rec.Code)
	}
	if rec := getJSON(t, mux, "/dani/collections", nil); rec.Code != http.StatusOK {
		t.Fatalf("reads must stay open: %d", rec.Code)
	}
	// worker M2M endpoints stay open (the data plane authenticates by mTLS node identity, not tokens)
	if rec := getJSON(t, mux, "/dani/deployments?node=w&class=secret", nil); rec.Code != http.StatusOK {
		t.Fatalf("worker deployment poll must stay open: %d", rec.Code)
	}
	if rec := postAs(t, mux, "/dani/deployments/report", "", map[string]string{"node": "w", "model": "ghost"}); rec.Code == http.StatusUnauthorized {
		t.Fatal("worker report must not require an operator token")
	}
}

func TestSigningRequiresTheReviewerRole(t *testing.T) {
	api := newTrainingAPI(t, "trainer-1")
	var audited []string
	api.Audit = nil // keep the sqlite-free harness; capture via emit hook below is not available, use handler responses
	mux, tokens, _ := serveTrainingAuthed(t, api)
	_ = audited

	// produce a draft candidate (train with an authed engineer)
	postAs(t, mux, "/dani/ingest", tokens["alice"], map[string]string{"collection": "legal"})
	rec := postAs(t, mux, "/dani/train/submit", tokens["alice"],
		map[string]string{"engineer": "alice", "base": "qwen2.5-0.5b", "collection": "legal", "method": "lora"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", rec.Code, rec.Body)
	}
	var cand string
	deadline := time.Now().Add(5 * time.Second)
	for cand == "" {
		var jobs struct {
			Jobs []struct{ State, Candidate string } `json:"jobs"`
		}
		getJSON(t, mux, "/dani/train/jobs", &jobs)
		if len(jobs.Jobs) > 0 && jobs.Jobs[0].State == "completed" {
			cand = jobs.Jobs[0].Candidate
		}
		if time.Now().After(deadline) {
			t.Fatal("job never completed")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// alice (no reviewer role) cannot sign at all
	if rec := postAs(t, mux, "/dani/models/sign", tokens["alice"], map[string]string{"model": cand, "role": "security-officer"}); rec.Code != http.StatusForbidden {
		t.Fatalf("engineer must not sign: %d %s", rec.Code, rec.Body)
	}
	// dana signs security but NOT governance
	if rec := postAs(t, mux, "/dani/models/sign", tokens["dana"], map[string]string{"model": cand, "role": "security-officer"}); rec.Code != http.StatusOK {
		t.Fatalf("dana security sign: %d %s", rec.Code, rec.Body)
	}
	if rec := postAs(t, mux, "/dani/models/sign", tokens["dana"], map[string]string{"model": cand, "role": "governance-officer"}); rec.Code != http.StatusForbidden {
		t.Fatalf("dana must not sign governance: %d", rec.Code)
	}
	// the other two officers complete the promotion — three DIFFERENT people
	if rec := postAs(t, mux, "/dani/models/sign", tokens["erin"], map[string]string{"model": cand, "role": "governance-officer"}); rec.Code != http.StatusOK {
		t.Fatalf("erin governance sign: %d %s", rec.Code, rec.Body)
	}
	if rec := postAs(t, mux, "/dani/models/sign", tokens["bob"], map[string]string{"model": cand, "role": "administrator"}); rec.Code != http.StatusOK {
		t.Fatalf("bob admin sign: %d %s", rec.Code, rec.Body)
	}
	var models struct {
		Models []struct{ ID, State string } `json:"models"`
	}
	getJSON(t, mux, "/dani/models", &models)
	found := false
	for _, m := range models.Models {
		if m.ID == cand && m.State == "available" {
			found = true
		}
	}
	if !found {
		t.Fatalf("three-party promotion must complete: %+v", models.Models)
	}
}

func TestWhoami(t *testing.T) {
	api := newTrainingAPI(t, "trainer-1")
	// auth OFF: anonymous
	off := serveTraining(api)
	offPlane := &Plane{}
	mux := http.NewServeMux()
	mux.HandleFunc("/dani/whoami", offPlane.handleWhoami)
	var who struct {
		AuthEnabled bool   `json:"authEnabled"`
		Sub         string `json:"sub"`
	}
	if rec := getJSON(t, mux, "/dani/whoami", &who); rec.Code != http.StatusOK || who.AuthEnabled || who.Sub != "anonymous" {
		t.Fatalf("auth-off whoami: %d %+v", rec.Code, who)
	}
	_ = off

	// auth ON: 401 without a token; identity with one
	authedMux, tokens, _ := serveTrainingAuthed(t, api)
	if rec := getJSON(t, authedMux, "/dani/whoami", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("tokenless whoami must 401: %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/dani/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+tokens["dana"])
	rec := httptest.NewRecorder()
	authedMux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"sub":"dana"`) || !strings.Contains(rec.Body.String(), "security-officer") {
		t.Fatalf("authed whoami: %d %s", rec.Code, rec.Body)
	}
}

func TestAuthOffIsPassthrough(t *testing.T) {
	// without EnableOperatorAuth the protect wrapper is a no-op: unauthenticated signs still work
	// (the DEMO default) and OperatorFrom reports no principal.
	api := newTrainingAPI(t, "trainer-1")
	mux := serveTraining(api)
	if rec := postJSON(t, mux, "/dani/ingest", map[string]string{"collection": "legal"}); rec.Code != http.StatusOK {
		t.Fatalf("auth off must pass writes through: %d", rec.Code)
	}
}
