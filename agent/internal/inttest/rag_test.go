package inttest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"dani.local/agent/internal/artifact"
	"dani.local/agent/internal/controller"
	"dani.local/agent/internal/engine"
	"dani.local/agent/internal/identity"
	"dani.local/agent/internal/ingest"
	"dani.local/agent/internal/modelreg"
	"dani.local/agent/internal/serving"
	"dani.local/agent/internal/training"
)

// TestRagEndToEnd drives a RAG-compound alias through the REAL data plane: gateway resolves the
// alias, authorizes the caller (D-09 ceiling), retrieves classification-filtered chunks, augments,
// and routes the request to a worker over mTLS — citations come back in the response headers.
func TestRagEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctrl, err := controller.Genesis(ctx, "AcmeBank", "dep-1", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := ctrl.Serve(lis)
	defer srv.Stop()

	plane, err := serving.NewPlane(serving.Identity{
		LeafRaw: ctrl.Cert.Raw, InterRaw: ctrl.CA.Intermediate.Raw, Key: ctrl.Key, Root: ctrl.CA.Root, UUID: ctrl.ID,
	}, "site-hq")
	if err != nil {
		t.Fatal(err)
	}
	linkAddr, _ := plane.ServeLink("127.0.0.1:0")
	_, linkPort, _ := net.SplitHostPort(linkAddr)

	// training/RAG surface with real ingest (BoW embedder) + aliases
	store, _ := artifact.Open(t.TempDir())
	models := modelreg.New(ctrl.KS, store)
	if err := models.InitSigners(ctx); err != nil {
		t.Fatal(err)
	}
	ident := identity.New("entra-id")
	ing := ingest.New()
	if _, err := ing.Ingest("legal"); err != nil {
		t.Fatal(err)
	}
	models.RegisterRagAlias("stub-slm", "legal")
	sub := training.New(training.Deps{
		Identity: serving.IdentAdapter{B: ident}, Data: serving.IngestAdapter{S: ing},
		Fleet: serving.PlaneRegistryFleet{Plane: plane, Reg: ctrl.Registry},
		Registry: models, Store: store, Trainer: training.StubTrainer{},
	})
	plane.EnableTraining(&serving.TrainingAPI{Ident: ident, Ingest: ing, Models: models, Training: sub, Store: store})
	gwAddr, _ := plane.ServeGateway("127.0.0.1:0")

	// a restricted-cleared stub worker serving the BASE model
	id := mustEnrollNamed(t, ctx, ctrl, lis.Addr().String(), "worker-rag")
	w := serving.NewWorker(serving.WorkerConfig{
		Identity: servingIdentityFromNode(id), Engine: engine.NewStub("stub-slm"), ModelID: "stub-slm",
		Class: "restricted", AdvertiseHost: "127.0.0.1",
		ControllerURLs: []string{"https://127.0.0.1:" + linkPort}, MaxConcurrent: 4, HeartbeatEvery: 200 * time.Millisecond,
	})
	go func() { _ = w.Serve(ctx, "127.0.0.1:0") }()
	if !waitFleet(t, gwAddr, 1, 5*time.Second) {
		t.Fatal("worker never registered")
	}

	// the alias is offered in /v1/models because its base is live
	mresp, _ := http.Get("http://" + gwAddr + "/v1/models")
	mb, _ := io.ReadAll(mresp.Body)
	mresp.Body.Close()
	if !strings.Contains(string(mb), "stub-slm-rag-legal") {
		t.Fatalf("alias missing from /v1/models: %s", mb)
	}

	// alice asks through the ALIAS: augmented, routed, answered — with citations
	body, _ := json.Marshal(map[string]any{
		"model":      "stub-slm-rag-legal",
		"messages":   []engine.Message{{Role: "user", Content: "What does the data processing addendum require?"}},
		"max_tokens": 64,
	})
	req, _ := http.NewRequest(http.MethodPost, "http://"+gwAddr+"/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Dani-User", "alice")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("rag chat failed: %d %s", resp.StatusCode, b)
	}
	cites := resp.Header.Get("X-Dani-Rag-Chunks")
	if !strings.Contains(cites, "legal/doc-") || !strings.Contains(cites, "restricted") {
		t.Fatalf("citations missing: %q", cites)
	}
	if got := resp.Header.Get("X-Dani-Classification"); got != "restricted" {
		t.Fatalf("augmented classification should be restricted, got %q", got)
	}
	if resp.Header.Get("X-Dani-Served-By") == "" {
		t.Fatal("routing trace missing")
	}

	// carol (internal) asking restricted-scanning content is DENIED at the gateway (D-09 ceiling)
	dreq, _ := http.NewRequest(http.MethodPost, "http://"+gwAddr+"/v1/chat/completions", bytes.NewReader(
		[]byte(`{"model":"stub-slm-rag-legal","messages":[{"role":"user","content":"summarize the revenue and capital risk"}]}`)))
	dreq.Header.Set("X-Dani-User", "carol")
	dresp, _ := http.DefaultClient.Do(dreq)
	db, _ := io.ReadAll(dresp.Body)
	dresp.Body.Close()
	if dresp.StatusCode != http.StatusForbidden || !strings.Contains(string(db), "policy") {
		t.Fatalf("carol must be denied by the ceiling, got %d %s", dresp.StatusCode, db)
	}
}
