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

// TestAutoDeployEndToEnd proves §6.17.4's final step with ZERO manual steps after the third
// signature: train -> sign x3 -> the worker's deploy loop pulls the artifact (hash-verified),
// hot-loads it, reports — and a chat aimed at the TUNED model id routes to it through the gateway.
func TestAutoDeployEndToEnd(t *testing.T) {
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

	store, _ := artifact.Open(t.TempDir())
	models := modelreg.New(ctrl.KS, store)
	if err := models.InitSigners(ctx); err != nil {
		t.Fatal(err)
	}
	ident := identity.New("entra-id")
	ing := ingest.New()
	if _, err := ing.Ingest("hr"); err != nil { // internal-classified data
		t.Fatal(err)
	}
	sub := training.New(training.Deps{
		Identity: serving.IdentAdapter{B: ident}, Data: serving.IngestAdapter{S: ing},
		Fleet: serving.PlaneRegistryFleet{Plane: plane, Reg: ctrl.Registry},
		Registry: models, Store: store, Trainer: training.StubTrainer{},
	})
	plane.EnableTraining(&serving.TrainingAPI{Ident: ident, Ingest: ing, Models: models, Training: sub, Store: store})
	gwAddr, _ := plane.ServeGateway("127.0.0.1:0")

	// a hot-load-capable worker (stub engine) with the gateway URL set — the deploy loop runs
	id := mustEnrollNamed(t, ctx, ctrl, lis.Addr().String(), "worker-hot")
	w := serving.NewWorker(serving.WorkerConfig{
		Identity: servingIdentityFromNode(id), Engine: engine.NewStub("base"), ModelID: "base",
		Class: "restricted", AdvertiseHost: "127.0.0.1",
		ControllerURLs: []string{"https://127.0.0.1:" + linkPort}, MaxConcurrent: 4, HeartbeatEvery: 200 * time.Millisecond,
		GatewayURL: "http://" + gwAddr,
	})
	go func() { _ = w.Serve(ctx, "127.0.0.1:0") }()
	if !waitFleet(t, gwAddr, 1, 5*time.Second) {
		t.Fatal("worker never registered")
	}

	// a trainer allocation target must exist (registry-only fallback: local stub executes)
	mustEnrollRole(t, ctx, ctrl, lis.Addr().String(), "trainer-x", []string{"trainer"})

	// train + sign x3 over HTTP — then TOUCH NOTHING
	gw := "http://" + gwAddr
	body, _ := json.Marshal(map[string]string{"engineer": "bob", "base": "base", "collection": "hr", "method": "lora"})
	resp, err := http.Post(gw+"/dani/train/submit", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var cand string
	deadline := time.Now().Add(8 * time.Second)
	for cand == "" {
		jr, _ := http.Get(gw + "/dani/train/jobs")
		var jobs struct {
			Jobs []struct{ State, Candidate string } `json:"jobs"`
		}
		json.NewDecoder(jr.Body).Decode(&jobs)
		jr.Body.Close()
		if len(jobs.Jobs) > 0 && jobs.Jobs[0].State == "completed" {
			cand = jobs.Jobs[0].Candidate
		}
		if time.Now().After(deadline) {
			t.Fatal("training never completed")
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, role := range []string{"security-officer", "governance-officer", "administrator"} {
		b, _ := json.Marshal(map[string]string{"model": cand, "role": role})
		r, err := http.Post(gw+"/dani/models/sign", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
	}

	// ... and the fleet picks it up on its own: deploy loop pulls+loads, heartbeat advertises it,
	// /v1/models lists it, and a chat routes to it.
	deadline = time.Now().Add(15 * time.Second)
	for {
		mr, _ := http.Get(gw + "/v1/models")
		mb, _ := io.ReadAll(mr.Body)
		mr.Body.Close()
		if strings.Contains(string(mb), cand) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tuned model never auto-deployed into /v1/models: %s", mb)
		}
		time.Sleep(200 * time.Millisecond)
	}
	chat, _ := json.Marshal(map[string]any{
		"model":    cand,
		"messages": []engine.Message{{Role: "user", Content: "hello tuned model"}},
	})
	cr, err := http.Post(gw+"/v1/chat/completions", "application/json", bytes.NewReader(chat))
	if err != nil {
		t.Fatal(err)
	}
	defer cr.Body.Close()
	if cr.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(cr.Body)
		t.Fatalf("chat with auto-deployed model failed: %d %s", cr.StatusCode, b)
	}
	if cr.Header.Get("X-Dani-Served-By") != "worker-hot" {
		t.Fatalf("expected worker-hot to serve, got %q", cr.Header.Get("X-Dani-Served-By"))
	}
	// the placement is recorded as loaded
	dr, _ := http.Get(gw + "/dani/models")
	db, _ := io.ReadAll(dr.Body)
	dr.Body.Close()
	if !strings.Contains(string(db), `"state":"loaded"`) || !strings.Contains(string(db), `"node":"worker-hot"`) {
		t.Fatalf("placement not recorded loaded: %s", db)
	}
}
