package serving

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"dani.local/agent/internal/artifact"
	"dani.local/agent/internal/engine"
)

// fakeGateway is a plain-HTTP stand-in for the controller gateway's deploy surface.
func fakeGateway(t *testing.T, model string, blob []byte, reported *int64) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/dani/deployments", func(rw http.ResponseWriter, r *http.Request) {
		json.NewEncoder(rw).Encode(map[string]any{"deployments": []map[string]string{{"Model": model, "State": "assigned"}}})
	})
	mux.HandleFunc("/dani/models/artifact", func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("X-Dani-Artifact-Hash", artifact.HashOf(blob))
		rw.Write(blob)
	})
	mux.HandleFunc("/dani/deployments/report", func(rw http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(reported, 1)
		rw.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func TestDeployLoopPullsLoadsReports(t *testing.T) {
	eng := engine.NewStub("base")
	var reported int64
	ts := fakeGateway(t, "base-ft-hr-v1", []byte("adapter-bytes"), &reported)
	w := NewWorker(WorkerConfig{Engine: eng, ModelID: "base", Class: "restricted", GatewayURL: ts.URL})
	w.id.UUID = "w-test"
	w.deployEvery = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.deployLoop(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for atomic.LoadInt64(&reported) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("deploy loop never reported")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if loaded := eng.Loaded(); len(loaded) != 1 || loaded[0] != "base-ft-hr-v1" {
		t.Fatalf("engine not loaded: %v", loaded)
	}
	// the loop must not re-deploy (done-set); give it a few more ticks
	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt64(&reported); got != 1 {
		t.Fatalf("re-reported a done deployment: %d", got)
	}
}

func TestDeployLoopUnloadsRemovedAssignment(t *testing.T) {
	// gateway first assigns the model, then withdraws it (operator undeploy / scale-down):
	// the worker must Unload so the engine stops advertising it.
	eng := engine.NewStub("base")
	blob := []byte("adapter-bytes")
	var withdrawn atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/dani/deployments", func(rw http.ResponseWriter, _ *http.Request) {
		if withdrawn.Load() {
			json.NewEncoder(rw).Encode(map[string]any{"deployments": []map[string]string{}})
			return
		}
		json.NewEncoder(rw).Encode(map[string]any{"deployments": []map[string]string{{"Model": "base-ft-hr-v1", "State": "assigned"}}})
	})
	mux.HandleFunc("/dani/models/artifact", func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("X-Dani-Artifact-Hash", artifact.HashOf(blob))
		rw.Write(blob)
	})
	mux.HandleFunc("/dani/deployments/report", func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusOK) })
	ts := httptest.NewServer(mux)
	defer ts.Close()

	w := NewWorker(WorkerConfig{Engine: eng, ModelID: "base", Class: "restricted", GatewayURL: ts.URL})
	w.id.UUID = "w-unload"
	w.deployEvery = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.deployLoop(ctx)

	waitFor := func(cond func() bool, msg string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatal(msg)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitFor(func() bool { return len(eng.Loaded()) == 1 }, "model never loaded")
	withdrawn.Store(true)
	waitFor(func() bool { return len(eng.Loaded()) == 0 }, "withdrawn assignment never unloaded")
	// and a re-assignment re-deploys (the done-set entry was cleared)
	withdrawn.Store(false)
	waitFor(func() bool { return len(eng.Loaded()) == 1 }, "re-assignment never re-deployed")
}

func TestPullAndLoadErrors(t *testing.T) {
	eng := engine.NewStub("base")
	w := NewWorker(WorkerConfig{Engine: eng, ModelID: "base", GatewayURL: "http://127.0.0.1:1"})
	client := &http.Client{Timeout: 2 * time.Second}
	// dial failure
	if err := w.pullAndLoad(client, eng, "m"); err == nil {
		t.Fatal("dial failure must error")
	}
	// refused pull (403)
	deny := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		http.Error(rw, "not routable", http.StatusForbidden)
	}))
	defer deny.Close()
	w.gatewayURL = deny.URL
	if err := w.pullAndLoad(client, eng, "m"); err == nil {
		t.Fatal("refused pull must error")
	}
	// hash mismatch: served bytes don't match the advertised hash
	lie := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("X-Dani-Artifact-Hash", artifact.HashOf([]byte("promised")))
		fmt.Fprint(rw, "delivered-something-else")
	}))
	defer lie.Close()
	w.gatewayURL = lie.URL
	if err := w.pullAndLoad(client, eng, "m"); err == nil {
		t.Fatal("hash mismatch must refuse to load")
	}
	if len(eng.Loaded()) != 0 {
		t.Fatal("nothing may load after failures")
	}
}

func TestDeployLoopDefaultsAndDeadGateway(t *testing.T) {
	// default interval branch (deployEvery unset) + unreachable-gateway GET error branch
	eng := engine.NewStub("base")
	w := NewWorker(WorkerConfig{Engine: eng, ModelID: "base", GatewayURL: "http://127.0.0.1:1"})
	w.id.UUID = "w-dead"
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	w.deployLoop(ctx) // default 3s ticker: exits on ctx before the first tick fires
	w2 := NewWorker(WorkerConfig{Engine: eng, ModelID: "base", GatewayURL: "http://127.0.0.1:1"})
	w2.id.UUID = "w-dead2"
	w2.deployEvery = 10 * time.Millisecond
	ctx2, cancel2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel2()
	w2.deployLoop(ctx2) // GET fails every tick; loop must survive
	if len(eng.Loaded()) != 0 {
		t.Fatal("nothing may load from a dead gateway")
	}
}

func TestPullAndLoadBodyReadError(t *testing.T) {
	// a truncated body (Content-Length lies) makes io.ReadAll fail
	lie := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Length", "100")
		rw.WriteHeader(http.StatusOK)
		rw.(http.Flusher).Flush()
		// write only 5 of the promised 100 bytes, then hijack-close
		rw.Write([]byte("short"))
	}))
	defer lie.Close()
	eng := engine.NewStub("base")
	w := NewWorker(WorkerConfig{Engine: eng, ModelID: "base", GatewayURL: lie.URL})
	client := &http.Client{Timeout: 2 * time.Second}
	if err := w.pullAndLoad(client, eng, "m"); err == nil {
		t.Fatal("truncated body must error")
	}
}

func TestDeployLoopToleratesBadGateway(t *testing.T) {
	// malformed deployments JSON + dead gateway: the loop keeps ticking without loading anything
	bad := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(rw, "{not json")
	}))
	defer bad.Close()
	eng := engine.NewStub("base")
	w := NewWorker(WorkerConfig{Engine: eng, ModelID: "base", GatewayURL: bad.URL})
	w.id.UUID = "w-bad"
	w.deployEvery = 10 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	w.deployLoop(ctx) // returns on ctx done; must not panic or load
	if len(eng.Loaded()) != 0 {
		t.Fatal("bad gateway must not cause loads")
	}
	// deploy failure path: assignments exist but the artifact pull always fails
	var reported int64
	mux := http.NewServeMux()
	mux.HandleFunc("/dani/deployments", func(rw http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(rw).Encode(map[string]any{"deployments": []map[string]string{{"Model": "m", "State": "assigned"}}})
	})
	mux.HandleFunc("/dani/models/artifact", func(rw http.ResponseWriter, _ *http.Request) {
		http.Error(rw, "boom", http.StatusInternalServerError)
	})
	mux.HandleFunc("/dani/deployments/report", func(rw http.ResponseWriter, _ *http.Request) { atomic.AddInt64(&reported, 1) })
	ts := httptest.NewServer(mux)
	defer ts.Close()
	w2 := NewWorker(WorkerConfig{Engine: eng, ModelID: "base", GatewayURL: ts.URL})
	w2.id.UUID = "w2"
	w2.deployEvery = 10 * time.Millisecond
	ctx2, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()
	w2.deployLoop(ctx2)
	if atomic.LoadInt64(&reported) != 0 {
		t.Fatal("failed deploys must not be reported loaded")
	}
}
