package serving

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"dani.local/agent/internal/training"
)

// captureTrainer records the spec it ran and returns a fixed result.
type captureTrainer struct {
	spec training.Spec
	err  error
}

func (c *captureTrainer) Run(_ context.Context, spec training.Spec, onCkpt func(int, int)) (training.Result, error) {
	c.spec = spec
	if c.err != nil {
		return training.Result{}, c.err
	}
	onCkpt(1, 2)
	onCkpt(2, 2)
	return training.Result{Bytes: []byte("node-adapter"), Evals: map[string]float64{"eval_loss": 0.9}}, nil
}

func postTrain(t *testing.T, n *TrainerNode, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if s, ok := body.(string); ok {
		buf.WriteString(s)
	} else {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(http.MethodPost, "/train", &buf)
	rec := httptest.NewRecorder()
	n.handleTrain(rec, req)
	return rec
}

func TestTrainerNodeHandleTrain(t *testing.T) {
	ct := &captureTrainer{}
	n := NewTrainerNode(TrainerNodeConfig{Trainer: ct, WorkDir: t.TempDir()})
	staged := `{"datasetId":"ds-1","chunks":[{"text":"hello"}]}`
	rec := postTrain(t, n, training.WireRequest{
		Base: "qwen2.5-0.5b", Method: "qlora", DatasetID: "ds-1",
		DatasetB64: base64.StdEncoding.EncodeToString([]byte(staged)),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	// The response IS the marker stream — decode it with the shared parser.
	var last int
	res, err := training.ParseMarkers(strings.NewReader(rec.Body.String()), func(done, total int) { last = done })
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Bytes) != "node-adapter" || last != 2 {
		t.Fatalf("stream wrong: %+v last=%d", res, last)
	}
	// The trainer ran against a locally-staged copy of EXACTLY the shipped dataset bytes.
	if ct.spec.DatasetFile == "" {
		t.Fatal("dataset file not staged")
	}
	if _, err := os.Stat(ct.spec.DatasetFile); !os.IsNotExist(err) {
		t.Fatal("staged dataset should be cleaned up after the job")
	}
	if ct.spec.BaseModelID != "qwen2.5-0.5b" || ct.spec.Method != "qlora" {
		t.Fatalf("spec wrong: %+v", ct.spec)
	}
}

func TestTrainerNodeHandleTrainErrors(t *testing.T) {
	n := NewTrainerNode(TrainerNodeConfig{Trainer: &captureTrainer{}, WorkDir: t.TempDir()})
	// method guard
	req := httptest.NewRequest(http.MethodGet, "/train", nil)
	rec := httptest.NewRecorder()
	n.handleTrain(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET should be 405, got %d", rec.Code)
	}
	// bad body
	if rec := postTrain(t, n, "{not json"); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad body should 400, got %d", rec.Code)
	}
	// bad dataset encoding
	if rec := postTrain(t, n, training.WireRequest{DatasetID: "x", DatasetB64: "@@@"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad b64 should 400, got %d", rec.Code)
	}
	// unstageable dataset (WorkDir is a file, not a dir)
	f := t.TempDir() + "/afile"
	os.WriteFile(f, []byte("x"), 0o600)
	nBad := NewTrainerNode(TrainerNodeConfig{Trainer: &captureTrainer{}, WorkDir: f + "/sub"})
	if rec := postTrain(t, nBad, training.WireRequest{DatasetID: "x", DatasetB64: base64.StdEncoding.EncodeToString([]byte("d"))}); rec.Code != http.StatusInternalServerError {
		t.Fatalf("unstageable dataset should 500, got %d", rec.Code)
	}
	// trainer failure -> ERROR marker in a 200 stream (the job already started)
	nErr := NewTrainerNode(TrainerNodeConfig{Trainer: &captureTrainer{err: errors.New("cuda oom")}, WorkDir: t.TempDir()})
	rec = postTrain(t, nErr, training.WireRequest{DatasetID: "x"})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ERROR cuda oom") {
		t.Fatalf("trainer failure should stream ERROR, got %d %q", rec.Code, rec.Body)
	}
	if _, err := training.ParseMarkers(strings.NewReader(rec.Body.String()), func(int, int) {}); err == nil {
		t.Fatal("the controller-side parser must surface the streamed ERROR")
	}
}

func TestTrainerNodeDefaults(t *testing.T) {
	n := NewTrainerNode(TrainerNodeConfig{Trainer: &captureTrainer{}})
	if n.cfg.HeartbeatEvery != 3*time.Second || n.cfg.AdvertiseHost != "127.0.0.1" || n.cfg.WorkDir == "" {
		t.Fatalf("defaults wrong: %+v", n.cfg)
	}
}

// --- PlaneRegistryFleet ---

type stubRoles struct {
	uuids []string
	err   error
}

func (s stubRoles) ActiveNodesWithRole(context.Context, string) ([]string, error) {
	return s.uuids, s.err
}

func planeWithTrainers(infos ...Heartbeat) *Plane {
	p := &Plane{workers: map[string]*workerState{}, inflight: map[string]int{}, stale: time.Minute}
	for _, hb := range infos {
		p.workers[hb.NodeUUID] = &workerState{Heartbeat: hb, LastSeen: time.Now()}
	}
	return p
}

func TestPlaneRegistryFleet(t *testing.T) {
	live := Heartbeat{NodeUUID: "trainer-1", DispatchAddr: "10.0.0.5:9444", Trainer: true, Health: "healthy"}
	// live + role-verified => remote execution with the /train address
	f := PlaneRegistryFleet{Plane: planeWithTrainers(live), Reg: stubRoles{uuids: []string{"trainer-1"}}, Ctx: context.Background()}
	if u, addr, ok := f.ActiveTrainer(); !ok || u != "trainer-1" || addr != "10.0.0.5:9444" {
		t.Fatalf("want live remote trainer, got %q %q %v", u, addr, ok)
	}
	// live heartbeat WITHOUT the registry role => untrusted; falls back to registry-only allocation
	f2 := PlaneRegistryFleet{Plane: planeWithTrainers(live), Reg: stubRoles{uuids: []string{"other-trainer"}}}
	if u, addr, ok := f2.ActiveTrainer(); !ok || u != "other-trainer" || addr != "" {
		t.Fatalf("unverified heartbeat must not win, got %q %q %v", u, addr, ok)
	}
	// no live trainers => registry-only (local execution)
	f3 := PlaneRegistryFleet{Plane: planeWithTrainers(), Reg: stubRoles{uuids: []string{"t"}}}
	if u, addr, ok := f3.ActiveTrainer(); !ok || u != "t" || addr != "" {
		t.Fatalf("registry fallback wrong: %q %q %v", u, addr, ok)
	}
	// registry empty / error => no allocation
	if _, _, ok := (PlaneRegistryFleet{Plane: planeWithTrainers(live), Reg: stubRoles{}}).ActiveTrainer(); ok {
		t.Fatal("no registry trainers should fail")
	}
	if _, _, ok := (PlaneRegistryFleet{Plane: planeWithTrainers(live), Reg: stubRoles{err: errors.New("db")}}).ActiveTrainer(); ok {
		t.Fatal("registry error should fail")
	}
}

func TestTrainerExcludedFromRouting(t *testing.T) {
	p := newTestPlane("site-hq",
		hb("worker-1", "m1", "secret", "site-hq", 500),
		workerState{Heartbeat: Heartbeat{NodeUUID: "trainer-1", DispatchAddr: "t:9444", ModelID: "m1",
			Class: "secret", MaxConcurrent: 8, QueueDepth: 8, Health: "healthy", Trainer: true}},
	)
	// reserve must never pick the trainer, even though it "serves" the same model id
	for i := 0; i < 5; i++ {
		c, ok := p.reserve("m1", "unrestricted", "", nil)
		if !ok || c.uuid == "trainer-1" {
			t.Fatalf("trainer must never serve inference (got %q ok=%v)", c.uuid, ok)
		}
	}
	// fleet ETA ignores the trainer
	if _, any := p.fleetETA("m1", "unrestricted"); !any {
		t.Fatal("worker should still match")
	}
	// /v1/models ignores the trainer's model id
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	rec := httptest.NewRecorder()
	p.handleModels(rec, req)
	if strings.Count(rec.Body.String(), `"m1"`) != 1 {
		t.Fatalf("trainer must not contribute models: %s", rec.Body)
	}
	// ActiveTrainers lists it (sorted), Dialer accessor works
	ts := p.ActiveTrainers()
	if len(ts) != 1 || ts[0].UUID != "trainer-1" || ts[0].Addr != "t:9444" {
		t.Fatalf("ActiveTrainers wrong: %+v", ts)
	}
	_ = p.Dialer() // nil for a bare test plane; accessor covered
}
