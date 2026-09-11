package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type mockGateway struct {
	mu        sync.Mutex
	jobState  string
	candidate string
	modelGate string
	signs     []string
	failSign  bool
	srv       *httptest.Server
}

func newMock(t *testing.T) *mockGateway {
	t.Helper()
	m := &mockGateway{jobState: "completed", candidate: "qwen-ft-legal-v1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/dani/fleet", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"count": 2, "workers": []any{
			map[string]any{"UUID": "trainer-1", "Health": "healthy", "Class": "restricted", "Trainer": true, "MaxConcurrent": 0},
			map[string]any{"UUID": "worker-0", "Model": "qwen", "Health": "healthy", "Class": "restricted", "Active": 1, "MaxConcurrent": 4},
		}})
	})
	mux.HandleFunc("/dani/models", func(w http.ResponseWriter, _ *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		state := "draft"
		if len(m.signs) == 3 {
			state = "available"
			if m.modelGate != "" {
				state = "draft"
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"models": []any{
			map[string]any{"id": m.candidate, "state": state, "classification": "restricted",
				"signatures": m.signs, "gate_failed": m.modelGate,
				"deployment": map[string]any{"Node": "worker-0", "State": "loaded"}},
		}})
	})
	mux.HandleFunc("/dani/train/jobs", func(w http.ResponseWriter, _ *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"jobs": []any{
			map[string]any{"ID": "job-1", "State": m.jobState, "Candidate": m.candidate, "TrainerUUID": "trainer-1", "CkptsDone": 3, "CkptsTotal": 3},
		}})
	})
	mux.HandleFunc("/dani/train/submit", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"ID": "job-1"})
	})
	mux.HandleFunc("/dani/models/sign", func(w http.ResponseWriter, r *http.Request) {
		if m.failSign {
			w.WriteHeader(403)
			json.NewEncoder(w).Encode(map[string]any{"error": "not in draft"})
			return
		}
		var b struct{ Role string }
		json.NewDecoder(r.Body).Decode(&b)
		m.mu.Lock()
		m.signs = append(m.signs, b.Role)
		m.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"id": m.candidate})
	})
	mux.HandleFunc("/dani/ingest", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"name": "legal", "chunks": []any{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}})
	})
	mux.HandleFunc("/dani/principals", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"principals": []string{"alice", "bob"}})
	})
	mux.HandleFunc("/dani/audit", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"records": 22, "signedHeads": 5, "integrity": map[string]any{"ok": true}})
	})
	mux.HandleFunc("/dani/audit/export", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"deployment": "dep-1", "events": 22, "bundle": map[string]any{"deployment": "dep-1"}})
	})
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func execCLI(t *testing.T, gw string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	full := append([]string{"--gateway", gw}, args...)
	code := run(full, &out, &errb)
	return code, out.String(), errb.String()
}

func TestReadCommands(t *testing.T) {
	m := newMock(t)
	gw := m.srv.URL
	if code, out, _ := execCLI(t, gw, "fleet"); code != 0 || !strings.Contains(out, "2 node") || !strings.Contains(out, "trainer") {
		t.Fatalf("fleet: %d %s", code, out)
	}
	m.signs = []string{"security-officer"}
	if code, out, _ := execCLI(t, gw, "models"); code != 0 || !strings.Contains(out, "sigs=1/3") || !strings.Contains(out, "@worker-0(loaded)") {
		t.Fatalf("models: %d %s", code, out)
	}
	if code, out, _ := execCLI(t, gw, "jobs"); code != 0 || !strings.Contains(out, "job-1") || !strings.Contains(out, "3/3") {
		t.Fatalf("jobs: %d %s", code, out)
	}
	if code, out, _ := execCLI(t, gw, "principals"); code != 0 || !strings.Contains(out, "alice") {
		t.Fatalf("principals: %d %s", code, out)
	}
	if code, out, _ := execCLI(t, gw, "audit"); code != 0 || !strings.Contains(out, "VERIFIED") || !strings.Contains(out, "22 records") {
		t.Fatalf("audit: %d %s", code, out)
	}
	if code, out, _ := execCLI(t, gw, "--json", "fleet"); code != 0 || !strings.Contains(out, "\"count\": 2") {
		t.Fatalf("json fleet: %d %s", code, out)
	}
}

func TestEmptyLists(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/dani/models", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"models":[]}`)) })
	mux.HandleFunc("/dani/train/jobs", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"jobs":[]}`)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	if code, out, _ := execCLI(t, srv.URL, "models"); code != 0 || !strings.Contains(out, "no models") {
		t.Fatalf("empty models: %d %s", code, out)
	}
	if code, out, _ := execCLI(t, srv.URL, "jobs"); code != 0 || !strings.Contains(out, "no jobs") {
		t.Fatalf("empty jobs: %d %s", code, out)
	}
}

func TestMutatingCommands(t *testing.T) {
	m := newMock(t)
	gw := m.srv.URL
	if code, out, _ := execCLI(t, gw, "ingest", "legal"); code != 0 || !strings.Contains(out, "ingested legal (12 chunks)") {
		t.Fatalf("ingest: %d %s", code, out)
	}
	if code, out, _ := execCLI(t, gw, "train", "alice", "qwen", "legal"); code != 0 || !strings.Contains(out, "submitted job job-1") {
		t.Fatalf("train: %d %s", code, out)
	}
	if code, out, _ := execCLI(t, gw, "sign", "m", "security-officer"); code != 0 || !strings.Contains(out, "signed m as security-officer") {
		t.Fatalf("sign: %d %s", code, out)
	}
	if code, out, _ := execCLI(t, gw, "audit", "export"); code != 0 || !strings.Contains(out, "\"bundle\"") {
		t.Fatalf("audit export: %d %s", code, out)
	}
	if code, out, _ := execCLI(t, gw, "audit", "export", "dep-custom"); code != 0 || !strings.Contains(out, "bundle") {
		t.Fatalf("audit export custom dep: %d %s", code, out)
	}
}

func TestPromoteHappyAndGateHeld(t *testing.T) {
	sleep = func(time.Duration) {}
	defer func() { sleep = time.Sleep }()
	m := newMock(t)
	code, out, _ := execCLI(t, m.srv.URL, "promote", "alice", "qwen", "legal")
	if code != 0 || !strings.Contains(out, "available") {
		t.Fatalf("promote happy: %d %s", code, out)
	}
	m2 := newMock(t)
	m2.modelGate = "safety 0.38 < min 0.80"
	code, out, _ = execCLI(t, m2.srv.URL, "promote", "alice", "qwen-unsafe", "legal")
	if code != 1 || !strings.Contains(out, "HELD") || !strings.Contains(out, "safety 0.38") {
		t.Fatalf("promote gate-held: %d %s", code, out)
	}
}

func TestPromoteJobFailed(t *testing.T) {
	sleep = func(time.Duration) {}
	defer func() { sleep = time.Sleep }()
	m := newMock(t)
	m.jobState = "failed"
	if code, _, errs := execCLI(t, m.srv.URL, "promote", "alice", "qwen", "legal"); code != 2 || !strings.Contains(errs, "training failed") {
		t.Fatalf("promote failed-job: %d %s", code, errs)
	}
}

func TestErrorsAndUsage(t *testing.T) {
	m := newMock(t)
	gw := m.srv.URL
	if code, _, _ := execCLI(t, gw); code != 2 {
		t.Fatal("no command must exit 2")
	}
	if code, _, e := execCLI(t, gw, "bogus"); code != 2 || !strings.Contains(e, "unknown command") {
		t.Fatal("unknown command must exit 2")
	}
	for _, a := range [][]string{{"ingest"}, {"train", "one"}, {"sign", "m"}, {"promote", "a"}} {
		if code, _, _ := execCLI(t, gw, a...); code != 2 {
			t.Fatalf("arity %v must exit 2", a)
		}
	}
	var o, e bytes.Buffer
	if code := run([]string{"--nope"}, &o, &e); code != 2 {
		t.Fatal("bad flag must exit 2")
	}
	m.failSign = true
	if code, _, e := execCLI(t, gw, "sign", "m", "security-officer"); code != 2 || !strings.Contains(e, "not in draft") {
		t.Fatalf("rejected sign: %d %s", code, e)
	}
}

func TestTransportErrors(t *testing.T) {
	bad := "http://127.0.0.1:1"
	for _, cmd := range [][]string{{"fleet"}, {"models"}, {"jobs"}, {"principals"}, {"audit"}, {"audit", "export"}, {"ingest", "x"}, {"train", "a", "b", "c"}, {"sign", "m", "r"}} {
		if code, _, _ := execCLI(t, bad, cmd...); code != 2 {
			t.Fatalf("unreachable %v must exit 2", cmd)
		}
	}
	if code, _, _ := execCLI(t, bad, "promote", "a", "b", "c"); code != 2 {
		t.Fatal("unreachable promote must exit 2")
	}
}

func TestEnvGatewayDefault(t *testing.T) {
	m := newMock(t)
	t.Setenv("DANI_GATEWAY", m.srv.URL)
	var out, errb bytes.Buffer
	if code := run([]string{"fleet"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "node") {
		t.Fatalf("DANI_GATEWAY default: %d %s", code, out.String())
	}
}

func TestUserHeaderAndJSONModes(t *testing.T) {
	m := newMock(t)
	gw := m.srv.URL
	if code, _, _ := execCLI(t, gw, "--user", "alice", "fleet"); code != 0 {
		t.Fatal("--user get path")
	}
	if code, _, _ := execCLI(t, gw, "--user", "alice", "ingest", "legal"); code != 0 {
		t.Fatal("--user post path")
	}
	for _, cmd := range []string{"models", "jobs", "audit"} {
		if code, out, _ := execCLI(t, gw, "--json", cmd); code != 0 || !strings.Contains(out, "{") {
			t.Fatalf("--json %s: %d %s", cmd, code, out)
		}
	}
}

func TestModelsGateDisplay(t *testing.T) {
	m := newMock(t)
	m.signs = []string{"security-officer", "governance-officer", "administrator"}
	m.modelGate = "safety 0.1 < min 0.8"
	if code, out, _ := execCLI(t, m.srv.URL, "models"); code != 0 || !strings.Contains(out, "gate:safety") {
		t.Fatalf("gate display: %d %s", code, out)
	}
}

func TestAuditFailed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/dani/audit", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"records":5,"integrity":{"ok":false,"why":"record hash mismatch"}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	if code, out, _ := execCLI(t, srv.URL, "audit"); code != 1 || !strings.Contains(out, "FAILED") {
		t.Fatalf("audit failed: %d %s", code, out)
	}
}

func TestSubmitNoID(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/dani/train/submit", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{}`)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	if code, _, e := execCLI(t, srv.URL, "train", "a", "b", "c"); code != 2 || !strings.Contains(e, "no job id") {
		t.Fatalf("no id: %d %s", code, e)
	}
}

func TestDecodeError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/dani/fleet", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`not json`)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	if code, _, e := execCLI(t, srv.URL, "fleet"); code != 2 || !strings.Contains(e, "decode") {
		t.Fatalf("decode err: %d %s", code, e)
	}
}

func TestPromoteWaitDotAndModelNotFound(t *testing.T) {
	sleep = func(time.Duration) {}
	defer func() { sleep = time.Sleep }()
	var polls int
	mux := http.NewServeMux()
	mux.HandleFunc("/dani/train/submit", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"ID":"job-1"}`)) })
	mux.HandleFunc("/dani/train/jobs", func(w http.ResponseWriter, _ *http.Request) {
		polls++
		state := "running"
		if polls >= 2 {
			state = "completed"
		}
		json.NewEncoder(w).Encode(map[string]any{"jobs": []any{map[string]any{"State": state, "Candidate": "ghost"}}})
	})
	mux.HandleFunc("/dani/models/sign", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{}`)) })
	mux.HandleFunc("/dani/models", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"models":[]}`)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	if code, out, _ := execCLI(t, srv.URL, "promote", "a", "b", "c"); code != 0 || !strings.Contains(out, ".") {
		t.Fatalf("waitjob dot + model-not-found: %d %s", code, out)
	}
}

func TestPromoteWaitGetError(t *testing.T) {
	sleep = func(time.Duration) {}
	defer func() { sleep = time.Sleep }()
	mux := http.NewServeMux()
	mux.HandleFunc("/dani/train/submit", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"ID":"job-1"}`)) })
	mux.HandleFunc("/dani/train/jobs", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	if code, _, _ := execCLI(t, srv.URL, "promote", "a", "b", "c"); code != 2 {
		t.Fatal("waitjob get-error must exit 2")
	}
}

func TestPromoteSignFails(t *testing.T) {
	sleep = func(time.Duration) {}
	defer func() { sleep = time.Sleep }()
	m := newMock(t)
	m.failSign = true
	if code, _, _ := execCLI(t, m.srv.URL, "promote", "a", "b", "c"); code != 2 {
		t.Fatal("promote with a failing sign must exit 2")
	}
}

func TestPromoteModelStateError(t *testing.T) {
	sleep = func(time.Duration) {}
	defer func() { sleep = time.Sleep }()
	mux := http.NewServeMux()
	mux.HandleFunc("/dani/train/submit", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"ID":"job-1"}`)) })
	mux.HandleFunc("/dani/train/jobs", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"jobs": []any{map[string]any{"State": "completed", "Candidate": "c1"}}})
	})
	mux.HandleFunc("/dani/models/sign", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{}`)) })
	mux.HandleFunc("/dani/models", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }) // final state lookup errors
	srv := httptest.NewServer(mux)
	defer srv.Close()
	if code, out, _ := execCLI(t, srv.URL, "promote", "a", "b", "c"); code != 0 || !strings.Contains(out, "c1: ?") {
		t.Fatalf("promote with modelState error: %d %s", code, out)
	}
}

func TestIngestJSONAndWaitTimeout(t *testing.T) {
	m := newMock(t)
	if code, out, _ := execCLI(t, m.srv.URL, "--json", "ingest", "legal"); code != 0 || !strings.Contains(out, "\"chunks\"") {
		t.Fatalf("ingest --json: %d %s", code, out)
	}
	// waitJob timeout: a job that never leaves "running" -> promote gives up (exit 2)
	sleep = func(time.Duration) {}
	defer func() { sleep = time.Sleep }()
	mux := http.NewServeMux()
	mux.HandleFunc("/dani/train/submit", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"ID":"job-1"}`)) })
	mux.HandleFunc("/dani/train/jobs", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"jobs":[{"State":"running","Candidate":""}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	if code, _, e := execCLI(t, srv.URL, "promote", "a", "b", "c"); code != 2 || !strings.Contains(e, "did not finish") {
		t.Fatalf("wait timeout: %d %s", code, e)
	}
}
