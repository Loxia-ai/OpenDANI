package training

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseMarkersErrorLine(t *testing.T) {
	_, err := ParseMarkers(strings.NewReader("CKPT 1/2\nERROR cuda out of memory\n"), func(int, int) {})
	if err == nil || !strings.Contains(err.Error(), "cuda out of memory") {
		t.Fatalf("ERROR marker should surface the trainer's message, got %v", err)
	}
}

func TestEncodeResultRoundTrip(t *testing.T) {
	res := Result{Bytes: []byte("adapter"), Evals: map[string]float64{"eval_loss": 1.5}}
	got, err := ParseMarkers(strings.NewReader(EncodeResult(res)+"\n"), func(int, int) {})
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Bytes) != "adapter" || got.Evals["eval_loss"] != 1.5 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

// remoteServer is a TLS test server standing in for a trainer node's /train endpoint.
func remoteServer(t *testing.T, handler http.HandlerFunc) (addr string, client *http.Client) {
	t.Helper()
	ts := httptest.NewTLSServer(handler)
	t.Cleanup(ts.Close)
	return strings.TrimPrefix(ts.URL, "https://"), ts.Client()
}

func stagedFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "staged.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRemoteTrainerHappyPath(t *testing.T) {
	var gotBody WireRequest
	addr, client := remoteServer(t, func(rw http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		fmt.Fprintln(rw, "CKPT 1/2")
		fmt.Fprintln(rw, "CKPT 2/2")
		fmt.Fprintln(rw, EncodeResult(Result{Bytes: []byte("remote-adapter"), Evals: map[string]float64{"eval_loss": 0.7}}))
	})
	rt := RemoteTrainer{Client: client}
	var last int
	res, err := rt.Run(context.Background(), Spec{
		BaseModelID: "m", Method: "qlora", DatasetID: "ds-1", TrainerAddr: addr,
		DatasetFile: stagedFile(t, `{"chunks":[{"text":"hi"}]}`),
	}, func(done, total int) { last = done })
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Bytes) != "remote-adapter" || res.Evals["eval_loss"] != 0.7 || last != 2 {
		t.Fatalf("remote result wrong: %+v last=%d", res, last)
	}
	// The staged dataset bytes traveled with the request.
	if gotBody.Base != "m" || gotBody.DatasetID != "ds-1" || gotBody.DatasetB64 == "" {
		t.Fatalf("wire request wrong: %+v", gotBody)
	}
}

func TestRemoteTrainerErrors(t *testing.T) {
	rt := RemoteTrainer{Client: http.DefaultClient}
	// no address on the spec
	if _, err := rt.Run(context.Background(), Spec{}, func(int, int) {}); err == nil {
		t.Fatal("no TrainerAddr should error")
	}
	// unreadable dataset file
	if _, err := rt.Run(context.Background(), Spec{TrainerAddr: "x", DatasetFile: filepath.Join(t.TempDir(), "missing")}, func(int, int) {}); err == nil {
		t.Fatal("missing dataset file should error")
	}
	// unreachable node
	if _, err := rt.Run(context.Background(), Spec{TrainerAddr: "127.0.0.1:1"}, func(int, int) {}); err == nil {
		t.Fatal("dial failure should error")
	}
	// malformed address -> request construction fails
	if _, err := rt.Run(context.Background(), Spec{TrainerAddr: "bad addr\x7f"}, func(int, int) {}); err == nil {
		t.Fatal("malformed addr should error at request build")
	}
	// non-200 from the node
	addr, client := remoteServer(t, func(rw http.ResponseWriter, _ *http.Request) {
		http.Error(rw, "no such trainer", http.StatusServiceUnavailable)
	})
	if _, err := (RemoteTrainer{Client: client}).Run(context.Background(), Spec{TrainerAddr: addr}, func(int, int) {}); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("non-200 should error with status, got %v", err)
	}
	// remote ERROR marker
	addr2, client2 := remoteServer(t, func(rw http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(rw, "ERROR gpu on fire")
	})
	if _, err := (RemoteTrainer{Client: client2}).Run(context.Background(), Spec{TrainerAddr: addr2}, func(int, int) {}); err == nil || !strings.Contains(err.Error(), "gpu on fire") {
		t.Fatalf("remote ERROR should surface, got %v", err)
	}
}

func TestDispatchTrainer(t *testing.T) {
	local := trainerFunc(func(_ context.Context, s Spec, _ func(int, int)) (Result, error) {
		return Result{Bytes: []byte("local")}, nil
	})
	remote := trainerFunc(func(_ context.Context, s Spec, _ func(int, int)) (Result, error) {
		return Result{Bytes: []byte("remote")}, nil
	})
	d := DispatchTrainer{Local: local, Remote: remote}
	if res, _ := d.Run(context.Background(), Spec{TrainerAddr: "node:9444"}, func(int, int) {}); string(res.Bytes) != "remote" {
		t.Fatal("addr set should dispatch remote")
	}
	if res, _ := d.Run(context.Background(), Spec{}, func(int, int) {}); string(res.Bytes) != "local" {
		t.Fatal("no addr should dispatch local")
	}
	// Remote nil (not wired) falls back to local even with an addr.
	d2 := DispatchTrainer{Local: local}
	if res, _ := d2.Run(context.Background(), Spec{TrainerAddr: "node:9444"}, func(int, int) {}); string(res.Bytes) != "local" {
		t.Fatal("nil Remote should fall back to local")
	}
}
