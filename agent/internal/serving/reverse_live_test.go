package serving

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"dani.local/agent/internal/engine"
)

// The reverse-tunnel end-to-end: a worker whose advertised dispatch address is UNREACHABLE (as it
// would be behind NAT) still serves a gateway request — proving dispatch went over the worker's
// OUTBOUND long-poll, not a dial. Real CA, real mTLS Link, real sockets (NAT-TRANSPORT.md).
func TestReverseTunnelEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	auth := newAuthority(t)
	_, linkAddr, gw := livePlane(t, auth)

	// AdvertiseHost is a black-hole address: if the controller ever tried to DIAL this worker the
	// request would hang/fail. The only way a chat succeeds is the reverse tunnel.
	w := NewWorker(WorkerConfig{
		Identity: auth.identity("w-rev"), Engine: engine.NewStub("m-rev"), ModelID: "m-rev",
		Class: "restricted", Site: "site-t", AdvertiseHost: "10.255.255.1", // unroutable (TEST-NET-ish black hole)
		ControllerURLs: []string{"https://" + linkAddr}, MaxConcurrent: 2, QueueDepth: 2,
		HeartbeatEvery: 100 * time.Millisecond, ReverseTunnel: true,
	})
	go func() { _ = w.Serve(ctx, "127.0.0.1:0") }()
	waitLiveFleet(t, gw, 1)

	// the fleet must report this worker as reverse-tunnel
	fresp, _ := http.Get("http://" + gw + "/dani/fleet")
	var fleet struct {
		Workers []struct {
			UUID          string
			ReverseTunnel bool
		}
	}
	json.NewDecoder(fresp.Body).Decode(&fleet)
	fresp.Body.Close()
	if len(fleet.Workers) != 1 || !fleet.Workers[0].ReverseTunnel {
		t.Fatalf("worker should advertise reverse_tunnel: %+v", fleet.Workers)
	}

	// chat through the gateway -> reserve picks the reverse worker -> job goes to its mailbox ->
	// the worker's pull loop serves it -> result returns. All while the dispatch address is dead.
	body, _ := json.Marshal(map[string]any{"model": "m-rev",
		"messages": []engine.Message{{Role: "user", Content: "over the tunnel"}}, "max_tokens": 16})
	resp, err := http.Post("http://"+gw+"/v1/chat/completions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reverse-tunnel chat failed: %d %s", resp.StatusCode, out)
	}
	if resp.Header.Get("X-Dani-Served-By") != "w-rev" {
		t.Fatalf("expected served-by w-rev, got %q", resp.Header.Get("X-Dani-Served-By"))
	}
	var parsed struct {
		Choices []struct {
			Message engine.Message
		}
	}
	if json.Unmarshal(out, &parsed); len(parsed.Choices) == 0 || parsed.Choices[0].Message.Content == "" {
		t.Fatalf("no answer over the tunnel: %s", out)
	}
}

// two concurrent requests are both served over the reverse tunnel (maxConcurrent pullers).
func TestReverseTunnelConcurrent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	auth := newAuthority(t)
	p, linkAddr, gw := livePlane(t, auth)
	_ = p
	w := NewWorker(WorkerConfig{
		Identity: auth.identity("w-rev2"), Engine: engine.NewStub("m-rev2"), ModelID: "m-rev2",
		Class: "restricted", Site: "site-t", AdvertiseHost: "10.255.255.1",
		ControllerURLs: []string{"https://" + linkAddr}, MaxConcurrent: 2, QueueDepth: 4,
		HeartbeatEvery: 100 * time.Millisecond, ReverseTunnel: true,
	})
	go func() { _ = w.Serve(ctx, "127.0.0.1:0") }()
	waitLiveFleet(t, gw, 1)

	results := make(chan int, 3)
	for i := 0; i < 3; i++ {
		go func() {
			body, _ := json.Marshal(map[string]any{"model": "m-rev2",
				"messages": []engine.Message{{Role: "user", Content: "concurrent"}}, "max_tokens": 8})
			resp, err := http.Post("http://"+gw+"/v1/chat/completions", "application/json", bytes.NewReader(body))
			if err != nil {
				results <- 0
				return
			}
			resp.Body.Close()
			results <- resp.StatusCode
		}()
	}
	ok := 0
	for i := 0; i < 3; i++ {
		if code := <-results; code == http.StatusOK {
			ok++
		}
	}
	if ok != 3 {
		t.Fatalf("expected all 3 served over the tunnel, got %d", ok)
	}
}
