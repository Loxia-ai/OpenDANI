package inttest

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"dani.local/agent/internal/controller"
	"dani.local/agent/internal/engine"
	"dani.local/agent/internal/enrollment"
	"dani.local/agent/internal/node"
	"dani.local/agent/internal/serving"
)

// servingIdentityFromNode mirrors the cmd/dani-agent adapter: split the CA bundle into intermediate
// + root and package the enrolled node's cert material for the data plane.
func servingIdentityFromNode(id *node.Identity) serving.Identity {
	var inter, root *x509.Certificate
	for _, c := range id.CABundle {
		if c.Subject.String() == c.Issuer.String() {
			root = c
		} else {
			inter = c
		}
	}
	si := serving.Identity{LeafRaw: id.Cert.Raw, Key: id.Key, UUID: id.Cert.Subject.CommonName, Root: root}
	if inter != nil {
		si.InterRaw = inter.Raw
	}
	return si
}

// mustEnrollNamed enrolls + approves a worker with an explicit uuid (Mode 2 batch-confirm).
func mustEnrollNamed(t *testing.T, ctx context.Context, ctrl *controller.Controller, addr, uuid string) *node.Identity {
	t.Helper()
	token, _, err := enrollment.IssueToken(ctx, ctrl.KS, "dep-1", []string{"worker"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	type res struct {
		id  *node.Identity
		err error
	}
	done := make(chan res, 1)
	go func() {
		id, err := node.Enroll(ctx, node.EnrollParams{
			Addr: addr, TrustRoot: ctrl.CA.Root, Token: token,
			NodeUUID: uuid, Roles: []string{"worker"}, Class: "restricted", Timeout: 10 * time.Second,
		})
		done <- res{id, err}
	}()
	deadline := time.Now().Add(8 * time.Second)
	for {
		w := ctrl.Enroll.Waiting()
		if len(w) > 0 {
			if _, err := ctrl.Enroll.Approve(ctx, w[0], []string{"worker"}, "restricted", "site-hq"); err != nil {
				t.Fatal(err)
			}
		}
		select {
		case r := <-done:
			if r.err != nil {
				t.Fatalf("enroll %s: %v", uuid, r.err)
			}
			return r.id
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("enroll %s timed out", uuid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestDataPlaneEndToEnd brings up the controller gateway + Link sink and two enrolled workers (stub
// engine) entirely over mTLS, then sends an OpenAI chat completion through the gateway and asserts it
// routes to a worker and returns an answer with the DANI trace headers.
func TestDataPlaneEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctrl, err := controller.Genesis(ctx, "AcmeBank", "dep-1", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := ctrl.Serve(lis)
	defer srv.Stop()
	addr := lis.Addr().String()

	// controller data plane on ephemeral ports
	plane, err := serving.NewPlane(serving.Identity{
		LeafRaw: ctrl.Cert.Raw, InterRaw: ctrl.CA.Intermediate.Raw, Key: ctrl.Key, Root: ctrl.CA.Root, UUID: ctrl.ID,
	}, "site-hq")
	if err != nil {
		t.Fatal(err)
	}
	plane.OnHeartbeat(func(hb serving.Heartbeat) {
		_ = ctrl.Registry.Heartbeat(context.Background(), hb.NodeUUID, hb.Health, "1")
	})
	linkAddr, err := plane.ServeLink("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gwAddr, err := plane.ServeGateway("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, linkPort, _ := net.SplitHostPort(linkAddr)

	// enroll two workers and start their data planes (stub engine)
	for i := 0; i < 2; i++ {
		id := mustEnrollNamed(t, ctx, ctrl, addr, fmt.Sprintf("worker-%d", i))
		w := serving.NewWorker(serving.WorkerConfig{
			Identity: servingIdentityFromNode(id), Engine: engine.NewStub("stub-slm"), ModelID: "stub-slm",
			Class: "restricted", AdvertiseHost: "127.0.0.1",
			ControllerURLs: []string{"https://127.0.0.1:" + linkPort}, MaxConcurrent: 4, HeartbeatEvery: 200 * time.Millisecond,
		})
		go func() { _ = w.Serve(ctx, "127.0.0.1:0") }()
	}

	// wait until both workers have heartbeated into the fleet table
	if !waitFleet(t, gwAddr, 2, 5*time.Second) {
		t.Fatal("workers never registered via heartbeat")
	}

	// send a chat completion through the gateway
	reqBody, _ := json.Marshal(map[string]any{
		"model":      "stub-slm",
		"messages":   []engine.Message{{Role: "user", Content: "What is DANI?"}},
		"max_tokens": 64,
	})
	resp, err := http.Post("http://"+gwAddr+"/v1/chat/completions", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("gateway status %d: %s", resp.StatusCode, b)
	}
	servedBy := resp.Header.Get("X-Dani-Served-By")
	if servedBy == "" {
		t.Fatal("missing X-Dani-Served-By header (routing trace)")
	}
	if resp.Header.Get("X-Dani-Worker") == "" {
		t.Fatal("missing X-Dani-Worker header (worker telemetry)")
	}
	var out struct {
		Choices []struct {
			Message engine.Message `json:"message"`
		} `json:"choices"`
		Usage map[string]int `json:"usage"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Choices) == 0 || out.Choices[0].Message.Content == "" {
		t.Fatalf("empty completion: %+v", out)
	}
	if out.Usage["completion_tokens"] == 0 {
		t.Fatal("expected non-zero completion_tokens")
	}
	t.Logf("routed to %s; answer: %q (%d tok)", servedBy, out.Choices[0].Message.Content, out.Usage["completion_tokens"])
}

// waitFleet polls the gateway's /dani/fleet until at least n workers are present.
func waitFleet(t *testing.T, gwAddr string, n int, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + gwAddr + "/dani/fleet")
		if err == nil {
			var fl struct {
				Count int `json:"count"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&fl)
			resp.Body.Close()
			if fl.Count >= n {
				return true
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}
