package serving

// The in-package live harness: a REAL CA issues identities for a controller Plane, a Worker, and a
// TrainerNode, which then talk over real sockets with mutual mTLS — so the data-plane paths
// (ServeLink/ServeGateway/dispatch/handleChat/back-pressure/heartbeats/WG endpoints) are covered
// in-package, per the retroactive-100% rule.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dani.local/agent/internal/ca"
	"dani.local/agent/internal/engine"
	"dani.local/agent/internal/kms"
	"dani.local/agent/pkg/dani"
)

// testAuthority mints one CA per test and issues serving identities from it.
type testAuthority struct {
	t  *testing.T
	ca *ca.CA
}

func newAuthority(t *testing.T) *testAuthority {
	t.Helper()
	ks, err := kms.NewSoftware()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := ca.Genesis(context.Background(), ks, "TestOrg")
	if err != nil {
		t.Fatal(err)
	}
	return &testAuthority{t: t, ca: authority}
}

func (a *testAuthority) identity(uuid string) Identity {
	return a.identityWithRoles(uuid, "worker")
}

// identityWithRoles issues an identity carrying specific DANI roles (a real controller's cert
// carries "controller" — the revocation-list signer check depends on it).
func (a *testAuthority) identityWithRoles(uuid string, roles ...string) Identity {
	a.t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	cert, err := a.ca.IssueNodeCert(context.Background(), ca.NodeCertParams{
		NodeUUID: uuid, SiteOU: "site-t", PubDER: pubDER,
		Claims:   dani.DANIClaims{SchemaVersion: 1, Roles: roles, Classification: "restricted"},
		NotAfter: time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		a.t.Fatal(err)
	}
	return Identity{LeafRaw: cert.Raw, InterRaw: a.ca.Intermediate.Raw, Key: priv, Root: a.ca.Root, UUID: uuid}
}

// livePlane brings up Link + Gateway on ephemeral ports.
func livePlane(t *testing.T, auth *testAuthority) (*Plane, string, string) {
	t.Helper()
	p, err := NewPlane(auth.identity("ctrl-t"), "site-t")
	if err != nil {
		t.Fatal(err)
	}
	linkAddr, err := p.ServeLink("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gwAddr, err := p.ServeGateway("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return p, linkAddr, gwAddr
}

func waitLiveFleet(t *testing.T, gw string, n int) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for {
		resp, err := http.Get("http://" + gw + "/dani/fleet")
		if err == nil {
			var out struct{ Count int }
			json.NewDecoder(resp.Body).Decode(&out)
			resp.Body.Close()
			if out.Count >= n {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("fleet never populated")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestLiveDataPlaneEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	auth := newAuthority(t)
	p, linkAddr, gw := livePlane(t, auth)

	var hbSeen atomic.Int64
	p.OnHeartbeat(func(hb Heartbeat) { hbSeen.Add(1) })

	// a real Worker (stub engine, 1 slot, tiny queue, tiny SLO — so back-pressure is reachable)
	w := NewWorker(WorkerConfig{
		Identity: auth.identity("w-live"), Engine: engine.NewStub("m-live"), ModelID: "m-live",
		Class: "restricted", Site: "site-t", AdvertiseHost: "127.0.0.1",
		ControllerURLs: []string{"https://" + linkAddr}, MaxConcurrent: 1, QueueDepth: 1,
		SLOBudget: 200 * time.Millisecond, HeartbeatEvery: 100 * time.Millisecond,
	})
	go func() { _ = w.Serve(ctx, "127.0.0.1:0") }()
	waitLiveFleet(t, gw, 1)
	if hbSeen.Load() == 0 {
		t.Fatal("OnHeartbeat hook never fired")
	}

	// chat through the gateway -> mTLS dispatch -> stub answer + trace headers
	body, _ := json.Marshal(map[string]any{"model": "m-live",
		"messages": []engine.Message{{Role: "user", Content: "hello live plane"}}, "max_tokens": 16})
	resp, err := http.Post("http://"+gw+"/v1/chat/completions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("X-Dani-Served-By") != "w-live" {
		t.Fatalf("gateway chat failed: %d %s", resp.StatusCode, b)
	}
	// method guard on the worker's own endpoint is covered via gateway POST; gateway 405:
	gr, _ := http.Get("http://" + gw + "/v1/chat/completions")
	if gr.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("gateway GET should be 405, got %d", gr.StatusCode)
	}
	gr.Body.Close()

	// unknown model -> hard 503 no-route
	nb, _ := json.Marshal(map[string]any{"model": "ghost", "messages": []engine.Message{{Role: "user", Content: "x"}}})
	nr, _ := http.Post("http://"+gw+"/v1/chat/completions", "application/json", bytes.NewReader(nb))
	if nr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("no-route should 503, got %d", nr.StatusCode)
	}
	nr.Body.Close()

	// saturate: 1 slot + 1 queue + 200ms SLO, slow stub (~1s/req) -> some requests get back-pressure
	// with Retry-After (either from the worker or the gateway's fleet-busy path)
	sat := func() int {
		req, _ := json.Marshal(map[string]any{"model": "m-live",
			"messages": []engine.Message{{Role: "user", Content: "saturate me now"}}, "max_tokens": 64})
		r, err := http.Post("http://"+gw+"/v1/chat/completions", "application/json", bytes.NewReader(req))
		if err != nil {
			return 0
		}
		defer r.Body.Close()
		io.Copy(io.Discard, r.Body)
		return r.StatusCode
	}
	codes := make(chan int, 6)
	for i := 0; i < 6; i++ {
		go func() { codes <- sat() }()
	}
	saw503 := false
	for i := 0; i < 6; i++ {
		if c := <-codes; c == http.StatusServiceUnavailable {
			saw503 = true
		}
	}
	if !saw503 {
		t.Fatal("saturation should trigger back-pressure somewhere in the path")
	}

	// /v1/models + fleet + console + WG surface
	mr, _ := http.Get("http://" + gw + "/v1/models")
	mb, _ := io.ReadAll(mr.Body)
	mr.Body.Close()
	if !strings.Contains(string(mb), "m-live") {
		t.Fatalf("models missing m-live: %s", mb)
	}
	app, _ := http.Get("http://" + gw + "/")
	ab, _ := io.ReadAll(app.Body)
	app.Body.Close()
	if !strings.Contains(string(ab), "DANI") {
		t.Fatal("console page not served")
	}
	nf, _ := http.Get("http://" + gw + "/nope")
	if nf.StatusCode != http.StatusNotFound {
		t.Fatal("unknown path should 404")
	}
	nf.Body.Close()

	// the worker advertised a WG key -> mesh has hub + spoke; ConfigFor both; unknown 404
	wm, _ := http.Get("http://" + gw + "/dani/wg/mesh")
	wmb, _ := io.ReadAll(wm.Body)
	wm.Body.Close()
	if !strings.Contains(string(wmb), "w-live") {
		t.Fatalf("mesh missing spoke: %s", wmb)
	}
	wc, _ := http.Get("http://" + gw + "/dani/wg/config") // hub default
	wcb, _ := io.ReadAll(wc.Body)
	wc.Body.Close()
	if !strings.Contains(string(wcb), "[Interface]") {
		t.Fatalf("hub config wrong: %s", wcb)
	}
	wu, _ := http.Get("http://" + gw + "/dani/wg/config?node=ghost")
	if wu.StatusCode != http.StatusNotFound {
		t.Fatal("unknown node config should 404")
	}
	wu.Body.Close()

	// hub's own importable config file (private key injected)
	out := filepath.Join(t.TempDir(), "hub.conf")
	if err := p.WriteHubWGConfig(out); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(out)
	if !strings.Contains(string(data), "PrivateKey = ") {
		t.Fatal("hub config must carry its private key locally")
	}

	// bad heartbeat body -> 400 (direct against the Link's handler shape via plane method)
	hb := struct{ Bad string }{"x"}
	hbb, _ := json.Marshal(hb) // decodes fine but empty uuid — exercise bad-json instead:
	_ = hbb
}

func TestWorkerWGConfigFetch(t *testing.T) {
	// the worker polls the gateway until its [Peer] appears, then writes the conf with its key
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	auth := newAuthority(t)
	_, linkAddr, gw := livePlane(t, auth)
	out := filepath.Join(t.TempDir(), "node.conf")
	w := NewWorker(WorkerConfig{
		Identity: auth.identity("w-wg"), Engine: engine.NewStub("m"), ModelID: "m",
		Class: "restricted", AdvertiseHost: "127.0.0.1",
		ControllerURLs: []string{"https://" + linkAddr}, HeartbeatEvery: 100 * time.Millisecond,
		WGConfOut: out, GatewayURL: "http://" + gw,
	})
	go func() { _ = w.Serve(ctx, "127.0.0.1:0") }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if data, err := os.ReadFile(out); err == nil && strings.Contains(string(data), "PrivateKey = ") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker never wrote its WG config")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestHandleHeartbeatBadBody(t *testing.T) {
	auth := newAuthority(t)
	p, _, _ := livePlane(t, auth)
	req, _ := http.NewRequest(http.MethodPost, "/link/heartbeat", strings.NewReader("{nope"))
	rec := httptestNewRecorder()
	p.handleHeartbeat(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad heartbeat should 400, got %d", rec.Code)
	}
}

func TestLiveTrainerNodeServe(t *testing.T) {
	// TrainerNode.Serve + heartbeatLoop in-package: it heartbeats Trainer-marked and answers /train
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	auth := newAuthority(t)
	p, linkAddr, _ := livePlane(t, auth)
	tn := NewTrainerNode(TrainerNodeConfig{
		Identity: auth.identity("tn-live"), Trainer: &captureTrainer{}, Class: "restricted", Site: "site-t",
		AdvertiseHost: "127.0.0.1", ControllerURLs: []string{"https://" + linkAddr},
		HeartbeatEvery: 100 * time.Millisecond, WorkDir: t.TempDir(),
	})
	go func() { _ = tn.Serve(ctx, "127.0.0.1:0") }()
	deadline := time.Now().Add(8 * time.Second)
	for len(p.ActiveTrainers()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("trainer heartbeat never arrived")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if p.ActiveTrainers()[0].UUID != "tn-live" {
		t.Fatalf("wrong trainer: %+v", p.ActiveTrainers())
	}
}
