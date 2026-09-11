package serving

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRankUnknownAndPrediction(t *testing.T) {
	if rank("martian") != 0 {
		t.Fatal("unknown class ranks 0")
	}
	if predictedServeMs(0, 0, 0) != 1000 { // ema default + slots floor
		t.Fatal("prediction defaults wrong")
	}
}

func TestServeAddrErrors(t *testing.T) {
	auth := newAuthority(t)
	p, err := NewPlane(auth.identity("c"), "s")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.ServeLink("999.999.999.999:0"); err == nil {
		t.Fatal("bad link addr must error")
	}
	if _, err := p.ServeGateway("999.999.999.999:0"); err == nil {
		t.Fatal("bad gateway addr must error")
	}
}

func TestMTLSHelpersRejectGarbage(t *testing.T) {
	auth := newAuthority(t)
	id := auth.identity("n")
	if _, err := serverTLS([]byte("junk"), id.InterRaw, id.Key, id.Root, nil); err == nil {
		t.Fatal("garbage leaf must fail serverTLS")
	}
	if _, err := clientTLS([]byte("junk"), id.InterRaw, id.Key, id.Root); err == nil {
		t.Fatal("garbage leaf must fail clientTLS")
	}
	// peerVerifier: no certs presented / unparseable cert
	v := peerVerifier(id.Root, x509.ExtKeyUsageClientAuth)
	if err := v(nil, nil); err == nil {
		t.Fatal("no raw certs must be rejected")
	}
	if err := v([][]byte{[]byte("junk")}, nil); err == nil {
		t.Fatal("unparseable peer cert must be rejected")
	}
	// a cert from a DIFFERENT authority fails chain verification
	other := newAuthority(t)
	stranger := other.identity("stranger")
	if err := v([][]byte{stranger.LeafRaw}, nil); err == nil {
		t.Fatal("stranger CA must fail chain verify")
	}
	// the genuine chain passes
	if err := v([][]byte{id.LeafRaw, id.InterRaw}, nil); err != nil {
		t.Fatalf("genuine chain must verify: %v", err)
	}
}

func TestReserveSkipsAndTieBreak(t *testing.T) {
	stale := workerState{Heartbeat: Heartbeat{NodeUUID: "stale", DispatchAddr: "s:1", ModelID: "m",
		Class: "secret", MaxConcurrent: 2, QueueDepth: 2, Health: "healthy"}}
	p := newTestPlane("site",
		hb("a-node", "m", "secret", "site", 500),
		hb("b-node", "m", "secret", "site", 500), // identical -> deterministic tie-break on uuid
		workerState{Heartbeat: Heartbeat{NodeUUID: "sick", DispatchAddr: "x:1", ModelID: "m",
			Class: "secret", MaxConcurrent: 2, QueueDepth: 2, Health: "degraded"}},
	)
	p.workers["stale"] = &stale // LastSeen zero -> stale-skipped
	c, ok := p.reserve("m", "unrestricted", "", nil)
	if !ok || c.uuid != "a-node" {
		t.Fatalf("tie-break should pick a-node, got %+v", c)
	}
	// fleetETA skips the same and floors ema/pos
	slow := workerState{Heartbeat: Heartbeat{NodeUUID: "z", DispatchAddr: "z:1", ModelID: "m",
		Class: "secret", MaxConcurrent: 0, QueueDepth: 2, Health: "healthy", EmaServiceMs: 0}}
	slow.LastSeen = time.Now()
	p.workers["z"] = &slow
	if eta, any := p.fleetETA("m", "unrestricted"); !any || eta <= 0 {
		t.Fatalf("fleetETA floors wrong: %d %v", eta, any)
	}
	// ActiveTrainers skips stale trainers
	tr := workerState{Heartbeat: Heartbeat{NodeUUID: "old-t", Trainer: true, Health: "healthy"}}
	p.workers["old-t"] = &tr // zero LastSeen
	for _, ti := range p.ActiveTrainers() {
		if ti.UUID == "old-t" {
			t.Fatal("stale trainer must be skipped")
		}
	}
}

func TestGatewayBodyReadError(t *testing.T) {
	p := newTestPlane("site")
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", errReader{})
	rec := httptest.NewRecorder()
	p.handleGateway(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unreadable body should 400, got %d", rec.Code)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// fakeMTLSWorker runs a TLS server with a fleet identity, answering with the given handler.
func fakeMTLSWorker(t *testing.T, auth *testAuthority, uuid string, h http.HandlerFunc) string {
	t.Helper()
	id := auth.identity(uuid)
	cfg, err := serverTLS(id.LeafRaw, id.InterRaw, id.Key, id.Root, nil)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(tls.NewListener(lis, cfg)) }()
	t.Cleanup(func() { _ = srv.Close() })
	return lis.Addr().String()
}

func TestGatewayRetryPathsAndBusyETA(t *testing.T) {
	auth := newAuthority(t)
	p, _, _ := livePlane(t, auth)

	// worker A: always 429 (back-pressure) — the gateway must release, mark tried, move on
	addrA := fakeMTLSWorker(t, auth, "w-429", func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusTooManyRequests)
	})
	// worker B: connection refused (dead addr) — dispatch error path
	deadLis, _ := net.Listen("tcp", "127.0.0.1:0")
	addrB := deadLis.Addr().String()
	deadLis.Close()

	now := time.Now()
	p.mu.Lock()
	p.workers["w-429"] = &workerState{LastSeen: now, Heartbeat: Heartbeat{NodeUUID: "w-429",
		DispatchAddr: addrA, ModelID: "m", Class: "secret", MaxConcurrent: 1, QueueDepth: 1, Health: "healthy"}}
	p.workers["w-dead"] = &workerState{LastSeen: now, Heartbeat: Heartbeat{NodeUUID: "w-dead",
		DispatchAddr: addrB, ModelID: "m", Class: "secret", MaxConcurrent: 1, QueueDepth: 1, Health: "healthy"}}
	p.mu.Unlock()

	body, _ := json.Marshal(map[string]any{"model": "m",
		"messages": []map[string]string{{"role": "user", "content": "x"}}})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	p.handleGateway(rec, req)
	// both candidates tried (429 + dial error) -> fleet-busy 503 with Retry-After + attempts
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("expected fleet-busy with Retry-After, got %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "attempts") || !strings.Contains(rec.Body.String(), "back-pressure") {
		t.Fatalf("attempt trail missing: %s", rec.Body)
	}
}

func TestDispatchBadAddr(t *testing.T) {
	auth := newAuthority(t)
	p, err := NewPlane(auth.identity("c"), "s")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.dispatch(httptest.NewRequest("POST", "/", nil).Context(),
		candidate{uuid: "x", addr: "bad host\x7f"}, []byte("{}"), "tr-1"); err == nil {
		t.Fatal("unbuildable dispatch URL must error")
	}
}

func TestModelsAliasSkipsTrainerEngines(t *testing.T) {
	// alias listing only considers non-trainer live models (the seen map excludes trainers already);
	// also cover the mesh-spoke skip for workers without WG keys
	p := newTestPlane("site", hb("w", "base", "secret", "site", 100))
	m := p.buildMesh()
	if len(m.Nodes) != 1 { // hub only — the test worker advertised no WG key
		t.Fatalf("keyless worker must not join the mesh: %+v", m.Nodes)
	}
}
