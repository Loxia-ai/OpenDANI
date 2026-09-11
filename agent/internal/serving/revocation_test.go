package serving

// P1-4 tests: the signed revocation list round-trips and rejects every forgery/rollback shape, the
// poller keeps a node's copy fresh (fail-static on errors), and — the live proof — a revoked node's
// still-valid certificate is refused at the TLS layer by the controller Link AND by other workers
// within one poll interval.

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dani.local/agent/internal/engine"
)

// ctrlPlane builds a plane whose identity carries the CONTROLLER role (CRL signer requirement).
func ctrlPlane(t *testing.T, auth *testAuthority, uuid string) *Plane {
	t.Helper()
	p, err := NewPlane(auth.identityWithRoles(uuid, "controller"), "site-t")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRevocationListSignVerifyAndForgeries(t *testing.T) {
	auth := newAuthority(t)
	p := ctrlPlane(t, auth, "ctrl-rev")
	p.mu.Lock()
	p.revoked["bad-node"] = true
	p.revoked["worse-node"] = true
	p.revSeq = 2
	p.mu.Unlock()

	rl, err := p.buildRevocationList()
	if err != nil {
		t.Fatal(err)
	}
	set, err := VerifyRevocationList(rl, auth.ca.Root)
	if err != nil {
		t.Fatalf("genuine list must verify: %v", err)
	}
	if !set["bad-node"] || !set["worse-node"] || len(set) != 2 {
		t.Fatalf("wrong set: %v", set)
	}
	if !strings.Contains(marshalRL(rl), `"seq":2`) {
		t.Fatalf("marshal: %s", marshalRL(rl))
	}

	// forgery shapes — every one must fail
	tamper := rl
	tamper.Revoked = []string{"bad-node"} // membership tampered
	if _, err := VerifyRevocationList(tamper, auth.ca.Root); err == nil {
		t.Fatal("tampered membership must fail")
	}
	replay := rl
	replay.Seq = 99 // seq tampered (signature covers it)
	if _, err := VerifyRevocationList(replay, auth.ca.Root); err == nil {
		t.Fatal("tampered seq must fail")
	}
	badsig := rl
	badsig.Sig = "!!!"
	if _, err := VerifyRevocationList(badsig, auth.ca.Root); err == nil {
		t.Fatal("bad sig encoding must fail")
	}
	badname := rl
	badname.IssuedBy = "someone-else"
	if _, err := VerifyRevocationList(badname, auth.ca.Root); err == nil {
		t.Fatal("issuedBy mismatch must fail")
	}
	nochain := rl
	nochain.Chain = nil
	if _, err := VerifyRevocationList(nochain, auth.ca.Root); err == nil {
		t.Fatal("missing chain must fail")
	}
	badb64 := rl
	badb64.Chain = []string{"%%%"}
	if _, err := VerifyRevocationList(badb64, auth.ca.Root); err == nil {
		t.Fatal("bad chain encoding must fail")
	}
	badder := rl
	badder.Chain = []string{base64.StdEncoding.EncodeToString([]byte("junk"))}
	if _, err := VerifyRevocationList(badder, auth.ca.Root); err == nil {
		t.Fatal("junk DER must fail")
	}

	// a WORKER cannot mint revocations: same CA, wrong role
	wp, err := NewPlane(auth.identity("rogue-worker"), "site-t")
	if err != nil {
		t.Fatal(err)
	}
	wrl, err := wp.buildRevocationList()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRevocationList(wrl, auth.ca.Root); err == nil || !strings.Contains(err.Error(), "controller role") {
		t.Fatalf("worker-signed list must be rejected for role, got %v", err)
	}

	// a controller from a DIFFERENT deployment (foreign CA) is rejected by chain verify
	other := newAuthority(t)
	op := ctrlPlane(t, other, "foreign-ctrl")
	orl, err := op.buildRevocationList()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRevocationList(orl, auth.ca.Root); err == nil {
		t.Fatal("foreign-CA list must fail chain verify")
	}
}

func TestRevocationBuildAndServeErrorPaths(t *testing.T) {
	// a plane whose identity key is not ed25519 cannot sign a CRL — surfaced, not panicked
	p := &Plane{workers: map[string]*workerState{}, inflight: map[string]int{}, revoked: map[string]bool{}, stale: time.Minute}
	if _, err := p.buildRevocationList(); err == nil {
		t.Fatal("nil key must fail buildRevocationList")
	}
	rec := httptest.NewRecorder()
	p.handleRevocations(rec, httptest.NewRequest(http.MethodGet, "/link/revocations", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("handleRevocations must 500 on signing failure, got %d", rec.Code)
	}
	// junk intermediate entries are skipped (chain verify then fails cleanly without them)
	auth := newAuthority(t)
	cp := ctrlPlane(t, auth, "ctrl-x")
	rl, err := cp.buildRevocationList()
	if err != nil {
		t.Fatal(err)
	}
	rl.Chain = []string{rl.Chain[0], base64.StdEncoding.EncodeToString([]byte("junk-intermediate"))}
	if _, err := VerifyRevocationList(rl, auth.ca.Root); err == nil {
		t.Fatal("leaf without a valid intermediate must fail chain verify")
	}
	// a chain-valid cert WITHOUT DANIClaims (the intermediate itself) fails the claims read
	rl2, err := cp.buildRevocationList()
	if err != nil {
		t.Fatal(err)
	}
	rl2.Chain[0] = base64.StdEncoding.EncodeToString(auth.ca.Intermediate.Raw)
	if _, err := VerifyRevocationList(rl2, auth.ca.Root); err == nil {
		t.Fatal("claims-less signer must fail")
	}
	// refresh: an unbuildable request URL is fail-static
	rp := newRevocationPoller("w", "http://\x7f", http.DefaultClient, auth.ca.Root, time.Hour)
	if rp.refresh(context.Background()) {
		t.Fatal("bad base URL must be fail-static")
	}
}

func TestRevocationPollerRefreshAndRollback(t *testing.T) {
	auth := newAuthority(t)
	p := ctrlPlane(t, auth, "ctrl-poll")
	p.mu.Lock()
	p.revoked["evil"] = true
	p.revSeq = 5
	p.mu.Unlock()
	fresh, err := p.buildRevocationList()
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock() // an OLDER signed list (genuine signature, lower seq) — the rollback-replay shape
	delete(p.revoked, "evil")
	p.revSeq = 1
	p.mu.Unlock()
	stale, err := p.buildRevocationList()
	if err != nil {
		t.Fatal(err)
	}

	serve := fresh
	status := http.StatusOK
	body := ""
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		if status != http.StatusOK {
			rw.WriteHeader(status)
			return
		}
		if body != "" {
			_, _ = rw.Write([]byte(body))
			return
		}
		_, _ = rw.Write([]byte(marshalRL(serve)))
	}))
	defer srv.Close()

	rp := newRevocationPoller("w-test", srv.URL, srv.Client(), auth.ca.Root, time.Hour)
	if !rp.refresh(context.Background()) {
		t.Fatal("first refresh must apply")
	}
	if !rp.isRevoked("evil") || rp.isRevoked("innocent") {
		t.Fatal("set wrong after refresh")
	}
	// rollback: an older (genuinely signed) list must NOT shrink the set
	serve = stale
	if rp.refresh(context.Background()) {
		t.Fatal("rollback must be rejected")
	}
	if !rp.isRevoked("evil") {
		t.Fatal("rollback shrank the revocation set")
	}
	// same seq again -> no change, no error
	serve = fresh
	if rp.refresh(context.Background()) {
		t.Fatal("same-seq refresh should report no change")
	}
	// fail-static: HTTP error / bad body / unreachable all keep the last verified set
	status = http.StatusInternalServerError
	if rp.refresh(context.Background()) || !rp.isRevoked("evil") {
		t.Fatal("HTTP error must be fail-static")
	}
	status = http.StatusOK
	body = "{not json"
	if rp.refresh(context.Background()) || !rp.isRevoked("evil") {
		t.Fatal("bad body must be fail-static")
	}
	body = `{"seq":9,"revoked":["x"],"sig":"","chain":[]}` // unverifiable document
	if rp.refresh(context.Background()) || !rp.isRevoked("evil") {
		t.Fatal("unverifiable list must be fail-static")
	}
	srv.Close()
	if rp.refresh(context.Background()) || !rp.isRevoked("evil") {
		t.Fatal("unreachable controller must be fail-static")
	}
}

// TestRevocationRefusedFleetWide is the live P1-4 proof: revoke node A on the controller; the
// controller's Link refuses A's next connection at TLS, and worker B — after one CRL poll —
// refuses A's cert on ITS server too, while non-revoked peers keep working.
func TestRevocationRefusedFleetWide(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	auth := newAuthority(t)
	p := ctrlPlane(t, auth, "ctrl-live")
	linkAddr, err := p.ServeLink("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gw, err := p.ServeGateway("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	// worker B: enrolled, fast CRL poll
	wb := NewWorker(WorkerConfig{
		Identity: auth.identity("w-b"), Engine: engine.NewStub("m-b"), ModelID: "m-b",
		Class: "restricted", Site: "site-t", AdvertiseHost: "127.0.0.1",
		ControllerURLs: []string{"https://" + linkAddr}, MaxConcurrent: 1,
		HeartbeatEvery: 100 * time.Millisecond,
	})
	wb.revEvery = 100 * time.Millisecond
	go func() { _ = wb.Serve(ctx, "127.0.0.1:0") }()
	waitLiveFleet(t, gw, 1)

	// node A: a valid fleet identity with a working mTLS client
	idA := auth.identity("w-a")
	tlsA, err := clientTLS(idA.LeafRaw, idA.InterRaw, idA.Key, idA.Root)
	if err != nil {
		t.Fatal(err)
	}
	// DisableKeepAlives: the revocation check runs at the TLS HANDSHAKE, so each probe must open a
	// fresh connection (a pooled pre-revocation connection would bypass it — in production dispatch
	// connections are per-request).
	trA := &http.Transport{TLSClientConfig: tlsA, DisableKeepAlives: true}
	clientA := &http.Client{Timeout: 5 * time.Second, Transport: trA}

	// BEFORE revocation: A reaches both the Link and worker B
	if r, err := clientA.Get("https://" + linkAddr + "/link/revocations"); err != nil {
		t.Fatalf("pre-revocation Link call failed: %v", err)
	} else {
		r.Body.Close()
	}
	if r, err := clientA.Get("https://" + wb.dispatchAddr + "/healthz"); err != nil {
		t.Fatalf("pre-revocation worker call failed: %v", err)
	} else {
		r.Body.Close()
	}

	// REVOKE A (the plane state a console revoke produces)
	p.mu.Lock()
	p.revoked["w-a"] = true
	p.revSeq++
	p.mu.Unlock()

	// the controller Link refuses A at the TLS layer immediately
	if r, err := clientA.Get("https://" + linkAddr + "/link/revocations"); err == nil {
		r.Body.Close()
		t.Fatal("controller Link still accepts the revoked cert")
	}
	// worker B refuses A within one poll interval
	deadline := time.Now().Add(5 * time.Second)
	for {
		r, err := clientA.Get("https://" + wb.dispatchAddr + "/healthz")
		if err != nil {
			break // TLS refused — distributed revocation took effect
		}
		r.Body.Close()
		if time.Now().After(deadline) {
			t.Fatal("worker B never picked up the revocation")
		}
		time.Sleep(100 * time.Millisecond)
	}
	// non-revoked peers still work: the controller's dialer reaches worker B
	if r, err := p.Dialer().Get("https://" + wb.dispatchAddr + "/healthz"); err != nil {
		t.Fatalf("non-revoked peer broken after revocation: %v", err)
	} else {
		r.Body.Close()
	}
}
