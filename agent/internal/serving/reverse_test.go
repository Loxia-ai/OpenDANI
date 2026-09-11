package serving

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// the mailbox rendezvous: a job submitted for a worker is picked up by that worker's pull and its
// posted result is handed back to the waiting submit() as the exact *http.Response the gateway wants.
func TestReverseSubmitDeliver(t *testing.T) {
	rd := newReverseDispatch()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan struct{})
	var resp *http.Response
	var serr error
	go func() {
		resp, serr = rd.submit(ctx, "w1", []byte(`{"model":"m"}`), map[string]string{"X-Dani-Trace-Id": "tr-1"})
		close(done)
	}()

	// act as the worker: pull the job, then deliver a result.
	var job *revJob
	select {
	case job = <-rd.mailbox("w1"):
	case <-time.After(2 * time.Second):
		t.Fatal("job never reached the worker mailbox")
	}
	if string(job.Body) != `{"model":"m"}` || job.Headers["X-Dani-Trace-Id"] != "tr-1" {
		t.Fatalf("job mangled: %+v", job)
	}
	if !rd.deliver(job.ID, &revResult{Status: 200, Headers: map[string]string{"X-Dani-Worker": "w1"}, Body: []byte(`{"ok":true}`)}) {
		t.Fatal("deliver to a waiting job must succeed")
	}
	<-done
	if serr != nil || resp.StatusCode != 200 || resp.Header.Get("X-Dani-Worker") != "w1" {
		t.Fatalf("submit result wrong: %v %+v", serr, resp)
	}
	b := make([]byte, 32)
	n, _ := resp.Body.Read(b)
	if string(b[:n]) != `{"ok":true}` {
		t.Fatalf("body wrong: %q", string(b[:n]))
	}
}

// deliver to a job nobody is waiting on (already timed out) is a no-op, not a panic.
func TestReverseDeliverNoWaiter(t *testing.T) {
	rd := newReverseDispatch()
	if rd.deliver(999, &revResult{Status: 200}) {
		t.Fatal("deliver to an unknown job must report false")
	}
}

// if the worker vanishes mid-job (never delivers), submit unblocks on ctx and the caller can
// release + try the next worker — same as a dial error today.
func TestReverseSubmitCtxCancel(t *testing.T) {
	rd := newReverseDispatch()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := rd.submit(ctx, "w1", []byte(`{}`), nil); done <- err }()
	<-rd.mailbox("w1") // consume the job so submit is blocked on the RESULT
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("submit must error when the worker vanishes")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("submit did not unblock on ctx cancel")
	}
}

// submit unblocks on ctx even while the MAILBOX SEND itself is blocked (buffer full) — a slow/absent
// puller can't wedge the router.
func TestReverseSubmitBlockedMailboxCtxCancel(t *testing.T) {
	rd := newReverseDispatch()
	mb := rd.mailbox("w1")
	for i := 0; i < cap(mb); i++ { // fill the buffer so the next send blocks
		mb <- &revJob{ID: int64(i)}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := rd.submit(ctx, "w1", []byte(`{}`), nil); err == nil {
		t.Fatal("submit must error when the mailbox is full and ctx is cancelled")
	}
}

// deliver is non-blocking: a second result for the same job (buffer already full) is dropped, not
// a deadlock.
func TestReverseDeliverChannelFull(t *testing.T) {
	rd := newReverseDispatch()
	rd.pending[1] = make(chan *revResult, 1)
	if !rd.deliver(1, &revResult{Status: 200}) {
		t.Fatal("first deliver should fill the buffer and succeed")
	}
	if rd.deliver(1, &revResult{Status: 200}) {
		t.Fatal("second deliver (buffer full) must be dropped, not block")
	}
}

// result routing success (200) and the no-waiter Gone (410) branch.
func TestReverseResultRouting(t *testing.T) {
	p := &Plane{workers: map[string]*workerState{}, inflight: map[string]int{}, stale: time.Minute, reverse: newReverseDispatch()}
	// 410: valid body but nobody waiting on job 42
	rec := httptest.NewRecorder()
	req := withCN("POST", "/link/dispatch/result?job=42", "w1")
	req.Body = io.NopCloser(bytes.NewReader([]byte(`{"status":200,"body":"aGk="}`)))
	p.handleReverseResult(rec, req)
	if rec.Code != http.StatusGone {
		t.Fatalf("result for an expired job must be 410, got %d", rec.Code)
	}
	// 200: a waiter is registered
	p.rev().pending[7] = make(chan *revResult, 1)
	rec = httptest.NewRecorder()
	req = withCN("POST", "/link/dispatch/result?job=7", "w1")
	req.Body = io.NopCloser(bytes.NewReader([]byte(`{"status":200,"headers":{"X-Dani-Worker":"w1"},"body":"aGk="}`)))
	p.handleReverseResult(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("result delivered to a waiter must be 200, got %d", rec.Code)
	}
}

// the reachability verdict is per-worker, thread-safe, and clearable.
func TestUnreachableVerdict(t *testing.T) {
	p := &Plane{workers: map[string]*workerState{}, inflight: map[string]int{}, stale: time.Minute}
	if p.isUnreachable("w1") {
		t.Fatal("unknown worker must default to reachable (try the dial)")
	}
	p.markUnreachable("w1")
	if !p.isUnreachable("w1") {
		t.Fatal("marked worker must read unreachable")
	}
	p.clearUnreachable("w1")
	if p.isUnreachable("w1") {
		t.Fatal("cleared worker must be reachable again")
	}
}

// a changed dispatch address forgets a stale "undialable" verdict (the node may have moved networks).
func TestReachabilityClearedOnAddrChange(t *testing.T) {
	p := &Plane{workers: map[string]*workerState{}, inflight: map[string]int{}, stale: time.Minute, unreachable: map[string]bool{}}
	post := func(addr string) {
		hb, _ := json.Marshal(Heartbeat{NodeUUID: "w1", DispatchAddr: addr, ModelID: "m", Health: "healthy"})
		p.handleHeartbeat(httptest.NewRecorder(), httptest.NewRequest("POST", "/link/heartbeat", bytes.NewReader(hb)))
	}
	post("10.0.0.5:9443")
	p.markUnreachable("w1")
	post("10.0.0.5:9443") // same addr — verdict stays
	if !p.isUnreachable("w1") {
		t.Fatal("verdict must persist while the address is unchanged")
	}
	post("192.168.1.9:9443") // moved networks — verdict cleared
	if p.isUnreachable("w1") {
		t.Fatal("verdict must clear when the dispatch address changes")
	}
}

// AUTO end-to-end at the reserve+dispatch layer: an auto worker whose dial FAILS is served over the
// tunnel and remembered as unreachable, so the next dispatch skips straight to the tunnel.
func TestAutoDialFailoverToTunnel(t *testing.T) {
	auth := newAuthority(t)
	p, err := NewPlane(auth.identity("ctrl-a"), "site-t")
	if err != nil {
		t.Fatal(err)
	}
	// an auto worker advertising a dispatch address that REFUSES instantly (nothing on 127.0.0.1:1)
	// — a deterministic dial failure, so the test exercises the failover without depending on an OS
	// connect-timeout. (Over a real NAT the failure is a timeout instead; the failover path is the same.)
	p.mu.Lock()
	p.workers["w-auto"] = &workerState{LastSeen: time.Now(), Heartbeat: Heartbeat{
		NodeUUID: "w-auto", DispatchAddr: "127.0.0.1:1", ModelID: "m", Class: "restricted",
		Health: "healthy", MaxConcurrent: 2, QueueDepth: 2, TunnelAvailable: true}}
	p.mu.Unlock()

	// first reserve: not yet known-unreachable -> candidate is NOT reverse (will dial)
	c1, ok := p.reserve("m", "unrestricted", "", nil)
	if !ok || c1.reverse || !c1.tunnelAvail {
		t.Fatalf("auto worker should first be dial-path with a tunnel fallback: %+v", c1)
	}
	// a puller stands in for the worker so the tunnel fallback can complete
	go func() {
		job := <-p.rev().mailbox("w-auto")
		p.rev().deliver(job.ID, &revResult{Status: 200, Headers: map[string]string{"X-Dani-Worker": "w-auto"}, Body: []byte(`{"ok":true}`)})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	resp, derr := p.dispatch(ctx, c1, []byte(`{"model":"m"}`), "")
	if derr != nil || resp.StatusCode != 200 {
		t.Fatalf("dial should fail then serve over the tunnel: %v %+v", derr, resp)
	}
	// the failed dial must have recorded the worker as unreachable...
	if !p.isUnreachable("w-auto") {
		t.Fatal("a failed dial on an auto worker must mark it unreachable")
	}
	// ...so the NEXT reserve returns it as reverse (straight to the tunnel, no dial penalty).
	c2, ok := p.reserve("m", "unrestricted", "", nil)
	if !ok || !c2.reverse {
		t.Fatalf("after a proven-undialable dial, the worker must route reverse: %+v", c2)
	}
}

// REGRESSION GUARD: an OFF worker (no tunnel) is never routed reverse and a dial failure is a hard
// error — it must NOT silently fall back to a tunnel it doesn't have.
func TestOffWorkerStaysDialOnly(t *testing.T) {
	auth := newAuthority(t)
	p, err := NewPlane(auth.identity("ctrl-off"), "site-t")
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.workers["w-off"] = &workerState{LastSeen: time.Now(), Heartbeat: Heartbeat{
		NodeUUID: "w-off", DispatchAddr: "127.0.0.1:1", ModelID: "m", Class: "restricted",
		Health: "healthy", MaxConcurrent: 2, QueueDepth: 2}} // ReverseTunnel=false, TunnelAvailable=false
	p.mu.Unlock()
	c, ok := p.reserve("m", "unrestricted", "", nil)
	if !ok || c.reverse || c.tunnelAvail {
		t.Fatalf("off worker must be pure dial (no reverse, no tunnel fallback): %+v", c)
	}
	// even marking it unreachable must NOT flip it to reverse (no TunnelAvailable to fall back to)
	p.markUnreachable("w-off")
	c2, _ := p.reserve("m", "unrestricted", "", nil)
	if c2.reverse {
		t.Fatal("an off worker must never route reverse, even if a prior dial failed")
	}
	// a dial failure returns the error (no tunnel), it does not get swallowed
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if _, derr := p.dispatch(ctx, c2, []byte(`{"model":"m"}`), ""); derr == nil {
		t.Fatal("a failed dial on an off worker must surface an error, not a silent tunnel fallback")
	}
}

// FORCE workers are always reverse regardless of any dial verdict.
func TestForceWorkerAlwaysReverse(t *testing.T) {
	p := &Plane{workers: map[string]*workerState{}, inflight: map[string]int{}, drained: map[string]bool{},
		revoked: map[string]bool{}, stale: time.Minute}
	p.mu.Lock()
	p.workers["w-force"] = &workerState{LastSeen: time.Now(), Heartbeat: Heartbeat{
		NodeUUID: "w-force", DispatchAddr: "10.255.255.1:9443", ModelID: "m", Class: "restricted",
		Health: "healthy", MaxConcurrent: 2, QueueDepth: 2, ReverseTunnel: true, TunnelAvailable: true}}
	p.mu.Unlock()
	c, ok := p.reserve("m", "unrestricted", "", nil)
	if !ok || !c.reverse {
		t.Fatalf("force worker must always route reverse: %+v", c)
	}
}

// the Link handlers reject an unauthenticated caller (no client cert => no identity).
func TestReverseHandlersRequirePeer(t *testing.T) {
	p := &Plane{workers: map[string]*workerState{}, inflight: map[string]int{}, stale: time.Minute}
	for _, path := range []string{"/link/dispatch/pull", "/link/dispatch/result?job=1"} {
		rec := httptest.NewRecorder()
		p.handleReversePull(rec, httptest.NewRequest("GET", path, nil))
		// pull uses peerCN; with no TLS it is 401
	}
	rec := httptest.NewRecorder()
	p.handleReversePull(rec, httptest.NewRequest("GET", "/link/dispatch/pull", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("pull without a peer cert must be 401, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	p.handleReverseResult(rec, httptest.NewRequest("POST", "/link/dispatch/result?job=1", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("result without a peer cert must be 401, got %d", rec.Code)
	}
}

// withCN returns a request carrying a synthetic verified-peer cert (the Link is mTLS, so in
// production this is real; here we fake the ConnectionState to unit-test the handler branches).
func withCN(method, path, cn string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: cn}}}}
	return r
}

// pull returns 204 when no work arrives within the window (shortened via the handler's own ctx).
func TestReversePullTimeout(t *testing.T) {
	p := &Plane{workers: map[string]*workerState{}, inflight: map[string]int{}, stale: time.Minute}
	// cancel the request context immediately so the long-poll returns 204 without waiting 25s.
	req := withCN("GET", "/link/dispatch/pull", "w1")
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	rec := httptest.NewRecorder()
	p.handleReversePull(rec, req.WithContext(ctx))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("empty pull window must be 204, got %d", rec.Code)
	}
}

// pull delivers a queued job to the authenticated worker.
func TestReversePullDeliversJob(t *testing.T) {
	p := &Plane{workers: map[string]*workerState{}, inflight: map[string]int{}, stale: time.Minute, reverse: newReverseDispatch()}
	p.rev().mailbox("w1") <- &revJob{ID: 7, Body: []byte(`{"model":"m"}`)}
	rec := httptest.NewRecorder()
	p.handleReversePull(rec, withCN("GET", "/link/dispatch/pull", "w1"))
	if rec.Code != http.StatusOK || rec.Header().Get("X-Dani-Job-Id") != "7" {
		t.Fatalf("pull should return the queued job: code=%d id=%q", rec.Code, rec.Header().Get("X-Dani-Job-Id"))
	}
}

// result routing: a bad job id is 400; a valid id with no waiter is 410 Gone.
func TestReverseResultErrors(t *testing.T) {
	p := &Plane{workers: map[string]*workerState{}, inflight: map[string]int{}, stale: time.Minute, reverse: newReverseDispatch()}
	rec := httptest.NewRecorder()
	p.handleReverseResult(rec, withCN("POST", "/link/dispatch/result?job=notanumber", "w1"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad job id must be 400, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	req := withCN("POST", "/link/dispatch/result?job=42", "w1")
	req.Body = http.NoBody
	p.handleReverseResult(rec, req)
	// empty body -> decode error -> 400 (json decode of NoBody fails)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty result body must be 400, got %d", rec.Code)
	}
}
