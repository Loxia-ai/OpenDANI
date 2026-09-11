package serving

// Reverse dispatch: NAT/firewall traversal for workers reachable ONLY outbound (UDP-blocked or
// no-privilege segments where WireGuard can't run — see NAT-TRANSPORT.md). Instead of the
// controller DIALING the worker, the worker long-polls the Link for jobs and posts results back;
// all worker connections are outbound HTTPS on the existing mTLS Link. The gateway, router, and
// OpenAI response shape are unchanged — only dispatch() branches.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// revJob is one unit of work handed to a reverse-tunnel worker.
type revJob struct {
	ID      int64
	Body    []byte            // the /v1/chat/completions request body
	Headers map[string]string // e.g. X-Dani-Trace-Id
	result  chan *revResult   // the dispatch() call waits here
}

// revResult is the worker's reply, carrying enough to rebuild the *http.Response the gateway expects.
type revResult struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body"`
}

// reverseDispatch is the controller-side registry: a per-worker job mailbox + a per-job rendezvous.
type reverseDispatch struct {
	mu      sync.Mutex
	inbox   map[string]chan *revJob   // uuid -> jobs waiting to be pulled by that worker
	pending map[int64]chan *revResult // jobID -> where the worker's result is delivered
	seq     int64
}

func newReverseDispatch() *reverseDispatch {
	return &reverseDispatch{inbox: map[string]chan *revJob{}, pending: map[int64]chan *revResult{}}
}

// rev lazily returns the plane's reverse registry (literal test planes don't call NewPlane).
func (p *Plane) rev() *reverseDispatch {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.reverse == nil {
		p.reverse = newReverseDispatch()
	}
	return p.reverse
}

// AUTO reverse-tunnel reachability verdict. A worker in auto mode stays dialable; the controller
// dials first and, only when a dial PROVES the worker undialable, records it here so subsequent
// dispatches skip straight to the tunnel. The verdict is cleared when the worker's dispatch address
// changes (it may have moved to a reachable network) — see handleHeartbeat.
func (p *Plane) markUnreachable(uuid string) {
	p.mu.Lock()
	if p.unreachable == nil {
		p.unreachable = map[string]bool{}
	}
	p.unreachable[uuid] = true
	p.mu.Unlock()
}

func (p *Plane) isUnreachable(uuid string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.unreachable[uuid]
}

func (p *Plane) clearUnreachable(uuid string) {
	p.mu.Lock()
	delete(p.unreachable, uuid)
	p.mu.Unlock()
}

// mailbox returns (creating if needed) the job channel for a worker uuid.
func (rd *reverseDispatch) mailbox(uuid string) chan *revJob {
	rd.mu.Lock()
	defer rd.mu.Unlock()
	ch, ok := rd.inbox[uuid]
	if !ok {
		ch = make(chan *revJob, 64) // buffered so a burst doesn't block the router on a slow poller
		rd.inbox[uuid] = ch
	}
	return ch
}

// submit enqueues a job for a worker and blocks until the worker returns a result or ctx fires.
// Returns a synthesized *http.Response identical in shape to a dialed worker's reply.
func (rd *reverseDispatch) submit(ctx context.Context, uuid string, body []byte, headers map[string]string) (*http.Response, error) {
	rd.mu.Lock()
	rd.seq++
	id := rd.seq
	res := make(chan *revResult, 1)
	rd.pending[id] = res
	rd.mu.Unlock()
	defer func() { rd.mu.Lock(); delete(rd.pending, id); rd.mu.Unlock() }()

	job := &revJob{ID: id, Body: body, Headers: headers, result: res}
	select {
	case rd.mailbox(uuid) <- job:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case r := <-res:
		return responseFrom(r), nil
	case <-ctx.Done():
		return nil, ctx.Err() // worker vanished mid-job — caller releases + tries the next worker
	}
}

// responseFrom rebuilds the *http.Response the gateway streams to the client.
func responseFrom(r *revResult) *http.Response {
	h := http.Header{}
	for k, v := range r.Headers {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: r.Status, Header: h, Body: io.NopCloser(bytes.NewReader(r.Body))}
}

// deliver routes a worker's posted result to the waiting submit() call. ok=false if nobody waits
// (the job already timed out) — the worker's effort is simply discarded.
func (rd *reverseDispatch) deliver(id int64, r *revResult) bool {
	rd.mu.Lock()
	ch, ok := rd.pending[id]
	rd.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case ch <- r:
		return true
	default:
		return false
	}
}

// peerCN returns the mutual-TLS client's certificate CommonName (a node's UUID). The Link server
// is RequireAndVerifyClientCert, so a present peer cert is already chain-verified; the CN is the
// authenticated worker identity, so one worker cannot pull another's jobs.
func peerCN(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	return r.TLS.PeerCertificates[0].Subject.CommonName
}

// handleReversePull is the worker's long-poll: block until a job for this worker (identity = client
// cert CN, verified by the mTLS Link) is available, or return 204 on timeout so the worker re-polls.
func (p *Plane) handleReversePull(rw http.ResponseWriter, r *http.Request) {
	uuid := peerCN(r)
	if uuid == "" {
		http.Error(rw, "unidentified peer", http.StatusUnauthorized)
		return
	}
	wait := 25 * time.Second
	ctx, cancel := context.WithTimeout(r.Context(), wait)
	defer cancel()
	select {
	case job := <-p.rev().mailbox(uuid):
		rw.Header().Set("Content-Type", "application/json")
		rw.Header().Set("X-Dani-Job-Id", strconv.FormatInt(job.ID, 10))
		_ = json.NewEncoder(rw).Encode(map[string]any{"id": job.ID, "body": job.Body, "headers": job.Headers})
	case <-ctx.Done():
		rw.WriteHeader(http.StatusNoContent) // no work this window — poll again
	}
}

// handleReverseResult receives the worker's inference result and hands it to the waiting dispatch().
func (p *Plane) handleReverseResult(rw http.ResponseWriter, r *http.Request) {
	if peerCN(r) == "" {
		http.Error(rw, "unidentified peer", http.StatusUnauthorized)
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("job"), 10, 64)
	if err != nil {
		http.Error(rw, "bad job id", http.StatusBadRequest)
		return
	}
	var res revResult
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(&res); err != nil {
		http.Error(rw, "bad result", http.StatusBadRequest)
		return
	}
	if !p.rev().deliver(id, &res) {
		http.Error(rw, "no waiter (job expired)", http.StatusGone)
		return
	}
	rw.WriteHeader(http.StatusOK)
}
