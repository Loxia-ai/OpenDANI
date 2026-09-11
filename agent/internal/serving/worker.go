package serving

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dani.local/agent/internal/artifact"
	"dani.local/agent/internal/engine"
	"dani.local/agent/internal/limits"
	"dani.local/agent/internal/wg"
)

// Heartbeat is the worker→controller Link message (DL-R11-06): liveness + load + how to reach this
// worker for dispatch. Sent periodically; the controller's router scores candidates from these.
type Heartbeat struct {
	NodeUUID        string   `json:"node_uuid"`
	DispatchAddr    string   `json:"dispatch_addr"` // host:port the controller dials for inference
	ModelID         string   `json:"model_id"`
	Engine          string   `json:"engine"`
	Class           string   `json:"class"`
	Site            string   `json:"site"`                       // worker's site tag (for locality routing on non-flat networks)
	Active          int      `json:"active"`                     // in-flight requests being served
	Queued          int      `json:"queued"`                     // requests waiting for a slot (DP4 admission queue)
	Served          int64    `json:"served"`                     // lifetime completions
	MaxConcurrent   int      `json:"max_concurrent"`             // serving slots
	QueueDepth      int      `json:"queue_depth"`                // max waiters before back-pressure
	EmaServiceMs    int64    `json:"ema_service_ms"`             // EMA of service time (for ETA estimates)
	WGPubKey        string   `json:"wg_pubkey"`                  // this node's WireGuard public key (DANI-coordinated overlay)
	WGEndpoint      string   `json:"wg_endpoint"`                // host:port for WireGuard, or "" if NAT'd
	Health          string   `json:"health"`                     // healthy | degraded
	Loaded          []string `json:"loaded,omitempty"`           // hot-loaded (auto-deployed) model ids this worker ALSO serves
	HotLoad         bool     `json:"hot_load,omitempty"`         // engine can accept deployments at runtime
	Trainer         bool     `json:"trainer,omitempty"`          // dedicated training hardware (D17): NEVER routed inference; DispatchAddr is its /train endpoint
	Accel           string   `json:"accel,omitempty"`            // detected acceleration backend (cuda|metal|vulkan|cpu) — hwcaps
	ReverseTunnel   bool     `json:"reverse_tunnel,omitempty"`   // FORCE mode: worker is UNREACHABLE inbound; the controller ALWAYS dispatches over the outbound long-poll (never dials; DispatchAddr unused)
	TunnelAvailable bool     `json:"tunnel_available,omitempty"` // AUTO mode: worker keeps an outbound long-poll open AS A FALLBACK but stays dialable — the controller dials first and falls back to the tunnel only if the dial fails
	Seed            bool     `json:"seed,omitempty"`             // OPEN-DANI: a TRUSTED node the operator runs — the correctness anchor for verifying volunteer output; never itself verified
	CapMode         string   `json:"cap_mode,omitempty"`         // resource budget mode: full | polite | custom (internal/limits)
	MaxCores        int      `json:"max_cores,omitempty"`        // CPU cores this node lets DANI use (0 = unset/all)
	MemBudgetMB     int      `json:"mem_budget_mb,omitempty"`    // model-memory budget in MB (0 = unbounded)
}

// Worker is the data-plane half of a worker node: it serves OpenAI chat completions over mTLS and
// heartbeats its load to the controller.
type Worker struct {
	id             Identity
	eng            engine.Engine
	modelID        string
	class          string
	site           string
	advertiseHost  string
	dispatchAddr   string   // set once the inference listener binds (host:boundport)
	controllerURLs []string // heartbeat to ALL controllers (HA fan-out) so any can route with full availability
	maxConcurrent  int
	queueDepth64   int64 // DP4: max waiters before back-pressure (atomic — live-configurable, P1-7)
	sloBudgetNs    int64 // DP4: max wait for a slot, nanoseconds (atomic — live-configurable, P1-7)
	hbEvery        time.Duration
	deployEvery    time.Duration // deploy-poll interval (default 3s; tests shrink it)
	drainTimeout   time.Duration // graceful-shutdown bound: max wait for in-flight requests (P1-3)

	sem    chan struct{} // serving-slot semaphore (cap = maxConcurrent)
	active int64
	queued int64
	served int64
	emaMs  int64 // EMA of service time, atomically updated

	wgKey      wg.Key // this worker's WireGuard key (DANI-coordinated overlay)
	wgEndpoint string // host:port advertised for WireGuard ("" = NAT'd, hub learns it)
	wgConfOut  string // if set, write the importable WireGuard config here
	gatewayURL string // controller gateway base (for fetching the DANI-rendered WG config)

	accel         string // detected acceleration backend (hwcaps) — advertised on every heartbeat
	reverseTunnel bool   // FORCE: receive jobs ONLY by outbound long-poll (never dialed)
	reverseAuto   bool   // AUTO: keep an outbound long-poll open as a fallback but stay dialable

	// resource budget (internal/limits) — live-configurable (worker.max-cores / worker.max-model-mem-mb)
	// and reported on every heartbeat so the console shows what each node lets DANI use.
	// flag* is the CLI baseline: when a config override is DELETED the node reverts here.
	flagCores int64        // the --max-cores baseline (0 = auto, limits.AllCores = dedicated)
	flagMemMB int64        // the --max-model-mem-mb baseline (0 = auto)
	ovrCores  int64        // atomic: the effective override (config wins over flag)
	ovrMemMB  int64        // atomic: the effective override, model-memory MB
	capCores  int64        // atomic: effective cores DANI may use (reported)
	capMemMB  int64        // atomic: effective model-memory budget MB (reported; 0 = unbounded)
	capMode   atomic.Value // string: full | polite | custom
	seed          bool   // OPEN-DANI: this is a trusted seed node (the verification anchor)

	controlURL string       // base for the node data plane (mTLS link when enrolled; gateway in tests)
	deployHTTP *http.Client // client for the data plane (mTLS when enrolled; plain otherwise)

	revPoll  *revocationPoller // fleet CRL copy (P1-4); nil when not enrolled
	revEvery time.Duration     // CRL poll interval (default 5s; tests shrink it)
	cfgEvery time.Duration     // config poll interval (default 15s; tests shrink it, P1-7)
}

// isPeerRevoked is the TLS-layer revocation check for this worker's mTLS server.
func (w *Worker) isPeerRevoked(cn string) bool {
	return w.revPoll != nil && w.revPoll.isRevoked(cn)
}

// WorkerConfig configures the worker data plane.
type WorkerConfig struct {
	Identity       Identity
	Engine         engine.Engine
	ModelID        string
	Class          string
	Site           string
	AdvertiseHost  string   // host the controller will dial; the port comes from the bound listener
	ControllerURLs []string // Link URLs to heartbeat to (one per controller, HA fan-out)
	MaxConcurrent  int
	QueueDepth     int           // DP4 admission queue depth (default 2× MaxConcurrent)
	SLOBudget      time.Duration // DP4 max queue wait before back-pressure (default 20s)
	WGPort         int           // WireGuard listen port advertised (default 51820)
	WGConfOut      string        // if set, write this node's full importable WireGuard config here
	GatewayURL     string        // controller gateway base (plain HTTP) for fetching the DANI WG config
	HeartbeatEvery time.Duration
	DrainTimeout   time.Duration // graceful shutdown: max wait for in-flight requests (default 30s)
	Accel          string        // detected acceleration backend (hwcaps): advertised on every heartbeat
	ReverseTunnel  bool          // FORCE reverse-tunnel: never dialed, dispatched only over the outbound long-poll
	ReverseAuto    bool          // AUTO reverse-tunnel: keep the tunnel open as a fallback but stay dialable
	Seed           bool          // OPEN-DANI: mark this node a trusted seed (verification anchor)
	OverrideCores  int           // operator --max-cores (0 = auto); live-tunable via worker.max-cores
	OverrideMemMB  int           // operator --max-model-mem-mb (0 = auto); live-tunable
	CapPlan        limits.Plan   // the resolved resource plan (from internal/limits) for reporting
}

func NewWorker(c WorkerConfig) *Worker {
	if c.MaxConcurrent <= 0 {
		c.MaxConcurrent = 4
	}
	if c.QueueDepth <= 0 {
		c.QueueDepth = 2 * c.MaxConcurrent
	}
	if c.SLOBudget <= 0 {
		c.SLOBudget = 20 * time.Second
	}
	if c.HeartbeatEvery <= 0 {
		c.HeartbeatEvery = 3 * time.Second
	}
	if c.DrainTimeout <= 0 {
		c.DrainTimeout = 30 * time.Second
	}
	if c.AdvertiseHost == "" {
		c.AdvertiseHost = "127.0.0.1"
	}
	if c.WGPort <= 0 {
		c.WGPort = 51820
	}
	wgKey, _ := wg.NewKey() // best-effort; empty key => simply not advertised
	w := &Worker{
		id: c.Identity, eng: c.Engine, modelID: c.ModelID, class: c.Class, site: c.Site,
		advertiseHost: c.AdvertiseHost, controllerURLs: c.ControllerURLs,
		maxConcurrent: c.MaxConcurrent, queueDepth64: int64(c.QueueDepth), sloBudgetNs: int64(c.SLOBudget), hbEvery: c.HeartbeatEvery,
		drainTimeout:  c.DrainTimeout,
		sem:           make(chan struct{}, c.MaxConcurrent),
		wgKey:         wgKey,
		wgEndpoint:    fmt.Sprintf("%s:%d", c.AdvertiseHost, c.WGPort),
		wgConfOut:     c.WGConfOut,
		gatewayURL:    c.GatewayURL,
		accel:         c.Accel,
		reverseTunnel: c.ReverseTunnel,
		reverseAuto:   c.ReverseAuto,
		seed:          c.Seed,
	}
	// The auto-deploy data plane (poll / artifact pull / report) runs over the mTLS LINK to the
	// controller — not the public browser gateway — so it works regardless of external gateway TLS.
	// When a node is enrolled it has controllerURLs (the mTLS link bases) + certs -> use those. A test
	// / gateway-only worker falls back to the plain gateway URL.
	if len(c.ControllerURLs) > 0 {
		w.controlURL = c.ControllerURLs[0]
		w.deployHTTP = w.linkClient()
	} else {
		w.controlURL = c.GatewayURL
		w.deployHTTP = &http.Client{Timeout: 30 * time.Second}
	}
	w.flagCores, w.flagMemMB = int64(c.OverrideCores), int64(c.OverrideMemMB)
	atomic.StoreInt64(&w.ovrCores, int64(c.OverrideCores))
	atomic.StoreInt64(&w.ovrMemMB, int64(c.OverrideMemMB))
	w.setCapPlan(c.CapPlan)
	return w
}

// setCapPlan records the resolved resource budget so it's reported on the next heartbeat.
func (w *Worker) setCapPlan(p limits.Plan) {
	atomic.StoreInt64(&w.capCores, int64(p.Cores))
	atomic.StoreInt64(&w.capMemMB, int64(p.MemBudgetMB()))
	w.capMode.Store(p.Mode)
}

// Serve starts the engine, the mTLS inference server on listenAddr, and the heartbeat loop. Blocks.
func (w *Worker) Serve(ctx context.Context, listenAddr string) error {
	if err := w.eng.Start(ctx); err != nil {
		return fmt.Errorf("engine start: %w", err)
	}
	defer w.eng.Close()
	log.Printf("worker %s: engine %q ready (model=%s)", w.id.UUID, w.eng.Name(), w.modelID)

	// The CRL copy must exist BEFORE the TLS config that consults it (handshakes race the assignment
	// otherwise); the poll goroutine itself starts after the listener below.
	if len(w.controllerURLs) > 0 { // enrolled — the CRL comes over the mTLS Link (P1-4)
		w.revPoll = newRevocationPoller(w.id.UUID, w.controllerURLs[0], w.linkClient(), w.id.Root, w.revEvery)
	}
	tlsCfg, err := serverTLS(w.id.LeafRaw, w.id.InterRaw, w.id.Key, w.id.Root, w.isPeerRevoked)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", w.handleChat)
	mux.HandleFunc("/healthz", func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusOK) })
	// P1-2 observability: the listener only binds after engine.Start, so serving == ready here.
	mux.HandleFunc("/readyz", func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte(`{"ready":true}`))
	})
	wm := newWorkerMetrics(w)
	mux.Handle("/metrics", wm.reg.Handler())

	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	_, port, _ := net.SplitHostPort(lis.Addr().String())
	w.dispatchAddr = net.JoinHostPort(w.advertiseHost, port) // advertise the actually-bound port
	srv := &http.Server{Handler: wm.instrument(mux), TLSConfig: tlsCfg}
	go func() { _ = srv.Serve(tls.NewListener(lis, tlsCfg)) }()
	log.Printf("worker %s: inference endpoint serving on %s (mTLS); advertising %s", w.id.UUID, lis.Addr(), w.dispatchAddr)

	go w.heartbeatLoop(ctx)
	if (w.reverseTunnel || w.reverseAuto) && len(w.controllerURLs) > 0 {
		go w.reversePullLoop(ctx) // NAT traversal: keep the outbound tunnel open (force OR auto-fallback)
	}
	if w.wgConfOut != "" {
		go w.writeWGConfig(ctx)
	}
	if _, ok := w.eng.(engine.HotLoader); ok && w.controlURL != "" {
		go w.deployLoop(ctx) // auto-deploy: pull + verify + load promoted models (§6.17.4)
	}
	if w.revPoll != nil {
		go w.revPoll.run(ctx) // keep the fleet CRL fresh (P1-4)
	}
	if len(w.controllerURLs) > 0 {
		go w.configLoop(ctx) // live-apply the node's effective §6.20 config (P1-7)
	}

	<-ctx.Done()
	// Graceful drain (P1-3): announce "draining" so every controller's router stops sending new
	// work IMMEDIATELY (reserve only routes to Health "healthy" — no staleness wait), then let the
	// server finish what's in flight, bounded by drainTimeout.
	log.Printf("worker %s: shutdown signal — draining (%d active, %d queued)",
		w.id.UUID, atomic.LoadInt64(&w.active), atomic.LoadInt64(&w.queued))
	announceCtx, cancelAnnounce := context.WithTimeout(context.Background(), 5*time.Second)
	w.postHeartbeat(announceCtx, w.linkClient(), w.heartbeat("draining"))
	cancelAnnounce()
	shCtx, cancelShutdown := context.WithTimeout(context.Background(), w.drainTimeout)
	defer cancelShutdown()
	if err := srv.Shutdown(shCtx); err != nil {
		log.Printf("worker %s: drain timeout — %d request(s) cut off: %v", w.id.UUID, atomic.LoadInt64(&w.active), err)
	} else {
		log.Printf("worker %s: drained cleanly — all in-flight requests completed", w.id.UUID)
	}
	return ctx.Err()
}

// writeWGConfig fetches THIS node's DANI-coordinated WireGuard config from the controller (which
// assigned the overlay IP + hub peer) and writes a complete, importable .conf locally — injecting the
// node's own private key, which never left this machine. The user imports it into WireGuard to join
// the DANI overlay. Polls until the hub has registered this node (a [Peer] section appears).
func (w *Worker) writeWGConfig(ctx context.Context) {
	if w.gatewayURL == "" || w.wgKey.Private == "" {
		return
	}
	url := w.gatewayURL + "/dani/wg/config?node=" + w.id.UUID
	client := &http.Client{Timeout: 8 * time.Second}
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		cfg := string(b)
		if resp.StatusCode != http.StatusOK || !strings.Contains(cfg, "[Peer]") {
			continue // hub hasn't registered us yet
		}
		// inject our private key (DANI distributes only public keys; the private key stays local).
		full := strings.Replace(cfg,
			"# PrivateKey is injected locally by the agent; never leaves the node",
			"PrivateKey = "+w.wgKey.Private, 1)
		if err := os.WriteFile(w.wgConfOut, []byte(full), 0o600); err != nil {
			log.Printf("worker %s: write WG config: %v", w.id.UUID, err)
			return
		}
		log.Printf("worker %s: wrote importable WireGuard config to %s — import it into WireGuard and Activate to join the DANI overlay", w.id.UUID, w.wgConfOut)
		return
	}
}

// reversePullLoop is the worker half of NAT/firewall traversal (NAT-TRANSPORT.md): instead of the
// controller dialing this worker, the worker keeps `maxConcurrent` outbound long-polls open on the
// mTLS Link, pulls one job per poll, runs it through the SAME inference core as an HTTP request, and
// posts the result back. Every connection is outbound HTTPS — nothing needs to reach this node.
func (w *Worker) reversePullLoop(ctx context.Context) {
	base := w.controllerURLs[0]
	// a long-poll can block up to ~25s server-side; the client timeout must exceed that.
	client := &http.Client{Timeout: 40 * time.Second, Transport: w.linkClient().Transport}
	pullers := w.maxConcurrent
	if pullers < 1 {
		pullers = 1
	}
	log.Printf("worker %s: reverse-tunnel ON — %d outbound puller(s) to %s (no inbound reachability needed)", w.id.UUID, pullers, base)
	var wg sync.WaitGroup
	for i := 0; i < pullers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				w.pullOne(ctx, client, base)
			}
		}()
	}
	wg.Wait()
}

// pullOne performs one pull→serve→result cycle. Errors and empty windows just loop (with a short
// backoff on error) — the controller re-queues nothing; an unclaimed job stays in the mailbox.
func (w *Worker) pullOne(ctx context.Context, client *http.Client, base string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/link/dispatch/pull", nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second): // controller unreachable — back off, then retry
		}
		return
	}
	if resp.StatusCode == http.StatusNoContent { // no work this window
		resp.Body.Close()
		return
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return
	}
	var job struct {
		ID      int64             `json:"id"`
		Body    []byte            `json:"body"`
		Headers map[string]string `json:"headers"`
	}
	dec := json.NewDecoder(resp.Body)
	derr := dec.Decode(&job)
	resp.Body.Close()
	if derr != nil {
		return
	}
	// run the SAME inference core as a dialed request → identical admission + telemetry + shape.
	status, headers, respBody := w.runChat(ctx, job.Body)
	out, _ := json.Marshal(map[string]any{"status": status, "headers": headers, "body": respBody})
	pr, err := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/link/dispatch/result?job="+strconv.FormatInt(job.ID, 10), bytes.NewReader(out))
	if err != nil {
		return
	}
	pr.Header.Set("Content-Type", "application/json")
	if rr, err := client.Do(pr); err == nil {
		rr.Body.Close()
	}
}

// deployLoop is the worker half of auto-deploy (§6.17.4): poll for assignments, PULL the artifact
// through the gateway's verify-on-use gate, VERIFY the content hash locally, LOAD it into the
// engine, and REPORT — the next heartbeat advertises the model and the router starts matching it.
func (w *Worker) deployLoop(ctx context.Context) {
	hl := w.eng.(engine.HotLoader)
	client := w.deployHTTP // mTLS link client when enrolled (never the plaintext gateway)
	if w.deployEvery <= 0 {
		w.deployEvery = 3 * time.Second
	}
	t := time.NewTicker(w.deployEvery)
	defer t.Stop()
	done := map[string]bool{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		resp, err := client.Get(w.controlURL + "/dani/deployments?node=" + w.id.UUID + "&class=" + w.class)
		if err != nil {
			continue
		}
		var out struct {
			Deployments []struct{ Model, State string } `json:"deployments"`
		}
		err = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if err != nil {
			continue
		}
		// The response is this node's FULL desired set: anything we hot-loaded that is no longer
		// listed was undeployed (operator action or scale-down) — unload it so the next heartbeat
		// stops advertising it and the router stops matching it here.
		desired := map[string]bool{}
		for _, d := range out.Deployments {
			desired[d.Model] = true
		}
		if hu, ok := w.eng.(engine.HotUnloader); ok {
			for m := range done {
				if desired[m] {
					continue
				}
				if err := hu.Unload(m); err != nil {
					log.Printf("worker %s: unload %s failed: %v", w.id.UUID, m, err)
					continue
				}
				delete(done, m)
				log.Printf("worker %s: UNDEPLOYED %s (assignment removed) — no longer serving it", w.id.UUID, m)
			}
		}
		for _, d := range out.Deployments {
			if done[d.Model] {
				continue
			}
			if err := w.pullAndLoad(client, hl, d.Model); err != nil {
				log.Printf("worker %s: deploy %s failed: %v", w.id.UUID, d.Model, err)
				continue
			}
			done[d.Model] = true
			body, _ := json.Marshal(map[string]string{"node": w.id.UUID, "model": d.Model})
			if rep, err := client.Post(w.controlURL+"/dani/deployments/report", "application/json", bytes.NewReader(body)); err == nil {
				rep.Body.Close()
			}
			log.Printf("worker %s: DEPLOYED %s (pulled, hash-verified, loaded) — serving it now", w.id.UUID, d.Model)
		}
	}
}

// pullAndLoad fetches a promoted model's artifact and loads it, re-verifying the content hash on
// this side of the wire (the third DP13 check on the pull path).
func (w *Worker) pullAndLoad(client *http.Client, hl engine.HotLoader, model string) error {
	resp, err := client.Get(w.controlURL + "/dani/models/artifact?id=" + model)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("artifact pull refused: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if want := resp.Header.Get("X-Dani-Artifact-Hash"); want != "" && artifact.HashOf(data) != want {
		return fmt.Errorf("artifact hash mismatch — refusing to load")
	}
	return hl.Load(model, data)
}

func (w *Worker) handleChat(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(r.Body)
	status, headers, respBody := w.runChat(r.Context(), body)
	for k, v := range headers {
		rw.Header().Set(k, v)
	}
	rw.WriteHeader(status)
	_, _ = rw.Write(respBody)
}

// runChat is the SHARED inference core used by both the HTTP handler and the reverse-tunnel pull
// loop (NAT-TRANSPORT.md), so a reverse-tunnel worker behaves identically to a dialed one — same
// DP4 admission, same telemetry, same OpenAI response. Returns (status, headers, body) instead of
// writing to a ResponseWriter so it works over either transport.
func (w *Worker) runChat(ctx context.Context, body []byte) (int, map[string]string, []byte) {
	// DP4 SLO-aware admission (§6.5, §6.17.1): take a serving slot if free, else WAIT in a bounded
	// queue up to the SLO budget; if the queue is full or the wait blows the budget, declare "busy"
	// with a Retry-After ESTIMATE (not an SLA — best-effort inference, D47).
	q := atomic.AddInt64(&w.queued, 1)
	total := atomic.LoadInt64(&w.active) + q // serving + waiting
	if int(total) > w.maxConcurrent+w.qDepth() {
		atomic.AddInt64(&w.queued, -1)
		return w.busyResult(int(total))
	}
	select {
	case w.sem <- struct{}{}: // acquired a serving slot
		atomic.AddInt64(&w.queued, -1)
		defer func() { <-w.sem }()
	case <-time.After(w.slo()): // waited too long → shed with back-pressure
		atomic.AddInt64(&w.queued, -1)
		return w.busyResult(int(total))
	case <-ctx.Done():
		atomic.AddInt64(&w.queued, -1)
		return http.StatusServiceUnavailable, map[string]string{"Content-Type": "application/json"}, []byte(`{"error":{"message":"cancelled"}}`)
	}
	atomic.AddInt64(&w.active, 1)
	defer atomic.AddInt64(&w.active, -1)

	var req engine.Request
	if err := json.Unmarshal(body, &req); err != nil {
		return http.StatusBadRequest, map[string]string{"Content-Type": "text/plain"}, []byte("bad request: " + err.Error())
	}
	start := time.Now()
	res, err := w.eng.Chat(ctx, req)
	if err != nil {
		return http.StatusBadGateway, map[string]string{"Content-Type": "text/plain"}, []byte("inference error: " + err.Error())
	}
	w.observeService(time.Since(start))
	atomic.AddInt64(&w.served, 1)

	out, _ := json.Marshal(map[string]any{
		"id":      "chatcmpl-" + w.id.UUID,
		"object":  "chat.completion",
		"model":   res.Model,
		"choices": []map[string]any{{"index": 0, "message": engine.Message{Role: "assistant", Content: res.Text}, "finish_reason": "stop"}},
		"usage":   map[string]int{"prompt_tokens": res.PromptTokens, "completion_tokens": res.CompletionTokens, "total_tokens": res.PromptTokens + res.CompletionTokens},
	})
	return http.StatusOK, map[string]string{
		"Content-Type":          "application/json",
		"X-Dani-Worker":         w.id.UUID,
		"X-Dani-Engine":         res.Engine,
		"X-Dani-Latency-Ms":     fmt.Sprintf("%d", res.TotalMs),
		"X-Dani-First-Token-Ms": fmt.Sprintf("%d", res.FirstTokenMs),
	}, out
}

// busyResult builds the "I'm busy" back-pressure reply (429 + Retry-After ESTIMATE, not an SLA;
// best-effort inference, D47) as a (status, headers, body) triple so it works over either transport.
func (w *Worker) busyResult(queuePos int) (int, map[string]string, []byte) {
	etaMs := w.estimateWaitMs(queuePos)
	retryS := (etaMs + 999) / 1000
	if retryS < 1 {
		retryS = 1
	}
	body, _ := json.Marshal(map[string]any{
		"error": map[string]any{"message": "worker busy — admission queue full or SLO budget exceeded", "type": "back_pressure", "code": "busy"},
		"dani":  map[string]any{"busy": true, "worker": w.id.UUID, "queue_position": queuePos, "estimated_wait_ms": etaMs, "note": "estimate, not a guarantee (best-effort inference, D47)"},
	})
	return http.StatusTooManyRequests, map[string]string{
		"Retry-After":              fmt.Sprintf("%d", retryS),
		"X-Dani-Worker":            w.id.UUID,
		"X-Dani-Busy":              "true",
		"X-Dani-Estimated-Wait-Ms": fmt.Sprintf("%d", etaMs),
		"Content-Type":             "application/json",
	}, body
}

// estimateWaitMs approximates time-to-a-free-slot: ~ceil(queuePos / maxConcurrent) "waves" of the
// EMA service time. A hint for callers, deliberately rough.
func (w *Worker) estimateWaitMs(queuePos int) int64 {
	ema := atomic.LoadInt64(&w.emaMs)
	if ema <= 0 {
		ema = 1000 // no samples yet → assume ~1s
	}
	if queuePos < 1 {
		queuePos = 1
	}
	waves := (queuePos + w.maxConcurrent - 1) / w.maxConcurrent
	return int64(waves) * ema
}

// observeService folds a completed request's service time into the EMA (alpha = 0.2).
func (w *Worker) observeService(d time.Duration) {
	ms := d.Milliseconds()
	for {
		old := atomic.LoadInt64(&w.emaMs)
		nv := ms
		if old > 0 {
			nv = (old*4 + ms) / 5
		}
		if atomic.CompareAndSwapInt64(&w.emaMs, old, nv) {
			return
		}
	}
}

// heartbeat builds this worker's Link message with the given health state.
func (w *Worker) heartbeat(health string) Heartbeat {
	hb := Heartbeat{
		NodeUUID: w.id.UUID, DispatchAddr: w.dispatchAddr, ModelID: w.modelID, Engine: w.eng.Name(),
		Class: w.class, Site: w.site, Active: int(atomic.LoadInt64(&w.active)), Queued: int(atomic.LoadInt64(&w.queued)),
		Served: atomic.LoadInt64(&w.served), MaxConcurrent: w.maxConcurrent, QueueDepth: w.qDepth(),
		EmaServiceMs: atomic.LoadInt64(&w.emaMs), WGPubKey: w.wgKey.Public, WGEndpoint: w.wgEndpoint, Health: health,
		Accel: w.accel, ReverseTunnel: w.reverseTunnel, TunnelAvailable: w.reverseTunnel || w.reverseAuto,
		Seed: w.seed,
	}
	hb.CapMode, _ = w.capMode.Load().(string)
	hb.MaxCores = int(atomic.LoadInt64(&w.capCores))
	hb.MemBudgetMB = int(atomic.LoadInt64(&w.capMemMB))
	if hl, ok := w.eng.(engine.HotLoader); ok {
		hb.HotLoad = true
		hb.Loaded = hl.Loaded()
	}
	return hb
}

// postHeartbeat fans a heartbeat out to every controller (HA: any of them can route with full
// availability). ctx bounds each POST.
func (w *Worker) postHeartbeat(ctx context.Context, client *http.Client, hb Heartbeat) {
	body, _ := json.Marshal(hb)
	for _, base := range w.controllerURLs {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/link/heartbeat", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("worker %s: heartbeat to %s failed: %v", w.id.UUID, base, err)
			continue
		}
		resp.Body.Close()
	}
}

func (w *Worker) heartbeatLoop(ctx context.Context) {
	client := w.linkClient()
	t := time.NewTicker(w.hbEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.postHeartbeat(ctx, client, w.heartbeat("healthy"))
		}
	}
}

func (w *Worker) linkClient() *http.Client {
	tlsCfg, _ := clientTLS(w.id.LeafRaw, w.id.InterRaw, w.id.Key, w.id.Root)
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
}
