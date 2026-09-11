package serving

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"dani.local/agent/internal/backup"
	"dani.local/agent/internal/ledger"
	"dani.local/agent/internal/reputation"
	"dani.local/agent/internal/wg"
)

//go:embed webapp/console.html
var consoleHTML []byte

//go:embed webapp/traces.html
var tracesHTML []byte

//go:embed all:webapp/console
var consoleFS embed.FS

func readerOf(b []byte) *bytes.Reader { return bytes.NewReader(b) }

// classRank orders classifications; a worker may serve a request iff its clearance >= the request's
// (dominance — the DEMO decision in DEMO-SCOPE §4.1: clearance is an upper-bound ceiling).
var classRank = map[string]int{"unrestricted": 0, "internal": 1, "restricted": 2, "secret": 3}

func rank(c string) int {
	if r, ok := classRank[c]; ok {
		return r
	}
	return 0
}

type workerState struct {
	Heartbeat
	LastSeen time.Time
}

// Plane is the controller-side data plane: the Link heartbeat sink + live worker table, the router,
// and the OpenAI gateway that dispatches to workers over mTLS.
type Plane struct {
	id   Identity
	site string

	mu       sync.RWMutex
	workers  map[string]*workerState
	inflight map[string]int  // requests the gateway has dispatched but not yet completed, per worker
	drained  map[string]bool // operator-drained nodes: enrolled + heartbeating but out of routing
	revoked  map[string]bool // revoked nodes: heartbeats rejected, evicted from the plane
	revSeq   int64           // revocation-list sequence (bumped on every revoke; replay protection)
	stale    time.Duration
	onHB     func(Heartbeat)

	admin  *NodeAdmin    // optional node-control surface (EnableNodeAdmin)
	opAuth *OperatorAuth // optional operator write-gating (EnableOperatorAuth)
	oidc   *OIDCAuth     // optional OIDC/SSO login (EnableOIDC)
	gwTLS  *GatewayTLS   // optional HTTPS for the external gateway (SetGatewayTLS)

	wgKey      wg.Key // the controller's own WireGuard key (DANI is the VPN coordinator)
	wgEndpoint string // the controller's reachable WireGuard endpoint (host:port)

	training *TrainingAPI // optional train->sign->serve control surface (EnableTraining)

	metrics *planeMetrics // optional observability surface (EnableMetrics)

	configAPI *configAPI // optional governed config store (EnableConfig, P1-7)

	limits *limitsState // live edge protection: body caps + per-IP rate limit (P2-1)

	backupDir string // when set, the Link serves this controller's backups for cross-site replication (P2-A2)

	tracer *tracer // optional per-request trace ring (EnableTracing, P2-A3)

	demo *demoConfig // optional fan-out coding demo surface (EnableDemo, Tier C — demo-only)

	clusterInfo func() ([]ClusterMember, string) // optional Raft membership provider (SetClusterInfo)

	reverse     *reverseDispatch // NAT/firewall traversal: mailbox for workers reachable only outbound
	unreachable map[string]bool  // AUTO reverse-tunnel: workers a dial has PROVEN undialable → use the mailbox (cleared when their dispatch addr changes)

	reputation  *reputation.Store // OPEN-DANI: per-node trust (EnableSeedVerify); nil in enterprise
	verify      *verifyConfig     // OPEN-DANI: seed cross-check thresholds; nil = verification off
	pow         *powConfig        // OPEN-DANI: NAT-agnostic per-request proof-of-work admission; nil = off
	moderation  *moderationConfig // OPEN-DANI: prompt/output content gate; nil = off
	ledger      *ledger.Store     // OPEN-DANI: contribution economy (EnableLedger); nil = off
	reserveFrac float64           // share of capacity held for contributors (best-effort rides the rest)

	srvMu   sync.Mutex
	servers []*http.Server // live listeners (gateway + link) for graceful Shutdown (P1-3)

	dialer *http.Client // mTLS client used to dispatch to workers
}

// track registers a live server for graceful shutdown.
func (p *Plane) track(srv *http.Server) {
	p.srvMu.Lock()
	p.servers = append(p.servers, srv)
	p.srvMu.Unlock()
}

// Shutdown drains the gateway + Link servers gracefully (P1-3): stop accepting, finish in-flight
// requests, bounded by ctx. Call on SIGTERM so a rolling restart never drops a request mid-flight.
func (p *Plane) Shutdown(ctx context.Context) error {
	p.srvMu.Lock()
	servers := append([]*http.Server(nil), p.servers...)
	p.srvMu.Unlock()
	var firstErr error
	for _, srv := range servers {
		if err := srv.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// NewPlane builds the controller data plane. site is the controller's site tag (for locality scoring).
func NewPlane(id Identity, site string) (*Plane, error) {
	tlsCfg, err := clientTLS(id.LeafRaw, id.InterRaw, id.Key, id.Root)
	if err != nil {
		return nil, err
	}
	wgKey, err := wg.NewKey()
	if err != nil {
		return nil, err
	}
	return &Plane{
		id: id, site: site, workers: map[string]*workerState{}, inflight: map[string]int{},
		drained: map[string]bool{}, revoked: map[string]bool{}, stale: 12 * time.Second,
		wgKey:       wgKey,
		limits:      newLimits(),
		reverse:     newReverseDispatch(),
		unreachable: map[string]bool{},
		// DialContext caps only the TCP CONNECT (3s) — not the response wait — so an undialable
		// worker (NAT'd, firewalled) fails fast and the AUTO path fails over to its tunnel quickly,
		// while a reachable-but-slow worker can still stream a long inference. TLSHandshakeTimeout
		// bounds the handshake similarly.
		dialer: &http.Client{Timeout: 5 * time.Minute, Transport: &http.Transport{
			TLSClientConfig:     tlsCfg,
			DialContext:         (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
			TLSHandshakeTimeout: 4 * time.Second,
		}},
	}, nil
}

// OnHeartbeat is an optional hook (e.g. persist to the Node Registry) called on each heartbeat.
func (p *Plane) OnHeartbeat(fn func(Heartbeat)) { p.onHB = fn }

// SetWGEndpoint sets the controller's reachable WireGuard endpoint (host:port) advertised to spokes.
func (p *Plane) SetWGEndpoint(ep string) { p.wgEndpoint = ep }

// WriteHubWGConfig writes the controller's own importable WireGuard config (hub interface, with its
// private key injected locally) so the host can bring up wg0. Peers (workers) are added live as they
// join. The private key never leaves this node.
func (p *Plane) WriteHubWGConfig(path string) error {
	cfg, ok := p.buildMesh().ConfigFor(p.id.UUID, 51820)
	if !ok {
		return fmt.Errorf("hub not in mesh")
	}
	full := strings.Replace(cfg,
		"# PrivateKey is injected locally by the agent; never leaves the node",
		"PrivateKey = "+p.wgKey.Private, 1)
	return os.WriteFile(path, []byte(full), 0o600)
}

// buildMesh computes the DANI-coordinated WireGuard overlay from the live fleet: the controller is the
// hub, each healthy worker that advertised a WG key is a spoke. DANI assigns the overlay IPs.
func (p *Plane) buildMesh() wg.Mesh {
	hub := wg.Node{UUID: p.id.UUID, PublicKey: p.wgKey.Public, Endpoint: p.wgEndpoint}
	var spokes []wg.Node
	p.mu.RLock()
	for _, w := range p.workers {
		if time.Since(w.LastSeen) > p.stale || w.WGPubKey == "" {
			continue
		}
		spokes = append(spokes, wg.Node{UUID: w.NodeUUID, PublicKey: w.WGPubKey, Endpoint: w.WGEndpoint})
	}
	p.mu.RUnlock()
	return wg.BuildMesh("10.55.0", hub, spokes)
}

// ServeLink starts the mTLS Link server (worker heartbeats land here). Non-blocking; returns the
// bound address.
func (p *Plane) ServeLink(linkAddr string) (string, error) {
	tlsCfg, err := serverTLS(p.id.LeafRaw, p.id.InterRaw, p.id.Key, p.id.Root, p.Revoked)
	if err != nil {
		return "", err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/link/heartbeat", p.handleHeartbeat)
	mux.HandleFunc("/link/revocations", p.handleRevocations)       // signed fleet CRL — nodes poll it (P1-4)
	mux.HandleFunc("/link/config", p.handleLinkConfig)             // per-node effective config (§6.20, P1-7)
	mux.HandleFunc("/link/dispatch/pull", p.handleReversePull)     // NAT traversal: worker long-polls for jobs
	mux.HandleFunc("/link/dispatch/result", p.handleReverseResult) // NAT traversal: worker returns the result
	if p.backupDir != "" {                                         // cross-site backup replication over the mesh (P2-A2)
		mux.HandleFunc("/link/backup/manifest", backup.ServeManifest(p.backupDir))
		mux.HandleFunc("/link/backup/latest", backup.ServeLatest(p.backupDir))
	}
	// Node↔controller DATA PLANE runs over this mutual-TLS link, NOT the public browser gateway:
	// auto-deploy poll, artifact pull (verify-on-use), and the loaded-report. This keeps internal
	// traffic on the authenticated control plane and works regardless of external gateway TLS. The
	// p.training read is deferred to REQUEST time so ServeLink/EnableTraining call order doesn't matter.
	trainingRoute := func(h func(*TrainingAPI) http.HandlerFunc) http.HandlerFunc {
		return func(rw http.ResponseWriter, r *http.Request) {
			if p.training == nil {
				http.Error(rw, "training not enabled", http.StatusServiceUnavailable)
				return
			}
			h(p.training)(rw, r)
		}
	}
	mux.HandleFunc("/dani/deployments", trainingRoute(func(t *TrainingAPI) http.HandlerFunc { return t.handleDeployments }))
	mux.HandleFunc("/dani/deployments/report", trainingRoute(func(t *TrainingAPI) http.HandlerFunc { return t.handleDeployReport }))
	mux.HandleFunc("/dani/models/artifact", trainingRoute(func(t *TrainingAPI) http.HandlerFunc { return t.handleArtifact }))
	lis, err := net.Listen("tcp", linkAddr)
	if err != nil {
		return "", err
	}
	srv := &http.Server{Handler: mux, TLSConfig: tlsCfg}
	p.track(srv)
	go func() { _ = srv.ServeTLS(lis, "", "") }()
	log.Printf("controller: Link heartbeat sink serving on %s (mTLS)", lis.Addr())
	return lis.Addr().String(), nil
}

// EnableBackupServe makes this controller's backups pullable over the mTLS Link (P2-A2). Call
// before ServeLink. Only fleet-identity peers can reach the Link, so backups stay in-perimeter.
func (p *Plane) EnableBackupServe(dir string) { p.backupDir = dir }

// SetGatewayTLS enables HTTPS on the external gateway (call before ServeGateway). Nil / disabled =
// plain HTTP (dev / benchmark / behind a TLS-terminating ingress).
func (p *Plane) SetGatewayTLS(t *GatewayTLS) { p.gwTLS = t }

// ServeGateway starts the external gateway (console + OpenAI /v1 + auth). Over HTTPS when
// SetGatewayTLS enabled it (production), otherwise plain HTTP (dev / behind an ingress). Non-blocking.
func (p *Plane) ServeGateway(gwAddr string) (string, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", p.handleGateway)
	mux.HandleFunc("/v1/models", p.handleModels)
	mux.HandleFunc("/dani/fleet", p.handleFleet)
	mux.HandleFunc("/dani/cluster", p.handleCluster) // control-plane members (Raft) — console topology
	mux.HandleFunc("/dani/traces", p.handleTraces)   // recent per-request traces (P2-A3; console + demo)
	mux.HandleFunc("/traces", p.handleTracesPage)    // styled live traces page (design system)
	mux.HandleFunc("/dani/whoami", p.handleWhoami)
	mux.HandleFunc("/healthz", func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", p.handleReadyz) // readiness = can route inference (P1-2); healthz stays liveness
	if p.metrics != nil {
		mux.Handle("/metrics", p.metrics.reg.Handler())
	}
	mux.HandleFunc("/dani/wg/config", p.handleWGConfig)
	mux.HandleFunc("/dani/wg/mesh", p.handleWGMesh)
	p.registerTrainingRoutes(mux)    // train->sign->serve endpoints (when EnableTraining was called)
	p.registerNodeRoutes(mux)        // node control endpoints (when EnableNodeAdmin was called)
	p.registerAuthRoutes(mux)        // OIDC/SSO login endpoints (when EnableOIDC was called)
	p.registerConfigRoutes(mux)      // governed config store (when EnableConfig was called, P1-7)
	p.registerDemoRoutes(mux)        // fan-out coding demo (when EnableDemo was called, Tier C)
	mux.HandleFunc("/", p.handleApp) // legacy single-page investor console (same-origin: no CORS)
	if sub, err := fs.Sub(consoleFS, "webapp/console"); err == nil {
		mux.Handle("/console/", http.StripPrefix("/console/", http.FileServer(http.FS(sub))))
		mux.HandleFunc("/console", func(rw http.ResponseWriter, r *http.Request) { http.Redirect(rw, r, "/console/", http.StatusFound) })
	}
	lis, err := net.Listen("tcp", gwAddr)
	if err != nil {
		return "", err
	}
	var handler http.Handler = mux
	if p.limits == nil {
		p.limits = newLimits() // literal test planes
	}
	handler = p.limitsHandler(handler) // edge protection: body caps + per-IP rate limit (P2-1)
	if p.metrics != nil {
		handler = p.metrics.instrument(handler) // request counts + latency by route (P1-2); sees 413/429 too
	}
	if p.demo != nil {
		// DEMO ONLY: browsers cap HTTP/1.1 at ~6 connections per origin, so the fan-out page shards
		// requests across the extra gateway lanes (ports) — cross-origin from the page's origin,
		// hence CORS. Never enabled outside --demo.
		handler = demoCORS(handler)
	}
	if p.gwTLS != nil && p.gwTLS.Enabled {
		tlsCfg, provenance, err := p.gwTLS.tlsConfig()
		if err != nil {
			_ = lis.Close()
			return "", err
		}
		srv := &http.Server{Handler: hstsHandler(handler), TLSConfig: tlsCfg}
		p.track(srv)
		go func() { _ = srv.ServeTLS(lis, "", "") }()
		log.Printf("controller: gateway serving HTTPS on %s (%s)", lis.Addr(), provenance)
		return lis.Addr().String(), nil
	}
	srv := &http.Server{Handler: handler}
	p.track(srv)
	go func() { _ = srv.Serve(lis) }()
	log.Printf("controller: gateway serving on %s (PLAIN HTTP — enable --gateway-tls or terminate TLS at your ingress for production)", lis.Addr())
	return lis.Addr().String(), nil
}

func (p *Plane) handleHeartbeat(rw http.ResponseWriter, r *http.Request) {
	var hb Heartbeat
	if err := json.NewDecoder(r.Body).Decode(&hb); err != nil {
		http.Error(rw, "bad heartbeat", http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	if p.revoked[hb.NodeUUID] {
		p.mu.Unlock()
		http.Error(rw, "node revoked", http.StatusForbidden)
		return
	}
	// AUTO reverse-tunnel: if a worker's dispatch address changed, forget any stale "undialable"
	// verdict — it may have moved to a reachable network, so give the dial another chance.
	if prev, ok := p.workers[hb.NodeUUID]; ok && prev.DispatchAddr != hb.DispatchAddr {
		delete(p.unreachable, hb.NodeUUID)
	}
	p.workers[hb.NodeUUID] = &workerState{Heartbeat: hb, LastSeen: time.Now()}
	p.mu.Unlock()
	if p.onHB != nil {
		p.onHB(hb)
	}
	rw.WriteHeader(http.StatusNoContent)
}

// candidate is a chosen, dispatchable worker.
type candidate struct {
	uuid, addr, site string
	load             int
	predMs           int64 // predicted time-to-serve (for observability)
	reverse          bool  // dispatch via the outbound long-poll mailbox, not a dial (NAT traversal)
	tunnelAvail      bool  // AUTO: a tunnel is available as a fallback if the dial fails
}

// predictedServeMs estimates when a NEW request would COMPLETE at a worker: ceil((load+1)/slots) waves
// of that worker's EMA service time. Lower = will serve sooner. This is what lets routing pick the
// fastest-to-respond node among identical candidates — a slow/busy worker loses to a quick/free one
// even when both can serve the model.
func predictedServeMs(emaMs int64, load, slots int) int64 {
	if emaMs <= 0 {
		emaMs = 1000 // no samples yet → assume ~1s
	}
	if slots < 1 {
		slots = 1
	}
	waves := (load + 1 + slots - 1) / slots // ceil((load+1)/slots)
	return int64(waves) * emaMs
}

// reserve atomically selects the best eligible worker and increments its gateway in-flight count, so
// concurrent requests load-balance instead of stampeding the same "best" worker (the heartbeat
// snapshot lags). Ports the sim router (routing.js): HARD classification + model availability, then
// soft score by health, site locality, and load (4-of-6 preferences, M7). exclude skips workers a
// request already tried. Returns ok=false if nothing is eligible.
func (p *Plane) reserve(model, classification, fromSite string, exclude map[string]bool) (candidate, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	best := candidate{}
	found := false
	var bestLocal bool
	for _, w := range p.workers {
		if exclude[w.NodeUUID] {
			continue
		}
		if w.Trainer { // D17: dedicated training hardware NEVER serves inference
			continue
		}
		if p.drained[w.NodeUUID] { // operator drained it out of routing
			continue
		}
		if time.Since(w.LastSeen) > p.stale || w.Health != "healthy" {
			continue
		}
		if rank(w.Class) < rank(classification) { // HARD: clearance ceiling (dominance)
			continue
		}
		if model != "" && w.ModelID != model && !containsModel(w.Loaded, model) { // model availability (incl. auto-deployed)
			continue
		}
		// Load = the gateway's own in-flight count. With a single controller this is EXACT (the
		// controller is the only dispatcher), so it's authoritative for admission — unlike the
		// heartbeat's Active, which lags up to a heartbeat interval and would wrongly block an
		// idle-but-recently-busy worker. (In multi-controller HA the replicated heartbeat view
		// supplements this for workers other controllers are driving.)
		load := p.inflight[w.NodeUUID]
		// Admit while there's a serving slot OR queue room (DP4): the worker queues the request and
		// serves it when a slot frees. Only when slots AND queue are full do we skip it.
		if load >= w.MaxConcurrent+w.QueueDepth {
			continue
		}
		// Preference order (spec §6.6): classification + model availability are HARD (filtered above);
		// then SITE LOCALITY, then LOAD-as-speed. We pick the locally-closest worker, and among those
		// the one predicted to RESPOND SOONEST — fastest among the capable nodes (load-balancing).
		local := w.Site != "" && fromSite != "" && w.Site == fromSite
		pred := predictedServeMs(w.EmaServiceMs, load, w.MaxConcurrent)
		better := false
		switch {
		case !found:
			better = true
		case local != bestLocal:
			better = local // locality wins over raw speed (avoid cross-site hops)
		case load != best.load:
			// LEAST-LOAD before predicted latency: EMA reflects past response LENGTH as much as node
			// speed (LLM generations vary wildly), so prediction-first herds bursts onto nodes with
			// short-answer history while idle nodes sit. Validated on a 30-node fleet: a 30-way burst
			// put 6 requests on one worker with 15 workers idle. Spread first; predict among equals.
			better = load < best.load
		case pred != best.predMs:
			better = pred < best.predMs // among equally-loaded: fastest-to-serve wins
		default:
			better = w.NodeUUID < best.uuid // deterministic tie-break
		}
		if better {
			// reverse iff FORCE mode, or AUTO mode where a dial has already PROVEN this worker
			// undialable; otherwise dial (auto workers get the fast path until proven otherwise).
			// NOTE: p.mu is already held here, so read p.unreachable directly (isUnreachable would
			// re-lock and deadlock — sync.RWMutex is not reentrant).
			rev := w.ReverseTunnel || (w.TunnelAvailable && p.unreachable[w.NodeUUID])
			best = candidate{uuid: w.NodeUUID, addr: w.DispatchAddr, site: w.Site, load: load, predMs: pred, reverse: rev, tunnelAvail: w.TunnelAvailable}
			bestLocal = local
			found = true
		}
	}
	if !found {
		return candidate{}, false
	}
	p.inflight[best.uuid]++
	return best, true
}

// nodeAlive reports whether a node's heartbeat is fresh and healthy (deployment re-assignment).
func (p *Plane) nodeAlive(uuid string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.drained[uuid] { // drained: placements migrate away and nothing new is assigned
		return false
	}
	w, ok := p.workers[uuid]
	return ok && time.Since(w.LastSeen) <= p.stale && w.Health == "healthy"
}

// Dialer exposes the controller's mTLS client (used by the RemoteTrainer to reach trainer nodes).
func (p *Plane) Dialer() *http.Client { return p.dialer }

// TrainerInfo is one live trainer node (D17 hardware) known from its heartbeat.
type TrainerInfo struct{ UUID, Addr string }

// ActiveTrainers lists live trainer-node heartbeats, ordered by UUID.
func (p *Plane) ActiveTrainers() []TrainerInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var out []TrainerInfo
	for _, w := range p.workers {
		if w.Trainer && !p.drained[w.NodeUUID] && time.Since(w.LastSeen) <= p.stale && w.Health == "healthy" {
			out = append(out, TrainerInfo{UUID: w.NodeUUID, Addr: w.DispatchAddr})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UUID < out[j].UUID })
	return out
}

// release decrements a worker's gateway in-flight count once its request finishes (or fails).
func (p *Plane) release(uuid string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.inflight[uuid] > 0 {
		p.inflight[uuid]--
	}
}

// fleetETA estimates the minimum time-to-availability across workers that could serve (model, class)
// — used to give a Retry-After hint when the whole eligible fleet is saturated. anyMatch is false if
// no worker serves this model/classification at all (a true "no route", not a "busy"). The ETA is an
// estimate, not an SLA (best-effort inference, D47).
// fleetMaxClass reports the highest classification any LIVE worker is cleared to process. Content
// above it is unservable BY DESIGN (dominance) — the RAG path caps retrieval there and reports the
// cap, instead of packing excerpts into a prompt that is guaranteed an unroutable 503.
func (p *Plane) fleetMaxClass() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	best := "unrestricted"
	for _, w := range p.workers {
		if time.Since(w.LastSeen) > p.stale || p.drained[w.NodeUUID] || p.revoked[w.NodeUUID] {
			continue
		}
		if rank(w.Class) > rank(best) {
			best = w.Class
		}
	}
	return best
}

func (p *Plane) fleetETA(model, classification string) (etaMs int64, anyMatch bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	best := int64(-1)
	for _, w := range p.workers {
		if w.Trainer || p.drained[w.NodeUUID] {
			continue
		}
		if time.Since(w.LastSeen) > p.stale || w.Health != "healthy" {
			continue
		}
		if rank(w.Class) < rank(classification) {
			continue
		}
		if model != "" && w.ModelID != model && !containsModel(w.Loaded, model) {
			continue
		}
		anyMatch = true
		ema := w.EmaServiceMs
		if ema <= 0 {
			ema = 1000
		}
		pos := p.inflight[w.NodeUUID] - w.MaxConcurrent + 1 // waiters ahead of a new arrival
		if pos < 1 {
			pos = 1
		}
		mc := w.MaxConcurrent
		if mc < 1 {
			mc = 1
		}
		waves := (pos + mc - 1) / mc
		eta := int64(waves) * ema
		if best < 0 || eta < best {
			best = eta
		}
	}
	if best < 0 {
		best = 0
	}
	return best, anyMatch
}

func (p *Plane) handleGateway(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(rw, "read body", http.StatusBadRequest)
		return
	}
	// OPEN-DANI public admission (no-op in enterprise): NAT-agnostic per-request proof-of-work +
	// content moderation, in front of the normal per-IP limiter. Writes its own refusal response.
	if !p.admitRequest(rw, r, body) {
		return
	}
	// OPEN-DANI contribution economy (no-op in enterprise): contributors get priority; best-effort
	// clients are deferred (never hard-blocked) only when the fleet is busy past the reserve.
	proceed, _ := p.admitLedger(rw, r)
	if !proceed {
		return
	}
	consumerID := clientID(r)
	var req struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &req)
	classification := r.Header.Get("X-Dani-Classification")
	if classification == "" {
		classification = "unrestricted"
	}
	fromSite := r.Header.Get("X-Dani-Site")
	if fromSite == "" {
		fromSite = p.site
	}

	// RAG-compound alias (M9 + D-09): authorize the caller (clearance ceiling), retrieve within
	// clearance, augment, and route to the BASE model at max(content, chunks). The RAG path runs the
	// Policy Engine internally; the plain path runs it here when a user is attributed.
	var rag *ragOutcome
	if p.training != nil {
		if alias, ok := p.training.Models.ResolveRag(req.Model); ok {
			user := r.Header.Get("X-Dani-User")
			if user == "" {
				user = "guest"
			}
			var status int
			var err error
			rag, status, err = p.training.buildRagChat(body, alias, user, p.fleetMaxClass())
			if err != nil {
				writeErr(rw, status, err)
				return
			}
			if rag.agentic { // N≥5 multi-doc: parallel map across the fleet + one reduce
				p.serveAgenticRag(rw, r, rag)
				return
			}
			body = rag.body
			req.Model = rag.baseModel
			classification = rag.classification
		} else if user := r.Header.Get("X-Dani-User"); user != "" {
			// plain (non-RAG) chat with an attributed caller: the live Policy Engine (DP13) decides
			// AuthZ + banned-content + rate limit + the D-09 content classification that routes it.
			if cls, ok := p.applyPolicy(rw, user, body); !ok {
				return
			} else {
				classification = cls
			}
		}
	}

	// P2-A3: one trace per request — which node/site served it, how long, how many it tried. The id
	// propagates to the worker and back on the response so a deep chain stays correlated.
	start := timeNow()
	var attempts []string // workers tried before landing (shared by the retry loop + trace + busy body)
	var trID, tServed, tSite, tStatus string
	var tPred int64
	if p.tracer != nil {
		trID = traceID(r)
		rw.Header().Set("X-Dani-Trace-Id", trID)
		defer func() {
			p.tracer.record(Trace{ID: trID, Model: req.Model, User: r.Header.Get("X-Dani-User"),
				Class: classification, ServedBy: tServed, Site: tSite, Status: tStatus,
				StartUnixMs: start.UnixMilli(), DurationMs: timeNow().Sub(start).Milliseconds(),
				PredictedMs: tPred, Attempts: attempts})
		}()
	}

	// Reserve the least-loaded eligible worker, dispatch, and on back-pressure/error release it and
	// try the next (sim gateway.js step 7). Reservation makes concurrent requests load-balance.
	tried := map[string]bool{}
	for {
		c, ok := p.reserve(req.Model, classification, fromSite, tried)
		if !ok {
			break
		}
		resp, err := p.dispatch(r.Context(), c, body, trID)
		if err != nil {
			p.release(c.uuid)
			tried[c.uuid] = true
			attempts = append(attempts, fmt.Sprintf("%s:%v", c.uuid, err))
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			p.release(c.uuid)
			tried[c.uuid] = true
			attempts = append(attempts, c.uuid+":back-pressure")
			continue
		}
		// Buffer the worker's OpenAI response — Open-DANI verification may compare/replace it.
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		servedUUID, servedBody, verifyNote := c.uuid, respBody, ""
		// OPEN-DANI seed-anchored verification: an answer from a low-reputation, non-seed volunteer is
		// cross-checked against a trusted seed. Agree -> serve it, reward. Disagree -> serve the SEED's
		// answer instead, penalize. No seed available -> serve as-is (best effort).
		if p.needsVerify(c.uuid, p.isSeed(c.uuid)) {
			if sc, ok := p.reserveSeed(req.Model, classification); ok {
				sresp, serr := p.dispatch(r.Context(), sc, body, trID)
				if serr == nil && sresp.StatusCode == http.StatusOK {
					sbody, _ := io.ReadAll(sresp.Body)
					sresp.Body.Close()
					if p.agrees(extractAnswer(respBody), extractAnswer(sbody)) {
						p.reputation.Reward(c.uuid)
						verifyNote = "seed-agreed"
					} else {
						servedUUID, servedBody = sc.uuid, sbody // poisoned/divergent — serve the seed
						p.reputation.Penalize(c.uuid)
						verifyNote = "seed-replaced"
					}
				} else if serr == nil {
					sresp.Body.Close()
				}
				p.release(sc.uuid)
			}
		}
		// annotate with the route (headers are the original worker's; served-by reflects the real server).
		for k, vs := range resp.Header {
			for _, v := range vs {
				rw.Header().Add(k, v)
			}
		}
		rw.Header().Set("X-Dani-Served-By", servedUUID)
		rw.Header().Set("X-Dani-Site", c.site)
		rw.Header().Set("X-Dani-Predicted-Ms", fmt.Sprintf("%d", c.predMs))
		if verifyNote != "" {
			rw.Header().Set("X-Dani-Verify", verifyNote)
		}
		tServed, tSite, tStatus, tPred = servedUUID, c.site, "served", c.predMs
		if rag != nil { // citations + the D-09 authz trace travel with the answer
			rw.Header().Set("X-Dani-Rag-Chunks", citationsJSON(rag.hits))
			rw.Header().Set("X-Dani-Rag-User", rag.user+"/"+rag.clear)
			rw.Header().Set("X-Dani-Classification", rag.classification)
			if rag.ceilingCapped {
				rw.Header().Set("X-Dani-Rag-Ceiling", rag.ceiling+" (fleet clearance)")
			}
			// grounding verifier: numbers/§refs/quotes/IDs in the answer must appear in the
			// retrieved excerpts (the body is already buffered here for the ledger economy)
			var parsed struct {
				Choices []struct {
					Message struct {
						Content string `json:"content"`
					} `json:"message"`
				} `json:"choices"`
			}
			if json.Unmarshal(servedBody, &parsed) == nil && len(parsed.Choices) > 0 {
				texts := make([]string, len(rag.hits))
				for i, h := range rag.hits {
					texts[i] = h.Text
				}
				g := verifyGrounding(parsed.Choices[0].Message.Content, texts)
				if rag.bridged && p.training != nil {
					if back := p.training.translateFromEnglish(parsed.Choices[0].Message.Content, rag.userLang); back != parsed.Choices[0].Message.Content {
						var full map[string]any
						if json.Unmarshal(servedBody, &full) == nil {
							if ch, ok := full["choices"].([]any); ok && len(ch) > 0 {
								if c0, ok := ch[0].(map[string]any); ok {
									if msg, ok := c0["message"].(map[string]any); ok {
										msg["content"] = back
										if nb, merr := json.Marshal(full); merr == nil {
											servedBody = nb
										}
									}
								}
							}
						}
						rw.Header().Set("X-Dani-Rag-Language", rag.userLang)
						rw.Header().Set("X-Dani-Rag-Translated", "query,answer")
					}
				}
				rw.Header().Set("X-Dani-Rag-Grounding", fmt.Sprintf("%.2f", g.Score))
				rw.Header().Set("X-Dani-Rag-Grounding-Checked", fmt.Sprintf("%d", g.Checked))
				if len(g.Unsupported) > 0 {
					detail := strings.Join(g.Unsupported, "; ")
					if len(detail) > 220 {
						detail = detail[:220]
					}
					rw.Header().Set("X-Dani-Rag-Ungrounded", detail)
					if p.training != nil {
						p.training.emit("rag.ungrounded", map[string]any{
							"user": rag.user, "score": g.Score, "unsupported": g.Unsupported, "node": c.uuid,
						})
					}
				}
			}
		}
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write(servedBody)
		// contribution economy: the consumer spends, the worker that served useful work earns.
		p.ledgerSettle(consumerID, servedUUID, servedBody, verifyNote == "seed-replaced")
		p.release(c.uuid)
		return
	}
	// Nothing served. Distinguish "no route" (no worker serves this model/class — a hard 503) from
	// "fleet busy" (workers exist but every serving slot AND queue is full — 503 + Retry-After ETA).
	eta, anyMatch := p.fleetETA(req.Model, classification)
	if !anyMatch {
		if p.metrics != nil {
			p.metrics.unrouted.Inc("no_route")
		}
		tStatus = "no_route"
		http.Error(rw, "no workers serving this model/classification", http.StatusServiceUnavailable)
		return
	}
	if p.metrics != nil {
		p.metrics.unrouted.Inc("busy")
	}
	tStatus = "busy"
	retryS := (eta + 999) / 1000
	if retryS < 1 {
		retryS = 1
	}
	rw.Header().Set("Retry-After", fmt.Sprintf("%d", retryS))
	rw.Header().Set("X-Dani-Busy", "true")
	rw.Header().Set("X-Dani-Estimated-Wait-Ms", fmt.Sprintf("%d", eta))
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(rw).Encode(map[string]any{
		"error": map[string]any{"message": "fleet busy — all eligible workers at capacity", "type": "back_pressure", "code": "fleet_busy"},
		"dani":  map[string]any{"busy": true, "estimated_wait_ms": eta, "attempts": attempts, "note": "estimate, not a guarantee (best-effort inference, D47)"},
	})
}

func (p *Plane) dispatch(ctx context.Context, c candidate, body []byte, traceID string) (*http.Response, error) {
	headers := map[string]string{}
	if traceID != "" { // propagate the trace to the worker so its logs correlate (P2-A3)
		headers["X-Dani-Trace-Id"] = traceID
	}
	if c.reverse {
		// NAT/firewall traversal: the worker is unreachable inbound — hand the job to its outbound
		// long-poll mailbox and wait for the result it posts back (NAT-TRANSPORT.md).
		return p.rev().submit(ctx, c.uuid, body, headers)
	}
	url := "https://" + c.addr + "/v1/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, readerOf(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := p.dialer.Do(req)
	if err != nil && c.tunnelAvail {
		// AUTO reverse-tunnel: the dial failed but this worker keeps a tunnel open — it's behind
		// NAT/a firewall. Remember that (so future dispatches skip the dial) and serve THIS request
		// over the tunnel instead of failing it.
		p.markUnreachable(c.uuid)
		log.Printf("controller: worker %s undialable (%v) — auto-switching it to the reverse tunnel", c.uuid, err)
		return p.rev().submit(ctx, c.uuid, body, headers)
	}
	return resp, err
}

func (p *Plane) handleModels(rw http.ResponseWriter, _ *http.Request) {
	seen := map[string]string{}
	p.mu.RLock()
	for _, w := range p.workers {
		if w.Trainer || time.Since(w.LastSeen) > p.stale {
			continue
		}
		if w.ModelID != "" {
			seen[w.ModelID] = w.Engine
		}
		for _, m := range w.Loaded { // auto-deployed models route like any other
			seen[m] = w.Engine
		}
	}
	p.mu.RUnlock()
	data := []map[string]any{}
	for m, eng := range seen {
		data = append(data, map[string]any{"id": m, "object": "model", "owned_by": "dani", "engine": eng})
	}
	// RAG-compound aliases are offered when their BASE model is live in the fleet (M9).
	if p.training != nil {
		for _, a := range p.training.Models.RagAliases() {
			if eng, ok := seen[a.BaseModelID]; ok {
				data = append(data, map[string]any{"id": a.Alias, "object": "model", "owned_by": "dani", "engine": "rag+" + eng})
			}
		}
	}
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(map[string]any{"object": "list", "data": data})
}

// handleFleet exposes the live worker table for the console/benchmark.
func (p *Plane) handleFleet(rw http.ResponseWriter, _ *http.Request) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	type row struct {
		UUID, Addr, Model, Engine, Class, Site, Health string
		Active, MaxConcurrent, Queued                  int
		Served                                         int64
		AgeMs                                          int64
		Trainer                                        bool
		Drained                                        bool
		Loaded                                         []string
		Accel                                          string  // detected acceleration backend (hwcaps)
		ReverseTunnel                                  bool    // FORCE reverse-tunnel worker (never dialed)
		TunnelAvailable                                bool    // AUTO: keeps a tunnel open as a fallback
		Unreachable                                    bool
		CapMode                                        string // resource budget mode: full | polite | custom
		MaxCores                                       int    // CPU cores this node lets DANI use (0 = all)
		MemBudgetMB                                    int    // model-memory budget in MB (0 = unbounded)    // AUTO: a dial has proven it undialable → routed over the tunnel
		Seed                                           bool    // OPEN-DANI: trusted seed node (verification anchor)
		Reputation                                     float64 // OPEN-DANI: trust score [0,1]; -1 when verification is off
	}
	rows := []row{}
	for _, w := range p.workers {
		rep := -1.0
		if p.reputation != nil && !w.Seed {
			rep = p.reputation.Get(w.NodeUUID)
		}
		rows = append(rows, row{
			UUID: w.NodeUUID, Addr: w.DispatchAddr, Model: w.ModelID, Engine: w.Engine, Class: w.Class,
			Site: w.Site, Health: w.Health, Active: w.Active, MaxConcurrent: w.MaxConcurrent, Queued: w.Queued,
			Served: w.Served, AgeMs: time.Since(w.LastSeen).Milliseconds(), Trainer: w.Trainer,
			Drained: p.drained[w.NodeUUID], Loaded: w.Loaded, Accel: w.Accel,
			ReverseTunnel: w.ReverseTunnel, TunnelAvailable: w.TunnelAvailable, Unreachable: p.unreachable[w.NodeUUID],
			CapMode: w.CapMode, MaxCores: w.MaxCores, MemBudgetMB: w.MemBudgetMB,
			Seed: w.Seed, Reputation: rep,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UUID < rows[j].UUID })
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(map[string]any{"workers": rows, "count": len(rows)})
}

// handleWGConfig renders the WireGuard config DANI assigns to a node (default: the controller/hub).
// This is the proof: DANI itself — not Tailscale/Headscale — coordinates the overlay from enrollment.
func (p *Plane) handleWGConfig(rw http.ResponseWriter, r *http.Request) {
	node := r.URL.Query().Get("node")
	if node == "" {
		node = p.id.UUID // the hub/controller by default
	}
	cfg, ok := p.buildMesh().ConfigFor(node, 51820)
	if !ok {
		http.Error(rw, "unknown node (not in the live mesh)", http.StatusNotFound)
		return
	}
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = rw.Write([]byte(cfg))
}

// handleWGMesh exposes the whole DANI-coordinated overlay (nodes, keys, assigned IPs) as JSON.
func (p *Plane) handleWGMesh(rw http.ResponseWriter, _ *http.Request) {
	m := p.buildMesh()
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(map[string]any{"cidr": m.CIDR, "nodes": m.Nodes})
}

// handleApp serves the single-page investor console (embedded; same-origin with the gateway APIs).
func (p *Plane) handleApp(rw http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(rw, r)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = rw.Write(consoleHTML)
}

// handleTracesPage serves the styled live traces page (design system); it polls /dani/traces.
func (p *Plane) handleTracesPage(rw http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/traces" {
		http.NotFound(rw, r)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = rw.Write(tracesHTML)
}

// containsModel reports whether a hot-loaded model list includes model.
func containsModel(loaded []string, model string) bool {
	for _, m := range loaded {
		if m == model {
			return true
		}
	}
	return false
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
