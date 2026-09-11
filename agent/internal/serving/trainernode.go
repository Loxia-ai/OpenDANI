package serving

// TrainerNode is the data-plane half of a DEDICATED trainer node (D17): it executes training jobs on
// its OWN hardware. It serves an mTLS /train endpoint that accepts a training.WireRequest (the spec +
// the staged dataset bytes), runs the node's local Trainer (ExecTrainer on a real GPU box, Stub in
// tests), and streams the SAME CKPT/RESULT marker contract back as the HTTP response — so the
// controller's RemoteTrainer decodes it with the exact parser the local subprocess path uses.
//
// It never serves inference: its heartbeat is marked Trainer, which the router skips (D17), while
// still giving the console liveness + the controller the /train address for allocation.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"dani.local/agent/internal/training"
)

// TrainerNodeConfig configures a trainer node's data plane.
type TrainerNodeConfig struct {
	Identity       Identity
	Trainer        training.Trainer // ExecTrainer on a real node; Stub for tests/dry runs
	Class          string
	Site           string
	AdvertiseHost  string   // host the controller dials; port comes from the bound listener
	ControllerURLs []string // Link URLs to heartbeat to (HA fan-out)
	HeartbeatEvery time.Duration
	WorkDir        string // staged datasets land here (default: os temp)
}

// TrainerNode runs the /train endpoint + trainer heartbeat.
type TrainerNode struct {
	cfg     TrainerNodeConfig
	addr    string // advertised host:boundport
	active  int64  // running jobs (observability; D17 hardware is typically 1-at-a-time)
	served  int64
	revPoll *revocationPoller // fleet CRL copy (P1-4)
}

// isPeerRevoked is the TLS-layer revocation check for the trainer's mTLS server.
func (n *TrainerNode) isPeerRevoked(cn string) bool {
	return n.revPoll != nil && n.revPoll.isRevoked(cn)
}

// NewTrainerNode builds a trainer node data plane.
func NewTrainerNode(cfg TrainerNodeConfig) *TrainerNode {
	if cfg.HeartbeatEvery <= 0 {
		cfg.HeartbeatEvery = 3 * time.Second
	}
	if cfg.AdvertiseHost == "" {
		cfg.AdvertiseHost = "127.0.0.1"
	}
	if cfg.WorkDir == "" {
		cfg.WorkDir = os.TempDir()
	}
	return &TrainerNode{cfg: cfg}
}

// Serve starts the mTLS /train server and the trainer heartbeat loop. Blocks until ctx is done.
func (n *TrainerNode) Serve(ctx context.Context, listenAddr string) error {
	if len(n.cfg.ControllerURLs) > 0 { // enrolled — keep the fleet CRL fresh (P1-4)
		cliTLS, _ := clientTLS(n.cfg.Identity.LeafRaw, n.cfg.Identity.InterRaw, n.cfg.Identity.Key, n.cfg.Identity.Root)
		client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: cliTLS}}
		n.revPoll = newRevocationPoller(n.cfg.Identity.UUID, n.cfg.ControllerURLs[0], client, n.cfg.Identity.Root, 0)
	}
	tlsCfg, err := serverTLS(n.cfg.Identity.LeafRaw, n.cfg.Identity.InterRaw, n.cfg.Identity.Key, n.cfg.Identity.Root, n.isPeerRevoked)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/train", n.handleTrain)
	mux.HandleFunc("/healthz", func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusOK) })
	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	_, port, _ := net.SplitHostPort(lis.Addr().String())
	n.addr = net.JoinHostPort(n.cfg.AdvertiseHost, port)
	srv := &http.Server{Handler: mux, TLSConfig: tlsCfg}
	go func() { _ = srv.Serve(tls.NewListener(lis, tlsCfg)) }()
	log.Printf("trainer %s: /train serving on %s (mTLS); advertising %s — dedicated training hardware (D17), no inference",
		n.cfg.Identity.UUID, lis.Addr(), n.addr)

	go n.heartbeatLoop(ctx)
	if n.revPoll != nil {
		go n.revPoll.run(ctx)
	}
	<-ctx.Done()
	_ = srv.Close()
	return ctx.Err()
}

// handleTrain executes one job and streams the marker contract as the response body.
func (n *TrainerNode) handleTrain(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req training.WireRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(rw, "bad request body", http.StatusBadRequest)
		return
	}
	// Stage the shipped dataset bytes locally (exactly what the controller's lineage recorded).
	var dsFile string
	if req.DatasetB64 != "" {
		data, err := base64.StdEncoding.DecodeString(req.DatasetB64)
		if err != nil {
			http.Error(rw, "bad dataset encoding", http.StatusBadRequest)
			return
		}
		dsFile = filepath.Join(n.cfg.WorkDir, "dani-ds-"+req.DatasetID+".json")
		if err := os.WriteFile(dsFile, data, 0o600); err != nil {
			http.Error(rw, "stage dataset: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer os.Remove(dsFile)
	}

	flusher, _ := rw.(http.Flusher)
	flush := func() {
		if flusher != nil {
			flusher.Flush()
		}
	}
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rw.WriteHeader(http.StatusOK)
	flush()

	atomic.AddInt64(&n.active, 1)
	defer atomic.AddInt64(&n.active, -1)
	log.Printf("trainer %s: job accepted — %s %s on dataset %s", n.cfg.Identity.UUID, req.Method, req.Base, req.DatasetID)
	spec := training.Spec{BaseModelID: req.Base, Method: req.Method, DatasetID: req.DatasetID,
		DatasetFile: dsFile, Hyper: req.Hyper}
	res, err := n.cfg.Trainer.Run(r.Context(), spec, func(done, total int) {
		fmt.Fprintf(rw, "CKPT %d/%d\n", done, total)
		flush()
	})
	if err != nil {
		fmt.Fprintf(rw, "ERROR %v\n", err)
		flush()
		return
	}
	fmt.Fprintln(rw, training.EncodeResult(res))
	flush()
	atomic.AddInt64(&n.served, 1)
	log.Printf("trainer %s: job done — adapter %d bytes", n.cfg.Identity.UUID, len(res.Bytes))
}

// heartbeatLoop announces this node as live TRAINER hardware: DispatchAddr is the /train endpoint;
// the router skips Trainer heartbeats entirely (D17), the allocator reads them.
func (n *TrainerNode) heartbeatLoop(ctx context.Context) {
	tlsCfg, _ := clientTLS(n.cfg.Identity.LeafRaw, n.cfg.Identity.InterRaw, n.cfg.Identity.Key, n.cfg.Identity.Root)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	t := time.NewTicker(n.cfg.HeartbeatEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			hb := Heartbeat{
				NodeUUID: n.cfg.Identity.UUID, DispatchAddr: n.addr, Engine: "trainer",
				Class: n.cfg.Class, Site: n.cfg.Site, Health: "healthy", Trainer: true,
				Active: int(atomic.LoadInt64(&n.active)), Served: atomic.LoadInt64(&n.served),
			}
			body, _ := json.Marshal(hb)
			for _, base := range n.cfg.ControllerURLs {
				req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/link/heartbeat", bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				resp, err := client.Do(req)
				if err != nil {
					log.Printf("trainer %s: heartbeat to %s failed: %v", n.cfg.Identity.UUID, base, err)
					continue
				}
				resp.Body.Close()
			}
		}
	}
}

// PlaneRegistryFleet allocates dedicated training hardware (D17) by JOINING two sources of truth:
// the live trainer heartbeats (liveness + the /train address) and the Node Registry's enrollment-
// assigned roles (a heartbeat cannot claim trainer-ness the registry never granted). A live,
// role-verified trainer executes jobs REMOTELY on its own hardware; with none live, it falls back to
// registry-only allocation (addr "" — the controller's local Trainer runs the job, the single-box
// mode).
type PlaneRegistryFleet struct {
	Plane *Plane
	Reg   nodeRoleLister
	Ctx   context.Context
}

// nodeRoleLister is the slice of the Node Registry the allocator needs (*registry.Registry satisfies it).
type nodeRoleLister interface {
	ActiveNodesWithRole(ctx context.Context, role string) ([]string, error)
}

// ActiveTrainer implements training.Fleet.
func (f PlaneRegistryFleet) ActiveTrainer() (uuid, addr string, ok bool) {
	ctx := f.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	uuids, err := f.Reg.ActiveNodesWithRole(ctx, "trainer")
	if err != nil || len(uuids) == 0 {
		return "", "", false
	}
	roleOK := map[string]bool{}
	for _, u := range uuids {
		roleOK[u] = true
	}
	for _, t := range f.Plane.ActiveTrainers() {
		if roleOK[t.UUID] {
			return t.UUID, t.Addr, true // live + role-verified: remote execution on the node itself
		}
	}
	return uuids[0], "", true // enrolled trainer exists but none live: local (single-box) execution
}
