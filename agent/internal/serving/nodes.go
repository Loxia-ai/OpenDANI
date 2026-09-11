package serving

// Node control — the operator's fleet-management surface (the console's "Nodes" tab):
//
//	GET  /dani/nodes           registry rows merged with the live heartbeat view + drain state
//	POST /dani/nodes/drain     {"node","drain":bool} — a drained node stays enrolled + heartbeating
//	                           but is removed from routing and its placements migrate away
//	POST /dani/nodes/revoke    {"node"} — refuse renewal (the cert dies at its next renewal window),
//	                           mark the registry lifecycle, and evict from the data plane NOW
//	GET  /dani/enroll/pending  queued join requests (only populated with --admit manual)
//	POST /dani/enroll/approve  {"id"} — admit a queued node (Mode-2 batch-confirm, the SO action)
//	POST /dani/enroll/reject   {"id","reason"}
//
// HONEST LIMIT (documented, D-29): revocation here is renewal-refusal + data-plane eviction — the
// node's EXISTING cert stays cryptographically valid until it expires. Full revocation needs CRL /
// gossip revocation distribution to every verifier (spec DL-R11-07), which the DEMO does not carry.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"time"

	"dani.local/agent/internal/enrollment"
	"dani.local/agent/internal/registry"
)

// NodeAdmin wires the controller's node-control dependencies into the gateway. Function fields keep
// serving decoupled from the controller wiring (and make failure injection trivial in tests).
type NodeAdmin struct {
	Nodes        func(ctx context.Context) ([]registry.RegRow, error) // registry dump (durable truth)
	SetLifecycle func(ctx context.Context, uuid, state string) error  // registry lifecycle write
	Revoke       func(uuid string)                                    // enrollment renewal refusal
	Pending      func() []enrollment.PendingInfo                      // queued joins (manual admit)
	Approve      func(ctx context.Context, reqID string) error        // admit a queued node
	Reject       func(reqID, reason string) error                     // refuse a queued node
	Audit        func(typ string, payload map[string]any)             // audit emission (optional)

	DrainFile string // persists the drained set across controller restarts (optional)
}

func (a *NodeAdmin) emit(typ string, payload map[string]any) {
	if a.Audit != nil {
		a.Audit(typ, payload)
	}
}

// EnableNodeAdmin attaches node control to the gateway (call before ServeGateway). Rehydrates the
// drained set from admin.DrainFile so a controller restart does not silently un-drain nodes.
func (p *Plane) EnableNodeAdmin(admin *NodeAdmin) {
	p.admin = admin
	if admin.DrainFile != "" {
		if data, err := os.ReadFile(admin.DrainFile); err == nil {
			var drained []string
			if json.Unmarshal(data, &drained) == nil {
				p.mu.Lock()
				for _, uuid := range drained {
					p.drained[uuid] = true
				}
				p.mu.Unlock()
			}
		}
	}
}

// saveDrains persists the drained set (p.mu must be held).
func (p *Plane) saveDrains() {
	if p.admin == nil || p.admin.DrainFile == "" {
		return
	}
	drained := make([]string, 0, len(p.drained))
	for uuid, on := range p.drained {
		if on {
			drained = append(drained, uuid)
		}
	}
	sort.Strings(drained)
	data, _ := json.Marshal(drained)
	_ = os.WriteFile(p.admin.DrainFile, data, 0o600)
}

// registerNodeRoutes adds the node-control endpoints to the gateway mux (no-op when not enabled).
func (p *Plane) registerNodeRoutes(mux *http.ServeMux) {
	if p.admin == nil {
		return
	}
	mux.HandleFunc("/dani/nodes", p.handleNodes)
	mux.HandleFunc("/dani/nodes/drain", p.protect(p.handleNodeDrain))
	mux.HandleFunc("/dani/nodes/revoke", p.protect(p.handleNodeRevoke))
	mux.HandleFunc("/dani/enroll/pending", p.handleEnrollPending)
	mux.HandleFunc("/dani/enroll/approve", p.protect(p.handleEnrollApprove))
	mux.HandleFunc("/dani/enroll/reject", p.protect(p.handleEnrollReject))
}

// handleNodes merges the durable registry (enrollment truth: cert serial/expiry, lifecycle,
// generation) with the live heartbeat table (what the node is doing RIGHT NOW) — the console's
// single fleet-management view.
func (p *Plane) handleNodes(rw http.ResponseWriter, r *http.Request) {
	rows, err := p.admin.Nodes(r.Context())
	if err != nil {
		writeErr(rw, http.StatusInternalServerError, err)
		return
	}
	type nodeRow struct {
		UUID       string    `json:"uuid"`
		Roles      []string  `json:"roles"`
		Class      string    `json:"class"`
		Site       string    `json:"site"`
		Lifecycle  string    `json:"lifecycle"`
		Tier       int       `json:"tier"`
		CertSerial string    `json:"certSerial"`
		CertExpiry time.Time `json:"certExpiry"`
		Generation int       `json:"generation"`
		Live       bool      `json:"live"`    // fresh healthy heartbeat
		Drained    bool      `json:"drained"` // operator removed it from routing
		Model      string    `json:"model,omitempty"`
		Engine     string    `json:"engine,omitempty"`
		Trainer    bool      `json:"trainer,omitempty"`
		Loaded     []string  `json:"loaded,omitempty"`
	}
	p.mu.RLock()
	out := make([]nodeRow, 0, len(rows))
	for _, n := range rows {
		row := nodeRow{
			UUID: n.UUID, Roles: n.Roles, Class: n.Class, Site: n.Site, Lifecycle: n.Lifecycle,
			Tier: n.Tier, CertSerial: n.CertSerial, CertExpiry: n.NotAfter, Generation: n.Generation,
			Drained: p.drained[n.UUID],
		}
		if w, ok := p.workers[n.UUID]; ok && time.Since(w.LastSeen) <= p.stale {
			row.Live = w.Health == "healthy"
			row.Model, row.Engine, row.Trainer, row.Loaded = w.ModelID, w.Engine, w.Trainer, w.Loaded
		}
		out = append(out, row)
	}
	p.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].UUID < out[j].UUID })
	writeJSON(rw, http.StatusOK, map[string]any{"nodes": out, "count": len(out)})
}

// handleNodeDrain toggles a node out of (or back into) routing. Draining is the graceful op:
// the node keeps its cert and heartbeat, but reserve()/fleetETA/trainer-allocation skip it and
// nodeAlive() reports false so its placements migrate to other capable nodes.
func (p *Plane) handleNodeDrain(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Node  string `json:"node"`
		Drain *bool  `json:"drain"` // nil = drain (the common case)
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Node == "" {
		http.Error(rw, "bad request body (need node)", http.StatusBadRequest)
		return
	}
	drain := req.Drain == nil || *req.Drain
	p.mu.Lock()
	if drain {
		p.drained[req.Node] = true
	} else {
		delete(p.drained, req.Node)
	}
	p.saveDrains()
	p.mu.Unlock()
	if drain {
		p.admin.emit("node.drained", map[string]any{"node": req.Node})
	} else {
		p.admin.emit("node.undrained", map[string]any{"node": req.Node})
	}
	writeJSON(rw, http.StatusOK, map[string]any{"node": req.Node, "drained": drain})
}

// handleNodeRevoke refuses the node's future renewals, marks the registry lifecycle, and evicts it
// from the data plane immediately (heartbeats from it are rejected from now on).
func (p *Plane) handleNodeRevoke(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Node string `json:"node"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Node == "" {
		http.Error(rw, "bad request body (need node)", http.StatusBadRequest)
		return
	}
	if p.admin.Revoke != nil {
		p.admin.Revoke(req.Node)
	}
	if p.admin.SetLifecycle != nil {
		if err := p.admin.SetLifecycle(r.Context(), req.Node, "revoked"); err != nil {
			writeErr(rw, http.StatusInternalServerError, err)
			return
		}
	}
	p.mu.Lock()
	p.revoked[req.Node] = true
	p.revSeq++                  // the signed revocation list advances; nodes pick it up on next poll (P1-4)
	delete(p.workers, req.Node) // evict NOW — don't wait for staleness
	p.mu.Unlock()
	p.admin.emit("node.revoked", map[string]any{"node": req.Node})
	writeJSON(rw, http.StatusOK, map[string]any{"node": req.Node, "revoked": true,
		"note": "renewal refused + evicted from routing + published on the signed revocation list (every node rejects its cert within one poll)"})
}

// handleEnrollPending lists queued join requests (populated when the controller runs --admit manual).
func (p *Plane) handleEnrollPending(rw http.ResponseWriter, _ *http.Request) {
	var pend []enrollment.PendingInfo
	if p.admin.Pending != nil {
		pend = p.admin.Pending()
	}
	if pend == nil {
		pend = []enrollment.PendingInfo{}
	}
	writeJSON(rw, http.StatusOK, map[string]any{"pending": pend, "count": len(pend)})
}

// handleEnrollApprove admits one queued node (the SO's Mode-2 batch-confirm click).
func (p *Plane) handleEnrollApprove(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(rw, "bad request body (need id)", http.StatusBadRequest)
		return
	}
	if p.admin.Approve == nil {
		writeErr(rw, http.StatusNotImplemented, fmt.Errorf("manual admission not enabled (--admit manual)"))
		return
	}
	if err := p.admin.Approve(r.Context(), req.ID); err != nil {
		writeErr(rw, http.StatusBadRequest, err)
		return
	}
	p.admin.emit("node.approved", map[string]any{"reqId": req.ID})
	writeJSON(rw, http.StatusOK, map[string]any{"id": req.ID, "approved": true})
}

// handleEnrollReject refuses one queued node.
func (p *Plane) handleEnrollReject(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID, Reason string
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(rw, "bad request body (need id)", http.StatusBadRequest)
		return
	}
	if p.admin.Reject == nil {
		writeErr(rw, http.StatusNotImplemented, fmt.Errorf("manual admission not enabled (--admit manual)"))
		return
	}
	if err := p.admin.Reject(req.ID, req.Reason); err != nil {
		writeErr(rw, http.StatusBadRequest, err)
		return
	}
	p.admin.emit("node.rejected", map[string]any{"reqId": req.ID, "reason": req.Reason})
	writeJSON(rw, http.StatusOK, map[string]any{"id": req.ID, "rejected": true})
}
