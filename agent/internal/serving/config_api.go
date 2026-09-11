package serving

// Config distribution (PRODUCTION-READINESS P1-7, spec §6.20): the controller owns the durable
// four-scope config store; operators write validated entries through the gateway (audited); every
// node fetches its EFFECTIVE map over the mTLS Link and live-applies the dynamic keys — a fleet-wide
// (or site/role/node-scoped) tuning change lands on running nodes within one poll, no restarts.

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"dani.local/agent/internal/config"
	"dani.local/agent/internal/limits"
)

// qDepth reads the live admission-queue depth (atomic — the config loop may change it).
func (w *Worker) qDepth() int { return int(atomic.LoadInt64(&w.queueDepth64)) }

// slo reads the live SLO wait budget (atomic — the config loop may change it).
func (w *Worker) slo() time.Duration { return time.Duration(atomic.LoadInt64(&w.sloBudgetNs)) }

// ---- controller side ----

type configAPI struct {
	store *config.Store
	audit func(string, map[string]any)
}

// EnableConfig attaches the governed config store to the plane (call before ServeGateway/ServeLink).
func (p *Plane) EnableConfig(store *config.Store, audit func(string, map[string]any)) {
	p.configAPI = &configAPI{store: store, audit: audit}
}

// registerConfigRoutes mounts the operator surface on the gateway (no-op until EnableConfig).
func (p *Plane) registerConfigRoutes(mux *http.ServeMux) {
	if p.configAPI == nil {
		return
	}
	mux.HandleFunc("/dani/config", p.protect(p.handleConfig))
	mux.HandleFunc("/dani/config/resolve", p.handleConfigResolve) // read-only: effective view per node
}

// handleConfig lists (GET) or writes (POST) config entries. Writes are validated by the store
// (§6.20: a bad value is refused HERE) and audited with the acting operator.
func (p *Plane) handleConfig(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	switch r.Method {
	case http.MethodGet:
		entries, err := p.configAPI.store.List(ctx)
		if err != nil {
			writeErr(rw, http.StatusInternalServerError, err)
			return
		}
		v, err := p.configAPI.store.Version(ctx)
		if err != nil {
			writeErr(rw, http.StatusInternalServerError, err)
			return
		}
		writeJSON(rw, http.StatusOK, map[string]any{"version": v, "entries": entries, "knownKeys": config.KnownKeys()})
	case http.MethodPost:
		var req struct {
			config.Entry
			Delete bool `json:"delete,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(rw, "bad request body", http.StatusBadRequest)
			return
		}
		var err error
		if req.Delete {
			err = p.configAPI.store.Delete(ctx, req.Scope, req.ScopeVal, req.Key)
		} else {
			err = p.configAPI.store.Set(ctx, req.Entry)
		}
		if err != nil {
			writeErr(rw, http.StatusBadRequest, err)
			return
		}
		if p.configAPI.audit != nil {
			p.configAPI.audit("config.updated", map[string]any{
				"scope": req.Scope, "scopeVal": req.ScopeVal, "key": req.Key,
				"value": req.Value, "deleted": req.Delete, "by": operatorSub(r),
			})
		}
		v, _ := p.configAPI.store.Version(ctx)
		writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "version": v})
	default:
		http.Error(rw, "GET or POST", http.StatusMethodNotAllowed)
	}
}

// handleConfigResolve shows a node's effective config (console detail / debugging).
func (p *Plane) handleConfigResolve(rw http.ResponseWriter, r *http.Request) {
	if p.configAPI == nil {
		http.Error(rw, "config store not enabled", http.StatusServiceUnavailable)
		return
	}
	attrs := config.NodeAttrs{
		UUID: r.URL.Query().Get("uuid"), Site: r.URL.Query().Get("site"),
		Roles: splitNonEmpty(r.URL.Query().Get("roles")),
	}
	v, eff, err := readConfigForPoll(r.Context(), p.configAPI.store, attrs)
	if err != nil {
		writeErr(rw, http.StatusInternalServerError, err)
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"version": v, "effective": eff})
}

type configPollReader interface {
	Version(context.Context) (int64, error)
	ResolveAll(context.Context, config.NodeAttrs) (map[string]config.Resolved, error)
}

// readConfigForPoll reads the version first so it never acknowledges a mutation
// newer than the returned entries. Set/Delete commit entries and version together.
// A write between these reads can make the watermark older than the entries (one
// harmless extra apply on the next poll), but cannot hide that write indefinitely
// behind the worker's unchanged-version fast path.
func readConfigForPoll(ctx context.Context, store configPollReader, attrs config.NodeAttrs) (int64, map[string]config.Resolved, error) {
	v, err := store.Version(ctx)
	if err != nil {
		return 0, nil, err
	}
	eff, err := store.ResolveAll(ctx, attrs)
	if err != nil {
		return 0, nil, err
	}
	return v, eff, nil
}

// handleLinkConfig serves a node's effective config over the mTLS Link (nodes poll it).
func (p *Plane) handleLinkConfig(rw http.ResponseWriter, r *http.Request) {
	p.handleConfigResolve(rw, r)
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// ---- worker side ----

// configLoop polls this node's effective config over the mTLS Link and live-applies the dynamic
// keys. The version makes unchanged polls free; changes are logged with their scope provenance so
// an operator can see WHY a node runs the value it runs.
func (w *Worker) configLoop(ctx context.Context) {
	client := w.linkClient()
	every := w.cfgEvery
	if every <= 0 {
		every = 15 * time.Second
	}
	url := w.controllerURLs[0] + "/link/config?uuid=" + w.id.UUID + "&site=" + w.site + "&roles=worker"
	var lastVersion int64 = -1
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return
		}
		resp, err := client.Do(req)
		if err == nil {
			var out struct {
				Version   int64                      `json:"version"`
				Effective map[string]config.Resolved `json:"effective"`
			}
			decodeErr := json.NewDecoder(resp.Body).Decode(&out)
			resp.Body.Close()
			if decodeErr == nil && resp.StatusCode == http.StatusOK && out.Version != lastVersion {
				w.applyConfig(out.Effective)
				lastVersion = out.Version
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// applyConfig applies the dynamic keys (values were validated at WRITE time by the store; a node
// still guards itself and skips anything malformed rather than dying on it).
func (w *Worker) applyConfig(eff map[string]config.Resolved) {
	if r, ok := eff["worker.queue-depth"]; ok {
		if n, err := strconv.Atoi(r.Value); err == nil && n >= 0 {
			if int64(n) != atomic.SwapInt64(&w.queueDepth64, int64(n)) {
				log.Printf("worker %s: config applied worker.queue-depth=%d (%s scope %s)", w.id.UUID, n, r.Scope, r.ScopeVal)
			}
		}
	}
	if r, ok := eff["worker.slo-budget"]; ok {
		if d, err := time.ParseDuration(r.Value); err == nil && d > 0 {
			if int64(d) != atomic.SwapInt64(&w.sloBudgetNs, int64(d)) {
				log.Printf("worker %s: config applied worker.slo-budget=%s (%s scope %s)", w.id.UUID, d, r.Scope, r.ScopeVal)
			}
		}
	}
	// resource caps (worker.max-cores / worker.max-model-mem-mb): update the override, re-resolve the
	// plan against this host, re-pin the CPU affinity, and report the new budget on the next heartbeat.
	// A key ABSENT from the effective map means "no config override" → revert to the CLI-flag baseline.
	capChanged := false
	var capProv config.Resolved
	wantCores := w.flagCores
	if r, ok := eff["worker.max-cores"]; ok {
		n, err := strconv.Atoi(r.Value)
		if strings.EqualFold(strings.TrimSpace(r.Value), "all") {
			n, err = limits.AllCores, nil // dedicated machine: every core
		}
		if err == nil && (n >= 0 || n == limits.AllCores) {
			wantCores = int64(n)
			capProv = r
		}
	}
	if atomic.SwapInt64(&w.ovrCores, wantCores) != wantCores {
		capChanged = true
	}
	wantMem := w.flagMemMB
	if r, ok := eff["worker.max-model-mem-mb"]; ok {
		if n, err := strconv.Atoi(r.Value); err == nil && n >= 0 {
			wantMem = int64(n)
			capProv = r
		}
	}
	if atomic.SwapInt64(&w.ovrMemMB, wantMem) != wantMem {
		capChanged = true
	}
	if capChanged {
		p := limits.Resolve(int(atomic.LoadInt64(&w.ovrCores)), int(atomic.LoadInt64(&w.ovrMemMB)))
		w.setCapPlan(p)
		if err := p.PinCPU(); err != nil {
			log.Printf("worker %s: re-pin CPU failed: %v", w.id.UUID, err)
		}
		prov := "reverted to flag baseline (override deleted)"
		if capProv.Scope != "" {
			prov = capProv.Scope + " scope " + capProv.ScopeVal
		}
		log.Printf("worker %s: config applied resource cap → %s (%s)", w.id.UUID, p.Summary(), prov)
	}
}
