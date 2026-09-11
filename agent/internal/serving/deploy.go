package serving

// Auto-deploy-on-promotion (§6.17.4 final step): "Routing schedules deployment; workers pull,
// verify, and load; report loaded." The moment a model is fully signed (available), it becomes
// assignable. Assignment is LAZY and pull-based: a hot-load-capable worker polls
// GET /dani/deployments?node=&class= and the gateway assigns it any promoted fine-tune below its
// desired replica count whose classification the node's clearance dominates (D-09). The worker
// pulls the artifact through the verify-on-use gate, hot-loads it, and reports.
//
// Operators steer placement over the same table (the console's "distribute models" surface):
//   POST /dani/models/deploy   {"model","replicas"} — scale the desired replica count (0 = park)
//   POST /dani/models/deploy   {"model","node"}     — pin an additional placement to a node
//   POST /dani/models/undeploy {"model"[,"node"]}   — remove one placement (or all + park)
// A worker whose assignment disappears UNLOADS the model on its next poll (engine.HotUnloader).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"dani.local/agent/internal/policy"
)

// Deployment is one model->node placement.
type Deployment struct {
	Model string    `json:"model"`
	Node  string    `json:"node"`
	State string    `json:"state"` // assigned | loaded
	At    time.Time `json:"at"`
}

// deployNowFn is a clock seam for tests.
var deployNowFn = time.Now

// deployments is the placement table (single controller owns it): every placement per model plus the
// desired replica count (unset = 1). In-memory by default; SetDurable persists it so a restarted
// controller remembers where each promoted model is serving instead of re-assigning from scratch.
type deployments struct {
	mu      sync.Mutex
	byMod   map[string][]*Deployment
	want    map[string]int // desired replicas; missing key = 1, explicit 0 = parked (not served)
	durable string
}

func newDeployments() *deployments {
	return &deployments{byMod: map[string][]*Deployment{}, want: map[string]int{}}
}

// NewDurableDeployments builds a placement table persisted at path (rehydrating existing state).
func NewDurableDeployments(path string) *deployments { return newDeployments().SetDurable(path) }

// durableSnapshot is the persisted shape (v2: placements + desired replicas).
type durableSnapshot struct {
	Placements map[string][]*Deployment `json:"placements"`
	Want       map[string]int           `json:"want"`
}

// SetDurable rehydrates placements from path (if present) and persists every subsequent change.
// Unlike the model registry, a corrupt/missing snapshot is NOT fatal: placements are reconstructible
// — an unplaced available model is simply re-assigned to the next capable poller. Legacy v1
// snapshots (model -> single placement) load transparently.
func (d *deployments) SetDurable(path string) *deployments {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.durable = path
	data, err := os.ReadFile(path)
	if err != nil {
		return d
	}
	var snap durableSnapshot
	if json.Unmarshal(data, &snap) == nil && snap.Placements != nil {
		d.byMod = snap.Placements
		if snap.Want != nil {
			d.want = snap.Want
		}
		return d
	}
	var legacy map[string]*Deployment // v1: one placement per model
	if json.Unmarshal(data, &legacy) == nil && legacy != nil {
		for m, p := range legacy {
			if p != nil {
				d.byMod[m] = []*Deployment{p}
			}
		}
	}
	return d
}

// save persists the placement table (mu must be held). Best-effort for the same reason SetDurable
// is lenient: the worst outcome of a lost snapshot is one redundant re-assignment.
func (d *deployments) save() {
	if d.durable == "" {
		return
	}
	data, _ := json.Marshal(durableSnapshot{Placements: d.byMod, Want: d.want})
	_ = os.WriteFile(d.durable, data, 0o600)
}

// wantOf reports a model's desired replica count (mu must be held). Missing = 1 (the auto-deploy
// default); an explicit 0 parks the model (operator undeployed it everywhere).
func (d *deployments) wantOf(model string) int {
	if n, ok := d.want[model]; ok {
		return n
	}
	return 1
}

// placementAt returns the placement of model on node (mu must be held).
func placementAt(list []*Deployment, node string) *Deployment {
	for _, p := range list {
		if p.Node == node {
			return p
		}
	}
	return nil
}

// handleDeployments assigns and reports placements for a polling worker: every available
// training-produced model (Lineage != nil) below its desired replica count is assigned to capable
// pollers whose clearance dominates the model's classification (D-09/F-01). Placements whose holder
// died (or was drained) migrate to the next capable poller. The response is the node's FULL desired
// set — a worker unloads anything it serves that is no longer listed.
func (t *TrainingAPI) handleDeployments(rw http.ResponseWriter, r *http.Request) {
	node := r.URL.Query().Get("node")
	class := r.URL.Query().Get("class")
	if node == "" {
		http.Error(rw, "node required", http.StatusBadRequest)
		return
	}
	t.Deploys.mu.Lock()
	defer t.Deploys.mu.Unlock()
	var mine []*Deployment
	for _, e := range t.Models.All() {
		if e.State != "available" || e.Lineage == nil {
			continue // only promoted fine-tunes deploy this way; bases are provisioned with the fleet
		}
		list := t.Deploys.byMod[e.ID]
		want := t.Deploys.wantOf(e.ID)
		// dead-node migration: a placement whose holder's heartbeat is gone (or drained) transfers to
		// THIS poller if it is capable and doesn't already hold one — the model must keep serving. The
		// stale record stays put until a capable poller shows up (observability: where it WAS matters).
		if t.Live != nil && placementAt(list, node) == nil && rank(class) >= rank(e.Classification) {
			for _, p := range list {
				if p.Node != node && !t.Live(p.Node) {
					t.emit("deployment.reassigned", map[string]any{"model": e.ID, "from": p.Node, "to": node})
					p.Node, p.State, p.At = node, "assigned", deployNowFn().UTC()
					break // at most one transfer per poll (others migrate on other polls)
				}
			}
		}
		// scale-down: too many placements (operator lowered replicas) — this poller's own placement
		// is released first so IT does the unload; others release on their own polls.
		for len(list) > want && placementAt(list, node) != nil {
			for i, p := range list {
				if p.Node == node {
					t.emit("deployment.released", map[string]any{"model": e.ID, "node": node})
					list = append(list[:i], list[i+1:]...)
					break
				}
			}
		}
		// scale-up: room below the desired count and this poller doesn't hold it yet.
		if len(list) < want && placementAt(list, node) == nil && rank(class) >= rank(e.Classification) {
			p := &Deployment{Model: e.ID, Node: node, State: "assigned", At: deployNowFn().UTC()}
			list = append(list, p)
			t.emit("deployment.assigned", map[string]any{"model": e.ID, "node": node})
		}
		t.Deploys.byMod[e.ID] = list
		if p := placementAt(list, node); p != nil {
			mine = append(mine, p)
		}
	}
	t.Deploys.save()
	writeJSON(rw, http.StatusOK, map[string]any{"deployments": mine})
}

// handleDeployReport records a worker's pull+verify+load completion.
func (t *TrainingAPI) handleDeployReport(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Node  string `json:"node"`
		Model string `json:"model"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(rw, "bad request body", http.StatusBadRequest)
		return
	}
	t.Deploys.mu.Lock()
	defer t.Deploys.mu.Unlock()
	d := placementAt(t.Deploys.byMod[req.Model], req.Node)
	if d == nil {
		writeErr(rw, http.StatusNotFound, fmt.Errorf("no such assignment: %s @ %s", req.Model, req.Node))
		return
	}
	d.State = "loaded"
	d.At = deployNowFn().UTC()
	t.Deploys.save()
	t.emit("deployment.loaded", map[string]any{"model": req.Model, "node": req.Node})
	writeJSON(rw, http.StatusOK, d)
}

// handleModelDeploy is the operator's distribution control: scale a promoted model's desired
// replica count, or pin an additional placement to a specific node.
func (t *TrainingAPI) handleModelDeploy(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Model    string `json:"model"`
		Node     string `json:"node"`
		Replicas *int   `json:"replicas"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Model == "" {
		http.Error(rw, "bad request body (need model)", http.StatusBadRequest)
		return
	}
	e := t.Models.Resolve(req.Model)
	if e == nil {
		writeErr(rw, http.StatusNotFound, fmt.Errorf("model %q is not deployable (unknown, draft, or failed verify-on-use)", req.Model))
		return
	}
	t.Deploys.mu.Lock()
	defer t.Deploys.mu.Unlock()
	if req.Replicas != nil {
		n := *req.Replicas
		if n < 0 {
			n = 0
		}
		t.Deploys.want[req.Model] = n
		t.emit("deployment.scaled", map[string]any{"model": req.Model, "replicas": n})
	}
	if req.Node != "" {
		if t.Live != nil && !t.Live(req.Node) {
			writeErr(rw, http.StatusBadRequest, fmt.Errorf("node %q is not live (no fresh healthy heartbeat)", req.Node))
			return
		}
		list := t.Deploys.byMod[req.Model]
		if placementAt(list, req.Node) == nil {
			list = append(list, &Deployment{Model: req.Model, Node: req.Node, State: "assigned", At: deployNowFn().UTC()})
			t.Deploys.byMod[req.Model] = list
			if t.Deploys.wantOf(req.Model) < len(list) {
				t.Deploys.want[req.Model] = len(list) // pinning grows the desired count
			}
			t.emit("deployment.assigned", map[string]any{"model": req.Model, "node": req.Node, "by": "operator"})
		}
	}
	t.Deploys.save()
	writeJSON(rw, http.StatusOK, map[string]any{
		"model": req.Model, "replicas": t.Deploys.wantOf(req.Model), "placements": t.Deploys.byMod[req.Model],
	})
}

// handleModelUndeploy removes one placement (the holder unloads on its next poll) or, with no node,
// parks the model everywhere (replicas 0 + all placements released).
func (t *TrainingAPI) handleModelUndeploy(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Model string `json:"model"`
		Node  string `json:"node"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Model == "" {
		http.Error(rw, "bad request body (need model)", http.StatusBadRequest)
		return
	}
	t.Deploys.mu.Lock()
	defer t.Deploys.mu.Unlock()
	list := t.Deploys.byMod[req.Model]
	if req.Node != "" {
		if placementAt(list, req.Node) == nil {
			writeErr(rw, http.StatusNotFound, fmt.Errorf("no placement of %s on %s", req.Model, req.Node))
			return
		}
		for i, p := range list {
			if p.Node == req.Node {
				list = append(list[:i], list[i+1:]...)
				break
			}
		}
		t.Deploys.byMod[req.Model] = list
		if n := t.Deploys.wantOf(req.Model); n > len(list) {
			t.Deploys.want[req.Model] = len(list) // shrink so auto-assign doesn't refill the slot
		}
		t.emit("deployment.undeployed", map[string]any{"model": req.Model, "node": req.Node})
	} else {
		t.Deploys.byMod[req.Model] = nil
		t.Deploys.want[req.Model] = 0 // parked until an operator scales it back up
		t.emit("deployment.undeployed", map[string]any{"model": req.Model, "node": "*"})
	}
	t.Deploys.save()
	writeJSON(rw, http.StatusOK, map[string]any{
		"model": req.Model, "replicas": t.Deploys.wantOf(req.Model), "placements": t.Deploys.byMod[req.Model],
	})
}

// applyPolicy runs the live Policy Engine on a plain (non-RAG) chat request for an attributed user.
// Returns the routing classification and ok=true when allowed; on denial it writes a 403 and returns
// ok=false. Unknown users fall through as allowed (guest-equivalent) — attribution is best-effort.
func (p *Plane) applyPolicy(rw http.ResponseWriter, user string, body []byte) (string, bool) {
	principal, err := p.training.Ident.Resolve(user)
	if err != nil {
		return "unrestricted", true // unknown attribution: no policy applied (best-effort)
	}
	var req struct {
		Messages []struct{ Role, Content string } `json:"messages"`
	}
	_ = json.Unmarshal(body, &req)
	prompt := ""
	for _, m := range req.Messages {
		if m.Role == "user" {
			prompt = m.Content
		}
	}
	dec := p.training.Policy.CheckPrompt(policy.Principal{Sub: principal.Sub, Clearance: principal.Clearance, Roles: principal.Roles}, prompt)
	if !dec.Allow {
		p.training.emit("policy.deny", map[string]any{"user": user, "reason": dec.Reason})
		writeErr(rw, http.StatusForbidden, fmt.Errorf("policy: %s", dec.Reason))
		return "", false
	}
	return dec.Classification, true
}

// deploymentsOf reports a model's placements (nil if none).
func (t *TrainingAPI) deploymentsOf(model string) []*Deployment {
	t.Deploys.mu.Lock()
	defer t.Deploys.mu.Unlock()
	return append([]*Deployment(nil), t.Deploys.byMod[model]...)
}
