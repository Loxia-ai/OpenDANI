package serving

// Training + Model Registry gateway endpoints — the control surface for the train -> sign -> serve
// story (§6.17.6, §6.17.4). Attached to the Plane with EnableTraining; the console drives them.
//
//	GET  /dani/collections            ingested collections + available corpora
//	POST /dani/ingest                 {"collection":"legal"} — classify-at-ingest + lineage
//	GET  /dani/train/jobs             all jobs with live checkpoint progress
//	POST /dani/train/submit           {"engineer","base","collection","method"} — AuthZ + D17,
//	                                  then executes async; poll jobs for progress
//	GET  /dani/models                 model registry entries (state, base, signatures, evals)
//	POST /dani/models/sign            {"model","role"} — one reviewer's cryptographic approval
//	GET  /dani/principals             the identity directory (who can submit; clearances)

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"dani.local/agent/internal/artifact"
	"dani.local/agent/internal/audit"
	"dani.local/agent/internal/identity"
	"dani.local/agent/internal/ingest"
	"dani.local/agent/internal/modelreg"
	"dani.local/agent/internal/policy"
	"dani.local/agent/internal/training"
)

// IdentAdapter bridges identity.Bridge to training.IdentityResolver.
type IdentAdapter struct{ B *identity.Bridge }

// Resolve maps the bridge's (Principal, error) to training's (Principal, bool).
func (a IdentAdapter) Resolve(engineer string) (training.Principal, bool) {
	p, err := a.B.Resolve(engineer)
	if err != nil {
		return training.Principal{}, false
	}
	return training.Principal{Name: p.Sub, Clearance: p.Clearance}, true
}

// IngestAdapter bridges ingest.Subsystem to training.DataSource.
type IngestAdapter struct{ S *ingest.Subsystem }

// Collection maps ingest chunks to training's classified-chunk view.
func (a IngestAdapter) Collection(name string) (training.Collection, bool) {
	c, ok := a.S.Collection(name)
	if !ok {
		return training.Collection{}, false
	}
	col := training.Collection{}
	for _, ch := range c.Chunks {
		col.Chunks = append(col.Chunks, training.Chunk{
			Text: ch.Text, Classification: ch.Classification,
			Format: ch.Format, Messages: ch.Messages, Tools: ch.Tools, // carry structured examples to the trainer
		})
	}
	return col, true
}

// TrainingAPI bundles the training control surface the gateway exposes.
type TrainingAPI struct {
	Ident    *identity.Bridge
	Ingest   *ingest.Subsystem
	Models   *modelreg.Registry
	Training *training.Subsystem
	Store    *artifact.Store        // artifact pulls (workers fetch promoted model bytes)
	Audit    *audit.Log             // hash-chained audit trail (optional; nil = not wired)
	Deploys  *deployments           // auto-deploy placements (lazily initialized)
	Live     func(node string) bool // fleet liveness (wired by EnableTraining; nil = assume alive)
	Policy   *policy.Engine         // live DP13 policy authority (defaulted by EnableTraining)
	Translate *Translator           // in-perimeter MT sidecar (nil = multilingual bridge off)
}

// EnsureDeploys initializes the placement table (call once at wiring; handlers tolerate it).
func (t *TrainingAPI) EnsureDeploys() {
	if t.Deploys == nil {
		t.Deploys = newDeployments()
	}
}

// emit appends to the audit chain, fire-and-forget: an audit hiccup must never fail the operation
// (the chain's own Verify reports gaps if the store is unhealthy).
func (t *TrainingAPI) emit(typ string, payload map[string]any) {
	if t.Audit != nil {
		_ = t.Audit.Emit(typ, payload)
	}
}

// EnableTraining attaches the training/model-registry endpoints to the gateway (call before
// ServeGateway).
func (p *Plane) EnableTraining(api *TrainingAPI) {
	p.training = api
	if api.Live == nil {
		api.Live = p.nodeAlive
	}
	if api.Policy == nil {
		api.Policy = policy.New(0, 0) // no rate limit unless configured
	}
}

// registerTrainingRoutes adds the training endpoints to the gateway mux (no-op when not enabled).
func (p *Plane) registerTrainingRoutes(mux *http.ServeMux) {
	if p.training == nil {
		return
	}
	mux.HandleFunc("/dani/collections", p.training.handleCollections)
	mux.HandleFunc("/dani/ingest", p.protect(p.training.handleIngest))
	p.registerConnectorRoutes(mux) // "Connect a source": live connector CRUD + dry-run test
	mux.HandleFunc("/dani/train/jobs", p.training.handleJobs)
	mux.HandleFunc("/dani/train/submit", p.protect(p.training.handleSubmit))
	mux.HandleFunc("/dani/models", p.training.handleModelList)
	mux.HandleFunc("/dani/models/sign", p.protect(p.training.handleSign))
	mux.HandleFunc("/dani/models/artifact", p.training.handleArtifact)
	mux.HandleFunc("/dani/rag/alias", p.protect(p.training.handleRagAlias))
	mux.HandleFunc("/dani/rag/search", p.training.handleRagSearch)
	mux.HandleFunc("/dani/audit", p.training.handleAudit)
	mux.HandleFunc("/dani/audit/export", p.training.handleAuditExport)
	p.training.EnsureDeploys()
	// /dani/deployments + /report are worker machine-to-machine calls, NOT operator actions — they
	// stay open under --console-auth (the data plane's authn is mTLS node identity, D-30).
	mux.HandleFunc("/dani/deployments", p.training.handleDeployments)
	mux.HandleFunc("/dani/deployments/report", p.training.handleDeployReport)
	mux.HandleFunc("/dani/models/deploy", p.protect(p.training.handleModelDeploy))
	mux.HandleFunc("/dani/models/undeploy", p.protect(p.training.handleModelUndeploy))
	mux.HandleFunc("/dani/principals", p.training.handlePrincipals)
}

func writeJSON(rw http.ResponseWriter, status int, v any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(v)
}

func writeErr(rw http.ResponseWriter, status int, err error) {
	writeJSON(rw, status, map[string]any{"error": err.Error()})
}

func (t *TrainingAPI) handleCollections(rw http.ResponseWriter, _ *http.Request) {
	type colRow struct {
		Name      string `json:"name"`
		Connector string `json:"connector"`
		Chunks    int    `json:"chunks"`
		Class     string `json:"classification"` // dataset class = max over chunks
	}
	rows := []colRow{}
	for _, c := range t.Ingest.List() {
		row := colRow{Name: c.Name, Connector: c.Connector, Chunks: len(c.Chunks), Class: "unrestricted"}
		for _, ch := range c.Chunks {
			if classRank[ch.Classification] > classRank[row.Class] {
				row.Class = ch.Classification
			}
		}
		rows = append(rows, row)
	}
	writeJSON(rw, http.StatusOK, map[string]any{"collections": rows, "corpora": t.Ingest.AvailableCorpora()})
}

// handleIngest ingests a known corpus, or — when docs are supplied — registers an operator-uploaded
// dataset first (the console's upload path) and ingests it: same classify-at-ingest + lineage.
func (t *TrainingAPI) handleIngest(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Collection     string   `json:"collection"`
		Docs           []string `json:"docs"`           // optional: upload these documents as the corpus
		Classification string   `json:"classification"` // optional source class for uploads (default internal)
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(rw, "bad request body", http.StatusBadRequest)
		return
	}
	if len(req.Docs) > 0 {
		class, err := t.Ingest.AddCustom(req.Collection, req.Docs, req.Classification)
		if err != nil {
			writeErr(rw, http.StatusBadRequest, err)
			return
		}
		t.emit("ingest.uploaded", map[string]any{"collection": req.Collection, "docs": len(req.Docs),
			"classification": class, "by": operatorSub(r)})
	}
	col, err := t.Ingest.Ingest(req.Collection)
	if err != nil {
		writeErr(rw, http.StatusNotFound, err)
		return
	}
	t.emit("ingest.complete", map[string]any{"collection": col.Name, "chunks": len(col.Chunks), "connector": col.Connector})
	writeJSON(rw, http.StatusOK, col)
}

func (t *TrainingAPI) handleJobs(rw http.ResponseWriter, _ *http.Request) {
	writeJSON(rw, http.StatusOK, map[string]any{"jobs": t.Training.List()})
}

func (t *TrainingAPI) handleSubmit(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Engineer   string `json:"engineer"`
		Base       string `json:"base"`
		Collection string `json:"collection"`
		Method     string `json:"method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(rw, "bad request body", http.StatusBadRequest)
		return
	}
	job, err := t.Training.Accept(r.Context(), training.Request{
		BaseModelID: req.Base, Collection: req.Collection, Method: req.Method, Engineer: req.Engineer,
	})
	if err != nil {
		// AuthZ denial / no trainer / unknown dataset — the honest, demoable failures.
		t.emit("training.denied", map[string]any{"engineer": req.Engineer, "collection": req.Collection, "reason": err.Error()})
		writeErr(rw, http.StatusForbidden, err)
		return
	}
	t.emit("training.start", map[string]any{"job": job.ID, "base": job.BaseModelID, "method": job.Method,
		"collection": job.Collection, "engineer": job.Engineer, "trainer": job.TrainerUUID, "out": job.OutputClass})
	// Execute async so the console can watch staging -> running -> ckpt k/N -> completed live.
	// The response must serialize a locked SNAPSHOT (Get), not the live job — Execute mutates the
	// same pointer on its goroutine.
	id := job.ID
	go t.Training.Execute(context.Background(), job)
	writeJSON(rw, http.StatusAccepted, t.Training.Get(id))
}

func (t *TrainingAPI) handleModelList(rw http.ResponseWriter, _ *http.Request) {
	type modelRow struct {
		ID          string             `json:"id"`
		Engine      string             `json:"engine"`
		Class       string             `json:"classification"`
		State       string             `json:"state"`
		Base        string             `json:"base,omitempty"`
		Hash        string             `json:"hash"`
		Signatures  []string           `json:"signatures"`
		Evals       map[string]float64 `json:"evals,omitempty"`
		Lineage     *modelreg.Lineage  `json:"lineage,omitempty"`
		Deployment  *Deployment        `json:"deployment,omitempty"`  // first placement (back-compat)
		Deployments []*Deployment      `json:"deployments,omitempty"` // every placement (replicas)
		Replicas    int                `json:"replicas"`              // desired replica count
		GateFailed  string             `json:"gate_failed,omitempty"`
	}
	rows := []modelRow{}
	for _, e := range t.Models.All() {
		row := modelRow{
			ID: e.ID, Engine: e.Engine, Class: e.Classification, State: e.State, Base: e.Base,
			Hash: shortHash(e.Artifact.Hash), Signatures: []string{}, Evals: e.Evals, Lineage: e.Lineage,
			GateFailed: e.GateFailed, Replicas: 1,
		}
		if t.Deploys != nil {
			row.Deployments = t.deploymentsOf(e.ID)
			if len(row.Deployments) > 0 {
				row.Deployment = row.Deployments[0]
			}
			t.Deploys.mu.Lock()
			row.Replicas = t.Deploys.wantOf(e.ID)
			t.Deploys.mu.Unlock()
		}
		for _, role := range []modelreg.Role{modelreg.RoleSecurity, modelreg.RoleGovernance, modelreg.RoleAdmin} {
			if _, ok := e.Signatures[role]; ok {
				row.Signatures = append(row.Signatures, string(role))
			}
		}
		rows = append(rows, row)
	}
	writeJSON(rw, http.StatusOK, map[string]any{"models": rows})
}

func (t *TrainingAPI) handleSign(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Model string `json:"model"`
		Role  string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(rw, "bad request body", http.StatusBadRequest)
		return
	}
	// Three-party control becomes REAL under --console-auth: an authenticated operator signs only as
	// a reviewer role their identity holds — one person cannot click all three buttons.
	if op, ok := OperatorFrom(r.Context()); ok && !op.HasRole(req.Role) {
		t.emit("model.sign.denied", map[string]any{"model": req.Model, "role": req.Role, "by": op.Sub})
		writeErr(rw, http.StatusForbidden, fmt.Errorf("operator %q does not hold the %q role — a different reviewer must sign", op.Sub, req.Role))
		return
	}
	e, err := t.Models.Sign(r.Context(), req.Model, modelreg.Role(req.Role))
	if err != nil {
		writeErr(rw, http.StatusBadRequest, err)
		return
	}
	t.emit("model.signed", map[string]any{"model": e.ID, "role": req.Role, "signatures": len(e.Signatures), "by": operatorSub(r)})
	if e.State == "available" {
		t.emit("model.approved", map[string]any{"model": e.ID, "hash": e.Artifact.Hash})
	} else if e.GateFailed != "" {
		t.emit("model.gate_failed", map[string]any{"model": e.ID, "reason": e.GateFailed})
	}
	writeJSON(rw, http.StatusOK, map[string]any{"id": e.ID, "state": e.State,
		"signatures": len(e.Signatures), "gate_failed": e.GateFailed})
}

// handleArtifact serves a promoted model's bytes to a puller (a worker deploying it). This is the
// §6.17.4 "workers pull + verify + load" step with DP13 twice over: the model must RESOLVE (state
// available AND all three signatures re-verify — a draft or tampered entry is refused), and the
// store re-hashes the blob on read. The response carries the content hash so the puller can verify
// a third time on its side.
func (t *TrainingAPI) handleArtifact(rw http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	e := t.Models.Resolve(id)
	if e == nil {
		t.emit("model.artifact.refused", map[string]any{"model": id})
		writeErr(rw, http.StatusForbidden, fmt.Errorf("model %q is not routable (unknown, draft, or failed verify-on-use)", id))
		return
	}
	data, err := t.Store.Get(e.Artifact.Hash)
	if err != nil {
		writeErr(rw, http.StatusInternalServerError, err)
		return
	}
	t.emit("model.artifact.pulled", map[string]any{"model": id, "hash": e.Artifact.Hash})
	rw.Header().Set("Content-Type", "application/octet-stream")
	rw.Header().Set("X-Dani-Artifact-Hash", e.Artifact.Hash)
	rw.Header().Set("X-Dani-Artifact-Kind", e.Artifact.Kind)
	rw.Header().Set("X-Dani-Model-Base", e.Base)
	_, _ = rw.Write(data)
}

// handleAudit reports the compliance trail: chain shape, full integrity verification (§6.17.12 —
// every hash re-computed, every signed head re-verified, on every call), and the recent events.
func (t *TrainingAPI) handleAudit(rw http.ResponseWriter, r *http.Request) {
	if t.Audit == nil {
		writeErr(rw, http.StatusNotFound, fmt.Errorf("audit chain not enabled"))
		return
	}
	integ, err := t.Audit.Verify(r.Context())
	if err != nil {
		writeErr(rw, http.StatusInternalServerError, err)
		return
	}
	limit := 12
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		if n > 500 {
			n = 500
		}
		limit = n
	}
	recent, err := t.Audit.RecentFiltered(r.Context(), limit, r.URL.Query().Get("type"))
	if err != nil {
		writeErr(rw, http.StatusInternalServerError, err)
		return
	}
	records, head, heads, _ := t.Audit.Stats(r.Context())
	writeJSON(rw, http.StatusOK, map[string]any{
		"records": records, "head": head, "signedHeads": heads,
		"integrity": integ, "recent": recent,
	})
}

// handleAuditExport seals the ENTIRE chain into a signed Compliance bundle (§6.15 Compliance tier)
// and returns it. The bundle is independently verifiable offline (audit.VerifyBundle) — the response
// includes a self-check so a caller sees the seal is valid without re-implementing the verifier.
func (t *TrainingAPI) handleAuditExport(rw http.ResponseWriter, r *http.Request) {
	if t.Audit == nil {
		writeErr(rw, http.StatusNotFound, fmt.Errorf("audit chain not enabled"))
		return
	}
	dep := r.URL.Query().Get("deployment")
	if dep == "" {
		dep = "dep-1"
	}
	bundle, err := t.Audit.Export(r.Context(), dep)
	if err != nil {
		writeErr(rw, http.StatusInternalServerError, err)
		return
	}
	integ, _ := audit.VerifyBundle(bundle) // offline self-check, proving the seal stands alone
	writeJSON(rw, http.StatusOK, map[string]any{
		"deployment": bundle.Deployment, "exportedAt": bundle.ExportedAt,
		"events": len(bundle.Events), "signedHeads": len(bundle.Heads),
		"offlineVerify": integ, "bundle": bundle,
	})
}

func (t *TrainingAPI) handlePrincipals(rw http.ResponseWriter, _ *http.Request) {
	writeJSON(rw, http.StatusOK, map[string]any{"principals": t.Ident.Principals()})
}

// shortHash truncates a content address for display.
func shortHash(h string) string {
	if len(h) > 19 {
		return h[:19] + "…"
	}
	return h
}
