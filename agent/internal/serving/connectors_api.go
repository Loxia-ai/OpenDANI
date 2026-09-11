package serving

// "Connect a source" (the console's Datasets tab): the governed API that turns connector wiring
// from boot flags into an operator action — list connected sources with live health, dry-run a
// prospective source, connect one (registers + first-syncs LIVE, persisted across restarts), and
// disconnect it. Every mutation is audited with the acting operator; secrets are write-only.

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"dani.local/agent/internal/ingest"
)

// registerConnectorRoutes mounts the surface (called from registerTrainingRoutes — the ingest
// subsystem arrives with the training API).
func (p *Plane) registerConnectorRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/dani/connectors", p.protect(p.training.handleConnectors))
	mux.HandleFunc("/dani/connectors/test", p.protect(p.training.handleConnectorTest))
}

// handleConnectors lists (GET), connects (POST) or disconnects (DELETE ?collection=) sources.
func (t *TrainingAPI) handleConnectors(rw http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(rw, http.StatusOK, map[string]any{"connectors": t.Ingest.ListConnectors()})

	case http.MethodPost:
		var def ingest.ConnectorDef
		if err := json.NewDecoder(r.Body).Decode(&def); err != nil {
			http.Error(rw, "bad request body", http.StatusBadRequest)
			return
		}
		def.Static = false // a console write can never mint a flag-locked source
		if err := t.Ingest.StartConnector(r.Context(), def); err != nil {
			writeErr(rw, http.StatusBadRequest, err)
			return
		}
		t.emit("connector.connected", map[string]any{
			"kind": def.Kind, "collection": def.Collection, "source": def.Path + def.URL,
			"classmap": def.ClassMap, "by": operatorSub(r),
		})
		writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "collection": def.Collection})

	case http.MethodDelete:
		collection := r.URL.Query().Get("collection")
		if collection == "" {
			http.Error(rw, "collection query parameter required", http.StatusBadRequest)
			return
		}
		if err := t.Ingest.RemoveConnector(r.Context(), collection); err != nil {
			writeErr(rw, http.StatusBadRequest, err)
			return
		}
		t.emit("connector.disconnected", map[string]any{"collection": collection, "by": operatorSub(r)})
		writeJSON(rw, http.StatusOK, map[string]any{"ok": true})

	default:
		http.Error(rw, "GET, POST or DELETE", http.StatusMethodNotAllowed)
	}
}

// handleConnectorTest dry-runs a def — reachability + supported-file count — WITHOUT registering
// anything. The console's "Test connection" button.
func (t *TrainingAPI) handleConnectorTest(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var def ingest.ConnectorDef
	if err := json.NewDecoder(r.Body).Decode(&def); err != nil {
		http.Error(rw, "bad request body", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	files, detail, err := t.Ingest.Probe(ctx, def)
	if err != nil {
		writeJSON(rw, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "files": files, "detail": detail})
}
