package serving

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dani.local/agent/internal/enrollment"
	"dani.local/agent/internal/registry"
)

// nodeAdminHarness builds a plane with one live worker + a NodeAdmin over fake closures.
func nodeAdminHarness(t *testing.T, drainFile string) (*Plane, *http.ServeMux, *[]string, *map[string]string) {
	t.Helper()
	p := newTestPlane("site-hq",
		workerState{Heartbeat: Heartbeat{NodeUUID: "w1", DispatchAddr: "w1:9443", ModelID: "m",
			Class: "restricted", MaxConcurrent: 2, QueueDepth: 2, Health: "healthy"}},
		workerState{Heartbeat: Heartbeat{NodeUUID: "t1", Trainer: true, DispatchAddr: "t1:9444",
			Class: "restricted", Health: "healthy"}},
	)
	var audited []string
	lifecycle := map[string]string{}
	admin := &NodeAdmin{
		Nodes: func(context.Context) ([]registry.RegRow, error) {
			return []registry.RegRow{
				{NodeRecord: registry.NodeRecord{UUID: "w1", CertSerial: "abc123", Roles: []string{"worker"},
					Class: "restricted", Site: "site-hq", NotAfter: time.Now().Add(90 * 24 * time.Hour)}, Lifecycle: "active"},
				{NodeRecord: registry.NodeRecord{UUID: "gone", CertSerial: "dead99", Roles: []string{"worker"},
					Class: "internal"}, Lifecycle: "active"},
			}, nil
		},
		SetLifecycle: func(_ context.Context, uuid, state string) error {
			lifecycle[uuid] = state
			return nil
		},
		Revoke:  func(uuid string) { audited = append(audited, "enroll-revoke:"+uuid) },
		Pending: func() []enrollment.PendingInfo { return nil },
		Audit:   func(typ string, payload map[string]any) { audited = append(audited, typ) },
	}
	if drainFile != "" {
		admin.DrainFile = drainFile
	}
	p.EnableNodeAdmin(admin)
	mux := http.NewServeMux()
	p.registerNodeRoutes(mux)
	return p, mux, &audited, &lifecycle
}

func TestNodesViewMergesRegistryAndHeartbeat(t *testing.T) {
	_, mux, _, _ := nodeAdminHarness(t, "")
	var out struct {
		Nodes []struct {
			UUID       string   `json:"uuid"`
			CertSerial string   `json:"certSerial"`
			Live       bool     `json:"live"`
			Drained    bool     `json:"drained"`
			Model      string   `json:"model"`
			Roles      []string `json:"roles"`
		} `json:"nodes"`
		Count int `json:"count"`
	}
	if rec := getJSON(t, mux, "/dani/nodes", &out); rec.Code != http.StatusOK {
		t.Fatalf("nodes: %d", rec.Code)
	}
	if out.Count != 2 {
		t.Fatalf("want 2 registry rows, got %d", out.Count)
	}
	// pending endpoint tolerates a nil-returning Pending closure (empty list, not null)
	var pend struct {
		Pending []any `json:"pending"`
		Count   int   `json:"count"`
	}
	if rec := getJSON(t, mux, "/dani/enroll/pending", &pend); rec.Code != http.StatusOK || pend.Count != 0 || pend.Pending == nil {
		t.Fatalf("nil pending must serialize as []: %d %+v", rec.Code, pend)
	}
	// "gone" is enrolled but not heartbeating -> not live; "w1" is both
	byUUID := map[string]bool{}
	for _, n := range out.Nodes {
		byUUID[n.UUID] = n.Live
		if n.UUID == "w1" && (n.CertSerial != "abc123" || n.Model != "m" || !n.Live) {
			t.Fatalf("w1 merge wrong: %+v", n)
		}
	}
	if byUUID["gone"] {
		t.Fatal("non-heartbeating node must not be live")
	}
}

func TestDrainRemovesFromRoutingAndMigratesPlacements(t *testing.T) {
	p, mux, audited, _ := nodeAdminHarness(t, "")
	// routable before
	if _, ok := p.reserve("m", "unrestricted", "", nil); !ok {
		t.Fatal("w1 must route before drain")
	}
	p.release("w1")
	if len(p.ActiveTrainers()) != 1 {
		t.Fatal("t1 must be an active trainer before drain")
	}
	// drain w1 + t1
	for _, n := range []string{"w1", "t1"} {
		if rec := postJSON(t, mux, "/dani/nodes/drain", map[string]any{"node": n}); rec.Code != http.StatusOK {
			t.Fatalf("drain %s: %d %s", n, rec.Code, rec.Body)
		}
	}
	if _, ok := p.reserve("m", "unrestricted", "", nil); ok {
		t.Fatal("drained worker must not route")
	}
	if _, any := p.fleetETA("m", "unrestricted"); any {
		t.Fatal("drained worker must not count toward ETA")
	}
	if len(p.ActiveTrainers()) != 0 {
		t.Fatal("drained trainer must not allocate")
	}
	if p.nodeAlive("w1") {
		t.Fatal("drained node must read not-alive so placements migrate")
	}
	// fleet view shows it
	rec := httptest.NewRecorder()
	p.handleFleet(rec, httptest.NewRequest(http.MethodGet, "/dani/fleet", nil))
	if !strings.Contains(rec.Body.String(), `"Drained":true`) {
		t.Fatalf("fleet must flag drained nodes: %s", rec.Body)
	}
	// undrain restores routing
	off := false
	if rec := postJSON(t, mux, "/dani/nodes/drain", map[string]any{"node": "w1", "drain": &off}); rec.Code != http.StatusOK {
		t.Fatalf("undrain: %d", rec.Code)
	}
	if _, ok := p.reserve("m", "unrestricted", "", nil); !ok {
		t.Fatal("undrained worker must route again")
	}
	p.release("w1")
	joined := strings.Join(*audited, ",")
	if !strings.Contains(joined, "node.drained") || !strings.Contains(joined, "node.undrained") {
		t.Fatalf("drain lifecycle must be audited: %s", joined)
	}
}

func TestDrainPersistsAcrossRestart(t *testing.T) {
	file := filepath.Join(t.TempDir(), "drained.json")
	p, mux, _, _ := nodeAdminHarness(t, file)
	postJSON(t, mux, "/dani/nodes/drain", map[string]any{"node": "w1"})
	if _, err := os.Stat(file); err != nil {
		t.Fatal("drain file must persist")
	}
	_ = p
	// "restart": a fresh plane over the same file rehydrates the drained set
	p2, _, _, _ := nodeAdminHarness(t, file)
	if _, ok := p2.reserve("m", "unrestricted", "", nil); ok {
		t.Fatal("drain must survive a controller restart")
	}
}

func TestRevokeEvictsAndRefusesHeartbeat(t *testing.T) {
	p, mux, audited, lifecycle := nodeAdminHarness(t, "")
	if rec := postJSON(t, mux, "/dani/nodes/revoke", map[string]any{"node": "w1"}); rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	// evicted from the plane NOW
	if _, ok := p.reserve("m", "unrestricted", "", nil); ok {
		t.Fatal("revoked node must be evicted from routing")
	}
	// future heartbeats rejected
	hb := httptest.NewRecorder()
	p.handleHeartbeat(hb, httptest.NewRequest(http.MethodPost, "/link/heartbeat",
		strings.NewReader(`{"node_uuid":"w1","health":"healthy"}`)))
	if hb.Code != http.StatusForbidden {
		t.Fatalf("revoked heartbeat must 403, got %d", hb.Code)
	}
	// enrollment refusal + registry lifecycle + audit all recorded
	joined := strings.Join(*audited, ",")
	if !strings.Contains(joined, "enroll-revoke:w1") || !strings.Contains(joined, "node.revoked") {
		t.Fatalf("revoke must hit enrollment + audit: %s", joined)
	}
	if (*lifecycle)["w1"] != "revoked" {
		t.Fatalf("registry lifecycle must be revoked: %+v", *lifecycle)
	}
}

func TestRevokeLifecycleWriteFailure(t *testing.T) {
	p, _, _, _ := nodeAdminHarness(t, "")
	p.admin.SetLifecycle = func(context.Context, string, string) error { return fmt.Errorf("db down") }
	mux := http.NewServeMux()
	p.registerNodeRoutes(mux)
	if rec := postJSON(t, mux, "/dani/nodes/revoke", map[string]any{"node": "w1"}); rec.Code != http.StatusInternalServerError {
		t.Fatalf("lifecycle write failure must 500: %d", rec.Code)
	}
}

func TestPendingApproveReject(t *testing.T) {
	p, _, audited, _ := nodeAdminHarness(t, "")
	approved, rejected := []string{}, []string{}
	p.admin.Pending = func() []enrollment.PendingInfo {
		return []enrollment.PendingInfo{{ReqID: "r1", NodeUUID: "new-node", DeclaredRoles: []string{"worker"}, DeclaredClass: "internal"}}
	}
	p.admin.Approve = func(_ context.Context, reqID string) error {
		if reqID == "bad" {
			return fmt.Errorf("no such request")
		}
		approved = append(approved, reqID)
		return nil
	}
	p.admin.Reject = func(reqID, reason string) error {
		if reqID == "bad" {
			return fmt.Errorf("no such request")
		}
		rejected = append(rejected, reqID+":"+reason)
		return nil
	}
	mux := http.NewServeMux()
	p.registerNodeRoutes(mux)

	var pend struct {
		Pending []struct {
			ReqID    string `json:"reqId"`
			NodeUUID string `json:"nodeUuid"`
		} `json:"pending"`
	}
	if rec := getJSON(t, mux, "/dani/enroll/pending", &pend); rec.Code != http.StatusOK || len(pend.Pending) != 1 || pend.Pending[0].NodeUUID != "new-node" {
		t.Fatalf("pending list wrong: %d %+v", rec.Code, pend)
	}
	if rec := postJSON(t, mux, "/dani/enroll/approve", map[string]string{"id": "r1"}); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	if rec := postJSON(t, mux, "/dani/enroll/approve", map[string]string{"id": "bad"}); rec.Code != http.StatusBadRequest {
		t.Fatal("approve of unknown request must 400")
	}
	if rec := postJSON(t, mux, "/dani/enroll/reject", map[string]string{"id": "r2", "reason": "untrusted"}); rec.Code != http.StatusOK {
		t.Fatalf("reject: %d", rec.Code)
	}
	if rec := postJSON(t, mux, "/dani/enroll/reject", map[string]string{"id": "bad"}); rec.Code != http.StatusBadRequest {
		t.Fatal("reject of unknown request must 400")
	}
	if len(approved) != 1 || approved[0] != "r1" || len(rejected) != 1 || rejected[0] != "r2:untrusted" {
		t.Fatalf("closures not hit: %v %v", approved, rejected)
	}
	joined := strings.Join(*audited, ",")
	if !strings.Contains(joined, "node.approved") || !strings.Contains(joined, "node.rejected") {
		t.Fatalf("admission must be audited: %s", joined)
	}
}

func TestNodeAdminErrorsAndGuards(t *testing.T) {
	p, mux, _, _ := nodeAdminHarness(t, "")
	// method guards
	for _, path := range []string{"/dani/nodes/drain", "/dani/nodes/revoke", "/dani/enroll/approve", "/dani/enroll/reject"} {
		if rec := getJSON(t, mux, path, nil); rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s must 405, got %d", path, rec.Code)
		}
	}
	// body guards
	for _, path := range []string{"/dani/nodes/drain", "/dani/nodes/revoke", "/dani/enroll/approve", "/dani/enroll/reject"} {
		if rec := postJSON(t, mux, path, "{bad"); rec.Code != http.StatusBadRequest {
			t.Fatalf("bad body on %s must 400, got %d", path, rec.Code)
		}
	}
	// approve/reject without manual admission (closures nil) -> 501
	p.admin.Approve, p.admin.Reject = nil, nil
	if rec := postJSON(t, mux, "/dani/enroll/approve", map[string]string{"id": "x"}); rec.Code != http.StatusNotImplemented {
		t.Fatalf("approve without manual admission must 501: %d", rec.Code)
	}
	if rec := postJSON(t, mux, "/dani/enroll/reject", map[string]string{"id": "x"}); rec.Code != http.StatusNotImplemented {
		t.Fatalf("reject without manual admission must 501: %d", rec.Code)
	}
	// registry dump failure -> 500
	p.admin.Nodes = func(context.Context) ([]registry.RegRow, error) { return nil, fmt.Errorf("db down") }
	if rec := getJSON(t, mux, "/dani/nodes", nil); rec.Code != http.StatusInternalServerError {
		t.Fatalf("registry failure must 500: %d", rec.Code)
	}
	// routes are a no-op without EnableNodeAdmin
	bare := newTestPlane("s")
	bareMux := http.NewServeMux()
	bare.registerNodeRoutes(bareMux)
	req := httptest.NewRequest(http.MethodGet, "/dani/nodes", nil)
	rec := httptest.NewRecorder()
	bareMux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("node routes must not register without admin: %d", rec.Code)
	}
	// corrupt drain file is lenient
	file := filepath.Join(t.TempDir(), "drained.json")
	os.WriteFile(file, []byte("{nope"), 0o600)
	p2 := newTestPlane("s")
	p2.EnableNodeAdmin(&NodeAdmin{DrainFile: file})
	if len(p2.drained) != 0 {
		t.Fatal("corrupt drain file must start empty")
	}
}
