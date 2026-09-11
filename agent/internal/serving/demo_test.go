package serving

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func demoMux(t *testing.T) *http.ServeMux {
	t.Helper()
	p := &Plane{}
	p.EnableDemo()
	mux := http.NewServeMux()
	p.registerDemoRoutes(mux)
	return mux
}

func TestDemoVerifyRunsGo(t *testing.T) {
	mux := demoMux(t)
	post := func(src string) map[string]any {
		body, _ := json.Marshal(map[string]string{"source": src})
		req := httptest.NewRequest(http.MethodPost, "/demo/verify", strings.NewReader(string(body)))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		out["_code"] = rec.Code
		return out
	}
	// a good program compiles + runs
	good := post("package main\nimport \"fmt\"\nfunc main(){ fmt.Print(\"fleet-ok\") }")
	if good["ok"] != true || !strings.Contains(good["output"].(string), "fleet-ok") {
		t.Fatalf("good program: %+v", good)
	}
	// broken code fails cleanly (ok=false, no panic)
	bad := post("package main\nfunc main(){ nonsense }")
	if bad["ok"] != false {
		t.Fatalf("broken program should fail: %+v", bad)
	}
	// method + body guards
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/demo/verify", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET must 405, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/demo/verify", strings.NewReader("{}")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty source must 400, got %d", rec.Code)
	}
}

func TestDemoPageServedAndTimeout(t *testing.T) {
	mux := demoMux(t)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/demo/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Fleet Fan-Out") {
		t.Fatalf("demo page: %d", rec.Code)
	}
	// a program that hangs is killed by the verify timeout (kept short for the test)
	p := &Plane{demo: &demoConfig{timeout: 500 * time.Millisecond}}
	m2 := http.NewServeMux()
	p.registerDemoRoutes(m2)
	body, _ := json.Marshal(map[string]string{"source": "package main\nfunc main(){ for{} }"})
	rec = httptest.NewRecorder()
	m2.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/demo/verify", strings.NewReader(string(body))))
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out["ok"] != false || !strings.Contains(out["status"].(string), "timed out") {
		t.Fatalf("infinite loop must time out: %+v", out)
	}
}

func TestDemoDisabled(t *testing.T) {
	p := &Plane{} // EnableDemo not called
	mux := http.NewServeMux()
	p.registerDemoRoutes(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/demo/", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("demo routes must be absent without EnableDemo, got %d", rec.Code)
	}
}
