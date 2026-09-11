package serving

// The investor "fan-out coding" demo (Tier C). It showcases DANI's core value in one visceral
// motion: hand the fleet a program SKELETON (function signatures + doc comments, empty bodies), and
// DANI dispatches ONE "implement this function" request per stub — the router scatters them across
// every node and site in parallel — then the browser reassembles the completed source and runs it.
// The headline: N functions come back in roughly the time of the single slowest one, so the fleet's
// aggregate throughput is the number on screen, and the result compiles and runs.
//
// The page itself does the fan-out (concurrent POSTs to /v1/chat/completions — the same gateway any
// client uses). The one server addition is /demo/verify, which `go run`s the assembled source so the
// demo can prove "it actually works." That endpoint EXECUTES code, so it is OFF unless --demo is set
// and is meant only for a controlled demo machine — never a production surface.

import (
	"context"
	"embed"
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

//go:embed all:webapp/demo
var demoFS embed.FS

type demoConfig struct {
	workdir string        // scratch dir for go-run verification
	timeout time.Duration // per-verify wall-clock cap
}

// EnableDemo mounts the fan-out demo page + the (code-executing, demo-only) /demo/verify endpoint.
func (p *Plane) EnableDemo() { p.demo = &demoConfig{timeout: 30 * time.Second} }

// demoCORS (demo mode only): the fan-out page shards its requests across the extra gateway lanes
// (other ports = other origins to a browser), so the gateway answers cross-origin. Wide-open CORS
// is acceptable ONLY because --demo is a demo-machine-only mode; production never sees this.
func demoCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Access-Control-Allow-Origin", "*")
		rw.Header().Set("Access-Control-Expose-Headers", "X-Dani-Served-By, X-Dani-Site, X-Dani-Trace-Id")
		if r.Method == http.MethodOptions {
			rw.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			rw.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Dani-Site, X-Dani-User")
			rw.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(rw, r)
	})
}

// ServeGatewayLanes (demo mode): bind the SAME gateway on n extra consecutive ports. Browsers cap
// HTTP/1.1 at ~6 connections per origin; each lane is its own origin, so the fan-out page reaches
// n*6-wide true parallelism. No-op unless EnableDemo was called.
func (p *Plane) ServeGatewayLanes(gwAddr string, n int) {
	if p.demo == nil || n <= 0 {
		return
	}
	host, portStr, err := net.SplitHostPort(gwAddr)
	if err != nil {
		return
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return
	}
	for i := 1; i <= n; i++ {
		lane := net.JoinHostPort(host, strconv.Itoa(port+i))
		if _, err := p.ServeGateway(lane); err != nil {
			log.Printf("controller: demo gateway lane %s unavailable: %v", lane, err)
		}
	}
}

// registerDemoRoutes attaches the demo surface (no-op until EnableDemo).
func (p *Plane) registerDemoRoutes(mux *http.ServeMux) {
	if p.demo == nil {
		return
	}
	if sub, err := fs.Sub(demoFS, "webapp/demo"); err == nil {
		mux.Handle("/demo/", http.StripPrefix("/demo/", http.FileServer(http.FS(sub))))
		mux.HandleFunc("/demo", func(rw http.ResponseWriter, r *http.Request) { http.Redirect(rw, r, "/demo/", http.StatusFound) })
	}
	mux.HandleFunc("/demo/verify", p.handleDemoVerify)
}

// handleDemoVerify writes the assembled Go source to a temp dir and `go run`s it, returning the
// exit status + combined output. DEMO ONLY — it runs model-generated code.
func (p *Plane) handleDemoVerify(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Source      string `json:"source"`
		CompileOnly bool   `json:"compileOnly"` // per-function contract checks: type-check, don't execute
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || req.Source == "" {
		http.Error(rw, "bad request (need source)", http.StatusBadRequest)
		return
	}
	base := p.demo.workdir
	if base == "" {
		base = os.TempDir()
	}
	dir, err := os.MkdirTemp(base, "dani-demo-run-*")
	if err != nil {
		writeErr(rw, http.StatusInternalServerError, err)
		return
	}
	defer os.RemoveAll(dir)
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(req.Source), 0o600); err != nil {
		writeErr(rw, http.StatusInternalServerError, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), p.demo.timeout)
	defer cancel()
	args := []string{"run", "main.go"}
	if req.CompileOnly {
		args = []string{"build", "-o", os.DevNull, "main.go"} // type-check + compile, no execution
	}
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	// This compiles + runs code GENERATED BY THE (untrusted) FLEET — an RCE surface on the operator's
	// own box. Shrink the blast radius: no module fetches (GOPROXY=off), caches confined to the temp
	// dir (no shared GOPATH/GOCACHE pollution), CGO off (no arbitrary C toolchain). Full OS sandboxing
	// (network namespace / container / seccomp) is the DEPLOY-time control — see OPEN-DANI-LAUNCH.md.
	cmd.Env = append(os.Environ(),
		"GOPROXY=off", "GOFLAGS=-mod=mod", "CGO_ENABLED=0",
		"GOCACHE="+filepath.Join(dir, ".gocache"),
		"GOPATH="+filepath.Join(dir, ".gopath"),
		"GOMODCACHE="+filepath.Join(dir, ".gomodcache"),
	)
	out, runErr := cmd.CombinedOutput()
	if len(out) > 64<<10 { // cap output so a runaway program can't stream unbounded text back
		out = append(out[:64<<10], []byte("\n...(output truncated)")...)
	}
	ok := runErr == nil && ctx.Err() == nil
	status := "compiled and ran"
	if req.CompileOnly {
		status = "compiled"
	}
	if ctx.Err() != nil {
		status = "timed out"
	} else if runErr != nil {
		status = "failed: " + runErr.Error()
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": ok, "status": status, "output": string(out)})
}
