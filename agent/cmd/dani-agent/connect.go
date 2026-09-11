package main

// `dani-agent connect` — the LOCAL RELAY that makes DANI reachable at one fixed loopback address on
// any machine. Every app on the box points at http://127.0.0.1:11435/v1 (or just inherits
// OPENAI_BASE_URL from the endpoint file) and needs zero per-app configuration: the relay owns the
// gateway address, failover, and — the real prize — IDENTITY. It stamps X-Dani-User from the
// logged-in OS user on every request, so an app cannot spoof another user's identity or clearance.
//
// Port policy (adoption over ceremony): one conventional default port everywhere; on collision fall
// back to the next free port and PUBLISH the resolved endpoint to a well-known file so tooling can
// `export OPENAI_BASE_URL=$(cat ...)`. An EXPLICIT --listen never falls back — the operator asked
// for that address, so failing loudly is correct.

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const connectDefaultListen = "127.0.0.1:11435"

func cmdConnect(args []string) {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	listen := fs.String("listen", connectDefaultListen, "loopback address to serve /v1 on (the fixed convention; explicit values never port-fall-back)")
	gateway := fs.String("gateway", "", "DANI gateway base URL, e.g. https://dani.corp.internal or http://10.0.0.1:8081 (required)")
	asUser := fs.String("user", "", "identity stamped on every request as X-Dani-User (default: the logged-in OS user)")
	endpointFile := fs.String("endpoint-file", defaultEndpointFile(), "write the resolved base URL here so tooling can discover it (empty = skip)")
	logJSON := fs.Bool("log-json", false, "emit structured JSON logs instead of plain lines")
	_ = fs.Parse(args)
	setupLogging(*logJSON)

	if *gateway == "" {
		fmt.Fprintln(os.Stderr, "connect: --gateway is required (the DANI gateway base URL)")
		os.Exit(2)
	}
	target, err := url.Parse(strings.TrimSuffix(*gateway, "/"))
	if err != nil || target.Scheme == "" || target.Host == "" {
		fmt.Fprintf(os.Stderr, "connect: --gateway %q is not a valid base URL\n", *gateway)
		os.Exit(2)
	}
	who := *asUser
	if who == "" {
		who = osUsername()
	}

	lis, addr, err := listenWithFallback(*listen, *listen == connectDefaultListen)
	check(err)
	base := "http://" + addr + "/v1"
	if *endpointFile != "" {
		if err := writeEndpointFile(*endpointFile, base); err != nil {
			logf("connect: endpoint file not written (%v) — export OPENAI_BASE_URL=%s manually", err, base)
		} else {
			logf("connect: endpoint published to %s", *endpointFile)
		}
	}
	logf("connect: relaying %s → %s as %q — point any OpenAI SDK at OPENAI_BASE_URL=%s", addr, target, who, base)

	srv := &http.Server{Handler: connectHandler(target, who)}
	// SIGTERM/SIGINT: close the listener and remove the endpoint file so tooling never reads a stale address.
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		<-ch
		if *endpointFile != "" {
			_ = os.Remove(*endpointFile)
		}
		_ = srv.Close()
	}()
	if err := srv.Serve(lis); err != nil && err != http.ErrServerClosed {
		check(err)
	}
}

// connectHandler proxies /v1/* to the gateway with the relay's identity stamped, streaming-safe.
// Anything the client sent in X-Dani-User is OVERWRITTEN — the relay is the identity authority on
// this box, which is exactly what makes the header trustworthy at the gateway.
func connectHandler(target *url.URL, who string) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(target)
	inner := proxy.Director
	proxy.Director = func(r *http.Request) {
		inner(r)
		r.Header.Set("X-Dani-User", who)
		r.Host = target.Host
	}
	proxy.FlushInterval = -1 // stream SSE tokens as they arrive, no buffering
	proxy.ErrorHandler = func(rw http.ResponseWriter, r *http.Request, err error) {
		log.Printf("connect: gateway unreachable: %v", err)
		http.Error(rw, `{"error":{"message":"DANI gateway unreachable through the local relay"}}`, http.StatusBadGateway)
	}

	mux := http.NewServeMux()
	mux.Handle("/v1/", proxy)
	mux.HandleFunc("/healthz", func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(rw, r)
			return
		}
		rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(rw, "DANI local relay — OpenAI-compatible endpoint at /v1 (upstream %s, identity %s)\n", target, who)
	})
	return mux
}

// listenWithFallback binds addr; when it's the DEFAULT convention and the port is taken, it walks
// up to 20 subsequent ports (the "bank") — an explicit address fails immediately instead.
func listenWithFallback(addr string, allowFallback bool) (net.Listener, string, error) {
	lis, err := net.Listen("tcp", addr)
	if err == nil {
		return lis, lis.Addr().String(), nil
	}
	if !allowFallback {
		return nil, "", fmt.Errorf("connect: cannot listen on %s: %w", addr, err)
	}
	host, portStr, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		return nil, "", fmt.Errorf("connect: cannot listen on %s: %w", addr, err)
	}
	port, _ := strconv.Atoi(portStr)
	for i := 1; i <= 20; i++ {
		next := net.JoinHostPort(host, strconv.Itoa(port+i))
		if lis, err2 := net.Listen("tcp", next); err2 == nil {
			logf("connect: %s is taken — fell back to %s (published to the endpoint file)", addr, next)
			return lis, lis.Addr().String(), nil
		}
	}
	return nil, "", fmt.Errorf("connect: no free port in %s..%s: %w", addr, net.JoinHostPort(host, strconv.Itoa(port+20)), err)
}

// defaultEndpointFile is the well-known discovery path: ~/.config/dani/endpoint (or the OS config dir).
func defaultEndpointFile() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "dani", "endpoint")
}

func writeEndpointFile(path, base string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(base+"\n"), 0o600)
}

// osUsername is the logged-in user, stripped of a Windows DOMAIN\ prefix; "guest" when unknowable.
func osUsername() string {
	u, err := user.Current()
	if err != nil || u.Username == "" {
		return "guest"
	}
	name := u.Username
	if i := strings.LastIndexByte(name, '\\'); i >= 0 {
		name = name[i+1:]
	}
	return name
}

// timeNow seam mirror (unused today; keeps the file self-contained for future retry logic).
var _ = time.Now
