package main

// `dani-agent connect` tests: the relay forwards /v1 to the gateway with the OS-user identity
// STAMPED (an app-supplied X-Dani-User is overwritten — the anti-spoof property), the default port
// falls back on collision while an explicit one fails loudly, and the endpoint file publishes the
// resolved address for tooling.

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConnectProxyStampsIdentity(t *testing.T) {
	var gotUser, gotPath string
	backend := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotUser = r.Header.Get("X-Dani-User")
		gotPath = r.URL.Path
		_, _ = rw.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()
	target, _ := url.Parse(backend.URL)

	relay := httptest.NewServer(connectHandler(target, "alice"))
	defer relay.Close()

	// the app tries to SPOOF mallory — the relay must overwrite it with the box identity
	req, _ := http.NewRequest(http.MethodPost, relay.URL+"/v1/chat/completions", strings.NewReader(`{}`))
	req.Header.Set("X-Dani-User", "mallory")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if gotUser != "alice" {
		t.Fatalf("identity not stamped: gateway saw %q, want alice (spoof must be overwritten)", gotUser)
	}
	if gotPath != "/v1/chat/completions" {
		t.Fatalf("path not forwarded: %q", gotPath)
	}
	if !strings.Contains(string(body), `"ok":true`) {
		t.Fatalf("body not relayed: %s", body)
	}
}

func TestConnectOnlyV1IsProxied(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		t.Error("non-/v1 path must not reach the gateway")
		rw.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	target, _ := url.Parse(backend.URL)
	relay := httptest.NewServer(connectHandler(target, "alice"))
	defer relay.Close()

	if resp, _ := http.Get(relay.URL + "/dani/config"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("/dani/* through the relay must 404, got %d", resp.StatusCode)
	}
	if resp, _ := http.Get(relay.URL + "/healthz"); resp.StatusCode != http.StatusOK {
		t.Fatalf("relay /healthz must 200, got %d", resp.StatusCode)
	}
	if resp, _ := http.Get(relay.URL + "/"); resp.StatusCode != http.StatusOK {
		t.Fatalf("relay / info must 200, got %d", resp.StatusCode)
	}
}

func TestConnectGatewayDownIs502(t *testing.T) {
	// a dead upstream → the relay answers 502 itself (an app sees a clean error, not a hang)
	target, _ := url.Parse("http://127.0.0.1:1") // nothing listens there
	relay := httptest.NewServer(connectHandler(target, "alice"))
	defer relay.Close()
	resp, err := http.Get(relay.URL + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("dead gateway must 502, got %d", resp.StatusCode)
	}
}

func TestConnectPortFallback(t *testing.T) {
	// occupy a port, then ask for it AS THE DEFAULT → the relay walks to the next free one
	hold, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	taken := hold.Addr().String()

	lis, addr, err := listenWithFallback(taken, true)
	if err != nil {
		t.Fatalf("default-port fallback failed: %v", err)
	}
	defer lis.Close()
	if addr == taken {
		t.Fatal("fallback returned the taken address")
	}

	// an EXPLICIT address must fail loudly instead of silently moving
	if _, _, err := listenWithFallback(taken, false); err == nil {
		t.Fatal("explicit taken address must error, not fall back")
	}
}

func TestConnectEndpointFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "endpoint")
	if err := writeEndpointFile(path, "http://127.0.0.1:11436/v1"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) != "http://127.0.0.1:11436/v1" {
		t.Fatalf("endpoint file content: %q", b)
	}
}

func TestOSUsernameNeverEmpty(t *testing.T) {
	if osUsername() == "" {
		t.Fatal("osUsername must never be empty (guest fallback)")
	}
	// DOMAIN\name form is stripped to the bare user
	if got := func() string {
		name := `CORP\dana`
		if i := strings.LastIndexByte(name, '\\'); i >= 0 {
			name = name[i+1:]
		}
		return name
	}(); got != "dana" {
		t.Fatalf("domain strip: %q", got)
	}
}
