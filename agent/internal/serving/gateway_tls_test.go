package serving

import (
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSelfSignedGatewayTLS: with TLS on and no mounted cert, the gateway serves HTTPS on a
// self-signed cert and sends HSTS; plain HTTP to it fails (it's TLS now).
func TestSelfSignedGatewayTLS(t *testing.T) {
	p := newTestPlane("s")
	p.gwTLS = &GatewayTLS{Enabled: true, Hosts: []string{"127.0.0.1"}}
	addr, err := p.ServeGateway("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	var resp *http.Response
	for i := 0; i < 20; i++ {
		if resp, err = client.Get("https://" + addr + "/healthz"); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("https healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz over https: %d", resp.StatusCode)
	}
	if hsts := resp.Header.Get("Strict-Transport-Security"); !strings.Contains(hsts, "max-age=") {
		t.Fatalf("HSTS missing over TLS: %q", hsts)
	}
	// plain HTTP to a TLS listener is refused at the TLS layer: Go's server answers a 400
	// "client sent an HTTP request to an HTTPS server" — never a 200/served response.
	if r2, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + addr + "/healthz"); err == nil {
		body, _ := io.ReadAll(r2.Body)
		r2.Body.Close()
		if r2.StatusCode == http.StatusOK || !strings.Contains(string(body), "HTTPS server") {
			t.Fatalf("plain HTTP to a TLS gateway must be refused, got %d: %s", r2.StatusCode, body)
		}
	}
}

// TestGatewayCertModes: mounted PEM loads (and is used); missing files error; no-files self-signs.
func TestGatewayCertModes(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM, err := selfSignedPEM([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	cf, kf := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(cf, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kf, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, prov, err := (&GatewayTLS{Enabled: true, CertFile: cf, KeyFile: kf}).tlsConfig()
	if err != nil || len(cfg.Certificates) != 1 || !strings.Contains(prov, "mounted") {
		t.Fatalf("mounted cert: %v %q", err, prov)
	}
	if _, _, err := (&GatewayTLS{Enabled: true, CertFile: "/no/such", KeyFile: "/no/such"}).tlsConfig(); err == nil {
		t.Fatal("missing cert files must error")
	}
	if _, prov, err := (&GatewayTLS{Enabled: true}).tlsConfig(); err != nil || !strings.Contains(prov, "self-signed") {
		t.Fatalf("no-files must self-sign: %v %q", err, prov)
	}
}

// TestGatewayPlainHTTPStillWorks: TLS off keeps the plain-HTTP path (dev / behind an ingress), and
// no HSTS is advertised over plaintext.
func TestGatewayPlainHTTPStillWorks(t *testing.T) {
	p := newTestPlane("s")
	addr, err := p.ServeGateway("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	var resp *http.Response
	for i := 0; i < 20; i++ {
		if resp, err = client.Get("http://" + addr + "/healthz"); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("http healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Strict-Transport-Security") != "" {
		t.Fatal("must not advertise HSTS over plaintext")
	}
}
