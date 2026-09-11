package serving

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// mockIdP is a minimal but standards-compliant OIDC provider: discovery, authorize (auto-approves a
// preconfigured user), token (issues a signed ID token), and JWKS. It lets the FULL login flow be
// exercised — signature verification, PKCE, nonce, group mapping — without a real Entra tenant.
type mockIdP struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	signer jose.Signer
	sub    string
	groups []string
	nonce  string // captured from the authorize request
	client string
}

func newMockIdP(t *testing.T, sub string, groups []string) *mockIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", "test-key").WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	m := &mockIdP{key: key, signer: signer, sub: sub, groups: groups, client: "dani-client"}
	mux := http.NewServeMux()
	m.srv = httptest.NewServer(mux)

	mux.HandleFunc("/.well-known/openid-configuration", func(rw http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(rw).Encode(map[string]any{
			"issuer":                                m.srv.URL,
			"authorization_endpoint":                m.srv.URL + "/authorize",
			"token_endpoint":                        m.srv.URL + "/token",
			"jwks_uri":                              m.srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(rw http.ResponseWriter, _ *http.Request) {
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test-key", Algorithm: "RS256", Use: "sig"}}}
		json.NewEncoder(rw).Encode(jwks)
	})
	// authorize: a real IdP would show a login page; the mock captures the nonce and immediately
	// redirects back with an auth code (the user "logged in").
	mux.HandleFunc("/authorize", func(rw http.ResponseWriter, r *http.Request) {
		m.nonce = r.URL.Query().Get("nonce")
		redirect := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")
		http.Redirect(rw, r, redirect+"?code=good-code&state="+state, http.StatusFound)
	})
	// token: exchange the code for an ID token carrying the user's sub + groups + nonce.
	mux.HandleFunc("/token", func(rw http.ResponseWriter, r *http.Request) {
		claims := map[string]any{
			"iss": m.srv.URL, "sub": m.sub, "aud": m.client,
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
			"nonce": m.nonce, "preferred_username": m.sub, "groups": m.groups,
		}
		raw, err := jwt.Signed(m.signer).Claims(claims).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		rw.Header().Set("Content-Type", "application/json")
		json.NewEncoder(rw).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": raw})
	})
	t.Cleanup(m.srv.Close)
	return m
}

func oidcHarness(t *testing.T, idp *mockIdP, roleMap map[string]IdPRole) (*Plane, string, *http.Client) {
	t.Helper()
	p := newTestPlane("s")
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })
	p.EnableTraining(newTrainingAPI(t, "trainer-1")) // gives whoami something to gate
	// Session cookies are Secure. Exercise the real HTTPS path rather than relying
	// on a cookie jar's toolchain-dependent treatment of plain HTTP on loopback.
	certPEM, keyPEM, err := selfSignedPEM([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "gateway.crt"), filepath.Join(dir, "gateway.key")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	p.gwTLS = &GatewayTLS{Enabled: true, CertFile: certFile, KeyFile: keyFile}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("could not trust gateway test certificate")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}
	t.Cleanup(transport.CloseIdleConnections)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar, Transport: transport, Timeout: 5 * time.Second}
	oa, err := NewOIDC(context.Background(), OIDCConfig{
		Issuer: idp.srv.URL, ClientID: idp.client, ClientSecret: "secret",
		RedirectURL: "https://127.0.0.1/auth/callback", GroupsClaim: "groups",
		RoleMap: roleMap, DefaultRole: IdPRole{Roles: []string{"user"}, Clearance: "internal"},
	})
	if err != nil {
		t.Fatalf("NewOIDC discovery: %v", err)
	}
	p.EnableOIDC(oa)
	addr, err := p.ServeGateway("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// the redirect URL must point back at THIS gateway for the callback to land
	oa.oauth.RedirectURL = "https://" + addr + "/auth/callback"
	return p, "https://" + addr, client
}

// TestOIDCLoginFlowMapsGroupsToRoles: the whole SSO flow — login redirect, IdP authorize, callback,
// ID-token verification, and IdP-group → DANI-role/clearance mapping — via a cookie session.
func TestOIDCLoginFlowMapsGroupsToRoles(t *testing.T) {
	idp := newMockIdP(t, "dana@corp", []string{"dani-security-officers"})
	roleMap := map[string]IdPRole{"dani-security-officers": {Roles: []string{"security-officer"}, Clearance: "secret"}}
	_, base, client := oidcHarness(t, idp, roleMap)

	// hit /auth/login; the client follows the whole chain (IdP authorize -> callback -> /console/)
	resp, err := client.Get(base + "/auth/login")
	if err != nil {
		t.Fatalf("login flow: %v", err)
	}
	resp.Body.Close()

	// a session cookie is now set; whoami reflects the mapped principal
	var who struct {
		AuthEnabled bool     `json:"authEnabled"`
		SSO         bool     `json:"sso"`
		Sub         string   `json:"sub"`
		Roles       []string `json:"roles"`
		Clearance   string   `json:"clearance"`
	}
	wr, err := client.Get(base + "/dani/whoami")
	if err != nil {
		t.Fatal(err)
	}
	json.NewDecoder(wr.Body).Decode(&who)
	wr.Body.Close()
	if !who.AuthEnabled || !who.SSO || who.Sub != "dana@corp" || who.Clearance != "secret" {
		t.Fatalf("SSO whoami wrong: %+v", who)
	}
	hasRole := func(r string) bool {
		for _, x := range who.Roles {
			if x == r {
				return true
			}
		}
		return false
	}
	if !hasRole("security-officer") {
		t.Fatalf("security-officer role not mapped from IdP group: %+v", who.Roles)
	}

	// the session authorizes a protected write (sign) as the mapped role
	body := strings.NewReader(`{"model":"m","role":"security-officer"}`)
	req, _ := http.NewRequest(http.MethodPost, base+"/dani/models/sign", body)
	req.Header.Set("Content-Type", "application/json")
	sr, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	sr.Body.Close()
	// 400 (unknown model) is fine — what matters is it was NOT 401 (the session authenticated us)
	if sr.StatusCode == http.StatusUnauthorized {
		t.Fatal("SSO session should authenticate a protected action")
	}

	// logout drops the session; whoami now 401s
	req2, _ := http.NewRequest(http.MethodPost, base+"/auth/logout", nil)
	lr, _ := client.Do(req2)
	lr.Body.Close()
	wr2, _ := client.Get(base + "/dani/whoami")
	if wr2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after logout whoami must 401, got %d", wr2.StatusCode)
	}
	wr2.Body.Close()
}

// TestOIDCRoleGatingDeniesWrongRole: a user whose IdP groups don't grant a reviewer role cannot sign
// as it — three-party control enforced through the IdP mapping.
func TestOIDCRoleGatingDeniesWrongRole(t *testing.T) {
	idp := newMockIdP(t, "alice@corp", []string{"dani-engineers"})
	roleMap := map[string]IdPRole{"dani-engineers": {Roles: []string{"user"}, Clearance: "restricted"}}
	_, base, client := oidcHarness(t, idp, roleMap)
	r, _ := client.Get(base + "/auth/login")
	r.Body.Close()

	// alice holds no reviewer role: signing as security-officer is refused at the handler
	req, _ := http.NewRequest(http.MethodPost, base+"/dani/models/sign", strings.NewReader(`{"model":"m","role":"security-officer"}`))
	req.Header.Set("Content-Type", "application/json")
	sr, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer sr.Body.Close()
	if sr.StatusCode != http.StatusForbidden {
		t.Fatalf("engineer must not sign as security-officer, got %d", sr.StatusCode)
	}
}

// TestOIDCBadStateRejected: a callback with an unknown state is refused (CSRF / replay guard).
func TestOIDCBadStateRejected(t *testing.T) {
	idp := newMockIdP(t, "x@corp", nil)
	_, base, client := oidcHarness(t, idp, nil)
	r, err := client.Get(base + "/auth/callback?code=x&state=forged")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("forged state must 400, got %d", r.StatusCode)
	}
}

// TestLoadRoleMap parses the IdP-group -> role JSON.
func TestLoadRoleMap(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/rolemap.json"
	if err := os.WriteFile(path, []byte(`{"defaultClearance":"internal","groups":{"g1":{"roles":["security-officer"],"clearance":"secret"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	groups, def, err := LoadRoleMap(path)
	if err != nil || groups["g1"].Clearance != "secret" || def.Clearance != "internal" {
		t.Fatalf("role map: %v %+v %+v", err, groups, def)
	}
	if _, _, err := LoadRoleMap(dir + "/nope.json"); err == nil {
		t.Fatal("missing role map file must error")
	}
}
