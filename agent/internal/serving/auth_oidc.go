package serving

// Real single-sign-on for the console (PRODUCTION-READINESS P0-2): the browser is redirected to the
// customer's identity provider (Entra ID / Okta / Keycloak / any OIDC provider), the user logs in
// with their real corporate account, and the gateway verifies the IdP's signed ID token and maps the
// caller's IdP GROUPS to DANI roles + clearance. This replaces the demo minted-token flow for humans
// (minted tokens remain as service / break-glass credentials).
//
// Backend-for-frontend (BFF): the OAuth2 authorization-code + PKCE exchange happens server-side and
// the tokens NEVER reach browser JavaScript — the browser only ever holds an opaque, httpOnly,
// Secure session cookie. Discovery, JWKS rotation, and ID-token verification (signature, iss, aud,
// exp, nonce) are handled by the standard coreos/go-oidc + golang.org/x/oauth2 libraries; we do not
// hand-roll auth crypto.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCConfig configures the SSO integration. In production these come from the secret store / config
// (see P0-3); ClientSecret is never logged.
type OIDCConfig struct {
	Issuer       string // e.g. https://login.microsoftonline.com/<tenant>/v2.0
	ClientID     string
	ClientSecret string
	RedirectURL  string // https://<gateway>/auth/callback
	Scopes       []string
	GroupsClaim  string             // claim holding the user's groups/roles (default "groups")
	RoleMap      map[string]IdPRole // IdP group value -> DANI roles + clearance
	DefaultRole  IdPRole            // fallback for an authenticated user in no mapped group
}

// IdPRole is what an IdP group grants inside DANI.
type IdPRole struct {
	Roles     []string `json:"roles"`
	Clearance string   `json:"clearance"`
}

// LoadRoleMap reads the IdP-group -> DANI-role mapping from a JSON file:
//
//	{"defaultClearance":"internal",
//	 "groups":{"dani-security-officers":{"roles":["security-officer"],"clearance":"secret"}, ...}}
func LoadRoleMap(path string) (map[string]IdPRole, IdPRole, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, IdPRole{}, err
	}
	var doc struct {
		DefaultClearance string             `json:"defaultClearance"`
		Groups           map[string]IdPRole `json:"groups"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, IdPRole{}, fmt.Errorf("oidc role map %s: %w", path, err)
	}
	def := IdPRole{Roles: []string{"user"}, Clearance: doc.DefaultClearance}
	if def.Clearance == "" {
		def.Clearance = "internal"
	}
	return doc.Groups, def, nil
}

// OIDCAuth is the live SSO integration (provider + verifier + session store).
type OIDCAuth struct {
	cfg      OIDCConfig
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config

	mu       sync.Mutex
	sessions map[string]sessionEntry // opaque session id -> principal
	flows    map[string]flowState    // state -> pkce/nonce (short-lived, pre-login)
}

type sessionEntry struct {
	p       OperatorPrincipal
	expires time.Time
}
type flowState struct {
	verifier string
	nonce    string
	created  time.Time
}

// NewOIDC builds the SSO integration: OIDC discovery against the issuer, an ID-token verifier bound
// to the client id, and the oauth2 code-flow config. Returns an error if discovery fails (bad issuer
// / unreachable IdP) so misconfiguration fails at boot, not at first login.
func NewOIDC(ctx context.Context, cfg OIDCConfig) (*OIDCAuth, error) {
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discover %s: %w", cfg.Issuer, err)
	}
	return &OIDCAuth{
		cfg:      cfg,
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth: &oauth2.Config{
			ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
			Endpoint: provider.Endpoint(), RedirectURL: cfg.RedirectURL, Scopes: cfg.Scopes,
		},
		sessions: map[string]sessionEntry{},
		flows:    map[string]flowState{},
	}, nil
}

// EnableOIDC attaches the SSO integration to the gateway (call before ServeGateway).
func (p *Plane) EnableOIDC(a *OIDCAuth) { p.oidc = a }

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// registerAuthRoutes mounts the OIDC login/callback/logout endpoints (no-op until EnableOIDC).
func (p *Plane) registerAuthRoutes(mux *http.ServeMux) {
	if p.oidc == nil {
		return
	}
	mux.HandleFunc("/auth/login", p.oidc.handleLogin)
	mux.HandleFunc("/auth/callback", p.oidc.handleCallback)
	mux.HandleFunc("/auth/logout", p.oidc.handleLogout)
}

// handleLogin starts the code+PKCE flow: mint state + PKCE verifier + nonce, stash them, and redirect
// the browser to the IdP's authorization endpoint.
func (a *OIDCAuth) handleLogin(rw http.ResponseWriter, r *http.Request) {
	state := randToken()
	verifier := oauth2.GenerateVerifier()
	nonce := randToken()
	a.mu.Lock()
	a.gcLocked()
	a.flows[state] = flowState{verifier: verifier, nonce: nonce, created: time.Now()}
	a.mu.Unlock()
	opts := []oauth2.AuthCodeOption{oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)}
	// forward an optional login_hint (pre-fills the username at the IdP) — a standard OIDC param.
	if hint := r.URL.Query().Get("login_hint"); hint != "" {
		opts = append(opts, oauth2.SetAuthURLParam("login_hint", hint))
	}
	http.Redirect(rw, r, a.oauth.AuthCodeURL(state, opts...), http.StatusFound)
}

// handleCallback finishes the flow: validate state, exchange the code (with the PKCE verifier),
// verify the ID token, map the caller's groups to a DANI principal, create a session, set the
// httpOnly Secure cookie, and bounce to the console.
func (a *OIDCAuth) handleCallback(rw http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	a.mu.Lock()
	flow, ok := a.flows[state]
	delete(a.flows, state)
	a.mu.Unlock()
	if !ok {
		http.Error(rw, "invalid or expired login state", http.StatusBadRequest)
		return
	}
	oauth2Token, err := a.oauth.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(flow.verifier))
	if err != nil {
		http.Error(rw, "token exchange failed", http.StatusBadGateway)
		return
	}
	rawID, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(rw, "no id_token in the IdP response", http.StatusBadGateway)
		return
	}
	idToken, err := a.verifier.Verify(r.Context(), rawID)
	if err != nil {
		http.Error(rw, "id_token verification failed", http.StatusUnauthorized)
		return
	}
	if idToken.Nonce != flow.nonce {
		http.Error(rw, "nonce mismatch", http.StatusUnauthorized)
		return
	}
	principal, err := a.principalFrom(idToken)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusForbidden)
		return
	}
	sid := randToken()
	a.mu.Lock()
	a.sessions[sid] = sessionEntry{p: principal, expires: time.Now().Add(8 * time.Hour)}
	a.mu.Unlock()
	http.SetCookie(rw, &http.Cookie{
		Name: "dani_session", Value: sid, Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteLaxMode, Expires: time.Now().Add(8 * time.Hour),
	})
	http.Redirect(rw, r, "/console/", http.StatusFound)
}

// handleLogout clears the session server-side and expires the cookie.
func (a *OIDCAuth) handleLogout(rw http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("dani_session"); err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(rw, &http.Cookie{Name: "dani_session", Value: "", Path: "/", HttpOnly: true, Secure: true, MaxAge: -1})
	rw.WriteHeader(http.StatusNoContent)
}

// principalFrom maps a verified ID token to a DANI operator principal: sub from the token, roles +
// clearance from the caller's IdP groups via the configured map (union of all matched groups; the
// highest clearance wins).
func (a *OIDCAuth) principalFrom(idToken *oidc.IDToken) (OperatorPrincipal, error) {
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return OperatorPrincipal{}, fmt.Errorf("read claims: %w", err)
	}
	sub, _ := claims["preferred_username"].(string)
	if sub == "" {
		sub = idToken.Subject
	}
	groups := stringSlice(claims[a.cfg.GroupsClaim])
	roleSet := map[string]bool{"user": true}
	clearance := ""
	matched := false
	for _, g := range groups {
		if mapped, ok := a.cfg.RoleMap[g]; ok {
			matched = true
			for _, r := range mapped.Roles {
				roleSet[r] = true
			}
			if rankClearance(mapped.Clearance) > rankClearance(clearance) {
				clearance = mapped.Clearance
			}
		}
	}
	if !matched {
		for _, r := range a.cfg.DefaultRole.Roles {
			roleSet[r] = true
		}
		clearance = a.cfg.DefaultRole.Clearance
	}
	if clearance == "" {
		clearance = "internal"
	}
	roles := make([]string, 0, len(roleSet))
	for r := range roleSet {
		roles = append(roles, r)
	}
	return OperatorPrincipal{Sub: sub, Roles: roles, Clearance: clearance}, nil
}

// FromSession resolves a request's session cookie to its principal (ok=false if none / expired).
func (a *OIDCAuth) FromSession(r *http.Request) (OperatorPrincipal, bool) {
	c, err := r.Cookie("dani_session")
	if err != nil {
		return OperatorPrincipal{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	e, ok := a.sessions[c.Value]
	if !ok || time.Now().After(e.expires) {
		delete(a.sessions, c.Value)
		return OperatorPrincipal{}, false
	}
	return e.p, true
}

// gcLocked drops stale pre-login flows (mu held).
func (a *OIDCAuth) gcLocked() {
	for s, f := range a.flows {
		if time.Since(f.created) > 10*time.Minute {
			delete(a.flows, s)
		}
	}
}

func stringSlice(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if x == "" {
			return nil
		}
		return strings.Split(x, ",")
	}
	return nil
}

var clearanceRank = map[string]int{"unrestricted": 0, "internal": 1, "restricted": 2, "secret": 3}

func rankClearance(c string) int { return clearanceRank[c] }
