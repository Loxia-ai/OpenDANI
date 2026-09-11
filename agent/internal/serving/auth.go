package serving

// Operator authentication for the console's WRITE surface (--console-auth). The controller mints a
// bearer token per directory principal at startup (written to the state dir; handed to operators
// out-of-band, exactly like bootstrap tokens are handed to nodes). Requests present it as
// `Authorization: Bearer <token>` (or `X-Dani-Operator`).
//
// What it enforces:
//   - every operator ACTION (ingest, train, sign, deploy, node control) needs a valid token;
//   - model signing additionally requires the ROLE: a principal signs only as a reviewer role it
//     holds in the identity directory — three-party control becomes real, not three buttons;
//   - the audit trail records WHO (the principal sub) performed each action.
//
// Reads stay open, as do the worker machine-to-machine endpoints (/dani/deployments poll+report,
// /dani/models/artifact): the data plane's authentication story is mTLS node identity, not operator
// tokens — the gateway carries those endpoints over plain HTTP in the DEMO (documented, D-30).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// OperatorPrincipal is an authenticated console operator (mirrors the identity directory entry).
type OperatorPrincipal struct {
	Sub       string   `json:"sub"`
	Roles     []string `json:"roles"`
	Clearance string   `json:"clearance"`
}

// HasRole reports whether the operator holds a role (e.g. "security-officer").
func (p OperatorPrincipal) HasRole(role string) bool {
	for _, r := range p.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// OperatorAuth maps bearer tokens to principals.
type OperatorAuth struct {
	mu     sync.Mutex
	tokens map[string]OperatorPrincipal
}

// NewOperatorAuth builds an empty token table.
func NewOperatorAuth() *OperatorAuth { return &OperatorAuth{tokens: map[string]OperatorPrincipal{}} }

// Mint creates (and remembers) a fresh bearer token for a principal.
func (a *OperatorAuth) Mint(p OperatorPrincipal) (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	a.mu.Lock()
	a.tokens[token] = p
	a.mu.Unlock()
	return token, nil
}

// FromRequest resolves the request's bearer token to its principal.
func (a *OperatorAuth) FromRequest(r *http.Request) (OperatorPrincipal, bool) {
	token := r.Header.Get("X-Dani-Operator")
	if token == "" {
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			token = strings.TrimPrefix(h, "Bearer ")
		}
	}
	if token == "" {
		return OperatorPrincipal{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.tokens[token]
	return p, ok
}

// operatorKey is the context key carrying the authenticated principal into handlers.
type operatorKey struct{}

// OperatorFrom extracts the authenticated operator (ok=false when auth is off / not required).
func OperatorFrom(ctx context.Context) (OperatorPrincipal, bool) {
	p, ok := ctx.Value(operatorKey{}).(OperatorPrincipal)
	return p, ok
}

// operatorSub names the acting operator for audit payloads ("anonymous" when auth is off).
func operatorSub(r *http.Request) string {
	if p, ok := OperatorFrom(r.Context()); ok {
		return p.Sub
	}
	return "anonymous"
}

// EnableOperatorAuth turns on write-gating for the console surface (call before ServeGateway).
func (p *Plane) EnableOperatorAuth(a *OperatorAuth) { p.opAuth = a }

// authEnabled reports whether ANY operator authentication is on (OIDC SSO or minted tokens).
func (p *Plane) authEnabled() bool { return p.opAuth != nil || p.oidc != nil }

// caller resolves the request's principal from EITHER an OIDC session cookie (SSO — the human path)
// OR a minted operator bearer token (service / break-glass). SSO wins when both are present.
func (p *Plane) caller(r *http.Request) (OperatorPrincipal, bool) {
	if p.oidc != nil {
		if pr, ok := p.oidc.FromSession(r); ok {
			return pr, true
		}
	}
	if p.opAuth != nil {
		if pr, ok := p.opAuth.FromRequest(r); ok {
			return pr, true
		}
	}
	return OperatorPrincipal{}, false
}

// protect wraps an operator-action handler: with auth enabled, non-GET requests must carry a valid
// session or token; the resolved principal rides the context so handlers can enforce roles + audit
// attribution. With auth off (DEMO default) it is a passthrough.
func (p *Plane) protect(h http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if !p.authEnabled() || r.Method == http.MethodGet {
			h(rw, r)
			return
		}
		pr, ok := p.caller(r)
		if !ok {
			writeErr(rw, http.StatusUnauthorized, fmt.Errorf("sign in required — use SSO (Sign in) or an operator token"))
			return
		}
		h(rw, r.WithContext(context.WithValue(r.Context(), operatorKey{}, pr)))
	}
}

// handleWhoami reports the caller's operator identity — the console's session header. With auth off
// it says so (the console then hides the sign-in box and marks actions as anonymous).
func (p *Plane) handleWhoami(rw http.ResponseWriter, r *http.Request) {
	if !p.authEnabled() {
		writeJSON(rw, http.StatusOK, map[string]any{"authEnabled": false, "sub": "anonymous"})
		return
	}
	pr, ok := p.caller(r)
	if !ok {
		// tell the console whether SSO is available so it can render the right sign-in affordance
		writeJSON(rw, http.StatusUnauthorized, map[string]any{"authEnabled": true, "sso": p.oidc != nil, "error": "not signed in"})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"authEnabled": true, "sso": p.oidc != nil, "sub": pr.Sub, "roles": pr.Roles, "clearance": pr.Clearance})
}
