// Command mockidp is a minimal, standards-compliant OIDC provider for DEMO / test / Azure validation
// of DANI's SSO integration WITHOUT a real Entra/Okta tenant. It implements discovery, JWKS, an
// auto-approving authorize endpoint (the "login page"), and a token endpoint that issues an RS256
// ID token carrying the chosen user's sub + groups. Which user logs in is picked by the OIDC
// `login_hint` (email); unknown hints fall back to the first configured user.
//
// NOT for production — it approves any authorize request. It stands in for the customer's IdP so the
// full code+PKCE + JWKS-verified login can be exercised end to end.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type user struct {
	Sub    string   `json:"sub"`
	Groups []string `json:"groups"`
}

func main() {
	listen := flag.String("listen", ":9000", "listen address")
	issuer := flag.String("issuer", "http://127.0.0.1:9000", "public issuer URL (must match how clients reach this)")
	clientID := flag.String("client-id", "dani-client", "expected client id (audience)")
	usersJSON := flag.String("users", `[{"sub":"dana@corp","groups":["dani-security-officers"]},{"sub":"erin@corp","groups":["dani-governance-officers"]},{"sub":"bob@corp","groups":["dani-administrators"]},{"sub":"alice@corp","groups":["dani-engineers"]}]`, "JSON array of users")
	flag.Parse()

	var users []user
	if err := json.Unmarshal([]byte(*usersJSON), &users); err != nil || len(users) == 0 {
		log.Fatalf("mockidp: bad --users: %v", err)
	}
	byEmail := map[string]user{}
	for _, u := range users {
		byEmail[u.Sub] = u
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", "mockidp").WithType("JWT"))
	if err != nil {
		log.Fatal(err)
	}

	var mu sync.Mutex
	codes := map[string]map[string]any{} // auth code -> claims to mint

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(rw http.ResponseWriter, _ *http.Request) {
		writeJSON(rw, map[string]any{
			"issuer":                                *issuer,
			"authorization_endpoint":                *issuer + "/authorize",
			"token_endpoint":                        *issuer + "/token",
			"jwks_uri":                              *issuer + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(rw http.ResponseWriter, _ *http.Request) {
		writeJSON(rw, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "mockidp", Algorithm: "RS256", Use: "sig"}}})
	})
	// authorize: pick the user from login_hint (default: first), mint a code carrying their claims,
	// redirect back to the client. A real IdP shows a login page here; this auto-approves.
	mux.HandleFunc("/authorize", func(rw http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		u := users[0]
		if hint := q.Get("login_hint"); hint != "" {
			if hu, ok := byEmail[hint]; ok {
				u = hu
			}
		}
		code := randStr()
		mu.Lock()
		codes[code] = map[string]any{
			"iss": *issuer, "sub": u.Sub, "aud": *clientID,
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
			"nonce": q.Get("nonce"), "preferred_username": u.Sub, "groups": u.Groups,
		}
		mu.Unlock()
		http.Redirect(rw, r, q.Get("redirect_uri")+"?code="+code+"&state="+q.Get("state"), http.StatusFound)
	})
	// token: swap the code for a signed ID token.
	mux.HandleFunc("/token", func(rw http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		code := r.FormValue("code")
		mu.Lock()
		claims, ok := codes[code]
		delete(codes, code)
		mu.Unlock()
		if !ok {
			http.Error(rw, "bad code", http.StatusBadRequest)
			return
		}
		raw, err := jwt.Signed(signer).Claims(claims).Serialize()
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(rw, map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": raw})
	})

	log.Printf("mockidp: OIDC provider on %s (issuer %s), %d users", *listen, *issuer, len(users))
	log.Fatal(http.ListenAndServe(*listen, mux))
}

func writeJSON(rw http.ResponseWriter, v any) {
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(v)
}

func randStr() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
