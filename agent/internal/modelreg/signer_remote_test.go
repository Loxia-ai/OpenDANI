package modelreg

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// hsmStub is an in-process stand-in for an officer's external signing service (HSM/cloud-KMS): it
// holds the private key and exposes the /public + /sign contract RemoteRoleSigner speaks. The key
// NEVER leaves this server — proving DANI signs without ever holding it.
func hsmStub(t *testing.T) (*httptest.Server, ed25519.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mux := http.NewServeMux()
	mux.HandleFunc("/public", func(w http.ResponseWriter, _ *http.Request) {
		der, _ := x509.MarshalPKIXPublicKey(pub)
		json.NewEncoder(w).Encode(map[string]string{"pub": base64.StdEncoding.EncodeToString(der)})
	})
	mux.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Payload string }
		json.NewDecoder(r.Body).Decode(&in)
		payload, _ := base64.StdEncoding.DecodeString(in.Payload)
		sig := ed25519.Sign(priv, payload)
		json.NewEncoder(w).Encode(map[string]string{"sig": base64.StdEncoding.EncodeToString(sig)})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, pub
}

// TestRemoteRoleSignerRoundTrip: DANI signs through an external service and the result verifies with
// the returned public key — the private key never entered DANI.
func TestRemoteRoleSignerRoundTrip(t *testing.T) {
	srv, wantPub := hsmStub(t)
	rs := RemoteRoleSigner{Client: srv.Client(), BaseURL: srv.URL}
	pubDER, err := rs.Public(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	wantDER, _ := x509.MarshalPKIXPublicKey(wantPub)
	if string(pubDER) != string(wantDER) {
		t.Fatal("remote public key mismatch")
	}
	msg := []byte("promote model X")
	sig, err := rs.Sign(t.Context(), msg)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(wantPub, msg, sig) {
		t.Fatal("remote signature must verify with the officer's public key")
	}
}

// TestRemoteRoleSignerErrors: every failure mode is fail-closed (returns an error).
func TestRemoteRoleSignerErrors(t *testing.T) {
	// unreachable
	down := RemoteRoleSigner{BaseURL: "http://127.0.0.1:1"}
	if _, err := down.Public(t.Context()); err == nil {
		t.Fatal("unreachable /public must error")
	}
	if _, err := down.Sign(t.Context(), []byte("x")); err == nil {
		t.Fatal("unreachable /sign must error")
	}
	// non-200
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer bad.Close()
	rb := RemoteRoleSigner{Client: bad.Client(), BaseURL: bad.URL}
	if _, err := rb.Public(t.Context()); err == nil {
		t.Fatal("500 /public must error")
	}
	if _, err := rb.Sign(t.Context(), []byte("x")); err == nil {
		t.Fatal("500 /sign must error")
	}
	// malformed JSON body
	garble := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("{bad")) }))
	defer garble.Close()
	rg := RemoteRoleSigner{Client: garble.Client(), BaseURL: garble.URL}
	if _, err := rg.Public(t.Context()); err == nil {
		t.Fatal("bad /public body must error")
	}
	if _, err := rg.Sign(t.Context(), []byte("x")); err == nil {
		t.Fatal("bad /sign body must error")
	}
	// bad base64 in a well-formed body
	b64bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/public" {
			w.Write([]byte(`{"pub":"!!!"}`))
		} else {
			w.Write([]byte(`{"sig":"!!!"}`))
		}
	}))
	defer b64bad.Close()
	rz := RemoteRoleSigner{Client: b64bad.Client(), BaseURL: b64bad.URL}
	if _, err := rz.Public(t.Context()); err == nil {
		t.Fatal("bad pub base64 must error")
	}
	if _, err := rz.Sign(t.Context(), []byte("x")); err == nil {
		t.Fatal("bad sig base64 must error")
	}
	// un-parseable URL -> NewRequest fails (before any transport)
	badurl := RemoteRoleSigner{BaseURL: "http:// bad"}
	if _, err := badurl.Public(t.Context()); err == nil {
		t.Fatal("bad URL /public must error at request build")
	}
	if _, err := badurl.Sign(t.Context(), []byte("x")); err == nil {
		t.Fatal("bad URL /sign must error at request build")
	}
	// nil client falls back to http.DefaultClient (exercise the default path against a live server)
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"pub":""}`)) }))
	defer ok.Close()
	if _, err := (RemoteRoleSigner{BaseURL: ok.URL}).Public(t.Context()); err != nil {
		t.Fatalf("nil client should default: %v", err)
	}
}
