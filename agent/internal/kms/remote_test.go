package kms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"dani.local/agent/internal/ca"
	"dani.local/agent/pkg/dani"
)

// mockHSM is an in-process signing service implementing the RemoteKeyStore contract: it holds the
// private keys (they never leave it) and a wrap key, so DANI signs/wraps by calling it.
type mockHSM struct {
	mu   sync.Mutex
	keys map[string]ed25519.PrivateKey
	gen  map[string]uint64
	aead cipher.AEAD
	srv  *httptest.Server
}

func newHSM(t *testing.T) *mockHSM {
	t.Helper()
	raw := make([]byte, 32)
	rand.Read(raw)
	block, _ := aes.NewCipher(raw)
	aead, _ := cipher.NewGCM(block)
	h := &mockHSM{keys: map[string]ed25519.PrivateKey{}, gen: map[string]uint64{}, aead: aead}
	mux := http.NewServeMux()
	dec := func(r *http.Request) map[string]string {
		var m map[string]string
		json.NewDecoder(r.Body).Decode(&m)
		return m
	}
	priv := func(p string) ed25519.PrivateKey {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.keys[p] == nil {
			_, k, _ := ed25519.GenerateKey(rand.Reader)
			h.keys[p] = k
			h.gen[p] = 1
		}
		return h.keys[p]
	}
	mux.HandleFunc("/publickey", func(w http.ResponseWriter, r *http.Request) {
		der, _ := x509.MarshalPKIXPublicKey(priv(dec(r)["purpose"]).Public())
		json.NewEncoder(w).Encode(map[string]string{"pub": base64.StdEncoding.EncodeToString(der)})
	})
	mux.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		m := dec(r)
		payload, _ := base64.StdEncoding.DecodeString(m["payload"])
		sig := ed25519.Sign(priv(m["purpose"]), payload)
		json.NewEncoder(w).Encode(map[string]string{"sig": base64.StdEncoding.EncodeToString(sig)})
	})
	mux.HandleFunc("/wrap", func(w http.ResponseWriter, r *http.Request) {
		m := dec(r)
		pt, _ := base64.StdEncoding.DecodeString(m["plaintext"])
		nonce := make([]byte, h.aead.NonceSize())
		rand.Read(nonce)
		ct := h.aead.Seal(nonce, nonce, pt, []byte(m["purpose"]))
		json.NewEncoder(w).Encode(map[string]string{"ciphertext": base64.StdEncoding.EncodeToString(ct)})
	})
	mux.HandleFunc("/unwrap", func(w http.ResponseWriter, r *http.Request) {
		m := dec(r)
		ct, _ := base64.StdEncoding.DecodeString(m["ciphertext"])
		ns := h.aead.NonceSize()
		pt, err := h.aead.Open(nil, ct[:ns], ct[ns:], []byte(m["purpose"]))
		if err != nil {
			w.WriteHeader(400)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"plaintext": base64.StdEncoding.EncodeToString(pt)})
	})
	mux.HandleFunc("/rotate", func(w http.ResponseWriter, r *http.Request) {
		p := dec(r)["purpose"]
		h.mu.Lock()
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		h.keys[p] = k
		h.gen[p]++
		g := h.gen[p]
		h.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]uint64{"generation": g})
	})
	mux.HandleFunc("/attest", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"tier": 3, "evidence": base64.StdEncoding.EncodeToString([]byte("quote")), "keyRef": "hsm:" + dec(r)["purpose"]})
	})
	h.srv = httptest.NewServer(mux)
	t.Cleanup(h.srv.Close)
	return h
}

func TestRemoteKeyStoreOps(t *testing.T) {
	h := newHSM(t)
	ks := &RemoteKeyStore{Client: h.srv.Client(), BaseURL: h.srv.URL}
	ctx := context.Background()

	// sign -> verify with the public key the HSM reports (key never left the HSM)
	pubDER, err := ks.GetPublicKey(ctx, dani.PurposeCASigning)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := x509.ParsePKIXPublicKey(pubDER)
	msg := []byte("issue this cert")
	sig, err := ks.Sign(ctx, dani.PurposeCASigning, msg)
	if err != nil || !ed25519.Verify(pub.(ed25519.PublicKey), msg, sig) {
		t.Fatalf("remote sign/verify failed: %v", err)
	}
	// wrap/unwrap round-trips (the dormant-root sealing genesis relies on)
	secret := []byte("dormant-root-private-key")
	ct, err := ks.Wrap(ctx, dani.PurposeCASigning, secret)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := ks.Unwrap(ctx, dani.PurposeCASigning, ct)
	if err != nil || string(pt) != string(secret) {
		t.Fatalf("wrap/unwrap round-trip failed: %v %q", err, pt)
	}
	// rotate + attest
	if g, err := ks.RotateKey(ctx, dani.PurposeAuditChainSigning); err != nil || g < 1 {
		t.Fatalf("rotate: %v %d", err, g)
	}
	att, err := ks.Attest(ctx, dani.PurposeCASigning)
	if err != nil || att.Tier != dani.TierHRoT || att.KeyRef == "" {
		t.Fatalf("attest: %+v %v", att, err)
	}
}

// TestRemoteBackedCA is the end-to-end proof: a full CA genesis with the issuing key in the HSM, then
// issue + verify a node cert. The intermediate private key never enters DANI.
func TestRemoteBackedCA(t *testing.T) {
	h := newHSM(t)
	ks := &RemoteKeyStore{Client: h.srv.Client(), BaseURL: h.srv.URL}
	ctx := context.Background()
	authority, err := ca.Genesis(ctx, ks, "AcmeBank")
	if err != nil {
		t.Fatalf("HSM-backed genesis: %v", err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	cert, err := authority.IssueNodeCert(ctx, ca.NodeCertParams{
		NodeUUID: "w1", SiteOU: "site", PubDER: pubDER,
		Claims:   dani.DANIClaims{SchemaVersion: 1, Roles: []string{"worker"}, Classification: "restricted"},
		NotAfter: authority.Intermediate.NotAfter,
	})
	if err != nil {
		t.Fatalf("HSM issue node cert: %v", err)
	}
	if err := authority.Verify(cert); err != nil {
		t.Fatalf("cert issued by the HSM-backed CA must verify: %v", err)
	}
}

func TestRemoteKeyStoreErrors(t *testing.T) {
	ctx := context.Background()
	// unreachable
	down := &RemoteKeyStore{BaseURL: "http://127.0.0.1:1"}
	if _, err := down.Sign(ctx, dani.PurposeCASigning, []byte("x")); err == nil {
		t.Fatal("unreachable sign must error")
	}
	if _, err := down.GetPublicKey(ctx, dani.PurposeCASigning); err == nil {
		t.Fatal("unreachable publickey must error")
	}
	if _, err := down.Wrap(ctx, dani.PurposeCASigning, []byte("x")); err == nil {
		t.Fatal("unreachable wrap must error")
	}
	if _, err := down.Unwrap(ctx, dani.PurposeCASigning, []byte("x")); err == nil {
		t.Fatal("unreachable unwrap must error")
	}
	if _, err := down.RotateKey(ctx, dani.PurposeCASigning); err == nil {
		t.Fatal("unreachable rotate must error")
	}
	if _, err := down.Attest(ctx, dani.PurposeCASigning); err == nil {
		t.Fatal("unreachable attest must error")
	}
	if _, err := down.Signer(dani.PurposeCASigning); err == nil {
		t.Fatal("Signer on unreachable must error")
	}
	// non-200
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer bad.Close()
	rb := &RemoteKeyStore{Client: bad.Client(), BaseURL: bad.URL}
	if _, err := rb.Sign(ctx, dani.PurposeCASigning, []byte("x")); err == nil {
		t.Fatal("500 must error")
	}
	// bad request build (un-parseable URL)
	if _, err := (&RemoteKeyStore{BaseURL: "http://\x7f x"}).Sign(ctx, dani.PurposeCASigning, []byte("x")); err == nil {
		t.Fatal("bad URL must error")
	}
	// default client path (nil client) against a live server
	h := newHSM(t)
	if _, err := (&RemoteKeyStore{BaseURL: h.srv.URL}).GetPublicKey(ctx, dani.PurposeCASigning); err != nil {
		t.Fatalf("nil client default: %v", err)
	}
}

func TestRemoteAttestEmptyRefAndBadSignerKey(t *testing.T) {
	ctx := context.Background()
	// HSM returns an empty keyRef -> RemoteKeyStore fills the default "hsm:<purpose>"
	att := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"tier": 1, "evidence": "", "keyRef": ""})
	}))
	defer att.Close()
	st, err := (&RemoteKeyStore{Client: att.Client(), BaseURL: att.URL}).Attest(ctx, dani.PurposeCASigning)
	if err != nil || st.KeyRef != "hsm:ca-signing" {
		t.Fatalf("empty keyRef must default: %+v %v", st, err)
	}
	// /publickey returns valid base64 that is NOT valid SPKI DER -> Signer parse error
	badpub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"pub": base64.StdEncoding.EncodeToString([]byte("not-a-spki-key"))})
	}))
	defer badpub.Close()
	if _, err := (&RemoteKeyStore{Client: badpub.Client(), BaseURL: badpub.URL}).Signer(dani.PurposeCASigning); err == nil {
		t.Fatal("un-parseable public key must fail Signer")
	}
}
