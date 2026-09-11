package controller

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

	"dani.local/agent/internal/kms"
)

// inlineHSM is a minimal in-process signing service (the RemoteKeyStore contract) so we can prove a
// controller genesis where the CA/enrollment/audit keys live in an HSM — the issuing key never enters
// DANI. Mirrors internal/kms's mockHSM (that one is unexported to this package).
func inlineHSM(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	rand.Read(raw)
	block, _ := aes.NewCipher(raw)
	aead, _ := cipher.NewGCM(block)
	var mu sync.Mutex
	keys := map[string]ed25519.PrivateKey{}
	priv := func(p string) ed25519.PrivateKey {
		mu.Lock()
		defer mu.Unlock()
		if keys[p] == nil {
			_, k, _ := ed25519.GenerateKey(rand.Reader)
			keys[p] = k
		}
		return keys[p]
	}
	dec := func(r *http.Request) map[string]string {
		var m map[string]string
		json.NewDecoder(r.Body).Decode(&m)
		return m
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/publickey", func(w http.ResponseWriter, r *http.Request) {
		der, _ := x509.MarshalPKIXPublicKey(priv(dec(r)["purpose"]).Public())
		json.NewEncoder(w).Encode(map[string]string{"pub": base64.StdEncoding.EncodeToString(der)})
	})
	mux.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		m := dec(r)
		payload, _ := base64.StdEncoding.DecodeString(m["payload"])
		json.NewEncoder(w).Encode(map[string]string{"sig": base64.StdEncoding.EncodeToString(ed25519.Sign(priv(m["purpose"]), payload))})
	})
	mux.HandleFunc("/wrap", func(w http.ResponseWriter, r *http.Request) {
		m := dec(r)
		pt, _ := base64.StdEncoding.DecodeString(m["plaintext"])
		nonce := make([]byte, aead.NonceSize())
		rand.Read(nonce)
		ct := aead.Seal(nonce, nonce, pt, []byte(m["purpose"]))
		json.NewEncoder(w).Encode(map[string]string{"ciphertext": base64.StdEncoding.EncodeToString(ct)})
	})
	mux.HandleFunc("/unwrap", func(w http.ResponseWriter, r *http.Request) {
		m := dec(r)
		ct, _ := base64.StdEncoding.DecodeString(m["ciphertext"])
		ns := aead.NonceSize()
		pt, err := aead.Open(nil, ct[:ns], ct[ns:], []byte(m["purpose"]))
		if err != nil {
			w.WriteHeader(400)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"plaintext": base64.StdEncoding.EncodeToString(pt)})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// TestGenesisWithKMS_Remote is the end-to-end proof for D-28: a controller boots its whole trust
// domain (CA + enrollment) on an HSM-backed KeyStore, issues its own identity cert, and — because the
// HSM has no exportable private material — the CA-bundle HA path is correctly refused.
func TestGenesisWithKMS_Remote(t *testing.T) {
	ctx := context.Background()
	prov, err := kms.Open("remote:" + inlineHSM(t))
	if err != nil {
		t.Fatal(err)
	}
	ctrl, err := GenesisWithKMS(ctx, prov.KS(), "AcmeBank", "dep-hsm", ":memory:")
	if err != nil {
		t.Fatalf("HSM-backed genesis: %v", err)
	}
	// The controller has a real identity cert issued by the HSM-backed CA.
	if ctrl.Cert == nil || len(ctrl.Cert.Raw) == 0 {
		t.Fatal("controller must hold an identity cert")
	}
	if err := ctrl.CA.Verify(ctrl.Cert); err != nil {
		t.Fatalf("identity cert must verify against the HSM-backed CA: %v", err)
	}
	// A remote HSM keystore has nothing to export — bundle/state HA is unavailable by design.
	if _, err := ctrl.ExportBundle(); err == nil {
		t.Fatal("ExportBundle must be refused for a non-exportable (HSM) keystore")
	}
}

// TestGenesisWithKMS_KMSDown proves genesis fails cleanly when the injected KMS is unreachable (the
// CA ceremony can't read the intermediate public key from a dead HSM).
func TestGenesisWithKMS_KMSDown(t *testing.T) {
	prov, err := kms.Open("remote:http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GenesisWithKMS(context.Background(), prov.KS(), "AcmeBank", "dep-x", ":memory:"); err == nil {
		t.Fatal("genesis against an unreachable KMS must error")
	}
}

// TestGenesisWithKMS_SoftwareExportable proves the software-backed injection path still supports the
// CA-bundle HA export (parity with the classic Genesis()).
func TestGenesisWithKMS_SoftwareExportable(t *testing.T) {
	ctx := context.Background()
	ks, err := kms.NewSoftware()
	if err != nil {
		t.Fatal(err)
	}
	ctrl, err := GenesisWithKMS(ctx, ks, "AcmeBank", "dep-sw", ":memory:")
	if err != nil {
		t.Fatalf("software genesis: %v", err)
	}
	b, err := ctrl.ExportBundle()
	if err != nil || b == nil || len(b.KMSExport) == 0 {
		t.Fatalf("software keystore must export a CA bundle: %v", err)
	}
	// The exported bundle rehydrates into a joining controller sharing the same deployment/CA.
	joiner, err := NewFromBundle(ctx, b, "ctrl-002", "site-hq", ":memory:")
	if err != nil {
		t.Fatalf("join from injected-KMS bundle: %v", err)
	}
	if joiner.DeploymentID != ctrl.DeploymentID {
		t.Fatal("joiner must share the deployment id")
	}
}
