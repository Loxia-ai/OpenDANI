package kms

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"encoding/json"
	"testing"

	"dani.local/agent/pkg/dani"
)

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("rng failure (injected)") }

// withFailingRNG runs fn with the package entropy source swapped for a failing reader.
func withFailingRNG(fn func()) {
	old := randReader
	randReader = failReader{}
	defer func() { randReader = old }()
	fn()
}

func TestErrorPaths_RNGFailures(t *testing.T) {
	ctx := context.Background()
	// NewSoftware: master-key read fails
	withFailingRNG(func() {
		if _, err := NewSoftware(); err == nil {
			t.Fatal("NewSoftware should fail on RNG error")
		}
	})
	// ensure() failures propagate through Sign / GetPublicKey / RotateKey / Signer
	ks, err := NewSoftware()
	if err != nil {
		t.Fatal(err)
	}
	withFailingRNG(func() {
		if _, err := ks.Sign(ctx, dani.PurposeCASigning, []byte("x")); err == nil {
			t.Fatal("Sign should fail when key generation fails")
		}
		if _, err := ks.GetPublicKey(ctx, dani.PurposeConfigSigning); err == nil {
			t.Fatal("GetPublicKey should fail when key generation fails")
		}
		if _, err := ks.RotateKey(ctx, dani.PurposeAuditChainSigning); err == nil {
			t.Fatal("RotateKey should fail when key generation fails (ensure)")
		}
		if _, err := ks.Signer(dani.PurposeRevocationSigning); err == nil {
			t.Fatal("Signer should fail when key generation fails")
		}
		// Wrap: nonce read fails (master key already exists)
		if _, err := ks.Wrap(ctx, dani.PurposeDataAtRest, []byte("x")); err == nil {
			t.Fatal("Wrap should fail when nonce RNG fails")
		}
	})
	// RotateKey: ensure() succeeds (key exists) but the new-generation key gen fails
	if _, err := ks.Sign(ctx, dani.PurposeEnrollmentSigning, []byte("seed")); err != nil { // create the DEK
		t.Fatal(err)
	}
	withFailingRNG(func() {
		if _, err := ks.RotateKey(ctx, dani.PurposeEnrollmentSigning); err == nil {
			t.Fatal("RotateKey should fail when the rotation key generation fails")
		}
	})
}

func TestSignAndPublicKey(t *testing.T) {
	ctx := context.Background()
	ks, err := NewSoftware()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("payload-to-sign")
	sig, err := ks.Sign(ctx, dani.PurposeCASigning, msg)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := ks.GetPublicKey(ctx, dani.PurposeCASigning)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		t.Fatal(err)
	}
	ed, ok := pub.(ed25519.PublicKey)
	if !ok {
		t.Fatal("public key is not ed25519")
	}
	if !ed25519.Verify(ed, msg, sig) {
		t.Fatal("signature did not verify against the purpose public key")
	}
}

func TestWrapUnwrap(t *testing.T) {
	ctx := context.Background()
	ks, _ := NewSoftware()
	pt := []byte("secret-dek-material")
	ct, err := ks.Wrap(ctx, dani.PurposeDataAtRest, pt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ks.Unwrap(ctx, dani.PurposeDataAtRest, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(pt) {
		t.Fatal("wrap/unwrap round-trip mismatch")
	}
	if _, err := ks.Unwrap(ctx, dani.PurposeConfigSigning, ct); err == nil {
		t.Fatal("expected failure unwrapping under a different purpose (AAD binding)")
	}
	bad := append([]byte(nil), ct...)
	bad[len(bad)-1] ^= 0xff
	if _, err := ks.Unwrap(ctx, dani.PurposeDataAtRest, bad); err == nil {
		t.Fatal("expected tamper detection on unwrap")
	}
	if _, err := ks.Unwrap(ctx, dani.PurposeDataAtRest, []byte("short")); err == nil {
		t.Fatal("expected short-ciphertext rejection")
	}
}

func TestRotateChangesKey(t *testing.T) {
	ctx := context.Background()
	ks, _ := NewSoftware()
	before, _ := ks.GetPublicKey(ctx, dani.PurposeConfigSigning)
	gen, err := ks.RotateKey(ctx, dani.PurposeConfigSigning)
	if err != nil {
		t.Fatal(err)
	}
	if gen != 2 {
		t.Fatalf("expected generation 2 after one rotation, got %d", gen)
	}
	after, _ := ks.GetPublicKey(ctx, dani.PurposeConfigSigning)
	if string(before) == string(after) {
		t.Fatal("rotation did not change the public key")
	}
}

func TestAttestTier0(t *testing.T) {
	ctx := context.Background()
	ks, _ := NewSoftware()
	st, err := ks.Attest(ctx, dani.PurposeCASigning)
	if err != nil {
		t.Fatal(err)
	}
	if st.Tier != dani.TierAdministrative || st.Evidence != nil {
		t.Fatalf("software tier must be Tier 0 with no evidence, got %+v", st)
	}
}

func TestSignerForX509(t *testing.T) {
	ks, _ := NewSoftware()
	signer, err := ks.Signer(dani.PurposeCASigning)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := signer.Public().(ed25519.PublicKey); !ok {
		t.Fatal("signer.Public() is not ed25519")
	}
	sig, err := signer.Sign(nil, []byte("tbs-certificate-bytes"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) == 0 {
		t.Fatal("signer produced an empty signature")
	}
}

func TestExportImportProvisionsIdenticalKeys(t *testing.T) {
	ctx := context.Background()
	src, err := NewSoftware()
	if err != nil {
		t.Fatal(err)
	}
	// materialize two purpose keys, sign something with one
	pubA, err := src.GetPublicKey(ctx, dani.PurposeCASigning)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := src.Sign(ctx, dani.PurposeEnrollmentSigning, []byte("token"))
	if err != nil {
		t.Fatal(err)
	}
	blob, err := src.Export()
	if err != nil {
		t.Fatal(err)
	}
	dst, err := ImportSoftware(blob)
	if err != nil {
		t.Fatal(err)
	}
	// identical CA public key + the peer verifies the origin's signature with ITS copy of the key
	pubB, err := dst.GetPublicKey(ctx, dani.PurposeCASigning)
	if err != nil || string(pubA) != string(pubB) {
		t.Fatalf("imported CA key differs: %v", err)
	}
	pubDER, _ := dst.GetPublicKey(ctx, dani.PurposeEnrollmentSigning)
	pubAny, _ := x509.ParsePKIXPublicKey(pubDER)
	if !ed25519.Verify(pubAny.(ed25519.PublicKey), []byte("token"), sig) {
		t.Fatal("peer must verify the origin's signatures (shared enrollment authority)")
	}
	// wrap on one side, unwrap on the other (same master KEK)
	ct, err := src.Wrap(ctx, dani.PurposeDataAtRest, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := dst.Unwrap(ctx, dani.PurposeDataAtRest, ct)
	if err != nil || string(pt) != "secret" {
		t.Fatalf("cross-unwrap failed: %q %v", pt, err)
	}
}

func TestImportSoftwareRejectsBadBlobs(t *testing.T) {
	if _, err := ImportSoftware([]byte("{not json")); err == nil {
		t.Fatal("bad json must be rejected")
	}
	if _, err := ImportSoftware([]byte(`{"master":"AAAA","deks":{}}`)); err == nil {
		t.Fatal("short master must be rejected")
	}
	// valid master, corrupt DEK length
	src, _ := NewSoftware()
	blob, _ := src.Export()
	var e map[string]any
	json.Unmarshal(blob, &e)
	e["deks"] = map[string]any{"ca-signing": map[string]any{"priv": "AAAA", "gen": 1}}
	bad, _ := json.Marshal(e)
	if _, err := ImportSoftware(bad); err == nil {
		t.Fatal("bad DEK length must be rejected")
	}
}
