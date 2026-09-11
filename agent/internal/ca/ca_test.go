package ca

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"dani.local/agent/internal/kms"
	"dani.local/agent/pkg/dani"
)

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("rng failure (injected)") }

// failAfter yields n deterministic bytes then fails — lets a test fail at a specific allocation.
type failAfter struct{ n int }

func (f *failAfter) Read(b []byte) (int, error) {
	if f.n <= 0 {
		return 0, errors.New("rng exhausted (injected)")
	}
	k := len(b)
	if k > f.n {
		k = f.n
	}
	for i := 0; i < k; i++ {
		b[i] = 1
	}
	f.n -= k
	return k, nil
}

func withRNG(r interface{ Read([]byte) (int, error) }, fn func()) {
	old := randReader
	randReader = r
	defer func() { randReader = old }()
	fn()
}

func newCAWithNode(t *testing.T) (*CA, *x509.Certificate) {
	t.Helper()
	ctx := context.Background()
	ks, err := kms.NewSoftware()
	if err != nil {
		t.Fatal(err)
	}
	c, err := Genesis(ctx, ks, "AcmeBank")
	if err != nil {
		t.Fatalf("genesis: %v", err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := c.IssueNodeCert(ctx, NodeCertParams{
		NodeUUID: "node-1", SiteOU: "site-hq", PubDER: pubDER,
		Claims: dani.DANIClaims{
			SchemaVersion: 1, Roles: []string{"worker"}, Classification: "restricted",
			AttestationTier: dani.TierAdministrative, EnrolledAt: time.Now().UTC().Format(time.RFC3339),
		},
		NotAfter: time.Now().AddDate(0, 0, 90),
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return c, cert
}

func TestGenesisIssueVerifyClaims(t *testing.T) {
	c, cert := newCAWithNode(t)
	if err := c.Verify(cert); err != nil {
		t.Fatalf("verify: %v", err)
	}
	cl, err := Claims(cert)
	if err != nil {
		t.Fatalf("claims: %v", err)
	}
	if cl.Classification != "restricted" || len(cl.Roles) != 1 || cl.Roles[0] != "worker" {
		t.Fatalf("claims mismatch: %+v", cl)
	}
}

func TestForeignCertRejected(t *testing.T) {
	c1, _ := newCAWithNode(t)
	_, foreign := newCAWithNode(t) // issued by a different CA/root
	if err := c1.Verify(foreign); err == nil {
		t.Fatal("expected foreign cert to fail chain verification")
	}
}

func TestBundleAndClaimsMissing(t *testing.T) {
	c, _ := newCAWithNode(t)
	if len(c.Bundle()) != 2 {
		t.Fatalf("bundle should be [intermediate, root], got %d", len(c.Bundle()))
	}
	// the root cert has no DANIClaims extension -> Claims must error
	if _, err := Claims(c.Root); err == nil {
		t.Fatal("expected Claims() to fail on a cert without the DANIClaims extension")
	}
}

func TestGenesisErrorPaths(t *testing.T) {
	ctx := context.Background()
	ks, _ := kms.NewSoftware()
	// root key generation fails
	withRNG(failReader{}, func() {
		if _, err := Genesis(ctx, ks, "Acme"); err == nil {
			t.Fatal("expected genesis to fail on root key RNG error")
		}
	})
	// root key ok (32 bytes) but the serial draw fails
	withRNG(&failAfter{n: 32}, func() {
		if _, err := Genesis(ctx, ks, "Acme"); err == nil {
			t.Fatal("expected genesis to fail on serial RNG error")
		}
	})
	// fail at a later draw (root key + first serial succeed, then a subsequent draw fails)
	withRNG(&failAfter{n: 48}, func() {
		if _, err := Genesis(ctx, ks, "Acme"); err == nil {
			t.Fatal("expected genesis to fail on a later RNG draw")
		}
	})
}

// mockKS wraps a real software KeyStore but can fail GetPublicKey / Wrap to exercise Genesis's
// error handling of KMS failures.
type mockKS struct {
	*kms.SoftwareKeyStore
	failPub, failWrap, failSigner bool
}

func (m *mockKS) Signer(p dani.KeyPurpose) (crypto.Signer, error) {
	if m.failSigner {
		return nil, errors.New("signer failure (injected)")
	}
	return m.SoftwareKeyStore.Signer(p)
}

func (m *mockKS) GetPublicKey(ctx context.Context, p dani.KeyPurpose) ([]byte, error) {
	if m.failPub {
		return nil, errors.New("getpublickey failure (injected)")
	}
	return m.SoftwareKeyStore.GetPublicKey(ctx, p)
}

func (m *mockKS) Wrap(ctx context.Context, p dani.KeyPurpose, pt []byte) ([]byte, error) {
	if m.failWrap {
		return nil, errors.New("wrap failure (injected)")
	}
	return m.SoftwareKeyStore.Wrap(ctx, p, pt)
}

func TestGenesisKeyStoreFailures(t *testing.T) {
	ctx := context.Background()
	base, _ := kms.NewSoftware()
	if _, err := Genesis(ctx, &mockKS{SoftwareKeyStore: base, failPub: true}, "Acme"); err == nil {
		t.Fatal("expected Genesis to fail when KMS GetPublicKey fails")
	}
	if _, err := Genesis(ctx, &mockKS{SoftwareKeyStore: base, failWrap: true}, "Acme"); err == nil {
		t.Fatal("expected Genesis to fail when KMS Wrap fails")
	}
}

func TestIssueNodeCertSignerFailure(t *testing.T) {
	ctx := context.Background()
	base, _ := kms.NewSoftware()
	c, err := Genesis(ctx, &mockKS{SoftwareKeyStore: base, failSigner: true}, "Acme")
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	if _, err := c.IssueNodeCert(ctx, NodeCertParams{NodeUUID: "n", PubDER: der, NotAfter: time.Now().Add(time.Hour)}); err == nil {
		t.Fatal("expected IssueNodeCert to fail when the CA signer fails")
	}
}

func TestIssueNodeCertErrorPaths(t *testing.T) {
	ctx := context.Background()
	c, _ := newCAWithNode(t)
	// bad public key DER
	if _, err := c.IssueNodeCert(ctx, NodeCertParams{NodeUUID: "n", PubDER: []byte("not-a-key"), NotAfter: time.Now().Add(time.Hour)}); err == nil {
		t.Fatal("expected IssueNodeCert to fail on a bad public key")
	}
	// valid key, but the serial draw fails
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	withRNG(failReader{}, func() {
		if _, err := c.IssueNodeCert(ctx, NodeCertParams{NodeUUID: "n", PubDER: der, NotAfter: time.Now().Add(time.Hour)}); err == nil {
			t.Fatal("expected IssueNodeCert to fail on serial RNG error")
		}
	})
}

func TestClaimsBadCBOR(t *testing.T) {
	// a cert carrying the DANIClaims OID but with undecodable CBOR in the value
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: OIDDaniClaims, Value: []byte{0xff}}}, // 0xff = invalid top-level CBOR
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	if _, err := Claims(cert); err == nil {
		t.Fatal("expected Claims() to fail decoding invalid CBOR")
	}
}

func TestLoadReconstructsSharedAuthority(t *testing.T) {
	ctx := context.Background()
	ks, _ := kms.NewSoftware()
	origin, err := Genesis(ctx, ks, "AcmeBank")
	if err != nil {
		t.Fatal(err)
	}
	if origin.Org() != "AcmeBank" {
		t.Fatalf("Org wrong: %s", origin.Org())
	}
	// HA peer: same KMS material (Export/Import path is kms's), same cert DERs
	blob, _ := ks.Export()
	ks2, err := kms.ImportSoftware(blob)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := Load(ks2, "AcmeBank", origin.Root.Raw, origin.Intermediate.Raw)
	if err != nil {
		t.Fatal(err)
	}
	// the peer ISSUES a cert that chains to the ORIGIN's root — one authority, two controllers
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	cert, err := peer.IssueNodeCert(ctx, NodeCertParams{
		NodeUUID: "node-via-peer", SiteOU: "site-b", PubDER: pubDER,
		Claims:   dani.DANIClaims{SchemaVersion: 1, Roles: []string{"worker"}, Classification: "restricted"},
		NotAfter: time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(origin.Root)
	inters := x509.NewCertPool()
	inters.AddCert(origin.Intermediate)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("peer-issued cert must chain to the shared root: %v", err)
	}
}

func TestLoadRejectsGarbageDER(t *testing.T) {
	ks, _ := kms.NewSoftware()
	if _, err := Load(ks, "o", []byte("junk"), []byte("junk")); err == nil {
		t.Fatal("garbage root must be rejected")
	}
	origin, _ := Genesis(context.Background(), ks, "o")
	if _, err := Load(ks, "o", origin.Root.Raw, []byte("junk")); err == nil {
		t.Fatal("garbage intermediate must be rejected")
	}
}
