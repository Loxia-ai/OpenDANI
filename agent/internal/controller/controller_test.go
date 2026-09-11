package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"dani.local/agent/internal/ca"
	"dani.local/agent/internal/enrollment"
	"dani.local/agent/pkg/dani"
)

// TestSharedCABundle: a peer controller provisioned from the genesis controller's bundle shares the
// SAME CA + enrollment-signing authority (so any controller can issue/verify/enroll), yet has its own
// distinct identity cert. This is the foundation for multi-controller HA.
func TestSharedCABundle(t *testing.T) {
	ctx := context.Background()
	c0, err := Genesis(ctx, "AcmeBank", "dep-1", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	b, err := c0.ExportBundle()
	if err != nil {
		t.Fatal(err)
	}
	c1, err := NewFromBundle(ctx, b, "ctrl-002", "site-dc2", ":memory:")
	if err != nil {
		t.Fatalf("NewFromBundle: %v", err)
	}

	// a node cert issued by the PEER controller must chain to the shared root (verified by the genesis
	// controller) — proving both wield the same intermediate signing key.
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	cert, err := c1.CA.IssueNodeCert(ctx, ca.NodeCertParams{
		NodeUUID: "w1", SiteOU: "site-dc2", PubDER: pubDER,
		Claims: dani.DANIClaims{
			SchemaVersion: 1, Roles: []string{"worker"}, Classification: "restricted",
			AttestationTier: dani.TierAdministrative, SiteTag: "site-dc2",
		},
		NotAfter: time.Now().AddDate(0, 0, 90),
	})
	if err != nil {
		t.Fatalf("peer issue: %v", err)
	}
	if err := c0.CA.Verify(cert); err != nil {
		t.Fatalf("cert issued by ctrl-002 must chain to the shared root: %v", err)
	}

	// shared enrollment-signing: a bootstrap token minted by c0 verifies under c1's keystore.
	tok, _, err := enrollment.IssueToken(ctx, c0.KS, "dep-1", []string{"worker"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enrollment.VerifyToken(ctx, c1.KS, "dep-1", tok); err != nil {
		t.Fatalf("peer controller must verify the genesis controller's tokens: %v", err)
	}

	// but the two controllers have DISTINCT identities (own leaf certs).
	if c0.Cert.Subject.CommonName == c1.Cert.Subject.CommonName {
		t.Fatalf("controllers must have distinct identities, both = %s", c0.Cert.Subject.CommonName)
	}
	if c0.CA.Root.Raw == nil || string(c0.CA.Root.Raw) != string(c1.CA.Root.Raw) {
		t.Fatal("controllers must share the identical root cert")
	}
}
