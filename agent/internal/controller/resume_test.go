package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dani.local/agent/internal/audit"
	"dani.local/agent/internal/ca"
	"dani.local/agent/internal/enrollment"
	"dani.local/agent/pkg/dani"
)

// TestGenesisOrResumeSurvivableRestart is the D-14 #2 fix: a standalone controller restarted with
// the same --state resumes the SAME authority — worker certs issued before the restart still chain,
// bootstrap tokens minted before the restart still verify, and audit anchors signed before the
// restart still validate under the resumed KMS.
func TestGenesisOrResumeSurvivableRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	state := filepath.Join(dir, "authority.json")
	auditDB := filepath.Join(dir, "audit.db")

	// boot 1: genesis + persist
	c1, resumed, err := GenesisOrResume(ctx, "AcmeBank", "dep-1", ":memory:", state, "ctrl-001", "site-hq")
	if err != nil {
		t.Fatal(err)
	}
	if resumed {
		t.Fatal("first boot must be a genesis, not a resume")
	}
	if _, err := os.Stat(state); err != nil {
		t.Fatalf("authority must be persisted at %s: %v", state, err)
	}

	// pre-restart artifacts: a worker cert, a bootstrap token, and a signed audit anchor
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	workerCert, err := c1.CA.IssueNodeCert(ctx, ca.NodeCertParams{
		NodeUUID: "w1", SiteOU: "site-hq", PubDER: pubDER,
		Claims: dani.DANIClaims{SchemaVersion: 1, Roles: []string{"worker"}, Classification: "restricted",
			AttestationTier: dani.TierAdministrative, SiteTag: "site-hq"},
		NotAfter: time.Now().AddDate(0, 0, 90),
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := enrollment.IssueToken(ctx, c1.KS, "dep-1", []string{"worker"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	aud1, err := audit.Open(ctx, auditDB, c1.KS)
	if err != nil {
		t.Fatal(err)
	}
	if err := aud1.Emit("genesis", map[string]any{"boot": 1}); err != nil {
		t.Fatal(err)
	}
	if err := aud1.SignHead(ctx); err != nil { // anchor signed by boot-1's KMS
		t.Fatal(err)
	}
	aud1.Close()

	// boot 2: resume from state
	c2, resumed, err := GenesisOrResume(ctx, "AcmeBank", "dep-1", ":memory:", state, "ctrl-001", "site-hq")
	if err != nil {
		t.Fatal(err)
	}
	if !resumed {
		t.Fatal("second boot must RESUME, not re-genesis")
	}
	if !bytes.Equal(c1.CA.Root.Raw, c2.CA.Root.Raw) || !bytes.Equal(c1.CA.Intermediate.Raw, c2.CA.Intermediate.Raw) {
		t.Fatal("resumed controller must wield the identical CA")
	}
	if err := c2.CA.Verify(workerCert); err != nil {
		t.Fatalf("pre-restart worker cert must still chain after resume: %v", err)
	}
	if _, err := enrollment.VerifyToken(ctx, c2.KS, "dep-1", tok); err != nil {
		t.Fatalf("pre-restart bootstrap token must still verify: %v", err)
	}
	// all long-lived signing keys are the SAME keys (not lazily re-minted)
	for _, p := range []dani.KeyPurpose{dani.PurposeAuditChainSigning, dani.PurposeEnrollmentSigning,
		dani.PurposeModelSignSecurity, dani.PurposeModelSignGovernance, dani.PurposeModelSignAdmin} {
		k1, err1 := c1.KS.GetPublicKey(ctx, p)
		k2, err2 := c2.KS.GetPublicKey(ctx, p)
		if err1 != nil || err2 != nil || !bytes.Equal(k1, k2) {
			t.Fatalf("purpose %s must survive the restart identically (%v/%v)", p, err1, err2)
		}
	}
	// the audit chain CONTINUES: boot-1's signed anchor verifies under the resumed KMS
	aud2, err := audit.Open(ctx, auditDB, c2.KS)
	if err != nil {
		t.Fatal(err)
	}
	defer aud2.Close()
	if err := aud2.Emit("controller.resumed", map[string]any{"boot": 2}); err != nil {
		t.Fatal(err)
	}
	integ, err := aud2.Verify(ctx)
	if err != nil || !integ.OK {
		t.Fatalf("audit chain must verify across the restart: %+v %v", integ, err)
	}
}

// TestGenesisOrResumeCorruptState: a corrupt state file must be a hard error — silently minting a
// fresh CA over a live deployment is exactly the failure this API exists to prevent.
func TestGenesisOrResumeCorruptState(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "authority.json")
	if err := os.WriteFile(state, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := GenesisOrResume(context.Background(), "o", "d", ":memory:", state, "ctrl-001", "site-hq"); err == nil {
		t.Fatal("corrupt state must refuse to boot")
	}
}

// TestGenesisOrResumeUnwritableState: failing to persist the authority is fatal (a boot that
// LOOKS survivable but isn't would defeat the point).
func TestGenesisOrResumeUnwritableState(t *testing.T) {
	state := filepath.Join(t.TempDir(), "no-such-dir", "authority.json")
	if _, _, err := GenesisOrResume(context.Background(), "o", "d", ":memory:", state, "ctrl-001", "site-hq"); err == nil {
		t.Fatal("unwritable state path must fail the boot")
	}
}

// TestGenesisOrResumeBadBundle: a well-formed JSON state whose KMS export is garbage fails at
// NewFromBundle (resume path error propagation).
func TestGenesisOrResumeBadBundle(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "authority.json")
	if err := os.WriteFile(state, []byte(`{"kms":"Z2FyYmFnZQ==","root":"","inter":"","org":"o","deployment_id":"d"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := GenesisOrResume(context.Background(), "o", "d", ":memory:", state, "ctrl-001", "site-hq"); err == nil {
		t.Fatal("bad bundle must fail the resume")
	}
}

// TestGenesisOrResumeGenesisError: a genesis failure (unopenable registry DSN) propagates.
func TestGenesisOrResumeGenesisError(t *testing.T) {
	badDSN := filepath.Join(t.TempDir(), "no-such-dir", "reg.db")
	state := filepath.Join(t.TempDir(), "authority.json")
	if _, _, err := GenesisOrResume(context.Background(), "o", "d", badDSN, state, "ctrl-001", "site-hq"); err == nil {
		t.Fatal("genesis failure must propagate")
	}
}
