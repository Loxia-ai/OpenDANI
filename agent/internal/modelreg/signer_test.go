package modelreg

import (
	"bytes"
	"context"
	"testing"

	"dani.local/agent/internal/artifact"
	"dani.local/agent/internal/kms"
	"dani.local/agent/pkg/dani"
)

// threePrincipalReg wires the three reviewer roles to THREE SEPARATE software keystores (each a
// stand-in for a distinct officer's HSM) and returns the registry plus the three keystores.
func threePrincipalReg(t *testing.T) (*Registry, *kms.SoftwareKeyStore, *kms.SoftwareKeyStore, *kms.SoftwareKeyStore) {
	t.Helper()
	sec, _ := kms.NewSoftware()
	gov, _ := kms.NewSoftware()
	adm, _ := kms.NewSoftware()
	store, err := artifact.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	shared, _ := kms.NewSoftware() // the registry's own ks (unused for signing once overridden)
	r := New(shared, store).WithRoleSigners(map[Role]RoleSigner{
		RoleSecurity:   KMSRoleSigner{KS: sec, Purpose: dani.PurposeModelSignSecurity},
		RoleGovernance: KMSRoleSigner{KS: gov, Purpose: dani.PurposeModelSignGovernance},
		RoleAdmin:      KMSRoleSigner{KS: adm, Purpose: dani.PurposeModelSignAdmin},
	})
	if err := r.InitSigners(context.Background()); err != nil {
		t.Fatal(err)
	}
	return r, sec, gov, adm
}

// TestThreePrincipalPromotion: a candidate promotes only when all three DISTINCT principals sign —
// and the three signatures come from three different keys (genuine three-party control).
func TestThreePrincipalPromotion(t *testing.T) {
	ctx := context.Background()
	r, sec, gov, adm := threePrincipalReg(t)
	if _, err := r.SubmitCandidate(ctx, CandidateMeta{ID: "m", Name: "m", Version: "1", Engine: "e",
		Lineage: &Lineage{}}, "adapter", []byte("bytes")); err != nil {
		t.Fatal(err)
	}
	// after two signatures the model is still a draft (no quorum)
	for _, role := range []Role{RoleSecurity, RoleGovernance} {
		if _, err := r.Sign(ctx, "m", role); err != nil {
			t.Fatal(err)
		}
	}
	if e := r.Get("m"); e.State != "draft" {
		t.Fatalf("two-of-three must stay draft, got %s", e.State)
	}
	// the third distinct principal completes the quorum -> available
	if _, err := r.Sign(ctx, "m", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	e := r.Get("m")
	if e.State != "available" || !r.VerifyApproval("m") {
		t.Fatalf("three distinct signatures must promote + verify: %+v", e)
	}

	// the three signatures are from THREE DIFFERENT keys
	secPub := e.Signatures[RoleSecurity].PubDER
	govPub := e.Signatures[RoleGovernance].PubDER
	admPub := e.Signatures[RoleAdmin].PubDER
	if bytes.Equal(secPub, govPub) || bytes.Equal(secPub, admPub) || bytes.Equal(govPub, admPub) {
		t.Fatal("three-party control violated: reviewer signatures share a key")
	}
	// each signature matches ITS OWN principal's public key, and NOT another principal's
	mustPub := func(ks *kms.SoftwareKeyStore, p dani.KeyPurpose) []byte {
		pub, err := ks.GetPublicKey(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		return pub
	}
	if !bytes.Equal(secPub, mustPub(sec, dani.PurposeModelSignSecurity)) {
		t.Fatal("security signature must come from the security principal")
	}
	if !bytes.Equal(govPub, mustPub(gov, dani.PurposeModelSignGovernance)) {
		t.Fatal("governance signature must come from the governance principal")
	}
	if !bytes.Equal(admPub, mustPub(adm, dani.PurposeModelSignAdmin)) {
		t.Fatal("admin signature must come from the admin principal")
	}
	// COMPROMISE MODEL: holding only the security officer's HSM cannot forge the governance approval —
	// the security keystore's governance-purpose key is a DIFFERENT key than the real governance sig.
	if bytes.Equal(govPub, mustPub(sec, dani.PurposeModelSignGovernance)) {
		t.Fatal("compromising one principal must not yield another's signature")
	}
}

// TestMissingSignerFails: a registry lacking a signer for a role cannot init or sign that role.
func TestMissingSignerFails(t *testing.T) {
	ctx := context.Background()
	store, _ := artifact.Open(t.TempDir())
	sec, _ := kms.NewSoftware()
	shared, _ := kms.NewSoftware()
	// only two of the three roles have signers
	r := New(shared, store).WithRoleSigners(map[Role]RoleSigner{
		RoleSecurity:   KMSRoleSigner{KS: sec, Purpose: dani.PurposeModelSignSecurity},
		RoleGovernance: KMSRoleSigner{KS: sec, Purpose: dani.PurposeModelSignGovernance},
	})
	if err := r.InitSigners(ctx); err == nil {
		t.Fatal("InitSigners must fail when a reviewer role has no signer")
	}
	if _, err := r.SubmitCandidate(ctx, CandidateMeta{ID: "m", Name: "m", Version: "1", Engine: "e"}, "adapter", []byte("b")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Sign(ctx, "m", RoleAdmin); err == nil {
		t.Fatal("Sign must fail for a role with no configured signer")
	}
}

func TestRolePurposes(t *testing.T) {
	m := RolePurposes()
	if len(m) != 3 || m[RoleSecurity] == "" || m[RoleGovernance] == "" || m[RoleAdmin] == "" {
		t.Fatalf("RolePurposes must map all three roles: %+v", m)
	}
	m[RoleSecurity] = "tampered" // must be a COPY — mutating it can't affect the registry
	if RolePurposes()[RoleSecurity] == "tampered" {
		t.Fatal("RolePurposes must return a copy")
	}
}
