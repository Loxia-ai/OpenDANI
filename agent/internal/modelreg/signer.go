package modelreg

import (
	"context"

	"dani.local/agent/pkg/dani"
)

// RoleSigner produces ONE reviewer role's signature and exposes its public key. It is the seam that
// makes the 3-signer control a genuine THREE-PARTY control (ROADMAP §2): in production each role's
// RoleSigner is a DISTINCT principal backed by its own HSM, so no single actor can mint all three
// approvals. The DEMO backs all three with one software KMS (via KMSRoleSigner) — same behavior as
// before, but now behind the seam.
//
// Verification never needs a RoleSigner: every signature carries its own public key (PubDER), so
// verify-on-use is keystore-independent and works on any controller that only holds public halves.
type RoleSigner interface {
	// Sign returns a signature over payload from this role's private key. On an HSM the key bytes
	// never enter DANI memory (the KeyStore contract).
	Sign(ctx context.Context, payload []byte) ([]byte, error)
	// Public returns this role's SPKI DER public key (safe to expose; travels inside each signature).
	Public(ctx context.Context) ([]byte, error)
}

// KMSRoleSigner adapts a dani.KeyStore + KeyPurpose to a RoleSigner — the DEMO/default backing where
// one keystore holds a role's key. Point three KMSRoleSigners at three DIFFERENT keystores (or one
// shared keystore) to choose separation vs. the shared-KMS DEMO model.
type KMSRoleSigner struct {
	KS      dani.KeyStore
	Purpose dani.KeyPurpose
}

// Sign signs payload with the purpose key.
func (s KMSRoleSigner) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	return s.KS.Sign(ctx, s.Purpose, payload)
}

// Public returns the purpose key's public half.
func (s KMSRoleSigner) Public(ctx context.Context) ([]byte, error) {
	return s.KS.GetPublicKey(ctx, s.Purpose)
}

// RolePurposes returns a copy of the reviewer-role → KeyPurpose map, so external provisioners (the
// signer-provider factory) can build a signer per role without importing the private mapping.
func RolePurposes() map[Role]dani.KeyPurpose {
	m := make(map[Role]dani.KeyPurpose, len(rolePurpose))
	for role, purpose := range rolePurpose {
		m[role] = purpose
	}
	return m
}

// defaultSigners builds the DEMO's three role signers over a single shared keystore (each role uses
// its own purpose key, but all three live in the same KMS). Production overrides via WithRoleSigners.
func defaultSigners(ks dani.KeyStore) map[Role]RoleSigner {
	m := make(map[Role]RoleSigner, len(rolePurpose))
	for role, purpose := range rolePurpose {
		m[role] = KMSRoleSigner{KS: ks, Purpose: purpose}
	}
	return m
}
