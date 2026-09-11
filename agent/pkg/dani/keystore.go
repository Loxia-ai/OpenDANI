// Package dani contains the foundational cross-tier contracts for the DANI agent.
//
// This is the contract from the repo root (keystore.go), placed into the agent module
// unchanged. Governing decisions:
//
//	DL-R11-11 : two-level envelope KMS — master KEK wraps purpose-specific DEKs
//	DL-R11-12 : single KeyStore interface implemented by all three tiers
//	            (software / TPM / HSM); only master-key protection + where signing
//	            executes vary across tiers. Mediated access — callers never see raw
//	            key bytes. Attest() feeds tier-appropriate attestation into enrollment.
//	DF-R11-02 : DANIClaims CBOR map carried in the single custom cert extension.
//	DL-R11.2-02 : attestation tiers 0..3, proven not claimed.
package dani

import "context"

// KeyPurpose identifies a purpose-specific DEK (DL-R11-11). Each key does exactly
// one job, keeping compromise/rotation/audit attribution clean.
type KeyPurpose string

const (
	PurposeCASigning         KeyPurpose = "ca-signing"          // issues node identity certs (intermediate)
	PurposeConfigSigning     KeyPurpose = "config-signing"      // signs config versions (DL-R11-10)
	PurposeAuditChainSigning KeyPurpose = "audit-chain-signing" // signs audit hash-chain heads
	PurposeRevocationSigning KeyPurpose = "revocation-signing"  // signs gossip revocation markers
	PurposeEnrollmentSigning KeyPurpose = "enrollment-signing"  // signs bootstrap tokens (DL-R11.2-01)
	PurposeDataAtRest        KeyPurpose = "data-at-rest"        // encrypts sensitive local state

	// Model-promotion signing keys (§6.17.4, D25). A training-produced candidate becomes routable
	// only after all three reviewer roles cryptographically sign it. In real HA these keys are held
	// by three DIFFERENT principals/HSMs; the DEMO controller holds all three in one KMS (flagged).
	PurposeModelSignSecurity   KeyPurpose = "model-sign-security"   // Security Officer: license/provenance/sig/classification
	PurposeModelSignGovernance KeyPurpose = "model-sign-governance" // Governance Officer: intended-use/lineage/regulatory
	PurposeModelSignAdmin      KeyPurpose = "model-sign-admin"      // DANI Administrator: operational fit
)

// AttestationTier is the PROVEN attestation level (DL-R11.2-02), 0..3.
type AttestationTier uint8

const (
	TierAdministrative AttestationTier = 0 // human vouched; no hardware backing
	TierTPMBound       AttestationTier = 1 // real TPM holds node key; possession proven
	TierMeasuredBoot   AttestationTier = 2 // Tier 1 + boot fingerprints match reference set
	TierHRoT           AttestationTier = 3 // Tier 2 + periodic/continuous re-attestation
)

// AttestationStatement is the tier-appropriate proof produced by KeyStore.Attest.
// Software tier returns Tier==0 with empty Evidence ("honestly returns none").
type AttestationStatement struct {
	Tier     AttestationTier
	Evidence []byte // TPM quote (Tier2+) or HSM attestation cert (HSM tier); nil for software
	KeyRef   string // opaque handle the verifier can correlate
}

// KeyStore is the single interface every KMS tier implements (DL-R11-12).
// The ONLY things that vary across tiers are how the master key is protected and
// where signing executes; this interface, the DEK layer, and all callers are
// tier-identical. No method ever returns raw private key bytes (mediated access).
type KeyStore interface {
	// Sign produces a signature over payload using the named purpose key.
	// Never exposes key bytes. On HSM tier the bytes never enter DANI memory.
	Sign(ctx context.Context, purpose KeyPurpose, payload []byte) (signature []byte, err error)

	// Wrap / Unwrap perform envelope operations under the master key (DL-R11-11).
	Wrap(ctx context.Context, purpose KeyPurpose, plaintext []byte) (ciphertext []byte, err error)
	Unwrap(ctx context.Context, purpose KeyPurpose, ciphertext []byte) (plaintext []byte, err error)

	// GetPublicKey returns the public half for a purpose key (safe to expose).
	GetPublicKey(ctx context.Context, purpose KeyPurpose) (publicKeyDER []byte, err error)

	// RotateKey creates a new generation of the purpose key; old generations are
	// retained per rotation state until retired (keystore.db, DL-R11-11).
	RotateKey(ctx context.Context, purpose KeyPurpose) (newGeneration uint64, err error)

	// Attest returns a tier-appropriate attestation statement, feeding the
	// enrollment/attestation flow without tier-specific branching in callers.
	Attest(ctx context.Context, purpose KeyPurpose) (AttestationStatement, error)
}

// DANIClaims is the CBOR map carried in the single custom cert extension (DF-R11-02).
// Integrity comes from the CA signature over the enclosing cert body — no inner signature.
// All fields are ADVISORY bearer claims; the live Policy Engine is authoritative (DP13/DL-R11-07).
type DANIClaims struct {
	SchemaVersion   uint            `cbor:"1,keyasint" json:"schemaVersion"`
	Roles           []string        `cbor:"2,keyasint" json:"roles"`
	Classification  string          `cbor:"3,keyasint" json:"classification"`
	AttestationTier AttestationTier `cbor:"4,keyasint" json:"attestationTier"`
	HardwareFprint  []byte          `cbor:"5,keyasint" json:"hardwareFprint"`
	EnrolledAt      string          `cbor:"6,keyasint" json:"enrolledAt"`
	SiteTag         string          `cbor:"7,keyasint,omitempty" json:"siteTag,omitempty"`
}
