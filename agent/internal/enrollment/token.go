// Package enrollment implements the Enrollment Service (enrollment.proto) — the six-step
// first-contact handshake (DF-R11.2-01) and renewal (DL-R11.2-05). The wire types are the
// generated gRPC messages in internal/gen/enrollmentv1.
package enrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/fxamacker/cbor/v2"

	"dani.local/agent/pkg/dani"
)

const rfc3339 = time.RFC3339

var tokenCBOR, _ = cbor.CanonicalEncOptions().EncMode()

// randReader is the entropy source; a package var so tests can inject failures.
var randReader io.Reader = rand.Reader

// TokenPayload is the bootstrap token (DL-R11.2-01). A7 (consistency report): the contracts left
// the token wire format unspecified — this is the DEMO fixture: a canonical-CBOR payload with a
// detached Ed25519 signature by the enrollment-signing DEK (NOT the CA key — per-purpose
// separation, DL-R11-11). Single-use is enforced by the queue at consumption time.
type TokenPayload struct {
	TokenID       string   `cbor:"1,keyasint"`
	DeploymentID  string   `cbor:"2,keyasint"` // replay-scope
	IssuedAt      string   `cbor:"3,keyasint"`
	ExpiresAt     string   `cbor:"4,keyasint"`
	IntendedRoles []string `cbor:"5,keyasint,omitempty"`
	Nonce         []byte   `cbor:"6,keyasint"`
}

type signedToken struct {
	Payload []byte `cbor:"1,keyasint"` // CBOR(TokenPayload)
	Sig     []byte `cbor:"2,keyasint"` // Ed25519 over Payload, enrollment-signing key
}

// IssueToken mints a signed bootstrap token with the given TTL.
func IssueToken(ctx context.Context, ks dani.KeyStore, deploymentID string, roles []string, ttl time.Duration) (token []byte, tokenID string, err error) {
	now := time.Now().UTC()
	nonce := make([]byte, 12)
	if _, err = io.ReadFull(randReader, nonce); err != nil {
		return nil, "", err
	}
	p := TokenPayload{
		TokenID: randHex(8), DeploymentID: deploymentID,
		IssuedAt: now.Format(rfc3339), ExpiresAt: now.Add(ttl).Format(rfc3339),
		IntendedRoles: roles, Nonce: nonce,
	}
	payload, err := tokenCBOR.Marshal(p)
	if err != nil {
		return nil, "", err
	}
	sig, err := ks.Sign(ctx, dani.PurposeEnrollmentSigning, payload)
	if err != nil {
		return nil, "", err
	}
	token, err = tokenCBOR.Marshal(signedToken{Payload: payload, Sig: sig})
	return token, p.TokenID, err
}

// VerifyToken checks the signature, deployment scope, and TTL; returns the decoded payload.
func VerifyToken(ctx context.Context, ks dani.KeyStore, deploymentID string, token []byte) (*TokenPayload, error) {
	var st signedToken
	if err := cbor.Unmarshal(token, &st); err != nil {
		return nil, fmt.Errorf("malformed token: %w", err)
	}
	pubDER, err := ks.GetPublicKey(ctx, dani.PurposeEnrollmentSigning)
	if err != nil {
		return nil, err
	}
	pubAny, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return nil, err
	}
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("enrollment-signing key is not ed25519")
	}
	if !ed25519.Verify(pub, st.Payload, st.Sig) {
		return nil, errors.New("bad token signature")
	}
	var p TokenPayload
	if err := cbor.Unmarshal(st.Payload, &p); err != nil {
		return nil, err
	}
	if p.DeploymentID != deploymentID {
		return nil, errors.New("token for a different deployment (replay scope)")
	}
	exp, err := time.Parse(rfc3339, p.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if time.Now().After(exp) {
		return nil, errors.New("token expired")
	}
	return &p, nil
}
