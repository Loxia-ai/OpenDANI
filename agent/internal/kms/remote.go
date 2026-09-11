package kms

// RemoteKeyStore is the HSM / cloud-KMS tier of the DL-R11-12 KeyStore contract: it implements the
// FULL dani.KeyStore (plus Signer for CA issuance) by delegating every key operation to an external
// signing service, so the private key material NEVER enters DANI's memory. This generalizes the
// reviewer-signer HSM path (D-20) to every key purpose — the CA-signing, audit-chain, and enrollment
// keys can all live in hardware. A controller opened with such a keystore has an HSM-backed CA: the
// issuing intermediate key is in the HSM (genesis only reads its public key + asks it to wrap the
// dormant root), and node-cert issuance signs through the HSM.
//
// Contract with the signing service (JSON over mTLS):
//
//	POST /publickey {"purpose":p}                     -> {"pub":  "<b64 SPKI DER>"}
//	POST /sign      {"purpose":p,"payload":"<b64>"}   -> {"sig":  "<b64>"}
//	POST /wrap      {"purpose":p,"plaintext":"<b64>"} -> {"ciphertext":"<b64>"}
//	POST /unwrap    {"purpose":p,"ciphertext":"<b64>"}-> {"plaintext":"<b64>"}
//	POST /rotate    {"purpose":p}                     -> {"generation": N}
//	POST /attest    {"purpose":p}                     -> {"tier":N,"evidence":"<b64>","keyRef":"..."}

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"dani.local/agent/pkg/dani"
)

// RemoteKeyStore delegates to an external HSM / cloud-KMS signing service at BaseURL.
type RemoteKeyStore struct {
	Client  *http.Client
	BaseURL string
}

var _ dani.KeyStore = (*RemoteKeyStore)(nil)

func (r *RemoteKeyStore) client() *http.Client {
	if r.Client != nil {
		return r.Client
	}
	return http.DefaultClient
}

// call POSTs body to /op and decodes the JSON response into out.
func (r *RemoteKeyStore) call(ctx context.Context, op string, body, out any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(r.BaseURL, "/")+"/"+op, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("kms/remote: %s: HTTP %d: %s", op, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// Sign signs payload with the purpose key (in the HSM; bytes never enter DANI).
func (r *RemoteKeyStore) Sign(ctx context.Context, p dani.KeyPurpose, payload []byte) ([]byte, error) {
	var out struct {
		Sig string `json:"sig"`
	}
	if err := r.call(ctx, "sign", map[string]string{"purpose": string(p), "payload": b64(payload)}, &out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Sig)
}

// GetPublicKey returns the SPKI DER public half of the purpose key.
func (r *RemoteKeyStore) GetPublicKey(ctx context.Context, p dani.KeyPurpose) ([]byte, error) {
	var out struct {
		Pub string `json:"pub"`
	}
	if err := r.call(ctx, "publickey", map[string]string{"purpose": string(p)}, &out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Pub)
}

// Wrap encrypts plaintext under the HSM's purpose key (envelope for data-at-rest / the dormant root).
func (r *RemoteKeyStore) Wrap(ctx context.Context, p dani.KeyPurpose, plaintext []byte) ([]byte, error) {
	var out struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := r.call(ctx, "wrap", map[string]string{"purpose": string(p), "plaintext": b64(plaintext)}, &out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Ciphertext)
}

// Unwrap reverses Wrap.
func (r *RemoteKeyStore) Unwrap(ctx context.Context, p dani.KeyPurpose, ciphertext []byte) ([]byte, error) {
	var out struct {
		Plaintext string `json:"plaintext"`
	}
	if err := r.call(ctx, "unwrap", map[string]string{"purpose": string(p), "ciphertext": b64(ciphertext)}, &out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Plaintext)
}

// RotateKey asks the HSM to create a new generation of the purpose key.
func (r *RemoteKeyStore) RotateKey(ctx context.Context, p dani.KeyPurpose) (uint64, error) {
	var out struct {
		Generation uint64 `json:"generation"`
	}
	if err := r.call(ctx, "rotate", map[string]string{"purpose": string(p)}, &out); err != nil {
		return 0, err
	}
	return out.Generation, nil
}

// Attest returns the HSM's attestation statement for the purpose key.
func (r *RemoteKeyStore) Attest(ctx context.Context, p dani.KeyPurpose) (dani.AttestationStatement, error) {
	var out struct {
		Tier     uint8  `json:"tier"`
		Evidence string `json:"evidence"`
		KeyRef   string `json:"keyRef"`
	}
	if err := r.call(ctx, "attest", map[string]string{"purpose": string(p)}, &out); err != nil {
		return dani.AttestationStatement{}, err
	}
	ev, _ := base64.StdEncoding.DecodeString(out.Evidence)
	ref := out.KeyRef
	if ref == "" {
		ref = "hsm:" + string(p)
	}
	return dani.AttestationStatement{Tier: dani.AttestationTier(out.Tier), Evidence: ev, KeyRef: ref}, nil
}

// Signer returns a crypto.Signer for x509 issuance, delegating signing to the HSM (mediated access —
// raw key bytes never exposed, DL-R11-12).
func (r *RemoteKeyStore) Signer(p dani.KeyPurpose) (crypto.Signer, error) {
	pubDER, err := r.GetPublicKey(context.Background(), p)
	if err != nil {
		return nil, err
	}
	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return nil, err
	}
	return &remoteSigner{ks: r, purpose: p, pub: pub}, nil
}

type remoteSigner struct {
	ks      *RemoteKeyStore
	purpose dani.KeyPurpose
	pub     crypto.PublicKey
}

func (s *remoteSigner) Public() crypto.PublicKey { return s.pub }

func (s *remoteSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	// Ed25519: x509 passes the full TBS as "digest" with opts.HashFunc()==0.
	return s.ks.Sign(context.Background(), s.purpose, digest)
}
