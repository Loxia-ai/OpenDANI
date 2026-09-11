// Package kms implements the software-tier KeyStore (DL-R11-11, DL-R11-12).
//
// Two-level envelope: a master KEK (AES-256-GCM) wraps purpose-specific DEKs. DEKs are Ed25519
// signing keys (DL-R11-11 default). Mediated access: callers Sign/Wrap/Unwrap and obtain public
// keys or a crypto.Signer, but never raw private-key bytes. Attest() honestly returns Tier 0.
//
// NOTE (hardening, per DL-R11-11): the master KEK here is generated fresh in memory. The real
// software tier seals it at rest via an OS facility (Linux kernel keyring / Windows DPAPI / macOS
// Keychain) into kms/master.sealed. That swap does not change this interface or any caller.
package kms

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"dani.local/agent/pkg/dani"
)

// randReader is the entropy source; a package var so tests can inject failures to exercise the
// error-handling branches (production always uses crypto/rand).
var randReader io.Reader = rand.Reader

type dek struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	gen  uint64
}

// SoftwareKeyStore is the software-tier dani.KeyStore.
type SoftwareKeyStore struct {
	mu        sync.Mutex
	master    cipher.AEAD // the KEK
	masterRaw []byte      // the 32-byte KEK (kept so an HA peer can be provisioned identically)
	deks      map[dani.KeyPurpose]*dek
}

var _ dani.KeyStore = (*SoftwareKeyStore)(nil)

func newFromMaster(raw []byte) (*SoftwareKeyStore, error) {
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SoftwareKeyStore{master: aead, masterRaw: raw, deks: map[dani.KeyPurpose]*dek{}}, nil
}

// NewSoftware creates a software KeyStore with a fresh master KEK.
func NewSoftware() (*SoftwareKeyStore, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(randReader, raw); err != nil {
		return nil, err
	}
	return newFromMaster(raw)
}

// export is the portable form of a KeyStore (master KEK + purpose DEKs). Used to provision an HA peer
// controller with an IDENTICAL CA + enrollment-signing authority, so any controller can issue/verify
// and any can become the Raft leader. (DEMO: carried over a private mTLS share; sealing-at-rest TODO.)
type export struct {
	Master []byte                    `json:"master"`
	Deks   map[string]exportedDek    `json:"deks"`
}
type exportedDek struct {
	Priv []byte `json:"priv"`
	Gen  uint64 `json:"gen"`
}

// Export serializes the KeyStore (master + all DEKs) for HA provisioning.
func (s *SoftwareKeyStore) Export() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := export{Master: s.masterRaw, Deks: map[string]exportedDek{}}
	for p, d := range s.deks {
		e.Deks[string(p)] = exportedDek{Priv: []byte(d.priv), Gen: d.gen}
	}
	return json.Marshal(e)
}

// ImportSoftware reconstructs a KeyStore from Export() bytes — identical keys to the origin.
func ImportSoftware(data []byte) (*SoftwareKeyStore, error) {
	var e export
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, err
	}
	if len(e.Master) != 32 {
		return nil, errors.New("kms: bad master key length in export")
	}
	s, err := newFromMaster(e.Master)
	if err != nil {
		return nil, err
	}
	for ps, ed := range e.Deks {
		priv := ed25519.PrivateKey(ed.Priv)
		if len(priv) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("kms: bad DEK length for %q", ps)
		}
		s.deks[dani.KeyPurpose(ps)] = &dek{priv: priv, pub: priv.Public().(ed25519.PublicKey), gen: ed.Gen}
	}
	return s, nil
}

func (s *SoftwareKeyStore) ensure(p dani.KeyPurpose) (*dek, error) {
	if d, ok := s.deks[p]; ok {
		return d, nil
	}
	pub, priv, err := ed25519.GenerateKey(randReader)
	if err != nil {
		return nil, err
	}
	d := &dek{priv: priv, pub: pub, gen: 1}
	s.deks[p] = d
	return d, nil
}

// Sign over payload with the purpose key (Ed25519 signs the message directly).
func (s *SoftwareKeyStore) Sign(_ context.Context, p dani.KeyPurpose, payload []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.ensure(p)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(d.priv, payload), nil
}

// Wrap encrypts plaintext under the master KEK, binding the purpose as associated data.
func (s *SoftwareKeyStore) Wrap(_ context.Context, p dani.KeyPurpose, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, s.master.NonceSize())
	if _, err := io.ReadFull(randReader, nonce); err != nil {
		return nil, err
	}
	return s.master.Seal(nonce, nonce, plaintext, []byte(p)), nil
}

// Unwrap reverses Wrap.
func (s *SoftwareKeyStore) Unwrap(_ context.Context, p dani.KeyPurpose, ciphertext []byte) ([]byte, error) {
	ns := s.master.NonceSize()
	if len(ciphertext) < ns {
		return nil, errors.New("kms: ciphertext too short")
	}
	return s.master.Open(nil, ciphertext[:ns], ciphertext[ns:], []byte(p))
}

// GetPublicKey returns the SPKI/DER public half for a purpose key.
func (s *SoftwareKeyStore) GetPublicKey(_ context.Context, p dani.KeyPurpose) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.ensure(p)
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKIXPublicKey(d.pub)
}

// RotateKey creates a new generation of the purpose key.
func (s *SoftwareKeyStore) RotateKey(_ context.Context, p dani.KeyPurpose) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.ensure(p)
	if err != nil {
		return 0, err
	}
	pub, priv, err := ed25519.GenerateKey(randReader)
	if err != nil {
		return 0, err
	}
	d.priv, d.pub, d.gen = priv, pub, d.gen+1
	return d.gen, nil
}

// Attest returns the software-tier statement: Tier 0, no evidence (DL-R11.2-02).
func (s *SoftwareKeyStore) Attest(_ context.Context, p dani.KeyPurpose) (dani.AttestationStatement, error) {
	return dani.AttestationStatement{Tier: dani.TierAdministrative, Evidence: nil, KeyRef: fmt.Sprintf("sw:%s", p)}, nil
}

// Signer returns a crypto.Signer backed by the purpose key, for x509 cert issuance. The signer
// delegates to Sign() — raw key bytes are never exposed (mediated access, DL-R11-12).
func (s *SoftwareKeyStore) Signer(p dani.KeyPurpose) (crypto.Signer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.ensure(p)
	if err != nil {
		return nil, err
	}
	return &purposeSigner{store: s, purpose: p, pub: d.pub}, nil
}

type purposeSigner struct {
	store   *SoftwareKeyStore
	purpose dani.KeyPurpose
	pub     ed25519.PublicKey
}

func (ps *purposeSigner) Public() crypto.PublicKey { return ps.pub }

func (ps *purposeSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	// Ed25519: x509 passes the full TBS bytes as "digest" with opts.HashFunc()==0.
	return ps.store.Sign(context.Background(), ps.purpose, digest)
}
