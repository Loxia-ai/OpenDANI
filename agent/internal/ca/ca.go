// Package ca implements the two-tier certificate authority (DL-R11-13) with real X.509.
//
// Structure: self-signed ROOT (~20yr, dormant after genesis) signs one online ISSUING
// INTERMEDIATE (~5yr, key in the KMS under PurposeCASigning); the intermediate signs every node
// identity cert (DF-R11-02) carrying the single DANIClaims custom extension.
//
// PHASE NOTE (RR-R11-27): full token-gated dormancy enforcement is stubbed for the DEMO; the
// two-tier structure is real. The root private key is wrapped by the KMS and discarded from memory
// after genesis (modelled dormancy) — node issuance only ever uses the online intermediate.
//
// DANIClaims is encoded as canonical CBOR in the extension (DF-R11-02, fxamacker/cbor canonical
// mode — integer keys via the struct's `cbor:"N,keyasint"` tags). The CA signature over the cert
// body provides integrity (no inner signature).
package ca

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"

	"dani.local/agent/pkg/dani"
)

// KeyStore is what the CA needs from the KMS: the mediated KeyStore plus a cert-issuance signer.
// Depending on the interface (not the concrete software KMS) keeps the CA tier-agnostic and
// testable. *kms.SoftwareKeyStore satisfies it.
type KeyStore interface {
	dani.KeyStore
	Signer(dani.KeyPurpose) (crypto.Signer, error)
}

// canonicalCBOR is fxamacker/cbor canonical/deterministic encoding (DF-R11-02).
var canonicalCBOR, _ = cbor.CanonicalEncOptions().EncMode()

// randReader is the entropy source; a package var so tests can inject failures to exercise the
// error-handling branches (production always uses crypto/rand).
var randReader io.Reader = rand.Reader

// OIDDaniClaims is a PLACEHOLDER arc under a private enterprise number (RR-R11-15: register a real
// IANA PEN before GA; DEMO/dev use a clearly-labelled placeholder).
var OIDDaniClaims = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}

// CA is the two-tier authority.
type CA struct {
	ks           KeyStore
	org          string
	Root         *x509.Certificate
	Intermediate *x509.Certificate
	rootSealed   []byte // KMS-wrapped root private key (dormant)
}

func serial() (*big.Int, error) {
	return rand.Int(randReader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// Genesis creates the two-tier CA (DL-R11-13). Returns the CA with the root sealed/dormant.
func Genesis(ctx context.Context, ks KeyStore, org string) (*CA, error) {
	now := time.Now()

	// ---- self-signed ROOT (~20yr) ----
	rootPub, rootPriv, err := ed25519.GenerateKey(randReader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: org + " Root CA", Organization: []string{org}, OrganizationalUnit: []string{"pki"}},
		NotBefore:             now,
		NotAfter:              now.AddDate(20, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(randReader, rootTmpl, rootTmpl, rootPub, rootPriv)
	if err != nil {
		return nil, fmt.Errorf("create root: %w", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, err
	}

	// ---- online ISSUING INTERMEDIATE (~5yr), signing key in the KMS ----
	intPubDER, err := ks.GetPublicKey(ctx, dani.PurposeCASigning)
	if err != nil {
		return nil, err
	}
	intPubAny, err := x509.ParsePKIXPublicKey(intPubDER)
	if err != nil {
		return nil, err
	}
	sn2, err := serial()
	if err != nil {
		return nil, err
	}
	intTmpl := &x509.Certificate{
		SerialNumber:          sn2,
		Subject:               pkix.Name{CommonName: org + " Issuing CA", Organization: []string{org}, OrganizationalUnit: []string{"pki"}},
		NotBefore:             now,
		NotAfter:              now.AddDate(5, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	// root signs the intermediate (root ceremony — DEMO stub: dormancy not enforced)
	intDER, err := x509.CreateCertificate(randReader, intTmpl, rootCert, intPubAny, rootPriv)
	if err != nil {
		return nil, fmt.Errorf("create intermediate: %w", err)
	}
	intCert, err := x509.ParseCertificate(intDER)
	if err != nil {
		return nil, err
	}

	// seal the root private key and discard it from memory (dormant root)
	sealed, err := ks.Wrap(ctx, dani.PurposeCASigning, rootPriv)
	if err != nil {
		return nil, err
	}

	return &CA{ks: ks, org: org, Root: rootCert, Intermediate: intCert, rootSealed: sealed}, nil
}

// Org returns the CA's organization name.
func (c *CA) Org() string { return c.org }

// Load reconstructs a CA from shared material (root + intermediate certs) on top of a KeyStore that
// already holds the matching PurposeCASigning key — used to provision an HA peer controller with the
// SAME authority as the genesis controller (so any controller can issue/verify/renew). Issuance only
// ever uses the online intermediate, so the (dormant) root private key is not needed here.
func Load(ks KeyStore, org string, rootDER, interDER []byte) (*CA, error) {
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, fmt.Errorf("parse root: %w", err)
	}
	inter, err := x509.ParseCertificate(interDER)
	if err != nil {
		return nil, fmt.Errorf("parse intermediate: %w", err)
	}
	return &CA{ks: ks, org: org, Root: root, Intermediate: inter}, nil
}

// NodeCertParams describes a node identity cert to issue.
type NodeCertParams struct {
	NodeUUID  string
	SiteOU    string
	PubDER    []byte // node public key (SPKI/DER)
	Claims    dani.DANIClaims
	NotAfter  time.Time
}

// IssueNodeCert signs a node identity cert with the ONLINE intermediate (never the root),
// embedding the DANIClaims custom extension (DF-R11-02).
func (c *CA) IssueNodeCert(ctx context.Context, p NodeCertParams) (*x509.Certificate, error) {
	nodePub, err := x509.ParsePKIXPublicKey(p.PubDER)
	if err != nil {
		return nil, fmt.Errorf("parse node pubkey: %w", err)
	}
	claimsVal, err := canonicalCBOR.Marshal(p.Claims) // canonical CBOR (DF-R11-02)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: p.NodeUUID, Organization: []string{c.org}, OrganizationalUnit: []string{p.SiteOU}},
		URIs:         nil, // SPIFFE URI-SAN added with the enrollment slice
		NotBefore:    now,
		NotAfter:     p.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{
			{Id: OIDDaniClaims, Critical: false, Value: claimsVal},
		},
	}
	signer, err := c.ks.Signer(dani.PurposeCASigning)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(randReader, tmpl, c.Intermediate, nodePub, signer)
	if err != nil {
		return nil, fmt.Errorf("sign node cert: %w", err)
	}
	return x509.ParseCertificate(der)
}

// Bundle returns the chain a node uses to verify others: [intermediate, root].
func (c *CA) Bundle() []*x509.Certificate { return []*x509.Certificate{c.Intermediate, c.Root} }

// Verify checks a leaf cert chains to this CA's root (DEMO: time = now).
func (c *CA) Verify(leaf *x509.Certificate) error {
	roots := x509.NewCertPool()
	roots.AddCert(c.Root)
	inter := x509.NewCertPool()
	inter.AddCert(c.Intermediate)
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err
}

// Claims extracts and decodes the DANIClaims extension from a node cert.
func Claims(cert *x509.Certificate) (*dani.DANIClaims, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDDaniClaims) {
			var cl dani.DANIClaims
			if err := cbor.Unmarshal(ext.Value, &cl); err != nil {
				return nil, err
			}
			return &cl, nil
		}
	}
	return nil, fmt.Errorf("DANIClaims extension not present")
}
