package node

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestParsePEMCertsEmpty(t *testing.T) {
	if _, err := parsePEMCerts(nil); err == nil {
		t.Fatal("expected empty CA bundle to error")
	}
	if _, err := parsePEMCerts([]byte("-----BEGIN CERTIFICATE-----\nbm90LWFzbjE=\n-----END CERTIFICATE-----\n")); err == nil {
		t.Fatal("expected malformed PEM cert to error")
	}
}

func TestVerifyServerChainErrors(t *testing.T) {
	roots := x509.NewCertPool()
	if err := verifyServerChain(nil, roots); err == nil {
		t.Fatal("expected no-peer-cert to error")
	}
	if err := verifyServerChain([][]byte{[]byte("not-a-cert")}, roots); err == nil {
		t.Fatal("expected unparseable leaf to error")
	}
	// a self-signed cert that does not chain to the (empty) roots pool
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err := verifyServerChain([][]byte{der}, roots); err == nil {
		t.Fatal("expected chain to empty roots to fail")
	}
}

func TestVerifyIssuedCertMismatch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	leaf, _ := x509.ParseCertificate(der)
	// verifying against an unrelated root must fail
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	der2, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub2, priv2)
	root2, _ := x509.ParseCertificate(der2)
	if err := verifyIssuedCert(leaf, []*x509.Certificate{root2}, root2); err == nil {
		t.Fatal("expected verification against an unrelated root to fail")
	}
}
