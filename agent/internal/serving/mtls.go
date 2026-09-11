// Package serving is the DANI data plane: the worker's inference endpoint, the controller's gateway
// + router, and the Link heartbeat between them — all over the SAME mTLS identities minted during
// enrollment (so a node's right to serve/receive traffic is exactly its certificate). The external
// API is OpenAI /v1/chat/completions (M6); internal dispatch + heartbeat ride mutual mTLS.
package serving

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
)

// peerVerifier builds a VerifyPeerCertificate that checks the peer chains to trustRoot, since DANI
// identity is by certificate chain, not DNS (DL-R11-08) — so we skip hostname verification and do
// the chain check ourselves, exactly as the enrollment node client does.
func peerVerifier(trustRoot *x509.Certificate, ku x509.ExtKeyUsage) func([][]byte, [][]*x509.Certificate) error {
	roots := x509.NewCertPool()
	roots.AddCert(trustRoot)
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("no peer certificate")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		inter := x509.NewCertPool()
		for _, r := range rawCerts[1:] {
			if c, err := x509.ParseCertificate(r); err == nil && !bytes.Equal(c.Raw, trustRoot.Raw) {
				inter.AddCert(c)
			}
		}
		_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{ku}})
		return err
	}
}

// serverTLS builds a TLS server config presenting (leaf+intermediate) and REQUIRING a client cert
// that chains to the CA root — mutual mTLS for inbound dispatch/heartbeat. isRevoked (optional)
// additionally rejects a chain-valid client whose CN is on the distributed revocation list (P1-4):
// stdlib verifies the chain first, then hands us the raw certs for the revocation check.
func serverTLS(leafRaw, interRaw []byte, key crypto.PrivateKey, root *x509.Certificate, isRevoked func(string) bool) (*tls.Config, error) {
	leaf, err := x509.ParseCertificate(leafRaw)
	if err != nil {
		return nil, err
	}
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(root)
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafRaw, interRaw}, PrivateKey: key, Leaf: leaf}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS12,
	}
	if isRevoked != nil {
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no peer certificate")
			}
			peer, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			if isRevoked(peer.Subject.CommonName) {
				return errors.New("peer certificate revoked: " + peer.Subject.CommonName)
			}
			return nil
		}
	}
	return cfg, nil
}

// clientTLS builds a TLS client config presenting (leaf+intermediate) and verifying the server
// chains to trustRoot (no DNS identity — custom chain check).
func clientTLS(leafRaw, interRaw []byte, key crypto.PrivateKey, trustRoot *x509.Certificate) (*tls.Config, error) {
	leaf, err := x509.ParseCertificate(leafRaw)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:          []tls.Certificate{{Certificate: [][]byte{leafRaw, interRaw}, PrivateKey: key, Leaf: leaf}},
		InsecureSkipVerify:    true, // we verify the chain ourselves (DL-R11-08)
		VerifyPeerCertificate: peerVerifier(trustRoot, x509.ExtKeyUsageServerAuth),
		MinVersion:            tls.VersionTLS12,
	}, nil
}

// Identity is the minimal cert material both roles hand the data plane.
type Identity struct {
	LeafRaw  []byte
	InterRaw []byte // the issuing intermediate
	Key      crypto.PrivateKey
	Root     *x509.Certificate // trust anchor
	UUID     string            // CN
}
