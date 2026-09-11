// Package node is the node-side of enrollment: it runs the six-step handshake (DF-R11.2-01) over a
// controller-authenticated TLS channel and installs the resulting identity. The node verifies the
// controller's cert chains to the provisioned trust anchor (identity by chain, not DNS — DL-R11-08);
// it presents no client cert during the handshake (it has none yet).
package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "dani.local/agent/internal/gen/enrollmentv1"
)

// Identity is what a node holds after a successful enrollment.
type Identity struct {
	Cert     *x509.Certificate
	Key      ed25519.PrivateKey
	CABundle []*x509.Certificate
}

// EnrollParams configures a node enrollment.
type EnrollParams struct {
	Addr      string            // controller gRPC address
	TrustRoot *x509.Certificate // provisioned out-of-band (the dormant root)
	Token     []byte            // bootstrap token (enterprise) or PoW nonce (Open-DANI open-join)
	NodeUUID  string
	Roles     []string
	Class     string
	Caps      []byte             // capability inventory (JSON/CBOR)
	Key       ed25519.PrivateKey // OPTIONAL: use this key instead of generating one — Open-DANI
	// derives NodeUUID from its public key, so the caller must pass the same key it derived from.
	PollEvery time.Duration
	Timeout   time.Duration
}

// Enroll runs the handshake and returns the installed identity.
func Enroll(ctx context.Context, p EnrollParams) (*Identity, error) {
	if p.PollEvery == 0 {
		p.PollEvery = 250 * time.Millisecond
	}
	if p.Timeout == 0 {
		p.Timeout = 30 * time.Second
	}
	if p.Caps == nil {
		p.Caps = []byte("{}")
	}
	priv := p.Key // Open-DANI passes a pre-generated key (NodeUUID is derived from its pubkey)
	if priv == nil {
		var err error
		if _, priv, err = ed25519.GenerateKey(rand.Reader); err != nil { // private key never leaves the node
			return nil, err
		}
	}

	roots := x509.NewCertPool()
	roots.AddCert(p.TrustRoot)
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, // we verify the chain ourselves (no DNS identity, DL-R11-08)
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyServerChain(rawCerts, roots)
		},
		MinVersion: tls.VersionTLS12,
	}
	conn, err := grpc.NewClient(p.Addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	cl := pb.NewEnrollmentServiceClient(conn)

	// 1->2 EnrollBegin
	ch, err := cl.EnrollBegin(ctx, &pb.EnrollBeginRequest{
		Token: p.Token, NodeUuid: p.NodeUUID, DeclaredRoles: p.Roles, DeclaredClass: p.Class,
		NodeTime: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return nil, fmt.Errorf("EnrollBegin: %w", err)
	}

	// 3->4 EnrollProof (with a real PKCS#10 CSR proving key possession)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: p.NodeUUID}}, priv)
	if err != nil {
		return nil, err
	}
	if _, err := cl.EnrollProof(ctx, &pb.EnrollProofRequest{RequestId: ch.RequestId, CsrDer: csrDER, CapabilityInventory: p.Caps}); err != nil {
		return nil, fmt.Errorf("EnrollProof: %w", err)
	}

	// 5 EnrollPoll until terminal (patient pollable state, DL-R11.2-04)
	deadline := time.Now().Add(p.Timeout)
	var complete *pb.EnrollComplete
	for {
		pr, err := cl.EnrollPoll(ctx, &pb.EnrollPollRequest{RequestId: ch.RequestId})
		if err != nil {
			return nil, fmt.Errorf("EnrollPoll: %w", err)
		}
		switch pr.Status {
		case pb.EnrollPollResponse_STATUS_APPROVED:
			complete = pr.Complete
		case pb.EnrollPollResponse_STATUS_REJECTED:
			return nil, fmt.Errorf("enrollment rejected: %s", pr.RejectReason)
		case pb.EnrollPollResponse_STATUS_EXPIRED:
			return nil, errors.New("enrollment expired")
		}
		if complete != nil {
			break
		}
		if time.Now().After(deadline) {
			return nil, errors.New("timed out waiting for approval")
		}
		time.Sleep(p.PollEvery)
	}

	// 6 install: parse + verify the issued cert chains to the trust anchor via the CA bundle
	cert, err := x509.ParseCertificate(complete.NodeCert)
	if err != nil {
		return nil, err
	}
	bundle, err := parsePEMCerts(complete.CaBundle)
	if err != nil {
		return nil, err
	}
	if err := verifyIssuedCert(cert, bundle, p.TrustRoot); err != nil {
		return nil, fmt.Errorf("issued cert chain verify: %w", err)
	}
	return &Identity{Cert: cert, Key: priv, CABundle: bundle}, nil
}

func verifyServerChain(rawCerts [][]byte, roots *x509.CertPool) error {
	if len(rawCerts) == 0 {
		return errors.New("no peer certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}
	inter := x509.NewCertPool()
	for _, r := range rawCerts[1:] {
		c, err := x509.ParseCertificate(r)
		if err != nil {
			return err
		}
		inter.AddCert(c)
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err
}

func verifyIssuedCert(leaf *x509.Certificate, bundle []*x509.Certificate, root *x509.Certificate) error {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	inter := x509.NewCertPool()
	for _, c := range bundle {
		if !bytes.Equal(c.Raw, root.Raw) {
			inter.AddCert(c)
		}
	}
	_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	return err
}

func parsePEMCerts(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("empty CA bundle")
	}
	return out, nil
}
