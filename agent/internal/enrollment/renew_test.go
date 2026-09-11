package enrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"dani.local/agent/internal/ca"
	"dani.local/agent/internal/kms"
	pb "dani.local/agent/internal/gen/enrollmentv1"
)

// peerCtx fabricates a gRPC context carrying a verified client cert with the given CN — the shape
// requirePeer inspects after a real mutual-mTLS handshake.
func peerCtx(cn string) context.Context {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}},
	})
}

// enrolledService spins a service with one fully-enrolled node (via the real handshake helpers used
// by the existing tests) and returns it plus a fresh CSR for that node.
func enrolledService(t *testing.T) (*Service, string, []byte) {
	t.Helper()
	ctx := context.Background()
	ks, _ := kms.NewSoftware()
	authority, err := ca.Genesis(ctx, ks, "AcmeBank")
	if err != nil {
		t.Fatal(err)
	}
	svc := New(ks, authority, "dep-1")
	token, _, err := IssueToken(ctx, ks, "dep-1", []string{"worker"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := svc.EnrollBegin(ctx, &pb.EnrollBeginRequest{
		Token: token, NodeUuid: "node-r", DeclaredRoles: []string{"worker"}, DeclaredClass: "restricted",
		NodeTime: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "node-r"},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub
	if _, err := svc.EnrollProof(ctx, &pb.EnrollProofRequest{
		RequestId: ch.RequestId, CsrDer: csrDER, CapabilityInventory: []byte(`{}`),
	}); err != nil {
		t.Fatal(err)
	}
	w := svc.Waiting()
	if len(w) != 1 {
		t.Fatalf("expected 1 waiting, got %d", len(w))
	}
	if _, err := svc.Approve(ctx, w[0], nil, "", "site-hq"); err != nil {
		t.Fatal(err)
	}
	// a fresh CSR for renewal (new keypair — rotation on renew)
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	csr2, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "node-r"},
	}, priv2)
	return svc, "node-r", csr2
}

func TestRenewCertHappyPath(t *testing.T) {
	svc, uuid, csr := enrolledService(t)
	var renewed int
	svc.OnRenew = func(u string, c *x509.Certificate, gen int) { renewed = gen }
	resp, err := svc.RenewCert(peerCtx(uuid), &pb.RenewRequest{NodeUuid: uuid, CsrDer: csr})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(resp.NodeCert)
	if err != nil || cert.Subject.CommonName != uuid {
		t.Fatalf("bad renewed cert: %v", err)
	}
	if renewed != 2 {
		t.Fatalf("generation should be 2 after first renewal, got %d", renewed)
	}
}

func TestRenewCertDenials(t *testing.T) {
	svc, uuid, csr := enrolledService(t)
	// no peer info at all
	if _, err := svc.RenewCert(context.Background(), &pb.RenewRequest{NodeUuid: uuid, CsrDer: csr}); err == nil {
		t.Fatal("no peer must be rejected")
	}
	// peer without TLS state
	bare := peer.NewContext(context.Background(), &peer.Peer{})
	if _, err := svc.RenewCert(bare, &pb.RenewRequest{NodeUuid: uuid, CsrDer: csr}); err == nil {
		t.Fatal("non-mTLS peer must be rejected")
	}
	// CN mismatch (a node renewing someone else's identity)
	if _, err := svc.RenewCert(peerCtx("impostor"), &pb.RenewRequest{NodeUuid: uuid, CsrDer: csr}); err == nil {
		t.Fatal("CN mismatch must be rejected")
	}
	// unknown node
	if _, err := svc.RenewCert(peerCtx("ghost"), &pb.RenewRequest{NodeUuid: "ghost", CsrDer: csr}); err == nil {
		t.Fatal("unknown node must be rejected (funnels to re-enrollment)")
	}
	// bad CSR bytes
	if _, err := svc.RenewCert(peerCtx(uuid), &pb.RenewRequest{NodeUuid: uuid, CsrDer: []byte("junk")}); err == nil {
		t.Fatal("bad CSR must be rejected")
	}
	// tampered CSR signature: flip a byte near the end (inside the signature)
	bad := append([]byte(nil), csr...)
	bad[len(bad)-1] ^= 0xff
	if _, err := svc.RenewCert(peerCtx(uuid), &pb.RenewRequest{NodeUuid: uuid, CsrDer: bad}); err == nil {
		t.Fatal("CSR possession-proof failure must be rejected")
	}
	// revoked node: renewal refused, full re-enrollment required
	svc.Revoke(uuid)
	if _, err := svc.RenewCert(peerCtx(uuid), &pb.RenewRequest{NodeUuid: uuid, CsrDer: csr}); err == nil {
		t.Fatal("revoked node must be refused")
	}
	// Revoke of an unknown node is a no-op (no panic)
	svc.Revoke("nobody")
}
