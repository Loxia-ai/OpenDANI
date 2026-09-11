package enrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"dani.local/agent/internal/ca"
	pb "dani.local/agent/internal/gen/enrollmentv1"
	"dani.local/agent/internal/kms"
	"dani.local/agent/internal/openid"
)

func openService(t *testing.T, powBits int) *Service {
	t.Helper()
	ks, err := kms.NewSoftware()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := ca.Genesis(context.Background(), ks, "OpenNet")
	if err != nil {
		t.Fatal(err)
	}
	s := New(ks, authority, "dep-open")
	s.EnableOpenEnroll(powBits)
	return s
}

// the whole open path: self-mint a key, derive the id, solve PoW, enroll — no token, auto-approved.
func TestOpenEnrollEndToEnd(t *testing.T) {
	s := openService(t, 8)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	uuid := openid.DeriveUUID(pub)
	nonce, ok := openid.Solve("dep-open", uuid, 8, 1<<24)
	if !ok {
		t.Fatal("PoW solve failed")
	}
	ctx := context.Background()
	ch, err := s.EnrollBegin(ctx, &pb.EnrollBeginRequest{Token: openid.EncodeNonce(nonce), NodeUuid: uuid, NodeTime: "2026-01-01T00:00:00Z"})
	if err != nil {
		t.Fatalf("EnrollBegin: %v", err)
	}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: uuid}}, priv)
	pend, err := s.EnrollProof(ctx, &pb.EnrollProofRequest{RequestId: ch.RequestId, CsrDer: csrDER, CapabilityInventory: []byte("{}")})
	if err != nil {
		t.Fatalf("EnrollProof: %v", err)
	}
	// open joins are auto-approved inline
	if pend.Mode != pb.DrainMode_DRAIN_MODE_AUTO_POLICY {
		t.Fatalf("open join should be auto-approved, got mode %v", pend.Mode)
	}
	pr, err := s.EnrollPoll(ctx, &pb.EnrollPollRequest{RequestId: ch.RequestId})
	if err != nil || pr.Status != pb.EnrollPollResponse_STATUS_APPROVED || pr.Complete == nil {
		t.Fatalf("poll should be APPROVED with a cert: %v %+v", err, pr)
	}
	cert, err := x509.ParseCertificate(pr.Complete.NodeCert)
	if err != nil || cert.Subject.CommonName != uuid {
		t.Fatalf("issued cert wrong: %v CN=%q", err, cert.Subject.CommonName)
	}
}

// a bad / too-weak proof-of-work is rejected at EnrollBegin.
func TestOpenEnrollRejectsBadPoW(t *testing.T) {
	s := openService(t, 20) // require 20 bits
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	uuid := openid.DeriveUUID(pub)
	// nonce 0 almost certainly does not satisfy 20 bits
	_, err := s.EnrollBegin(context.Background(), &pb.EnrollBeginRequest{Token: openid.EncodeNonce(0), NodeUuid: uuid, NodeTime: "2026-01-01T00:00:00Z"})
	if err == nil {
		t.Fatal("a weak proof-of-work must be rejected")
	}
}

// a non-open uuid (operator-style name) is refused in open mode.
func TestOpenEnrollRejectsNonOpenUUID(t *testing.T) {
	s := openService(t, 0) // even at 0 bits, the id shape is enforced
	_, err := s.EnrollBegin(context.Background(), &pb.EnrollBeginRequest{Token: openid.EncodeNonce(0), NodeUuid: "worker-7", NodeTime: "2026-01-01T00:00:00Z"})
	if err == nil {
		t.Fatal("a non-self-minted id must be rejected in open mode")
	}
}

// claiming an open id whose key you do NOT hold is caught at EnrollProof (id/key binding).
func TestOpenEnrollRejectsKeyMismatch(t *testing.T) {
	s := openService(t, 0)
	pubA, _, _ := ed25519.GenerateKey(rand.Reader)
	uuidA := openid.DeriveUUID(pubA) // the victim's id
	_, privB, _ := ed25519.GenerateKey(rand.Reader)
	ctx := context.Background()
	ch, err := s.EnrollBegin(ctx, &pb.EnrollBeginRequest{Token: openid.EncodeNonce(0), NodeUuid: uuidA, NodeTime: "2026-01-01T00:00:00Z"})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	// prove possession of key B while claiming id A -> must be rejected
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: uuidA}}, privB)
	if _, err := s.EnrollProof(ctx, &pb.EnrollProofRequest{RequestId: ch.RequestId, CsrDer: csrDER, CapabilityInventory: []byte("{}")}); err == nil {
		t.Fatal("claiming another node's open id with a different key must be rejected")
	}
}

// the enterprise token path still works when open mode is OFF (no regression).
func TestTokenPathStillWorksWhenOpenOff(t *testing.T) {
	ks, _ := kms.NewSoftware()
	authority, _ := ca.Genesis(context.Background(), ks, "Ent")
	s := New(ks, authority, "dep-1") // open NOT enabled
	tok, _, err := IssueToken(context.Background(), ks, "dep-1", []string{"worker"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnrollBegin(context.Background(), &pb.EnrollBeginRequest{Token: tok, NodeUuid: "worker-1", NodeTime: "2026-01-01T00:00:00Z"}); err != nil {
		t.Fatalf("enterprise token path must still work: %v", err)
	}
}
