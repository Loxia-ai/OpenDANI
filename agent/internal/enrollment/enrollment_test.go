package enrollment

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"

	"dani.local/agent/internal/ca"
	pb "dani.local/agent/internal/gen/enrollmentv1"
	"dani.local/agent/internal/kms"
	"dani.local/agent/pkg/dani"
)

type failRNG struct{}

func (failRNG) Read([]byte) (int, error) { return 0, errors.New("rng failure (injected)") }

// failingKS can make Sign / GetPublicKey fail to exercise token error handling.
type failingKS struct {
	*kms.SoftwareKeyStore
	failSign, failPub, failSigner bool
}

func (m *failingKS) Signer(p dani.KeyPurpose) (crypto.Signer, error) {
	if m.failSigner {
		return nil, errors.New("signer failure (injected)")
	}
	return m.SoftwareKeyStore.Signer(p)
}

func (m *failingKS) Sign(ctx context.Context, p dani.KeyPurpose, payload []byte) ([]byte, error) {
	if m.failSign {
		return nil, errors.New("sign failure (injected)")
	}
	return m.SoftwareKeyStore.Sign(ctx, p, payload)
}

func (m *failingKS) GetPublicKey(ctx context.Context, p dani.KeyPurpose) ([]byte, error) {
	if m.failPub {
		return nil, errors.New("getpublickey failure (injected)")
	}
	return m.SoftwareKeyStore.GetPublicKey(ctx, p)
}

func newSvc(t *testing.T) (*Service, *kms.SoftwareKeyStore, *ca.CA) {
	t.Helper()
	ks, err := kms.NewSoftware()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := ca.Genesis(context.Background(), ks, "AcmeBank")
	if err != nil {
		t.Fatal(err)
	}
	return New(ks, authority, "dep-1"), ks, authority
}

func TestTokenRoundTrip(t *testing.T) {
	ctx := context.Background()
	_, ks, _ := newSvc(t)
	tok, id, err := IssueToken(ctx, ks, "dep-1", []string{"worker"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	p, err := VerifyToken(ctx, ks, "dep-1", tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if p.TokenID != id {
		t.Fatalf("token id mismatch: %s != %s", p.TokenID, id)
	}
	if _, err := VerifyToken(ctx, ks, "other-deployment", tok); err == nil {
		t.Fatal("expected wrong-deployment rejection")
	}
	if _, err := VerifyToken(ctx, ks, "dep-1", []byte("garbage")); err == nil {
		t.Fatal("expected malformed-token rejection")
	}
	tok[len(tok)-1] ^= 0xff // tamper
	if _, err := VerifyToken(ctx, ks, "dep-1", tok); err == nil {
		t.Fatal("expected tamper rejection")
	}
}

func TestExpiredToken(t *testing.T) {
	ctx := context.Background()
	_, ks, _ := newSvc(t)
	tok, _, _ := IssueToken(ctx, ks, "dep-1", nil, -time.Second) // already expired
	if _, err := VerifyToken(ctx, ks, "dep-1", tok); err == nil {
		t.Fatal("expected expired-token rejection")
	}
}

// nodeCSR makes an Ed25519 key + a PKCS#10 CSR (the node proves key possession).
func nodeCSR(t *testing.T, cn string) (ed25519.PublicKey, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return pub, der
}

func TestFullHandshake(t *testing.T) {
	ctx := context.Background()
	svc, ks, authority := newSvc(t)
	tok, _, _ := IssueToken(ctx, ks, "dep-1", []string{"worker"}, time.Hour)

	// 1->2 EnrollBegin
	ch, err := svc.EnrollBegin(ctx, &pb.EnrollBeginRequest{
		Token: tok, NodeUuid: "worker-1", DeclaredRoles: []string{"worker"}, DeclaredClass: "restricted",
		NodeTime: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("EnrollBegin: %v", err)
	}

	// 3->4 EnrollProof (with a real CSR)
	_, csrDER := nodeCSR(t, "worker-1")
	pend, err := svc.EnrollProof(ctx, &pb.EnrollProofRequest{RequestId: ch.RequestId, CsrDer: csrDER, CapabilityInventory: []byte(`{"engines":["llama.cpp"]}`)})
	if err != nil {
		t.Fatalf("EnrollProof: %v", err)
	}
	if pend.Mode != pb.DrainMode_DRAIN_MODE_BATCH_CONFIRM {
		t.Fatalf("expected batch-confirm, got %v", pend.Mode)
	}

	// 5 poll -> waiting
	if pr, _ := svc.EnrollPoll(ctx, &pb.EnrollPollRequest{RequestId: ch.RequestId}); pr.Status != pb.EnrollPollResponse_STATUS_WAITING {
		t.Fatalf("expected WAITING, got %v", pr.Status)
	}
	if w := svc.Waiting(); len(w) != 1 {
		t.Fatalf("expected 1 waiting, got %d", len(w))
	}
	// PendingList carries the DECLARED attributes for the operator's approval screen
	if pl := svc.PendingList(); len(pl) != 1 || pl[0].ReqID != ch.RequestId || pl[0].NodeUUID == "" || pl[0].DeclaredClass == "" {
		t.Fatalf("PendingList must expose declared attributes: %+v", pl)
	}

	// approve with ASSIGNED attributes (may differ from declared)
	if _, err := svc.Approve(ctx, ch.RequestId, []string{"worker"}, "restricted", "site-hq"); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	// 5 poll -> approved + complete
	pr2, _ := svc.EnrollPoll(ctx, &pb.EnrollPollRequest{RequestId: ch.RequestId})
	if pr2.Status != pb.EnrollPollResponse_STATUS_APPROVED || pr2.Complete == nil {
		t.Fatalf("expected APPROVED+complete, got %v", pr2.Status)
	}

	// the issued node cert must chain to the CA and carry the assigned claims
	cert, err := x509.ParseCertificate(pr2.Complete.NodeCert)
	if err != nil {
		t.Fatalf("parse node cert: %v", err)
	}
	if err := authority.Verify(cert); err != nil {
		t.Fatalf("issued cert chain verify: %v", err)
	}
	cl, err := ca.Claims(cert)
	if err != nil {
		t.Fatalf("claims: %v", err)
	}
	if cl.Classification != "restricted" || len(cl.Roles) != 1 || cl.Roles[0] != "worker" || cl.SiteTag != "site-hq" {
		t.Fatalf("unexpected claims: %+v", cl)
	}

	// token burned on success: approving again is non-waiting
	if _, err := svc.Approve(ctx, ch.RequestId, nil, "", "site-hq"); err == nil {
		t.Fatal("expected re-approve to fail (already approved)")
	}
}

func TestEnrollBeginAndProofRejections(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newSvc(t)
	// bad token at begin
	if _, err := svc.EnrollBegin(ctx, &pb.EnrollBeginRequest{Token: []byte("garbage"), NodeTime: time.Now().Format(time.RFC3339)}); err == nil {
		t.Fatal("expected bad-token rejection at EnrollBegin")
	}
	// proof for unknown request
	if _, err := svc.EnrollProof(ctx, &pb.EnrollProofRequest{RequestId: "nope", CsrDer: []byte("x")}); err == nil {
		t.Fatal("expected unknown-request rejection at EnrollProof")
	}
}

func TestRejectPath(t *testing.T) {
	ctx := context.Background()
	svc, ks, _ := newSvc(t)
	tok, _, _ := IssueToken(ctx, ks, "dep-1", nil, time.Hour)
	ch, _ := svc.EnrollBegin(ctx, &pb.EnrollBeginRequest{Token: tok, NodeUuid: "n", NodeTime: time.Now().UTC().Format(time.RFC3339)})
	_, csr := nodeCSR(t, "n")
	if _, err := svc.EnrollProof(ctx, &pb.EnrollProofRequest{RequestId: ch.RequestId, CsrDer: csr}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Reject(ch.RequestId, "denied by SO"); err != nil {
		t.Fatal(err)
	}
	pr, _ := svc.EnrollPoll(ctx, &pb.EnrollPollRequest{RequestId: ch.RequestId})
	if pr.Status != pb.EnrollPollResponse_STATUS_REJECTED || pr.RejectReason == "" {
		t.Fatalf("expected REJECTED, got %v", pr.Status)
	}
	if err := svc.Reject(ch.RequestId, "again"); err == nil {
		t.Fatal("expected reject of a non-waiting request to fail")
	}
}

func TestBadCSRAndUnknownPollApprove(t *testing.T) {
	ctx := context.Background()
	svc, ks, _ := newSvc(t)
	tok, _, _ := IssueToken(ctx, ks, "dep-1", nil, time.Hour)
	ch, _ := svc.EnrollBegin(ctx, &pb.EnrollBeginRequest{Token: tok, NodeUuid: "n", NodeTime: time.Now().UTC().Format(time.RFC3339)})
	if _, err := svc.EnrollProof(ctx, &pb.EnrollProofRequest{RequestId: ch.RequestId, CsrDer: []byte("not-a-csr")}); err == nil {
		t.Fatal("expected bad-CSR rejection")
	}
	if pr, _ := svc.EnrollPoll(ctx, &pb.EnrollPollRequest{RequestId: "unknown"}); pr.Status != pb.EnrollPollResponse_STATUS_EXPIRED {
		t.Fatal("expected EXPIRED for an unknown poll")
	}
	if _, err := svc.Approve(ctx, "unknown", nil, "", ""); err == nil {
		t.Fatal("expected approve of unknown request to fail")
	}
}

func TestIssueTokenErrors(t *testing.T) {
	ctx := context.Background()
	base, _ := kms.NewSoftware()
	if _, _, err := IssueToken(ctx, &failingKS{SoftwareKeyStore: base, failSign: true}, "dep-1", nil, time.Hour); err == nil {
		t.Fatal("expected IssueToken to fail when Sign fails")
	}
	old := randReader
	randReader = failRNG{}
	_, _, err := IssueToken(ctx, base, "dep-1", nil, time.Hour)
	randReader = old
	if err == nil {
		t.Fatal("expected IssueToken to fail on nonce RNG error")
	}
}

func TestVerifyTokenErrors(t *testing.T) {
	ctx := context.Background()
	base, _ := kms.NewSoftware()
	good, _, _ := IssueToken(ctx, base, "dep-1", nil, time.Hour)
	if _, err := VerifyToken(ctx, &failingKS{SoftwareKeyStore: base, failPub: true}, "dep-1", good); err == nil {
		t.Fatal("expected VerifyToken to fail when GetPublicKey fails")
	}
	// valid signature over an undecodable payload
	garbage := []byte{0xff}
	sig, _ := base.Sign(ctx, dani.PurposeEnrollmentSigning, garbage)
	badPayload, _ := tokenCBOR.Marshal(signedToken{Payload: garbage, Sig: sig})
	if _, err := VerifyToken(ctx, base, "dep-1", badPayload); err == nil {
		t.Fatal("expected VerifyToken to fail decoding a bad payload")
	}
	// payload with an unparseable ExpiresAt
	bp, _ := tokenCBOR.Marshal(TokenPayload{TokenID: "t", DeploymentID: "dep-1", ExpiresAt: "not-a-time"})
	sig2, _ := base.Sign(ctx, dani.PurposeEnrollmentSigning, bp)
	badExp, _ := tokenCBOR.Marshal(signedToken{Payload: bp, Sig: sig2})
	if _, err := VerifyToken(ctx, base, "dep-1", badExp); err == nil {
		t.Fatal("expected VerifyToken to fail on a bad ExpiresAt")
	}
}

func TestEnrollBeginSkew(t *testing.T) {
	ctx := context.Background()
	svc, ks, _ := newSvc(t)
	tok, _, _ := IssueToken(ctx, ks, "dep-1", nil, time.Hour)
	ch, err := svc.EnrollBegin(ctx, &pb.EnrollBeginRequest{Token: tok, NodeUuid: "n", NodeTime: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	if !ch.SkewWarning {
		t.Fatal("expected a skew warning for a clock an hour off")
	}
}

func TestEnrollProofBadCSRSignature(t *testing.T) {
	ctx := context.Background()
	svc, ks, _ := newSvc(t)
	tok, _, _ := IssueToken(ctx, ks, "dep-1", nil, time.Hour)
	ch, _ := svc.EnrollBegin(ctx, &pb.EnrollBeginRequest{Token: tok, NodeUuid: "n", NodeTime: time.Now().UTC().Format(time.RFC3339)})
	_, csr := nodeCSR(t, "n")
	csr[len(csr)-5] ^= 0xff // corrupt a signature byte (structure still parses, signature fails)
	if _, err := svc.EnrollProof(ctx, &pb.EnrollProofRequest{RequestId: ch.RequestId, CsrDer: csr}); err == nil {
		t.Fatal("expected EnrollProof to fail on a bad CSR signature")
	}
}

func TestApproveTokenAlreadyConsumed(t *testing.T) {
	ctx := context.Background()
	svc, ks, _ := newSvc(t)
	tok, _, _ := IssueToken(ctx, ks, "dep-1", []string{"worker"}, time.Hour)
	enroll := func(uuid string) string {
		ch, _ := svc.EnrollBegin(ctx, &pb.EnrollBeginRequest{Token: tok, NodeUuid: uuid, NodeTime: time.Now().UTC().Format(time.RFC3339)})
		_, csr := nodeCSR(t, uuid)
		if _, err := svc.EnrollProof(ctx, &pb.EnrollProofRequest{RequestId: ch.RequestId, CsrDer: csr}); err != nil {
			t.Fatal(err)
		}
		return ch.RequestId
	}
	r1, r2 := enroll("a"), enroll("b") // two requests sharing one token
	if _, err := svc.Approve(ctx, r1, nil, "", "site"); err != nil {
		t.Fatalf("first approve: %v", err)
	}
	if _, err := svc.Approve(ctx, r2, nil, "", "site"); err == nil {
		t.Fatal("expected second approve to fail (token already consumed)")
	}
}

func TestOnApproveHook(t *testing.T) {
	ctx := context.Background()
	svc, ks, _ := newSvc(t)
	called := false
	svc.OnApprove = func(nodeUUID string, cert *x509.Certificate, roles []string, class, site string, caps []byte) {
		called = nodeUUID == "n" && class == "restricted"
	}
	tok, _, _ := IssueToken(ctx, ks, "dep-1", []string{"worker"}, time.Hour)
	ch, _ := svc.EnrollBegin(ctx, &pb.EnrollBeginRequest{Token: tok, NodeUuid: "n", NodeTime: time.Now().UTC().Format(time.RFC3339)})
	_, csr := nodeCSR(t, "n")
	if _, err := svc.EnrollProof(ctx, &pb.EnrollProofRequest{RequestId: ch.RequestId, CsrDer: csr}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Approve(ctx, ch.RequestId, []string{"worker"}, "restricted", "site-hq"); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("OnApprove hook was not invoked with the expected args")
	}
}

func TestRenewCertRequiresMutualMTLS(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newSvc(t)
	// no peer / no client cert in the context -> renewal must be refused
	if _, err := svc.RenewCert(ctx, &pb.RenewRequest{NodeUuid: "n"}); err == nil {
		t.Fatal("expected RenewCert without a client certificate to be refused")
	}
}

func TestEnrollPollExpired(t *testing.T) {
	ctx := context.Background()
	svc, ks, _ := newSvc(t)
	tok, _, _ := IssueToken(ctx, ks, "dep-1", nil, time.Hour)
	ch, _ := svc.EnrollBegin(ctx, &pb.EnrollBeginRequest{Token: tok, NodeUuid: "n", NodeTime: time.Now().UTC().Format(time.RFC3339)})
	_, csr := nodeCSR(t, "n")
	if _, err := svc.EnrollProof(ctx, &pb.EnrollProofRequest{RequestId: ch.RequestId, CsrDer: csr}); err != nil {
		t.Fatal(err)
	}
	old := nowFn
	nowFn = func() time.Time { return time.Now().Add(48 * time.Hour) } // past the 24h pending TTL
	defer func() { nowFn = old }()
	pr, _ := svc.EnrollPoll(ctx, &pb.EnrollPollRequest{RequestId: ch.RequestId})
	if pr.Status != pb.EnrollPollResponse_STATUS_EXPIRED {
		t.Fatalf("expected EXPIRED after the TTL, got %v", pr.Status)
	}
}

func TestApproveIssueFailure(t *testing.T) {
	ctx := context.Background()
	base, _ := kms.NewSoftware()
	authority, err := ca.Genesis(ctx, &failingKS{SoftwareKeyStore: base, failSigner: true}, "Acme")
	if err != nil {
		t.Fatal(err)
	}
	svc := New(base, authority, "dep-1")
	tok, _, _ := IssueToken(ctx, base, "dep-1", []string{"worker"}, time.Hour)
	ch, _ := svc.EnrollBegin(ctx, &pb.EnrollBeginRequest{Token: tok, NodeUuid: "n", NodeTime: time.Now().UTC().Format(time.RFC3339)})
	_, csr := nodeCSR(t, "n")
	if _, err := svc.EnrollProof(ctx, &pb.EnrollProofRequest{RequestId: ch.RequestId, CsrDer: csr}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Approve(ctx, ch.RequestId, nil, "", "site"); err == nil {
		t.Fatal("expected Approve to fail when cert issuance fails")
	}
}
