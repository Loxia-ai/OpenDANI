package modelreg

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dani.local/agent/internal/artifact"
	"dani.local/agent/internal/kms"
	"dani.local/agent/pkg/dani"
)

func newReg(t *testing.T) (*Registry, *artifact.Store) {
	t.Helper()
	ks, err := kms.NewSoftware()
	if err != nil {
		t.Fatal(err)
	}
	store, err := artifact.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := New(ks, store)
	if err := r.InitSigners(context.Background()); err != nil {
		t.Fatal(err)
	}
	return r, store
}

func fixedNow(t *testing.T) {
	t.Helper()
	orig := nowFn
	nowFn = func() time.Time { return time.Unix(1700000000, 0).UTC() }
	t.Cleanup(func() { nowFn = orig })
}

func TestRegisterDirectlyAvailable(t *testing.T) {
	r, _ := newReg(t)
	ctx := context.Background()
	e, err := r.Register(ctx, RegisterMeta{ID: "qwen2.5-1.5b", Name: "qwen", Version: "1", Engine: "llama.cpp", Aliases: []string{"q"}}, []byte("weights"))
	if err != nil {
		t.Fatal(err)
	}
	if e.State != "available" || e.Classification != "unrestricted" {
		t.Fatalf("bad entry %+v", e)
	}
	if r.Resolve("qwen2.5-1.5b") == nil || r.Resolve("qwen") == nil || r.Resolve("q") == nil {
		t.Fatal("should resolve by id, name, and alias")
	}
	if r.Resolve("nope") != nil {
		t.Fatal("unknown should not resolve")
	}
}

func TestThreeSignerPromotion(t *testing.T) {
	fixedNow(t)
	r, _ := newReg(t)
	ctx := context.Background()
	_, err := r.SubmitCandidate(ctx, CandidateMeta{
		ID: "qwen-ft-legal-v1", Name: "qwen-ft-legal", Version: "1", Engine: "llama.cpp",
		Classification: "restricted", Base: "qwen2.5-1.5b",
		Lineage: &Lineage{Base: "qwen2.5-1.5b", Method: "lora", Collection: "legal"},
		Evals:   map[string]float64{"task": 0.8},
	}, "adapter", []byte("adapter-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	// Draft is not routable.
	if r.Resolve("qwen-ft-legal-v1") != nil {
		t.Fatal("draft must not resolve")
	}
	if len(r.Drafts()) != 1 {
		t.Fatalf("expected 1 draft, got %d", len(r.Drafts()))
	}
	// Sign by two roles — still draft.
	if _, err := r.Sign(ctx, "qwen-ft-legal-v1", RoleSecurity); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Sign(ctx, "qwen-ft-legal-v1", RoleGovernance); err != nil {
		t.Fatal(err)
	}
	if r.Get("qwen-ft-legal-v1").State != "draft" {
		t.Fatal("two signatures must not promote")
	}
	if r.VerifyApproval("qwen-ft-legal-v1") {
		t.Fatal("two-of-three must not verify as approved")
	}
	// Third signature flips to available.
	e, err := r.Sign(ctx, "qwen-ft-legal-v1", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if e.State != "available" {
		t.Fatalf("three signatures must promote, got %s", e.State)
	}
	if r.Resolve("qwen-ft-legal-v1") == nil {
		t.Fatal("promoted model must resolve")
	}
	if !r.VerifyApproval("qwen-ft-legal-v1") {
		t.Fatal("promoted model must verify")
	}
}

func TestSignErrors(t *testing.T) {
	r, _ := newReg(t)
	ctx := context.Background()
	if _, err := r.Sign(ctx, "ghost", RoleSecurity); err == nil {
		t.Fatal("unknown model should error")
	}
	if _, err := r.Sign(ctx, "x", Role("mayor")); err == nil {
		t.Fatal("unknown role should error")
	}
	// Sign a non-draft (available) model.
	r.Register(ctx, RegisterMeta{ID: "base", Name: "base", Version: "1", Engine: "e"}, []byte("w"))
	if _, err := r.Sign(ctx, "base", RoleSecurity); err == nil {
		t.Fatal("signing a non-draft should error")
	}
}

func TestVerifyApprovalUnknown(t *testing.T) {
	r, _ := newReg(t)
	if r.VerifyApproval("nobody") {
		t.Fatal("unknown model is not approved")
	}
}

func TestTamperBreaksVerifyOnUse(t *testing.T) {
	r, _ := newReg(t)
	ctx := context.Background()
	r.SubmitCandidate(ctx, CandidateMeta{ID: "m", Name: "m", Version: "1", Engine: "e"}, "adapter", []byte("bytes"))
	for _, role := range signerRoles {
		if _, err := r.Sign(ctx, "m", role); err != nil {
			t.Fatal(err)
		}
	}
	if r.Resolve("m") == nil {
		t.Fatal("precondition: should resolve before tamper")
	}
	// Tamper: repoint the artifact hash. Signatures were over the original hash → verify fails.
	r.Get("m").Artifact.Hash = artifact.HashOf([]byte("evil"))
	if r.Resolve("m") != nil {
		t.Fatal("tampered artifact must stop routing (verify-on-use, DP13)")
	}
	if r.VerifyApproval("m") {
		t.Fatal("tampered artifact must fail approval verification")
	}
}

func TestVerifyRejectsGarbagePubDER(t *testing.T) {
	r, _ := newReg(t)
	ctx := context.Background()
	r.SubmitCandidate(ctx, CandidateMeta{ID: "m", Name: "m", Version: "1", Engine: "e"}, "adapter", []byte("bytes"))
	for _, role := range signerRoles {
		r.Sign(ctx, "m", role)
	}
	// Corrupt a stored public key → ParsePKIXPublicKey fails inside verify.
	e := r.Get("m")
	s := e.Signatures[RoleSecurity]
	s.PubDER = []byte("not-a-key")
	e.Signatures[RoleSecurity] = s
	if r.VerifyApproval("m") {
		t.Fatal("garbage pubDER must fail verification")
	}
}

func TestVerifyRejectsNonEd25519Key(t *testing.T) {
	r, _ := newReg(t)
	ctx := context.Background()
	r.SubmitCandidate(ctx, CandidateMeta{ID: "m", Name: "m", Version: "1", Engine: "e"}, "adapter", []byte("bytes"))
	for _, role := range signerRoles {
		r.Sign(ctx, "m", role)
	}
	// Swap in a valid-but-wrong-type SPKI (an RSA/ECDSA key marshals fine but isn't ed25519).
	e := r.Get("m")
	s := e.Signatures[RoleAdmin]
	s.PubDER = nonEd25519SPKI(t)
	e.Signatures[RoleAdmin] = s
	if r.VerifyApproval("m") {
		t.Fatal("non-ed25519 key must fail the type assertion in verify")
	}
}

// --- injected KMS failures for the Sign/GetPublicKey error branches ---

type failKS struct {
	dani.KeyStore
	failSign bool
	failPub  bool
}

func (f failKS) Sign(ctx context.Context, p dani.KeyPurpose, b []byte) ([]byte, error) {
	if f.failSign {
		return nil, errors.New("kms sign boom")
	}
	return f.KeyStore.Sign(ctx, p, b)
}
func (f failKS) GetPublicKey(ctx context.Context, p dani.KeyPurpose) ([]byte, error) {
	if f.failPub {
		return nil, errors.New("kms pub boom")
	}
	return f.KeyStore.GetPublicKey(ctx, p)
}

func TestInitSignersError(t *testing.T) {
	base, _ := kms.NewSoftware()
	store, _ := artifact.Open(t.TempDir())
	r := New(failKS{KeyStore: base, failPub: true}, store)
	if err := r.InitSigners(context.Background()); err == nil {
		t.Fatal("InitSigners should surface a KMS GetPublicKey failure")
	}
}

func TestSignKMSSignError(t *testing.T) {
	base, _ := kms.NewSoftware()
	store, _ := artifact.Open(t.TempDir())
	r := New(failKS{KeyStore: base, failSign: true}, store)
	ctx := context.Background()
	r.SubmitCandidate(ctx, CandidateMeta{ID: "m", Name: "m", Version: "1", Engine: "e"}, "adapter", []byte("b"))
	if _, err := r.Sign(ctx, "m", RoleSecurity); err == nil {
		t.Fatal("Sign should surface a KMS Sign failure")
	}
}

func TestSignKMSPubError(t *testing.T) {
	base, _ := kms.NewSoftware()
	store, _ := artifact.Open(t.TempDir())
	r := New(failKS{KeyStore: base, failPub: true}, store)
	ctx := context.Background()
	r.SubmitCandidate(ctx, CandidateMeta{ID: "m", Name: "m", Version: "1", Engine: "e"}, "adapter", []byte("b"))
	if _, err := r.Sign(ctx, "m", RoleSecurity); err == nil {
		t.Fatal("Sign should surface a KMS GetPublicKey failure")
	}
}

func TestRegisterPutError(t *testing.T) {
	ks, _ := kms.NewSoftware()
	dir := filepath.Join(t.TempDir(), "store")
	store, err := artifact.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Replace the store's directory with a regular file so any Put (write into dir/<hash>) fails.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := New(ks, store)
	ctx := context.Background()
	if _, err := r.Register(ctx, RegisterMeta{ID: "x", Name: "x", Version: "1", Engine: "e"}, []byte("w")); err == nil {
		t.Fatal("Register should surface an artifact Put failure")
	}
	if _, err := r.SubmitCandidate(ctx, CandidateMeta{ID: "y", Name: "y", Version: "1", Engine: "e"}, "adapter", []byte("w")); err == nil {
		t.Fatal("SubmitCandidate should surface an artifact Put failure")
	}
}

// nonEd25519SPKI returns a valid SPKI DER for a non-ed25519 key (ECDSA P-256), so verify's type
// assertion to ed25519.PublicKey fails.
func nonEd25519SPKI(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestRagAliases(t *testing.T) {
	r, _ := newReg(t)
	a := r.RegisterRagAlias("qwen2.5-0.5b", "legal")
	if a.Alias != "qwen2.5-0.5b-rag-legal" {
		t.Fatalf("alias name wrong: %s", a.Alias)
	}
	got, ok := r.ResolveRag(a.Alias)
	if !ok || got.BaseModelID != "qwen2.5-0.5b" || got.Collection != "legal" {
		t.Fatalf("resolve wrong: %+v ok=%v", got, ok)
	}
	if _, ok := r.ResolveRag("nope"); ok {
		t.Fatal("unknown alias must not resolve")
	}
	r.RegisterRagAlias("a-model", "hr")
	all := r.RagAliases()
	if len(all) != 2 || all[0].Alias != "a-model-rag-hr" {
		t.Fatalf("RagAliases must be ordered: %+v", all)
	}
}

func TestAllOrdered(t *testing.T) {
	r, _ := newReg(t)
	ctx := context.Background()
	r.Register(ctx, RegisterMeta{ID: "c", Name: "c", Version: "1", Engine: "e"}, []byte("1"))
	r.Register(ctx, RegisterMeta{ID: "a", Name: "a", Version: "1", Engine: "e"}, []byte("2"))
	r.Register(ctx, RegisterMeta{ID: "b", Name: "b", Version: "1", Engine: "e"}, []byte("3"))
	all := r.All()
	if len(all) != 3 || all[0].ID != "a" || all[1].ID != "b" || all[2].ID != "c" {
		t.Fatalf("All must be id-ordered, got %v", []string{all[0].ID, all[1].ID, all[2].ID})
	}
	if r.Get("zzz") != nil {
		t.Fatal("Get unknown should be nil")
	}
}

func TestEvalGate(t *testing.T) {
	// unit: the check() thresholds
	g := EvalGate{MinTask: 0.5, MinSafety: 0.8, MaxPerplexity: 20}
	if g.check(map[string]float64{"task": 0.6, "safety": 0.9, "eval_perplexity": 10}) != "" {
		t.Fatal("passing evals must clear the gate")
	}
	for _, ev := range []map[string]float64{
		{"task": 0.3, "safety": 0.9, "eval_perplexity": 10},   // task too low
		{"task": 0.6, "safety": 0.5, "eval_perplexity": 10},   // safety too low
		{"task": 0.6, "safety": 0.9, "eval_perplexity": 99},   // perplexity too high
	} {
		if g.check(ev) == "" {
			t.Fatalf("evals %v must fail the gate", ev)
		}
	}
	// a missing metric is not penalized (absent != failing)
	if (EvalGate{MinTask: 0.5}).check(map[string]float64{"safety": 0.9}) != "" {
		t.Fatal("absent task metric must not fail the gate")
	}
	// zero gate = no check
	if (EvalGate{}).check(map[string]float64{"task": 0.0}) != "" {
		t.Fatal("zero gate never fails")
	}
}

func TestSignGateBlocksLowQualityPromotion(t *testing.T) {
	r, _ := newReg(t)
	r.SetGate(EvalGate{MinTask: 0.7})
	ctx := context.Background()
	// a candidate below the task bar
	r.SubmitCandidate(ctx, CandidateMeta{ID: "weak", Name: "weak", Version: "1", Engine: "e",
		Evals: map[string]float64{"task": 0.2}}, "adapter", []byte("bytes"))
	var last *Entry
	for _, role := range signerRoles {
		last, _ = r.Sign(ctx, "weak", role)
	}
	// fully signed (3 sigs) but HELD at draft with a gate reason
	if last.State != "draft" || last.GateFailed == "" || len(last.Signatures) != 3 {
		t.Fatalf("low-quality candidate must be held: state=%s gate=%q sigs=%d", last.State, last.GateFailed, len(last.Signatures))
	}
	if r.Resolve("weak") != nil {
		t.Fatal("gate-held model must not route")
	}

	// a candidate that clears the bar promotes normally
	r.SubmitCandidate(ctx, CandidateMeta{ID: "strong", Name: "strong", Version: "1", Engine: "e",
		Evals: map[string]float64{"task": 0.9}}, "adapter", []byte("bytes2"))
	for _, role := range signerRoles {
		last, _ = r.Sign(ctx, "strong", role)
	}
	if last.State != "available" || last.GateFailed != "" {
		t.Fatalf("passing candidate must promote: %+v", last)
	}
	if r.Resolve("strong") == nil {
		t.Fatal("passing model must route")
	}
}
