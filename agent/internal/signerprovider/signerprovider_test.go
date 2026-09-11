package signerprovider

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"dani.local/agent/internal/artifact"
	"dani.local/agent/internal/kms"
	"dani.local/agent/internal/modelreg"
	"dani.local/agent/pkg/dani"
)

func hsmStub(t *testing.T) *httptest.Server {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mux := http.NewServeMux()
	mux.HandleFunc("/public", func(w http.ResponseWriter, _ *http.Request) {
		der, _ := x509.MarshalPKIXPublicKey(pub)
		json.NewEncoder(w).Encode(map[string]string{"pub": base64.StdEncoding.EncodeToString(der)})
	})
	mux.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Payload string }
		json.NewDecoder(r.Body).Decode(&in)
		p, _ := base64.StdEncoding.DecodeString(in.Payload)
		json.NewEncoder(w).Encode(map[string]string{"sig": base64.StdEncoding.EncodeToString(ed25519.Sign(priv, p))})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestBuildBackends(t *testing.T) {
	shared, _ := kms.NewSoftware()
	// kms (default) + empty both resolve to the shared KMS
	for _, spec := range []string{"", "kms"} {
		s, err := Build(spec, dani.PurposeModelSignSecurity, shared)
		if err != nil {
			t.Fatalf("kms spec %q: %v", spec, err)
		}
		if _, ok := s.(modelreg.KMSRoleSigner); !ok {
			t.Fatalf("kms spec must yield KMSRoleSigner, got %T", s)
		}
	}
	// kms with no shared keystore -> error
	if _, err := Build("kms", dani.PurposeModelSignSecurity, nil); err == nil {
		t.Fatal("kms backend without a keystore must error")
	}
	// file: creates a persisted keystore
	dir := t.TempDir()
	fp := filepath.Join(dir, "gov.kms")
	s, err := Build("file:"+fp, dani.PurposeModelSignGovernance, shared)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.(modelreg.KMSRoleSigner); !ok {
		t.Fatalf("file spec must yield KMSRoleSigner, got %T", s)
	}
	if _, err := os.Stat(fp); err != nil {
		t.Fatal("file backend must persist the keystore")
	}
	// re-Build loads the SAME persisted keystore (same public key)
	pub1, _ := s.Public(t.Context())
	s2, _ := Build("file:"+fp, dani.PurposeModelSignGovernance, shared)
	pub2, _ := s2.Public(t.Context())
	if string(pub1) != string(pub2) {
		t.Fatal("file backend must reload the same key")
	}
	// remote:
	srv := hsmStub(t)
	rs, err := Build("remote:"+srv.URL, dani.PurposeModelSignAdmin, shared)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rs.(modelreg.RemoteRoleSigner); !ok {
		t.Fatalf("remote spec must yield RemoteRoleSigner, got %T", rs)
	}
	// error specs
	for _, bad := range []string{"file:", "remote:", "banana", "pkcs11:whatever"} {
		if _, err := Build(bad, dani.PurposeModelSignSecurity, shared); err == nil {
			t.Fatalf("spec %q must error", bad)
		}
	}
}

func TestParseSpecMap(t *testing.T) {
	m, err := ParseSpecMap("security=remote:https://a, governance=file:/k/g ,admin=kms")
	if err != nil {
		t.Fatal(err)
	}
	if m[modelreg.RoleSecurity] != "remote:https://a" || m[modelreg.RoleGovernance] != "file:/k/g" || m[modelreg.RoleAdmin] != "kms" {
		t.Fatalf("parse wrong: %+v", m)
	}
	if got, _ := ParseSpecMap(""); len(got) != 0 {
		t.Fatal("blank spec map must be empty")
	}
	for _, bad := range []string{"security", "=kms", "security=", "bogus=kms"} {
		if _, err := ParseSpecMap(bad); err == nil {
			t.Fatalf("bad spec map %q must error", bad)
		}
	}
}

// TestBuildAllEndToEndPromotion: three roles wired to three DIFFERENT backends (kms + file + remote)
// promote a real candidate — the KMS-provider seam works end-to-end across mixed custodians.
func TestBuildAllEndToEndPromotion(t *testing.T) {
	shared, _ := kms.NewSoftware()
	store, _ := artifact.Open(t.TempDir())
	srv := hsmStub(t)
	specs := map[modelreg.Role]string{
		modelreg.RoleSecurity:   "kms",
		modelreg.RoleGovernance: "file:" + filepath.Join(t.TempDir(), "gov.kms"),
		modelreg.RoleAdmin:      "remote:" + srv.URL,
	}
	signers, err := BuildAll(specs, shared)
	if err != nil {
		t.Fatal(err)
	}
	r := modelreg.New(shared, store).WithRoleSigners(signers)
	if err := r.InitSigners(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.SubmitCandidate(t.Context(), modelreg.CandidateMeta{ID: "m", Name: "m", Version: "1",
		Engine: "e", Lineage: &modelreg.Lineage{}}, "adapter", []byte("bytes")); err != nil {
		t.Fatal(err)
	}
	for _, role := range []modelreg.Role{modelreg.RoleSecurity, modelreg.RoleGovernance, modelreg.RoleAdmin} {
		if _, err := r.Sign(t.Context(), "m", role); err != nil {
			t.Fatalf("sign %s: %v", role, err)
		}
	}
	e := r.Get("m")
	if e.State != "available" || !r.VerifyApproval("m") {
		t.Fatalf("mixed-backend promotion must succeed: %+v", e)
	}
	// BuildAll surfaces a bad spec
	if _, err := BuildAll(map[modelreg.Role]string{modelreg.RoleSecurity: "nonsense"}, shared); err == nil {
		t.Fatal("BuildAll must surface a bad spec")
	}
}

// TestFileBackendErrors: a corrupt keystore file and an unwritable path both fail (real I/O paths).
func TestFileBackendErrors(t *testing.T) {
	dir := t.TempDir()
	// corrupt existing file -> ImportSoftware fails
	bad := filepath.Join(dir, "corrupt.kms")
	os.WriteFile(bad, []byte("not a keystore"), 0o600)
	if _, err := Build("file:"+bad, dani.PurposeModelSignSecurity, nil); err == nil {
		t.Fatal("corrupt keystore file must error")
	}
	// unwritable path (parent dir does not exist) -> persist fails
	if _, err := Build("file:"+filepath.Join(dir, "no-such-dir", "x.kms"), dani.PurposeModelSignSecurity, nil); err == nil {
		t.Fatal("unwritable keystore path must error")
	}
}
