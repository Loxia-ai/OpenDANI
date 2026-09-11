package kms

import (
	"context"
	"crypto"
	"os"
	"path/filepath"
	"testing"

	"dani.local/agent/pkg/dani"
)

func TestOpenBackends(t *testing.T) {
	// software (default + explicit)
	for _, spec := range []string{"", "software"} {
		p, err := Open(spec)
		if err != nil || p.KeyStore == nil || !p.Exportable {
			t.Fatalf("software spec %q: %v %+v", spec, err, p)
		}
	}
	// software-file: creates + reloads the same keystore
	fp := filepath.Join(t.TempDir(), "ca.kms")
	p1, err := Open("software-file:" + fp)
	if err != nil || p1.KeyStore == nil {
		t.Fatal(err)
	}
	pub1, _ := p1.KeyStore.GetPublicKey(context.Background(), dani.PurposeCASigning)
	if _, err := os.Stat(fp); err != nil {
		t.Fatal("software-file must persist")
	}
	p2, _ := Open("software-file:" + fp)
	pub2, _ := p2.KeyStore.GetPublicKey(context.Background(), dani.PurposeCASigning)
	if string(pub1) != string(pub2) {
		t.Fatal("software-file must reload the same key")
	}
	// remote: not exportable
	p3, err := Open("remote:https://hsm.internal")
	if err != nil || p3.Remote == nil || p3.Exportable {
		t.Fatalf("remote spec: %v %+v", err, p3)
	}
	// KS() returns the software backend for exportable providers and the remote for HSM providers,
	// both as the ca.KeyStore-shaped value handed to controller.GenesisWithKMS.
	if p, _ := Open("software"); p.KS() != interface {
		dani.KeyStore
		Signer(dani.KeyPurpose) (crypto.Signer, error)
	}(p.KeyStore) {
		t.Fatal("software KS() must return the software keystore")
	}
	if got, ok := p3.KS().(*RemoteKeyStore); !ok || got != p3.Remote {
		t.Fatalf("remote KS() must return the RemoteKeyStore, got %T", p3.KS())
	}
	// errors
	for _, bad := range []string{"software-file:", "remote:", "banana", "pkcs11:x"} {
		if _, err := Open(bad); err == nil {
			t.Fatalf("bad spec %q must error", bad)
		}
	}
}

func TestOpenSoftwareFileErrors(t *testing.T) {
	dir := t.TempDir()
	// corrupt existing file -> ImportSoftware error
	bad := filepath.Join(dir, "corrupt.kms")
	os.WriteFile(bad, []byte("not a keystore"), 0o600)
	if _, err := Open("software-file:" + bad); err == nil {
		t.Fatal("corrupt keystore file must error")
	}
	// unwritable path
	if _, err := Open("software-file:" + filepath.Join(dir, "no-dir", "x.kms")); err == nil {
		t.Fatal("unwritable keystore path must error")
	}
}
