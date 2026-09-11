package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dani.local/agent/internal/audit"
	"dani.local/agent/internal/kms"
)

// makeBundle produces a REAL sealed bundle (live audit.Log + KMS) and its signing key (base64 SPKI).
func makeBundle(t *testing.T) (*audit.ComplianceBundle, string) {
	t.Helper()
	ks, _ := kms.NewSoftware()
	l, err := audit.Open(context.Background(), ":memory:", ks)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for i, typ := range []string{"genesis", "node.enrolled", "model.approved"} {
		if err := l.Emit(typ, map[string]any{"i": i}); err != nil {
			t.Fatal(err)
		}
		if err := l.SignHead(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	b, err := l.Export(context.Background(), "dep-1")
	if err != nil {
		t.Fatal(err)
	}
	return b, base64.StdEncoding.EncodeToString(b.BundlePub)
}

func writeBundle(t *testing.T, b *audit.ComplianceBundle) string {
	t.Helper()
	data, _ := json.Marshal(b)
	p := filepath.Join(t.TempDir(), "seal.json")
	os.WriteFile(p, data, 0o600)
	return p
}

func runCLI(t *testing.T, args []string, stdin string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestVerifyCleanBundle(t *testing.T) {
	b, pub := makeBundle(t)
	p := writeBundle(t, b)
	// plain
	code, out, _ := runCLI(t, []string{p}, "")
	if code != 0 || !strings.Contains(out, "VERIFIED") || !strings.Contains(out, "3 records") {
		t.Fatalf("clean bundle: code=%d out=%s", code, out)
	}
	if !strings.Contains(out, "not pinned") {
		t.Fatal("unpinned run must nudge toward --pub")
	}
	// with the CORRECT pin
	code, out, _ = runCLI(t, []string{"--pub", pub, p}, "")
	if code != 0 || !strings.Contains(out, "matches the pinned deployment key") {
		t.Fatalf("pinned verify: code=%d out=%s", code, out)
	}
	// JSON verdict
	code, out, _ = runCLI(t, []string{"--json", p}, "")
	var v struct {
		Deployment string          `json:"deployment"`
		Verdict    audit.Integrity `json:"verdict"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &v) != nil || !v.Verdict.OK || v.Deployment != "dep-1" {
		t.Fatalf("json verdict: code=%d out=%s", code, out)
	}
}

func TestVerifyTamperedBundle(t *testing.T) {
	b, _ := makeBundle(t)
	b.Events[1].Payload = json.RawMessage(`{"i":999}`)
	p := writeBundle(t, b)
	code, out, _ := runCLI(t, []string{p}, "")
	if code != 1 || !strings.Contains(out, "FAILED") || !strings.Contains(out, "seq 2") {
		t.Fatalf("tampered bundle must fail with location: code=%d out=%s", code, out)
	}
	// JSON failure verdict
	code, out, _ = runCLI(t, []string{"--json", p}, "")
	if code != 1 || !strings.Contains(out, `"ok":false`) {
		t.Fatalf("json failure: code=%d out=%s", code, out)
	}
}

func TestPinMismatch(t *testing.T) {
	b, _ := makeBundle(t)
	_, otherPub := makeBundle(t) // a different deployment's key
	p := writeBundle(t, b)
	code, out, _ := runCLI(t, []string{"--pub", otherPub, p}, "")
	if code != 1 || !strings.Contains(out, "does not match the pinned deployment key") {
		t.Fatalf("wrong pin must fail: code=%d out=%s", code, out)
	}
}

func TestPinFromFileAndBadPin(t *testing.T) {
	b, pub := makeBundle(t)
	p := writeBundle(t, b)
	pinFile := filepath.Join(t.TempDir(), "audit.pub")
	os.WriteFile(pinFile, []byte(pub+"\n"), 0o600)
	code, out, _ := runCLI(t, []string{"--pub", "@" + pinFile, p}, "")
	if code != 0 || !strings.Contains(out, "VERIFIED") {
		t.Fatalf("@file pin: code=%d out=%s", code, out)
	}
	// bad base64 pin -> usage error
	if code, _, _ := runCLI(t, []string{"--pub", "!!!", p}, ""); code != 2 {
		t.Fatal("bad pin base64 must exit 2")
	}
	// missing pin file -> usage error
	if code, _, _ := runCLI(t, []string{"--pub", "@/no/such/file", p}, ""); code != 2 {
		t.Fatal("missing pin file must exit 2")
	}
}

func TestStdinAndEndpointWrapper(t *testing.T) {
	b, _ := makeBundle(t)
	// the gateway /dani/audit/export wrapper shape
	wrapped, _ := json.Marshal(map[string]any{"deployment": b.Deployment, "bundle": b})
	code, out, _ := runCLI(t, []string{"-"}, string(wrapped))
	if code != 0 || !strings.Contains(out, "VERIFIED") {
		t.Fatalf("stdin + wrapper: code=%d out=%s", code, out)
	}
}

func TestUsageAndReadErrors(t *testing.T) {
	if code, _, _ := runCLI(t, nil, ""); code != 2 {
		t.Fatal("no args must exit 2")
	}
	if code, _, _ := runCLI(t, []string{"a", "b"}, ""); code != 2 {
		t.Fatal("two args must exit 2")
	}
	if code, _, _ := runCLI(t, []string{"--nope"}, ""); code != 2 {
		t.Fatal("bad flag must exit 2")
	}
	if code, _, errs := runCLI(t, []string{"/no/such/bundle.json"}, ""); code != 2 || !strings.Contains(errs, "read") {
		t.Fatal("missing file must exit 2")
	}
	// not-a-bundle inputs
	bad := filepath.Join(t.TempDir(), "x.json")
	os.WriteFile(bad, []byte(`{"hello":"world"}`), 0o600)
	if code, _, errs := runCLI(t, []string{bad}, ""); code != 2 || !strings.Contains(errs, "not a compliance bundle") {
		t.Fatalf("non-bundle JSON must exit 2: %s", errs)
	}
	os.WriteFile(bad, []byte(`{not json`), 0o600)
	if code, _, _ := runCLI(t, []string{bad}, ""); code != 2 {
		t.Fatal("malformed JSON must exit 2")
	}
}
