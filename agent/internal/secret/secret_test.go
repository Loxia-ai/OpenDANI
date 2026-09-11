package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolve(t *testing.T) {
	// literal
	if v, err := Resolve("plainvalue"); err != nil || v != "plainvalue" {
		t.Fatalf("literal: %v %q", err, v)
	}
	// env
	os.Setenv("DANI_TEST_SECRET", "s3cr3t")
	if v, err := Resolve("env:DANI_TEST_SECRET"); err != nil || v != "s3cr3t" {
		t.Fatalf("env: %v %q", err, v)
	}
	if _, err := Resolve("env:DANI_MISSING_XYZ"); err == nil {
		t.Fatal("missing env must error")
	}
	// file (trailing newline trimmed)
	dir := t.TempDir()
	f := filepath.Join(dir, "sec")
	os.WriteFile(f, []byte("filesecret\n"), 0o600)
	if v, err := Resolve("file:" + f); err != nil || v != "filesecret" {
		t.Fatalf("file: %v %q", err, v)
	}
	if _, err := Resolve("file:/no/such/path"); err == nil {
		t.Fatal("missing file must error")
	}
	// empty
	if v, err := Resolve(""); err != nil || v != "" {
		t.Fatalf("empty: %v %q", err, v)
	}
}

func TestIsLiteralAndRedact(t *testing.T) {
	if !IsLiteral("plain") || IsLiteral("env:X") || IsLiteral("file:/x") || IsLiteral("") {
		t.Fatal("IsLiteral wrong")
	}
	// Redact never reveals the value
	if r := Redact("supersecret"); strings.Contains(r, "supersecret") {
		t.Fatalf("Redact leaked the value: %q", r)
	}
	if Redact("") != "(empty)" {
		t.Fatal("empty redact")
	}
}

func TestRedactDSN(t *testing.T) {
	// URL DSN with credentials -> userinfo stripped, host/db kept (debuggable, not leaky)
	if got := RedactDSN("postgres://dani:hunter2@db.internal:5432/dani"); got != "postgres://***@db.internal:5432/dani" {
		t.Fatalf("RedactDSN url: %q", got)
	}
	if got := RedactDSN("postgres://dani:hunter2@db/x"); strings.Contains(got, "hunter2") {
		t.Fatalf("RedactDSN leaked the password: %q", got)
	}
	// URL without credentials passes through
	if got := RedactDSN("postgres://db.internal/dani"); got != "postgres://db.internal/dani" {
		t.Fatalf("RedactDSN no-creds: %q", got)
	}
	// plain SQLite path passes through
	if got := RedactDSN(`C:\data\ingest.db`); got != `C:\data\ingest.db` {
		t.Fatalf("RedactDSN path: %q", got)
	}
}
