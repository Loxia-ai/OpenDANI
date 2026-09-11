// Package secret resolves a secret REFERENCE to its value, so secrets never have to live in
// command-line flags, process args, or logs (PRODUCTION-READINESS P0-3). A reference is one of:
//
//	env:NAME       read from environment variable NAME   (Kubernetes Secret -> env; the default)
//	file:/path     read from a file (trimmed)            (Kubernetes Secret / Docker secret -> file)
//	<literal>      the value itself                       (dev only; discouraged — logged as a warning)
//
// The point: an operator sets --oidc-client-secret=env:OIDC_CLIENT_SECRET and the actual value comes
// from a mounted Secret at runtime — it is never in the flag, the ps output, the shell history, or a
// container manifest.
package secret

import (
	"fmt"
	"os"
	"strings"
)

// Resolve turns a reference into its value. Empty ref -> empty (a caller may treat that as "unset").
func Resolve(ref string) (string, error) {
	switch {
	case ref == "":
		return "", nil
	case strings.HasPrefix(ref, "env:"):
		name := strings.TrimPrefix(ref, "env:")
		v, ok := os.LookupEnv(name)
		if !ok {
			return "", fmt.Errorf("secret: env var %q is not set", name)
		}
		return v, nil
	case strings.HasPrefix(ref, "file:"):
		path := strings.TrimPrefix(ref, "file:")
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("secret: read %s: %w", path, err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	default:
		return ref, nil // literal
	}
}

// IsLiteral reports whether a reference is an inline literal (so callers can warn — a literal secret
// on the command line is a footgun in production).
func IsLiteral(ref string) bool {
	return ref != "" && !strings.HasPrefix(ref, "env:") && !strings.HasPrefix(ref, "file:")
}

// Redact returns a safe-to-log placeholder for a secret value (never log the value itself).
func Redact(v string) string {
	if v == "" {
		return "(empty)"
	}
	return fmt.Sprintf("(set, %d chars, redacted)", len(v))
}

// RedactDSN makes a database DSN safe to log: URL DSNs (postgres://user:pw@host/db) get their
// userinfo stripped; plain paths (SQLite) carry no credentials and pass through unchanged.
func RedactDSN(dsn string) string {
	scheme, rest, ok := strings.Cut(dsn, "://")
	if !ok {
		return dsn
	}
	if _, host, hasCreds := strings.Cut(rest, "@"); hasCreds {
		return scheme + "://***@" + host
	}
	return dsn
}
