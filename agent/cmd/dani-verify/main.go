// Command dani-verify is the standalone OFFLINE auditor (ROADMAP deliverable): it verifies a DANI
// Compliance export bundle with no access to the live deployment — no database, no controller, no
// network. Hand the bundle file and this binary to a regulator; the verdict is reproducible anywhere.
//
//	dani-verify audit-seal.json
//	dani-verify --json audit-seal.json          machine-readable verdict
//	dani-verify --pub <base64 SPKI> seal.json   ALSO pin the expected audit-signing key
//	curl .../dani/audit/export | dani-verify -  read from stdin (accepts the endpoint wrapper too)
//
// What it checks (audit.VerifyBundle): the hash chain (every record re-hashed, sequence + prev-hash
// links), every KMS-signed head anchor, and the outer bundle seal. A bundle is SELF-DESCRIBING (it
// carries its signing public key), so without --pub a forger could fabricate a chain and self-sign
// it; pinning the deployment's known audit key closes that. Exit codes: 0 verified, 1 verification
// failed, 2 usage/read error.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"dani.local/agent/internal/audit"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run is the testable entrypoint.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("dani-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "emit the verdict as JSON")
	pubPin := fs.String("pub", "", "pin the expected audit-signing public key (base64 SPKI DER, or @file)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: dani-verify [--json] [--pub <b64|@file>] <bundle.json | ->")
		return 2
	}

	data, err := readInput(fs.Arg(0), stdin)
	if err != nil {
		fmt.Fprintf(stderr, "dani-verify: read: %v\n", err)
		return 2
	}
	bundle, err := decodeBundle(data)
	if err != nil {
		fmt.Fprintf(stderr, "dani-verify: %v\n", err)
		return 2
	}

	// Optional key pin: the bundle must be signed by the DEPLOYMENT'S key, not merely self-consistent.
	pinned := ""
	if *pubPin != "" {
		want, err := loadPin(*pubPin)
		if err != nil {
			fmt.Fprintf(stderr, "dani-verify: pin: %v\n", err)
			return 2
		}
		if !bytes.Equal(want, bundle.BundlePub) {
			return verdict(stdout, *jsonOut, bundle, audit.Integrity{
				Records: int64(len(bundle.Events)), SignedHeads: len(bundle.Heads),
				Why: "bundle signing key does not match the pinned deployment key",
			})
		}
		pinned = " (signing key matches the pinned deployment key)"
	}

	integ, err := audit.VerifyBundle(bundle)
	if err != nil {
		fmt.Fprintf(stderr, "dani-verify: verify: %v\n", err)
		return 2
	}
	if integ.OK && pinned != "" {
		integ.Why = "" // clean verdict; the pin note is printed separately
	}
	code := verdict(stdout, *jsonOut, bundle, integ)
	if integ.OK && !*jsonOut {
		fmt.Fprintf(stdout, "  key pin: %s\n", map[bool]string{true: "verified" + pinned, false: "not pinned (pass --pub to require the deployment's known key)"}[pinned != ""])
	}
	return code
}

// readInput loads the bundle bytes from a path or stdin ("-").
func readInput(arg string, stdin io.Reader) ([]byte, error) {
	if arg == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(arg)
}

// decodeBundle accepts either a raw ComplianceBundle (ExportFile output) or the gateway
// /dani/audit/export response, which wraps it as {"bundle": {...}}.
func decodeBundle(data []byte) (*audit.ComplianceBundle, error) {
	var wrapper struct {
		Bundle *audit.ComplianceBundle `json:"bundle"`
	}
	if err := json.Unmarshal(data, &wrapper); err == nil && wrapper.Bundle != nil && len(wrapper.Bundle.BundleSig) > 0 {
		return wrapper.Bundle, nil
	}
	var b audit.ComplianceBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("not a compliance bundle: %w", err)
	}
	if len(b.BundleSig) == 0 || len(b.Events) == 0 {
		return nil, fmt.Errorf("not a compliance bundle (missing events or bundle seal)")
	}
	return &b, nil
}

// loadPin decodes the pinned public key: base64 SPKI DER, or @file containing it.
func loadPin(s string) ([]byte, error) {
	if len(s) > 1 && s[0] == '@' {
		data, err := os.ReadFile(s[1:])
		if err != nil {
			return nil, err
		}
		s = string(bytes.TrimSpace(data))
	}
	return base64.StdEncoding.DecodeString(s)
}

// verdict prints the outcome and returns the exit code (0 verified, 1 failed).
func verdict(w io.Writer, asJSON bool, b *audit.ComplianceBundle, integ audit.Integrity) int {
	if asJSON {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"deployment": b.Deployment, "exportedAt": b.ExportedAt, "verdict": integ,
		})
	} else if integ.OK {
		fmt.Fprintf(w, "VERIFIED: deployment %q — %d records, %d signed heads, chain + head signatures + bundle seal all valid\n",
			b.Deployment, integ.Records, integ.SignedHeads)
	} else {
		fmt.Fprintf(w, "FAILED: deployment %q — %s", b.Deployment, integ.Why)
		if integ.BrokenAt > 0 {
			fmt.Fprintf(w, " (at seq %d)", integ.BrokenAt)
		}
		fmt.Fprintln(w)
	}
	if integ.OK {
		return 0
	}
	return 1
}
