package main

import (
	"strings"
	"testing"
)

// a fully-hardened posture passes with the expected advisories.
func goodProd() prodInputs {
	return prodInputs{
		demo: false, gwTLS: true, consoleAuth: true, admit: "manual",
		statePath: "/var/lib/dani/authority.json", auditDB: "/var/lib/dani/audit.db",
		kmsSpec: "pkcs11:slot=0", backupDir: "/backups", replicateFrom: "https://peer:8444",
	}
}

func TestProductionGatePasses(t *testing.T) {
	warns, err := productionGate(goodProd())
	if err != nil {
		t.Fatalf("hardened posture must pass: %v", err)
	}
	if len(warns) != 0 {
		t.Fatalf("fully-provisioned posture should have no warnings: %v", warns)
	}
}

// every hard violation is caught INDIVIDUALLY and named in the error.
func TestProductionGateCatchesEachViolation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*prodInputs)
		expect string
	}{
		{"demo on", func(p *prodInputs) { p.demo = true }, "--demo is ON"},
		{"plaintext gateway", func(p *prodInputs) { p.gwTLS = false }, "gateway is plaintext"},
		{"console auth off", func(p *prodInputs) { p.consoleAuth = false }, "console auth is OFF"},
		{"auto admit", func(p *prodInputs) { p.admit = "auto" }, "admission is \"auto\""},
		{"no state", func(p *prodInputs) { p.statePath = "" }, "NEW CA"},
		{"memory audit", func(p *prodInputs) { p.auditDB = "" }, ":memory:"},
	} {
		in := goodProd()
		tc.mutate(&in)
		_, err := productionGate(in)
		if err == nil || !strings.Contains(err.Error(), tc.expect) {
			t.Fatalf("%s: gate must name the violation %q, got: %v", tc.name, tc.expect, err)
		}
	}
}

// ALL violations are reported at once — one restart to fix everything, not six.
func TestProductionGateAggregates(t *testing.T) {
	_, err := productionGate(prodInputs{demo: true, admit: "auto"}) // everything wrong
	if err == nil {
		t.Fatal("must refuse")
	}
	for _, want := range []string{"--demo is ON", "plaintext", "console auth", "manual", "NEW CA", ":memory:"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("aggregated error missing %q:\n%v", want, err)
		}
	}
	if n := strings.Count(err.Error(), "\n  - "); n != 6 {
		t.Fatalf("expected 6 aggregated violations, got %d:\n%v", n, err)
	}
}

// the behind-ingress escape hatch works but earns a warning; soft gaps warn without refusing.
func TestProductionGateWarnings(t *testing.T) {
	in := goodProd()
	in.gwTLS = false
	in.plainGateway = true
	in.kmsSpec = ""
	in.backupDir = ""
	in.replicateFrom = ""
	warns, err := productionGate(in)
	if err != nil {
		t.Fatalf("advisories must not refuse: %v", err)
	}
	joined := strings.Join(warns, " | ")
	for _, want := range []string{"software keystore", "backup", "warm copy", "terminates upstream"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing warning %q in: %s", want, joined)
		}
	}
}
