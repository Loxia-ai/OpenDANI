package main

import "testing"

// a public volunteer node must be inference-only — no code-execution surface.
func TestEnforceOpenWorkerSafety(t *testing.T) {
	if err := enforceOpenWorkerSafety("worker", ""); err != nil {
		t.Fatalf("a plain worker is allowed: %v", err)
	}
	if err := enforceOpenWorkerSafety("trainer", ""); err == nil {
		t.Fatal("the trainer role executes code — must be refused for an open node")
	}
	if err := enforceOpenWorkerSafety("TRAINER", ""); err == nil {
		t.Fatal("role check must be case-insensitive")
	}
	if err := enforceOpenWorkerSafety("worker", "python train.py"); err == nil {
		t.Fatal("a --trainer-exec is a code-execution surface — must be refused for an open node")
	}
}
