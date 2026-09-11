package hwcaps

import "testing"

// The default probes are thin closures over os/exec + filepath; exercise them directly so the
// package holds the 100%-coverage bar on any build machine (results are machine-dependent —
// we assert behavior, not hardware).
func TestDefaultProbesExercised(t *testing.T) {
	p := defaultProbes()
	if p.goos == "" || p.goarch == "" {
		t.Fatal("goos/goarch must be populated")
	}
	if _, err := p.lookPath("definitely-not-a-real-binary-xyz"); err == nil {
		t.Fatal("lookPath should fail for a nonsense binary")
	}
	if _, err := p.runCommand("definitely-not-a-real-binary-xyz"); err == nil {
		t.Fatal("runCommand should fail for a nonsense binary")
	}
	if m := p.glob("[]"); m != nil { // invalid pattern -> empty, never panic
		t.Fatalf("glob on bad pattern should be empty, got %v", m)
	}
	_ = p.glob("/dev/dri/renderD*") // representative real pattern: must not panic anywhere
}
