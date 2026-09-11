package main

import "testing"

// the manual overrides + auto must map exactly; a typo must be safe (dial-only), never accidentally
// force a tunnel.
func TestParseReverseMode(t *testing.T) {
	for _, tc := range []struct {
		in                 string
		wantForce, wantAut bool
	}{
		{"off", false, false},
		{"", false, false},
		{"on", true, false},
		{"ON", true, false},
		{"force", true, false},
		{"auto", false, true},
		{"AUTO", false, true},
		{" auto ", false, true},
		{"banana", false, false}, // typo -> dial-only, not a surprise tunnel
	} {
		force, auto := parseReverseMode(tc.in)
		if force != tc.wantForce || auto != tc.wantAut {
			t.Fatalf("parseReverseMode(%q) = force %v auto %v, want %v %v", tc.in, force, auto, tc.wantForce, tc.wantAut)
		}
		if force && auto {
			t.Fatalf("%q produced BOTH force and auto — mutually exclusive", tc.in)
		}
	}
}
