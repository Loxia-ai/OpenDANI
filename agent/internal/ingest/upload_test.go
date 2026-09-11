package ingest

import (
	"strings"
	"testing"
)

func TestAddCustomAndIngest(t *testing.T) {
	s := New()
	// happy path: upload -> listed -> ingests like any corpus
	class, err := s.AddCustom("contracts-2026", []string{
		"The renewal clause fixes pricing for 24 months.",
		"  ", // empty docs are dropped, not chunked
		"Termination requires 90 days written notice and a risk assessment.",
	}, "internal")
	if err != nil || class != "internal" {
		t.Fatalf("AddCustom: %v %q", err, class)
	}
	found := false
	for _, n := range s.AvailableCorpora() {
		if n == "contracts-2026" {
			found = true
		}
	}
	if !found {
		t.Fatalf("uploaded corpus must be listed: %v", s.AvailableCorpora())
	}
	col, err := s.Ingest("contracts-2026")
	if err != nil || col.Connector != "upload" || len(col.Chunks) == 0 {
		t.Fatalf("ingest of upload: %v %+v", err, col)
	}
	// content classification can only RAISE the source class (D-09 direction): the "risk" doc
	// classifies restricted even though the upload declared internal
	raised := false
	for _, ch := range col.Chunks {
		if strings.Contains(ch.Text, "risk") && ch.Classification == "restricted" {
			raised = true
		}
		if ch.Source != "upload" {
			t.Fatalf("lineage must record the upload connector: %+v", ch)
		}
	}
	if !raised {
		t.Fatal("content scan must raise the risk doc to restricted")
	}
	// default class when omitted
	if class, err := s.AddCustom("notes", []string{"plain text"}, ""); err != nil || class != "internal" {
		t.Fatalf("default class: %v %q", err, class)
	}
}

func TestAddCustomRejections(t *testing.T) {
	s := New()
	cases := []struct {
		name, class string
		docs        []string
	}{
		{"", "internal", []string{"x"}},              // no name
		{"c1", "internal", nil},                      // no docs
		{"legal", "internal", []string{"x"}},         // clashes with a built-in corpus
		{"c2", "banana", []string{"x"}},              // unknown classification
		{"c3", "internal", []string{"", "   ", "	"}}, // only empty docs
	}
	for _, c := range cases {
		if _, err := s.AddCustom(c.name, c.docs, c.class); err == nil {
			t.Fatalf("AddCustom(%q,%v,%q) must be rejected", c.name, c.docs, c.class)
		}
	}
}
