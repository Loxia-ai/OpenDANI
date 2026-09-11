package engine

import (
	"context"
	"testing"
	"time"
)

func TestStubChat(t *testing.T) {
	e := NewStub("test-slm")
	if e.Name() != "stub" {
		t.Fatalf("name = %q", e.Name())
	}
	if err := e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	res, err := e.Chat(context.Background(), Request{
		Model:     "test-slm",
		Messages:  []Message{{Role: "system", Content: "be brief"}, {Role: "user", Content: "what is in-perimeter inference?"}},
		MaxTokens: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Text == "" {
		t.Fatal("empty completion")
	}
	if res.CompletionTokens == 0 || res.CompletionTokens > 64 {
		t.Fatalf("completion tokens out of range: %d", res.CompletionTokens)
	}
	if res.PromptTokens == 0 {
		t.Fatal("expected non-zero prompt tokens")
	}
	if res.Engine != "stub" || res.Model != "test-slm" {
		t.Fatalf("unexpected engine/model: %+v", res)
	}
	// deterministic: same prompt → same canned template
	res2, _ := e.Chat(context.Background(), Request{Messages: []Message{{Role: "user", Content: "what is in-perimeter inference?"}}})
	if res2.Text != res.Text {
		t.Fatal("stub should be deterministic for the same prompt")
	}
}

func TestStubRespectsContextCancel(t *testing.T) {
	e := NewStub("slow")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	// the stub paces tokens over ~hundreds of ms; a 10ms deadline must cancel it.
	if _, err := e.Chat(ctx, Request{Messages: []Message{{Role: "user", Content: "a very long answer please"}}, MaxTokens: 256}); err == nil {
		t.Fatal("expected context cancellation to abort the paced generation")
	}
}

func TestStubMaxTokensCap(t *testing.T) {
	e := NewStub("m")
	res, err := e.Chat(context.Background(), Request{Messages: []Message{{Role: "user", Content: "hi"}}, MaxTokens: 3})
	if err != nil {
		t.Fatal(err)
	}
	if res.CompletionTokens > 3 {
		t.Fatalf("completion exceeded max_tokens cap: %d", res.CompletionTokens)
	}
}

func TestStubHotLoad(t *testing.T) {
	s := NewStub("base")
	if err := s.Load("ft-1", []byte("w")); err != nil {
		t.Fatal(err)
	}
	if err := s.Load("ft-1", []byte("w")); err != nil { // idempotent
		t.Fatal(err)
	}
	s.Load("ft-2", nil)
	got := s.Loaded()
	if len(got) != 2 || got[0] != "ft-1" || got[1] != "ft-2" {
		t.Fatalf("loaded wrong: %v", got)
	}
	// the returned slice is a copy
	got[0] = "mutated"
	if s.Loaded()[0] != "ft-1" {
		t.Fatal("Loaded must return a copy")
	}
}

func TestStubUnload(t *testing.T) {
	s := NewStub("m")
	_ = s.Load("ft-1", []byte("w"))
	_ = s.Load("ft-2", []byte("w"))
	if err := s.Unload("ft-1"); err != nil || len(s.Loaded()) != 1 || s.Loaded()[0] != "ft-2" {
		t.Fatalf("unload: %v %v", err, s.Loaded())
	}
	if err := s.Unload("ghost"); err != nil { // no-op
		t.Fatal(err)
	}
}
