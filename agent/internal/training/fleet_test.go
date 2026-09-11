package training

import (
	"context"
	"errors"
	"testing"
)

type fakeLister struct {
	uuids []string
	err   error
}

func (f fakeLister) ActiveNodesWithRole(context.Context, string) ([]string, error) {
	return f.uuids, f.err
}

func TestRegistryFleet(t *testing.T) {
	// happy path with an explicit context: first trainer wins (registry orders by UUID); registry-only
	// allocation has no address (local execution).
	f := RegistryFleet{Reg: fakeLister{uuids: []string{"trainer-a", "trainer-b"}}, Ctx: context.Background()}
	if u, addr, ok := f.ActiveTrainer(); !ok || u != "trainer-a" || addr != "" {
		t.Fatalf("expected trainer-a with no addr, got %q %q ok=%v", u, addr, ok)
	}
	// nil context defaults to context.Background() (no panic).
	f2 := RegistryFleet{Reg: fakeLister{uuids: []string{"t"}}}
	if u, _, ok := f2.ActiveTrainer(); !ok || u != "t" {
		t.Fatalf("nil-ctx path failed: %q %v", u, ok)
	}
	// no trainer nodes.
	f3 := RegistryFleet{Reg: fakeLister{uuids: nil}}
	if _, _, ok := f3.ActiveTrainer(); ok {
		t.Fatal("expected no trainer")
	}
	// registry error.
	f4 := RegistryFleet{Reg: fakeLister{err: errors.New("db down")}}
	if _, _, ok := f4.ActiveTrainer(); ok {
		t.Fatal("registry error should yield no trainer")
	}
}
