package cluster

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"encoding/json"

	"github.com/hashicorp/raft"
)

// fakeModelSink is a minimal ModelSink for exercising model-registry replication without importing
// modelreg (keeps cluster dependency-free) — it records the last snapshot the FSM loaded.
type fakeModelSink struct {
	mu   sync.Mutex
	last []byte
	snap []byte
	err  error
}

func (f *fakeModelSink) LoadSnapshotBytes(b []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.last = append([]byte{}, b...)
	return nil
}
func (f *fakeModelSink) SnapshotBytes() []byte { return f.snap }
func (f *fakeModelSink) loaded() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.last
}

// TestModelSnapshotReplication: a promotion snapshot applied at the LEADER replicates into every
// controller's model sink — the whole point of D-18 (any controller routes the same promoted models).
func TestModelSnapshotReplication(t *testing.T) {
	addrA, addrB := freeAddr(t), freeAddr(t)
	regA, regB := openReg(t), openReg(t)
	sinkA, sinkB := &fakeModelSink{}, &fakeModelSink{}

	a, err := New(Config{ID: "a", RaftBind: addrA, Bootstrap: true,
		Peers: []Peer{{ID: "a", RaftAddr: addrA}}, Reg: regA, Models: sinkA})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err := a.WaitForLeader(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	b, err := New(Config{ID: "b", RaftBind: addrB,
		Peers: []Peer{{ID: "a", RaftAddr: addrA}, {ID: "b", RaftAddr: addrB}}, Reg: regB, Models: sinkB})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := a.AddVoter("b", addrB); err != nil {
		t.Fatal(err)
	}
	if err := b.WaitForLeader(10 * time.Second); err != nil {
		t.Fatal(err)
	}

	promo := []byte(`{"models":{"m1":{"ID":"m1","State":"available"}}}`)
	if err := a.ApplyModelSnapshot(promo); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*fakeModelSink{sinkA, sinkB} {
		deadline := time.Now().Add(8 * time.Second)
		for !bytes.Equal(s.loaded(), promo) {
			if time.Now().After(deadline) {
				t.Fatalf("model snapshot did not replicate: got %s", s.loaded())
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	// a promotion at the FOLLOWER forwards to the leader
	var forwarded bool
	b.Forward = func(_, _ string, data []byte) error {
		forwarded = true
		return a.LocalApplyRaw(data)
	}
	promo2 := []byte(`{"models":{"m2":{"ID":"m2","State":"available"}}}`)
	if err := b.ApplyModelSnapshot(promo2); err != nil {
		t.Fatal(err)
	}
	if !forwarded {
		t.Fatal("follower promotion must forward to the leader")
	}
	deadline := time.Now().Add(8 * time.Second)
	for !bytes.Equal(sinkA.loaded(), promo2) {
		if time.Now().After(deadline) {
			t.Fatal("forwarded promotion did not apply at the leader")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestFSMModelApplyAndSnapshot: OpModelSnapshot dispatch (with and without a sink) and the combined
// FSM snapshot/restore carrying model state to a joiner.
func TestFSMModelApplyAndSnapshot(t *testing.T) {
	// apply with no sink wired -> no-op, no error
	f0 := &fsm{reg: openReg(t)}
	ms, _ := (&Node{}).encodeModel([]byte(`{"models":{}}`))
	if res := f0.Apply(&raft.Log{Data: ms}); res != nil {
		if err, ok := res.(error); ok && err != nil {
			t.Fatalf("model apply with nil sink must be a no-op: %v", err)
		}
	}
	// apply WITH a sink -> loads the snapshot
	sink := &fakeModelSink{}
	f := &fsm{reg: openReg(t), models: sink}
	if res := f.Apply(&raft.Log{Data: ms}); res != nil {
		if err, ok := res.(error); ok && err != nil {
			t.Fatalf("model apply: %v", err)
		}
	}
	if sink.loaded() == nil {
		t.Fatal("sink must receive the snapshot")
	}

	// combined snapshot carries the model bytes; restore delivers them to a joiner's sink
	src := &fsm{reg: openReg(t), models: &fakeModelSink{snap: []byte(`{"models":{"z":{"ID":"z"}}}`)}}
	snap, err := src.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := snap.Persist(&memSink{buf: &buf}); err != nil {
		t.Fatal(err)
	}
	dstSink := &fakeModelSink{}
	dst := &fsm{reg: openReg(t), models: dstSink}
	if err := dst.Restore(nopReadCloser{&buf}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(dstSink.loaded(), []byte(`"z"`)) {
		t.Fatalf("restore must deliver model snapshot to the joiner: %s", dstSink.loaded())
	}
}

// encodeModel is a tiny test shim mirroring ApplyModelSnapshot's wire encoding without a live raft.
func (n *Node) encodeModel(snap []byte) ([]byte, error) {
	return json.Marshal(Mutation{Op: OpModelSnapshot, Data: snap})
}
