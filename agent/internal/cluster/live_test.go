package cluster

// In-package coverage for the Raft-replicated registry: a real 2-node cluster over TCP transports
// (join via AddVoter), all three mutation types replicating to BOTH replicas, follower write-
// forwarding, and a full snapshot -> restore cycle through the raft FSM interfaces.

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"dani.local/agent/internal/registry"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := lis.Addr().String()
	lis.Close()
	return addr
}

func openReg(t *testing.T) *registry.Registry {
	t.Helper()
	r, err := registry.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func rec(uuid string) registry.NodeRecord {
	return registry.NodeRecord{UUID: uuid, CertSerial: "01", NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		Generation: 1, HardwareFprint: []byte{1}, Roles: []string{"worker"}, Class: "restricted"}
}

func waitRow(t *testing.T, r *registry.Registry, uuid string) *registry.Row {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for {
		if row, err := r.Get(context.Background(), uuid); err == nil {
			return row
		}
		if time.Now().After(deadline) {
			t.Fatalf("row %s never replicated", uuid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestTwoNodeReplicationAndForwarding(t *testing.T) {
	addrA, addrB := freeAddr(t), freeAddr(t)
	regA, regB := openReg(t), openReg(t)

	// A bootstraps ALONE (quorum of one), then B joins via AddVoter — the same sequence the Azure
	// multi-controller deploy uses.
	a, err := New(Config{ID: "a", RaftBind: addrA, Bootstrap: true,
		Peers: []Peer{{ID: "a", RaftAddr: addrA}}, Reg: regA})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err := a.WaitForLeader(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	if a.Transport() == nil {
		t.Fatal("transport accessor")
	}

	b, err := New(Config{ID: "b", RaftBind: addrB,
		Peers: []Peer{{ID: "a", RaftAddr: addrA}, {ID: "b", RaftAddr: addrB}}, Reg: regB})
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
	if !a.IsLeader() || b.IsLeader() {
		t.Fatal("a should lead, b should follow")
	}
	if _, id := b.LeaderID(); id != "a" { // LeaderID returns (address, id)
		t.Fatalf("leader id wrong: %s", id)
	}

	// all three mutation types through the LEADER replicate to BOTH registries
	if err := a.ApplyUpsert(rec("n1")); err != nil {
		t.Fatal(err)
	}
	if err := a.ApplyRenew(RenewArgs{UUID: "n1", Serial: "02", NotBefore: time.Now(),
		NotAfter: time.Now().Add(2 * time.Hour), Generation: 2}); err != nil {
		t.Fatal(err)
	}
	if err := a.ApplyLifecycle(LifecycleArgs{UUID: "n1", State: "draining"}); err != nil {
		t.Fatal(err)
	}
	for _, r := range []*registry.Registry{regA, regB} {
		row := waitRow(t, r, "n1")
		deadline := time.Now().Add(8 * time.Second)
		for row == nil || row.Generation != 2 || row.Lifecycle != "draining" {
			if time.Now().After(deadline) {
				t.Fatalf("replication incomplete: %+v", row)
			}
			time.Sleep(50 * time.Millisecond)
			row, _ = r.Get(context.Background(), "n1") // may transiently error on a slow replica
		}
	}

	// a write at the FOLLOWER forwards to the leader (Forward hook)
	var forwarded bool
	b.Forward = func(leaderID, leaderRaftAddr string, data []byte) error {
		forwarded = true
		return a.LocalApplyRaw(data) // stand-in for the mTLS hop controller provides
	}
	if err := b.ApplyUpsert(rec("n2")); err != nil {
		t.Fatal(err)
	}
	if !forwarded {
		t.Fatal("follower write must forward")
	}
	waitRow(t, regA, "n2")

	// follower without a Forward hook fails loudly; leader-only LocalApplyRaw on a follower too
	b.Forward = nil
	if err := b.ApplyUpsert(rec("n3")); err == nil {
		t.Fatal("follower without forwarder must error")
	}
	if err := b.LocalApplyRaw([]byte("x")); err == nil {
		t.Fatal("LocalApplyRaw on a follower must refuse")
	}
}

func TestFSMSnapshotRestore(t *testing.T) {
	// drive the raft FSM interfaces directly: snapshot a populated registry, restore into a fresh one
	regSrc := openReg(t)
	if err := regSrc.UpsertEnrolled(context.Background(), rec("s1")); err != nil {
		t.Fatal(err)
	}
	f := &fsm{reg: regSrc}
	snap, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	sink := &memSink{buf: &buf}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}
	snap.Release()

	regDst := openReg(t)
	f2 := &fsm{reg: regDst}
	if err := f2.Restore(nopReadCloser{&buf}); err != nil {
		t.Fatal(err)
	}
	if row, err := regDst.Get(context.Background(), "s1"); err != nil || row.Class != "restricted" {
		t.Fatalf("restore lost data: %+v %v", row, err)
	}
	// bad snapshot payload
	if err := f2.Restore(nopReadCloser{bytes.NewBufferString("{oops")}); err == nil {
		t.Fatal("garbage snapshot must error")
	}
}

func TestFSMApplyBranches(t *testing.T) {
	reg := openReg(t)
	f := &fsm{reg: reg}
	up, _ := EncodeUpsert(rec("x1"))
	if res := f.Apply(&raft.Log{Data: up}); res != nil {
		if err, ok := res.(error); ok && err != nil {
			t.Fatalf("apply upsert: %v", err)
		}
	}
	rn, _ := encodeRenew(RenewArgs{UUID: "x1", Serial: "03", NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), Generation: 3})
	f.Apply(&raft.Log{Data: rn})
	lc, _ := encodeLifecycle(LifecycleArgs{UUID: "x1", State: "revoked"})
	f.Apply(&raft.Log{Data: lc})
	row, err := reg.Get(context.Background(), "x1")
	if err != nil || row.Generation != 3 || row.Lifecycle != "revoked" {
		t.Fatalf("fsm apply chain wrong: %+v %v", row, err)
	}
	// malformed entry + unknown op
	if res := f.Apply(&raft.Log{Data: []byte("{oops")}); res == nil {
		t.Fatal("garbage log entry must yield an error result")
	}
	if res := f.Apply(&raft.Log{Data: []byte(`{"op":99,"v":{}}`)}); res == nil {
		t.Fatal("unknown op must yield an error result")
	}
}

func TestNewErrors(t *testing.T) {
	reg := openReg(t)
	if _, err := New(Config{ID: "x", RaftBind: "999.999.999.999:1", Reg: reg}); err == nil {
		t.Fatal("bad raft bind must error")
	}
}

// memSink implements raft.SnapshotSink over a buffer.
type memSink struct {
	buf *bytes.Buffer
}

func (m *memSink) Write(p []byte) (int, error) { return m.buf.Write(p) }
func (m *memSink) Close() error                { return nil }
func (m *memSink) ID() string                  { return "mem" }
func (m *memSink) Cancel() error               { return nil }

type nopReadCloser struct{ *bytes.Buffer }

func (nopReadCloser) Close() error { return nil }

func TestLocalApplyRawSurfacesFSMError(t *testing.T) {
	reg := openReg(t)
	a, err := New(Config{ID: "solo", RaftBind: freeAddr(t), Bootstrap: true,
		Peers: []Peer{{ID: "solo", RaftAddr: "unused"}}, Reg: reg})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err := a.WaitForLeader(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	// a malformed op applied through the real Raft leader -> the FSM returns an error result,
	// surfaced by LocalApplyRaw's fut.Response() path
	if err := a.LocalApplyRaw([]byte(`{"op":99,"v":{}}`)); err == nil {
		t.Fatal("unknown-op mutation must surface the FSM error")
	}
	if err := a.LocalApplyRaw([]byte("{not json")); err == nil {
		t.Fatal("malformed mutation must surface the FSM error")
	}
}

// failSink is a raft.SnapshotSink whose Write always fails.
type failSink struct{ cancelled bool }

func (f *failSink) Write([]byte) (int, error) { return 0, errFakeWrite }
func (f *failSink) Close() error              { return nil }
func (f *failSink) ID() string                { return "fail" }
func (f *failSink) Cancel() error             { f.cancelled = true; return nil }

var errFakeWrite = fmtErrorf("sink write boom")

func fmtErrorf(s string) error { return &strErr{s} }

type strErr struct{ s string }

func (e *strErr) Error() string { return e.s }

func TestSnapshotPersistErrorAndRelease(t *testing.T) {
	reg := openReg(t)
	reg.UpsertEnrolled(context.Background(), rec("s1"))
	snap, err := (&fsm{reg: reg}).Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	fs := &failSink{}
	if err := snap.Persist(fs); err == nil {
		t.Fatal("a failing sink must surface the write error")
	}
	if !fs.cancelled {
		t.Fatal("Persist must Cancel the sink on write failure")
	}
	snap.Release() // no-op, but must not panic
}
