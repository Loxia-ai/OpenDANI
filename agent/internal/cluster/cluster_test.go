package cluster

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"dani.local/agent/internal/registry"
)

func sampleRec(uuid string) registry.NodeRecord {
	return registry.NodeRecord{
		UUID: uuid, CertSerial: "01", NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		Generation: 1, HardwareFprint: []byte{0xab}, Roles: []string{"worker"}, Class: "restricted", Site: "hq", Tier: 0,
	}
}

func waitCount(t *testing.T, reg *registry.Registry, want int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if n, _ := reg.Count(context.Background()); n == want {
			return
		}
		time.Sleep(30 * time.Millisecond)
	}
	n, _ := reg.Count(context.Background())
	t.Fatalf("registry never reached count %d (got %d) within %s", want, n, within)
}

func leaderOf(nodes []*Node) *Node {
	for _, n := range nodes {
		if n.IsLeader() {
			return n
		}
	}
	return nil
}

// Three controllers, one Raft-replicated registry. A mutation applied on the leader appears on EVERY
// controller's local replica; after the leader dies, a new one is elected and replication continues.
func TestClusterReplicatesAndFailsOver(t *testing.T) {
	const n = 3
	regs := make([]*registry.Registry, n)
	trs := make([]*raft.InmemTransport, n)
	addrs := make([]raft.ServerAddress, n)
	for i := 0; i < n; i++ {
		r, err := registry.Open(context.Background(), ":memory:")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = r.Close() })
		regs[i] = r
		a, tr := raft.NewInmemTransport("")
		addrs[i], trs[i] = a, tr
	}
	// fully connect the in-memory transports
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i != j {
				trs[i].Connect(addrs[j], trs[j])
			}
		}
	}
	peers := make([]Peer, n)
	ids := []string{"ctrl-0", "ctrl-1", "ctrl-2"}
	for i := 0; i < n; i++ {
		peers[i] = Peer{ID: ids[i], RaftAddr: string(addrs[i])}
	}

	nodes := make([]*Node, n)
	for i := 0; i < n; i++ {
		nd, err := New(Config{ID: ids[i], Reg: regs[i], Transport: trs[i], FastElect: true, Bootstrap: i == 0, Peers: peers})
		if err != nil {
			t.Fatalf("New ctrl-%d: %v", i, err)
		}
		nodes[i] = nd
	}
	if err := nodes[0].WaitForLeader(5 * time.Second); err != nil {
		t.Fatal(err)
	}

	// apply on the leader → all three replicas converge
	ldr := leaderOf(nodes)
	if ldr == nil {
		t.Fatal("no leader")
	}
	if err := ldr.ApplyUpsert(sampleRec("worker-1")); err != nil {
		t.Fatalf("apply: %v", err)
	}
	for i := 0; i < n; i++ {
		waitCount(t, regs[i], 1, 3*time.Second)
	}
	t.Logf("replicated worker-1 to all %d controllers (leader=%s)", n, func() string { _, id := ldr.LeaderID(); return id }())

	// kill the leader; a new one must take over and keep replicating
	deadIdx := -1
	for i, nd := range nodes {
		if nd == ldr {
			deadIdx = i
			break
		}
	}
	_ = ldr.Close()

	var newLdr *Node
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if l := leaderOf(nodes); l != nil && l != ldr {
			newLdr = l
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if newLdr == nil {
		t.Fatal("no new leader elected after failover")
	}
	if err := newLdr.ApplyUpsert(sampleRec("worker-2")); err != nil {
		t.Fatalf("apply after failover: %v", err)
	}
	for i := 0; i < n; i++ {
		if i == deadIdx {
			continue // the dead controller won't advance
		}
		waitCount(t, regs[i], 2, 3*time.Second)
	}
	t.Logf("after failover, new leader replicated worker-2 to the surviving controllers")

	for i, nd := range nodes {
		if i != deadIdx {
			_ = nd.Close()
		}
	}
}
