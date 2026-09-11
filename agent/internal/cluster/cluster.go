package cluster

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"

	"dani.local/agent/internal/registry"
)

// Peer is a controller in the Raft cluster.
type Peer struct {
	ID       string // unique server id (controller id)
	RaftAddr string // raft transport address (host:port)
}

// Config configures a controller's cluster membership.
type Config struct {
	ID        string             // this controller's id
	RaftBind  string             // TCP raft bind (host:port); ignored if Transport is set
	Advertise string             // advertised raft addr (defaults to RaftBind)
	DataDir   string             // bolt store dir; "" = in-memory stores (tests)
	Bootstrap bool               // bootstrap a new cluster from Peers (exactly one controller)
	Peers     []Peer             // initial server set (used when Bootstrap)
	Reg       *registry.Registry // local registry replica (the FSM target)
	Models    ModelSink          // local model-registry replica (optional; enables promotion replication)
	Transport raft.Transport     // injected transport (tests); nil = build TCP from RaftBind
	FastElect bool               // tighten timeouts (tests)
}

// Node is a controller's handle to the Raft-replicated registry.
type Node struct {
	raft *raft.Raft
	fsm  *fsm
	id   string
	tr   raft.Transport
	// Forward sends a mutation to the leader when this node is a follower (set by the controller to a
	// POST to the leader's /cluster/apply endpoint). nil = single-node / leader-only.
	Forward func(leaderID, leaderRaftAddr string, data []byte) error
}

// New starts (or joins) the Raft cluster and returns the node handle.
func New(c Config) (*Node, error) {
	if c.Reg == nil {
		return nil, errors.New("cluster: nil registry")
	}
	cfg := raft.DefaultConfig()
	cfg.LocalID = raft.ServerID(c.ID)
	if c.FastElect {
		cfg.HeartbeatTimeout = 200 * time.Millisecond
		cfg.ElectionTimeout = 200 * time.Millisecond
		cfg.LeaderLeaseTimeout = 100 * time.Millisecond
		cfg.CommitTimeout = 20 * time.Millisecond
	}

	f := &fsm{reg: c.Reg, models: c.Models}

	var logStore raft.LogStore
	var stableStore raft.StableStore
	var snaps raft.SnapshotStore
	if c.DataDir == "" {
		logStore = raft.NewInmemStore()
		stableStore = raft.NewInmemStore()
		snaps = raft.NewInmemSnapshotStore()
	} else {
		if err := os.MkdirAll(c.DataDir, 0o755); err != nil {
			return nil, err
		}
		bolt, err := raftboltdb.NewBoltStore(filepath.Join(c.DataDir, "raft.db"))
		if err != nil {
			return nil, fmt.Errorf("bolt store: %w", err)
		}
		logStore, stableStore = bolt, bolt
		fs, err := raft.NewFileSnapshotStore(c.DataDir, 2, os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("snapshot store: %w", err)
		}
		snaps = fs
	}

	tr := c.Transport
	if tr == nil {
		adv := c.Advertise
		if adv == "" {
			adv = c.RaftBind
		}
		addr, err := raftTCP(c.RaftBind, adv)
		if err != nil {
			return nil, err
		}
		tr = addr
	}

	r, err := raft.NewRaft(cfg, f, logStore, stableStore, snaps, tr)
	if err != nil {
		return nil, fmt.Errorf("raft: %w", err)
	}
	n := &Node{raft: r, fsm: f, id: c.ID, tr: tr}

	if c.Bootstrap {
		servers := make([]raft.Server, 0, len(c.Peers))
		for _, p := range c.Peers {
			servers = append(servers, raft.Server{ID: raft.ServerID(p.ID), Address: raft.ServerAddress(p.RaftAddr)})
		}
		if len(servers) == 0 { // single-node
			servers = []raft.Server{{ID: cfg.LocalID, Address: tr.LocalAddr()}}
		}
		if err := r.BootstrapCluster(raft.Configuration{Servers: servers}).Error(); err != nil &&
			!errors.Is(err, raft.ErrCantBootstrap) {
			return nil, fmt.Errorf("bootstrap: %w", err)
		}
	}
	return n, nil
}

func raftTCP(bind, advertise string) (raft.Transport, error) {
	addr, err := net.ResolveTCPAddr("tcp", advertise)
	if err != nil {
		return nil, fmt.Errorf("resolve advertise %q: %w", advertise, err)
	}
	return raft.NewTCPTransport(bind, addr, 3, 10*time.Second, os.Stderr)
}

// Transport exposes the raft transport (used by tests to wire in-memory transports together).
func (n *Node) Transport() raft.Transport { return n.tr }

// IsLeader reports whether this node is the current Raft leader.
func (n *Node) IsLeader() bool { return n.raft.State() == raft.Leader }

// LeaderID returns the current leader's (address, id).
func (n *Node) LeaderID() (string, string) {
	addr, id := n.raft.LeaderWithID()
	return string(addr), string(id)
}

// Members returns the raft membership (id + raft address per controller) from the replicated
// configuration — the same view every peer agrees on. Empty on a config read error.
func (n *Node) Members() []Peer {
	f := n.raft.GetConfiguration()
	if f.Error() != nil {
		return nil
	}
	var out []Peer
	for _, s := range f.Configuration().Servers {
		out = append(out, Peer{ID: string(s.ID), RaftAddr: string(s.Address)})
	}
	return out
}

// WaitForLeader blocks until a leader is elected or timeout.
func (n *Node) WaitForLeader(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, id := n.raft.LeaderWithID(); id != "" {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return errors.New("no leader elected within timeout")
}

// AddVoter adds a peer (leader only) — used when controllers join an existing cluster.
func (n *Node) AddVoter(id, raftAddr string) error {
	return n.raft.AddVoter(raft.ServerID(id), raft.ServerAddress(raftAddr), 0, 10*time.Second).Error()
}

// ApplyUpsert/ApplyRenew/ApplyLifecycle replicate a registry mutation through the cluster.
func (n *Node) ApplyUpsert(rec registry.NodeRecord) error {
	data, err := encodeUpsert(rec)
	if err != nil {
		return err
	}
	return n.apply(data)
}
func (n *Node) ApplyRenew(a RenewArgs) error {
	data, err := encodeRenew(a)
	if err != nil {
		return err
	}
	return n.apply(data)
}
func (n *Node) ApplyLifecycle(a LifecycleArgs) error {
	data, err := encodeLifecycle(a)
	if err != nil {
		return err
	}
	return n.apply(data)
}

// ApplyModelSnapshot replicates a model-registry promotion snapshot through the cluster. snap is the
// registry's own serialized state (opaque to the FSM's node-registry path). A follower forwards it to
// the leader; the leader commits it, and every replica's FSM loads it — so any controller routes the
// same promoted models. This is what modelreg.SetReplicator points at.
func (n *Node) ApplyModelSnapshot(snap []byte) error {
	data, err := json.Marshal(Mutation{Op: OpModelSnapshot, Data: json.RawMessage(snap)})
	if err != nil {
		return err
	}
	return n.apply(data)
}

// apply commits a mutation: directly if leader, else forwards to the leader.
func (n *Node) apply(data []byte) error {
	if n.raft.State() == raft.Leader {
		return n.LocalApplyRaw(data)
	}
	if n.Forward == nil {
		return errors.New("cluster: not leader and no forwarder configured")
	}
	addr, id := n.raft.LeaderWithID()
	if id == "" {
		return errors.New("cluster: no leader")
	}
	return n.Forward(string(id), string(addr), data)
}

// LocalApplyRaw applies a pre-encoded mutation via the local Raft (must be leader). Also the target
// of a follower's Forward on the leader side.
func (n *Node) LocalApplyRaw(data []byte) error {
	fut := n.raft.Apply(data, 10*time.Second)
	if err := fut.Error(); err != nil {
		return err
	}
	if resp := fut.Response(); resp != nil {
		if e, ok := resp.(error); ok && e != nil {
			return e
		}
	}
	return nil
}

// Close shuts down the Raft node.
func (n *Node) Close() error {
	return n.raft.Shutdown().Error()
}
