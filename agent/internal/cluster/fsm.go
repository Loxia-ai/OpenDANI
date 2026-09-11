// Package cluster makes the Node Registry a Raft-replicated state machine (DL-R11-03b: hashicorp/raft
// + raft-boltdb), so a multi-controller deployment shares one consistent enrolled-node registry and
// ANY controller can serve routing with the same view. Durable registry mutations (enrollment
// admissions, renewals, lifecycle/revocation) go through the Raft log; the FSM applies each to every
// controller's local SQLite replica. Soft availability (heartbeat load) is NOT replicated through Raft
// — it's per-controller heartbeat state (spec §6.6: the Registry is consensus, beacons are gossip).
package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/hashicorp/raft"

	"dani.local/agent/internal/registry"
)

// Op is a replicated registry mutation kind.
type Op string

const (
	OpUpsert        Op = "upsert"         // admit/refresh an enrolled node
	OpRenew         Op = "renew"          // cert renewal (new serial/window/generation)
	OpLifecycle     Op = "lifecycle"      // active|draining|revoked|decommissioned
	OpModelSnapshot Op = "model-snapshot" // replicate the full model-registry snapshot (promotions)
)

// Mutation is one replicated log entry.
type Mutation struct {
	Op   Op              `json:"op"`
	Data json.RawMessage `json:"data"`
}

// RenewArgs is the payload for OpRenew.
type RenewArgs struct {
	UUID       string    `json:"uuid"`
	Serial     string    `json:"serial"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	Generation int       `json:"generation"`
}

// LifecycleArgs is the payload for OpLifecycle.
type LifecycleArgs struct {
	UUID  string `json:"uuid"`
	State string `json:"state"`
}

// encodeMutation builds a log entry; helpers keep call sites tidy.
func encodeUpsert(n registry.NodeRecord) ([]byte, error)   { return enc(OpUpsert, n) }

// EncodeUpsert exposes the wire encoding of an upsert mutation (write-forwarding + tests).
func EncodeUpsert(n registry.NodeRecord) ([]byte, error) { return encodeUpsert(n) }
func encodeRenew(a RenewArgs) ([]byte, error)               { return enc(OpRenew, a) }
func encodeLifecycle(a LifecycleArgs) ([]byte, error)       { return enc(OpLifecycle, a) }

func enc(op Op, v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Mutation{Op: op, Data: data})
}

// ModelSink is the replicated model-registry target (satisfied by *modelreg.Registry): the FSM loads
// replicated promotion snapshots into it on every replica. Kept as an interface so cluster does not
// import modelreg (avoids a dependency knot; the controller injects the concrete registry).
type ModelSink interface {
	LoadSnapshotBytes(data []byte) error
	SnapshotBytes() []byte
}

// fsm is the Raft finite state machine: it applies replicated mutations to the local node registry
// and (optionally) the local model registry.
type fsm struct {
	reg    *registry.Registry
	models ModelSink // nil when model-registry replication is not wired
}

func (f *fsm) Apply(l *raft.Log) interface{} {
	var m Mutation
	if err := json.Unmarshal(l.Data, &m); err != nil {
		return err
	}
	ctx := context.Background()
	switch m.Op {
	case OpUpsert:
		var n registry.NodeRecord
		if err := json.Unmarshal(m.Data, &n); err != nil {
			return err
		}
		return f.reg.UpsertEnrolled(ctx, n)
	case OpRenew:
		var a RenewArgs
		if err := json.Unmarshal(m.Data, &a); err != nil {
			return err
		}
		return f.reg.Renew(ctx, a.UUID, a.Serial, a.NotBefore, a.NotAfter, a.Generation)
	case OpLifecycle:
		var a LifecycleArgs
		if err := json.Unmarshal(m.Data, &a); err != nil {
			return err
		}
		return f.reg.SetLifecycle(ctx, a.UUID, a.State)
	case OpModelSnapshot:
		if f.models == nil {
			return nil // model replication not enabled on this controller
		}
		return f.models.LoadSnapshotBytes(m.Data)
	default:
		return fmt.Errorf("unknown mutation op %q", m.Op)
	}
}

// fsmSnap is the combined FSM snapshot: node-registry rows plus the model-registry snapshot, so a
// joining controller catches up on BOTH the enrolled fleet and the promoted models in one restore.
type fsmSnap struct {
	Nodes  []registry.RegRow `json:"nodes"`
	Models json.RawMessage   `json:"models,omitempty"`
}

// Snapshot captures the full registry (durable rows + model registry) for log compaction / catch-up.
func (f *fsm) Snapshot() (raft.FSMSnapshot, error) {
	rows, err := f.reg.DumpAll(context.Background())
	if err != nil {
		return nil, err
	}
	var models json.RawMessage
	if f.models != nil {
		models = f.models.SnapshotBytes()
	}
	data, err := json.Marshal(fsmSnap{Nodes: rows, Models: models})
	if err != nil {
		return nil, err
	}
	return &snapshot{data: data}, nil
}

// Restore replaces the registries with a snapshot (on join / catch-up).
func (f *fsm) Restore(rc io.ReadCloser) error {
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return err
	}
	var s fsmSnap
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if err := f.reg.LoadAll(context.Background(), s.Nodes); err != nil {
		return err
	}
	if f.models != nil && len(s.Models) > 0 {
		return f.models.LoadSnapshotBytes(s.Models)
	}
	return nil
}

type snapshot struct{ data []byte }

func (s *snapshot) Persist(sink raft.SnapshotSink) error {
	if _, err := sink.Write(s.data); err != nil {
		_ = sink.Cancel()
		return err
	}
	return sink.Close()
}
func (s *snapshot) Release() {}
