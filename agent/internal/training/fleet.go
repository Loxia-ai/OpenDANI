package training

import "context"

// roleLister is the slice of the Node Registry the trainer allocator needs (satisfied by
// *registry.Registry.ActiveNodesWithRole). Kept as an interface so training doesn't depend on SQLite.
type roleLister interface {
	ActiveNodesWithRole(ctx context.Context, role string) ([]string, error)
}

// RegistryFleet allocates dedicated training hardware (D17) from the live Node Registry: an active
// node whose assigned roles include "trainer" — never an inference worker.
type RegistryFleet struct {
	Reg roleLister
	Ctx context.Context
}

// ActiveTrainer returns the first active trainer-role node (deterministic: registry orders by UUID).
// The registry knows roles, not addresses, so addr is "" — the job executes in-process (the local
// Trainer). For remote execution on the node's own hardware, use serving.PlaneRegistryFleet, which
// joins this role check with the live trainer heartbeats (which carry the /train address).
func (f RegistryFleet) ActiveTrainer() (uuid, addr string, ok bool) {
	ctx := f.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	uuids, err := f.Reg.ActiveNodesWithRole(ctx, "trainer")
	if err != nil || len(uuids) == 0 {
		return "", "", false
	}
	return uuids[0], "", true
}
