package serving

import (
	"encoding/json"
	"net/http"
)

// GET /dani/cluster — the CONTROL PLANE members (multi-controller Raft), for the console/demo.
// Workers are /dani/fleet; this is the other half of the topology: how many controllers exist,
// which one leads, and which one answered this request. On a standalone controller (no Raft)
// it reports a single self-led member, so clients render both shapes with one code path.

// ClusterMember is one controller in the (possibly single-node) control plane.
type ClusterMember struct {
	ID     string `json:"id"`
	Addr   string `json:"addr,omitempty"`
	Leader bool   `json:"leader"`
	Self   bool   `json:"self"`
}

// SetClusterInfo wires the Raft membership provider (multi-controller mode). fn returns the
// members and the current leader id. Without it /dani/cluster reports this controller standalone.
func (p *Plane) SetClusterInfo(fn func() ([]ClusterMember, string)) { p.clusterInfo = fn }

func (p *Plane) handleCluster(rw http.ResponseWriter, _ *http.Request) {
	var members []ClusterMember
	leader := ""
	if p.clusterInfo != nil {
		members, leader = p.clusterInfo()
	}
	if len(members) == 0 { // standalone (no Raft): this controller IS the control plane
		members = []ClusterMember{{ID: p.id.UUID, Leader: true, Self: true}}
		leader = p.id.UUID
	}
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(map[string]any{
		"count": len(members), "leader": leader, "site": p.site, "self": p.id.UUID, "members": members,
	})
}
