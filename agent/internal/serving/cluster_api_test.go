package serving

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

// standalone (no Raft): /dani/cluster reports this controller as a single self-led member.
func TestClusterStandalone(t *testing.T) {
	p := &Plane{id: Identity{UUID: "ctrl-solo"}, site: "site-x",
		workers: map[string]*workerState{}, inflight: map[string]int{}, stale: time.Minute}
	rec := httptest.NewRecorder()
	p.handleCluster(rec, httptest.NewRequest("GET", "/dani/cluster", nil))
	var got struct {
		Count   int    `json:"count"`
		Leader  string `json:"leader"`
		Site    string `json:"site"`
		Self    string `json:"self"`
		Members []ClusterMember
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if got.Count != 1 || got.Leader != "ctrl-solo" || got.Site != "site-x" || got.Self != "ctrl-solo" {
		t.Fatalf("standalone shape wrong: %+v", got)
	}
	if !got.Members[0].Leader || !got.Members[0].Self {
		t.Fatalf("standalone member should be self-led: %+v", got.Members[0])
	}
}

// clustered: the provider's members + leader are surfaced verbatim.
func TestClusterWithProvider(t *testing.T) {
	p := &Plane{id: Identity{UUID: "ctrl-001"}, site: "site-alpha",
		workers: map[string]*workerState{}, inflight: map[string]int{}, stale: time.Minute}
	p.SetClusterInfo(func() ([]ClusterMember, string) {
		return []ClusterMember{
			{ID: "ctrl-001", Addr: "10.0.0.1:7001", Leader: true, Self: true},
			{ID: "ctrl-002", Addr: "10.0.0.2:7001"},
			{ID: "ctrl-003", Addr: "10.0.0.3:7001"},
		}, "ctrl-001"
	})
	rec := httptest.NewRecorder()
	p.handleCluster(rec, httptest.NewRequest("GET", "/dani/cluster", nil))
	var got struct {
		Count   int    `json:"count"`
		Leader  string `json:"leader"`
		Members []ClusterMember
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if got.Count != 3 || got.Leader != "ctrl-001" || len(got.Members) != 3 {
		t.Fatalf("cluster shape wrong: %+v", got)
	}
	if got.Members[1].Leader || got.Members[1].Self {
		t.Fatalf("follower flags wrong: %+v", got.Members[1])
	}
}
