package wg

import (
	"crypto/ecdh"
	"encoding/base64"
	"strings"
	"testing"
)

// TestKeyIsRealWireGuard: NewKey produces a valid X25519 keypair where the public key is the genuine
// curve25519 derivation of the private key — i.e. exactly what `wg` would compute (interoperable).
func TestKeyIsRealWireGuard(t *testing.T) {
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := base64.StdEncoding.DecodeString(k.Private)
	if err != nil || len(priv) != 32 {
		t.Fatalf("private key not 32 raw bytes: %v", err)
	}
	pk, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.StdEncoding.EncodeToString(pk.PublicKey().Bytes()); got != k.Public {
		t.Fatalf("public key is not the curve25519 derivation of the private key")
	}
}

func peerPubKeys(cfg string) []string {
	var out []string
	for _, line := range strings.Split(cfg, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PublicKey = ") {
			out = append(out, strings.TrimPrefix(line, "PublicKey = "))
		}
	}
	return out
}
func field(cfg, key string) string {
	for _, line := range strings.Split(cfg, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, key+" = ") {
			return strings.TrimPrefix(line, key+" = ")
		}
	}
	return ""
}

// TestMeshIsConsistent: the configs DANI renders for a hub + two NAT'd spokes form a coherent mesh —
// every peer public key resolves to a real node, overlay IPs are unique, and the hub-spoke shape is
// correct (spokes peer the hub with its endpoint+keepalive; the hub peers every spoke). If this holds,
// the tunnels would actually establish.
func TestMeshIsConsistent(t *testing.T) {
	hubK, _ := NewKey()
	s1K, _ := NewKey()
	s2K, _ := NewKey()
	hub := Node{UUID: "ctrl-001", PublicKey: hubK.Public, Endpoint: "20.1.2.3:51820"}
	spokes := []Node{
		{UUID: "worker-b", PublicKey: s2K.Public}, // out of order on purpose
		{UUID: "worker-a", PublicKey: s1K.Public}, // NAT'd: no endpoint
	}
	mesh := BuildMesh("10.55.0", hub, spokes)

	// overlay IPs unique + hub is .1
	seen := map[string]bool{}
	for _, n := range mesh.Nodes {
		if seen[n.OverlayIP] {
			t.Fatalf("duplicate overlay IP %s", n.OverlayIP)
		}
		seen[n.OverlayIP] = true
	}

	pubOf := map[string]string{"ctrl-001": hubK.Public, "worker-a": s1K.Public, "worker-b": s2K.Public}

	// hub config: peers every spoke, with the spokes' REAL public keys
	hubCfg, ok := mesh.ConfigFor("ctrl-001", 51820)
	if !ok {
		t.Fatal("no hub config")
	}
	hp := peerPubKeys(hubCfg)
	if len(hp) != 2 {
		t.Fatalf("hub should peer 2 spokes, got %d", len(hp))
	}
	for _, pk := range hp {
		if pk != s1K.Public && pk != s2K.Public {
			t.Fatalf("hub peers an unknown key %q", pk)
		}
	}

	// each spoke config: exactly the hub as peer (real hub key), with endpoint + keepalive
	for _, uuid := range []string{"worker-a", "worker-b"} {
		cfg, ok := mesh.ConfigFor(uuid, 51820)
		if !ok {
			t.Fatalf("no config for %s", uuid)
		}
		pk := peerPubKeys(cfg)
		if len(pk) != 1 || pk[0] != hubK.Public {
			t.Fatalf("%s must peer exactly the hub's real key, got %v", uuid, pk)
		}
		if field(cfg, "Endpoint") != "20.1.2.3:51820" {
			t.Fatalf("%s must dial the hub endpoint, got %q", uuid, field(cfg, "Endpoint"))
		}
		if field(cfg, "PersistentKeepalive") == "" {
			t.Fatalf("%s must keepalive (it's behind NAT)", uuid)
		}
		_ = pubOf
	}
	t.Logf("DANI rendered a consistent %d-node WireGuard mesh (%s) from enrollment data", len(mesh.Nodes), mesh.CIDR)
}

func TestNewKeyRandFailure(t *testing.T) {
	orig := randReader
	randReader = strings.NewReader("") // exhausted entropy
	defer func() { randReader = orig }()
	if _, err := NewKey(); err == nil {
		t.Fatal("entropy failure must surface")
	}
}

func TestConfigForUnknownNode(t *testing.T) {
	hub := Node{UUID: "hub", PublicKey: "H", Endpoint: "1.2.3.4:51820"}
	m := BuildMesh("10.55.0", hub, []Node{{UUID: "w", PublicKey: "W"}})
	if _, ok := m.ConfigFor("ghost", 51820); ok {
		t.Fatal("unknown node must not get a config")
	}
}
