// Package wg makes DANI its own WireGuard coordinator: the agent generates WireGuard (Curve25519)
// keys, and the control plane DANI already runs (enrollment → registry → heartbeat) distributes the
// public keys + endpoints and assigns overlay IPs, then renders ready-to-apply WireGuard configs.
// No Tailscale, no Headscale, no third-party coordination server — the network fabric is part of the
// product, fully in-perimeter. WireGuard is just the encrypted transport; DANI is the control plane.
//
// Keys are standard X25519 via crypto/ecdh (Go stdlib) — base64 of the 32-byte scalar/pubkey, exactly
// what `wg` expects — so no extra dependency and the output is interoperable with real WireGuard.
package wg

import (
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
)

// Key is a base64-encoded WireGuard keypair (interoperable with `wg`).
type Key struct {
	Private string
	Public  string
}

// randReader is the entropy seam (tests inject failures; production is crypto/rand).
var randReader io.Reader = rand.Reader

// NewKey generates a fresh WireGuard keypair.
func NewKey() (Key, error) {
	priv, err := ecdh.X25519().GenerateKey(randReader)
	if err != nil {
		return Key{}, err
	}
	return Key{
		Private: base64.StdEncoding.EncodeToString(priv.Bytes()),
		Public:  base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()),
	}, nil
}

// Node is a member of the DANI overlay mesh, as DANI knows it from enrollment + heartbeat.
type Node struct {
	UUID      string
	PublicKey string // WireGuard public key (advertised at enrollment)
	Endpoint  string // host:port reachable for WireGuard, or "" if NAT'd (hub learns it from traffic)
	OverlayIP string // assigned by DANI, e.g. 10.55.0.2
	IsHub     bool   // controllers are hubs (stable endpoint); workers are spokes
}

// Mesh is the overlay DANI computes from the live fleet.
type Mesh struct {
	CIDR  string // overlay subnet, e.g. 10.55.0.0/24
	Nodes []Node
}

// BuildMesh assigns overlay IPs deterministically (hub = .1, spokes = .2.. by sorted UUID) so every
// controller computes the same mesh from the same registry — DANI is the source of truth.
func BuildMesh(cidrPrefix string, hub Node, spokes []Node) Mesh {
	sort.Slice(spokes, func(i, j int) bool { return spokes[i].UUID < spokes[j].UUID })
	hub.OverlayIP = cidrPrefix + ".1"
	hub.IsHub = true
	out := []Node{hub}
	for i, s := range spokes {
		s.OverlayIP = fmt.Sprintf("%s.%d", cidrPrefix, i+2)
		s.IsHub = false
		out = append(out, s)
	}
	return Mesh{CIDR: cidrPrefix + ".0/24", Nodes: out}
}

// ConfigFor renders the WireGuard config a given node should apply. Spokes get the hub as their only
// peer (with the hub's endpoint + keepalive, so the NAT'd spoke dials out and stays reachable). The
// hub gets every spoke as a peer (no endpoint — learned from the incoming tunnel).
func (m Mesh) ConfigFor(uuid string, listenPort int) (string, bool) {
	var self *Node
	for i := range m.Nodes {
		if m.Nodes[i].UUID == uuid {
			self = &m.Nodes[i]
			break
		}
	}
	if self == nil {
		return "", false
	}
	// the hub addresses the whole overlay /24 (it routes the subnet); spokes take a /32.
	mask := "/32"
	if self.IsHub {
		mask = "/24"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\n# %s (DANI %s)\nAddress = %s%s\nListenPort = %d\n# PrivateKey is injected locally by the agent; never leaves the node\n",
		self.UUID, hubOrSpoke(self.IsHub), self.OverlayIP, mask, listenPort)

	if self.IsHub {
		for _, n := range m.Nodes {
			if n.IsHub {
				continue
			}
			fmt.Fprintf(&b, "\n[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = %s/32\n", n.UUID, n.PublicKey, n.OverlayIP)
		}
	} else {
		for _, n := range m.Nodes {
			if !n.IsHub {
				continue
			}
			fmt.Fprintf(&b, "\n[Peer]\n# %s (hub)\nPublicKey = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\n", n.UUID, n.PublicKey, m.CIDR)
			if n.Endpoint != "" {
				fmt.Fprintf(&b, "Endpoint = %s\n", n.Endpoint)
			}
		}
	}
	return b.String(), true
}

func hubOrSpoke(hub bool) string {
	if hub {
		return "hub/controller"
	}
	return "spoke/worker"
}
