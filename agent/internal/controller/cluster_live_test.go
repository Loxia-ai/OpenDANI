package controller

// In-package coverage for the HA surfaces: CA-bundle provisioning of a peer, the Raft-backed
// registry hooks, and the mTLS write-forwarding transport between controllers.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"dani.local/agent/internal/ca"
	"dani.local/agent/internal/cluster"
	"dani.local/agent/internal/registry"
	"dani.local/agent/pkg/dani"
)

func TestBundlePeerAndServe(t *testing.T) {
	ctx := context.Background()
	genesis, err := Genesis(ctx, "TestOrg", "dep-b", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	// Serve the enrollment API (statements in Serve/ServerTLSConfig execute in-package)
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := genesis.Serve(lis)
	defer srv.Stop()
	// the served endpoint speaks TLS with the controller's identity
	conn, err := tls.Dial("tcp", lis.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if cn := conn.ConnectionState().PeerCertificates[0].Subject.CommonName; cn != "ctrl-001" {
		t.Fatalf("server identity wrong: %s", cn)
	}
	conn.Close()

	// bundle round-trip provisions an identical-authority peer with its own identity
	b, err := genesis.ExportBundle()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := NewFromBundle(ctx, b, "ctrl-002", "site-b", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if peer.ID != "ctrl-002" || peer.CA.Root.SerialNumber.Cmp(genesis.CA.Root.SerialNumber) != 0 {
		t.Fatal("peer must share the genesis root")
	}
	// bad bundle: KMS blob garbage
	if _, err := NewFromBundle(ctx, &Bundle{KMSExport: []byte("junk")}, "x", "s", ":memory:"); err == nil {
		t.Fatal("garbage KMS export must be rejected")
	}
	// bad bundle: valid KMS, garbage certs
	blob, _ := genesis.KS.(interface{ Export() ([]byte, error) }).Export()
	if _, err := NewFromBundle(ctx, &Bundle{KMSExport: blob, RootDER: []byte("junk")}, "x", "s", ":memory:"); err == nil {
		t.Fatal("garbage root DER must be rejected")
	}
}

// bootCluster starts a single-node bootstrapped Raft cluster bound to this controller's registry.
func bootCluster(t *testing.T, ctrl *Controller, id string) *cluster.Node {
	t.Helper()
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := lis.Addr().String()
	lis.Close()
	n, err := cluster.New(cluster.Config{
		ID: id, RaftBind: addr, Bootstrap: true,
		Peers: []cluster.Peer{{ID: id, RaftAddr: addr}}, Reg: ctrl.Registry,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = n.Close() })
	if err := n.WaitForLeader(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestEnableClusterHooksReplicate(t *testing.T) {
	ctx := context.Background()
	ctrl, err := Genesis(ctx, "TestOrg", "dep-c", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	node := bootCluster(t, ctrl, "ctrl-001")
	ctrl.EnableCluster(node)
	// the admission hook now applies through Raft into the local registry; the cert must carry
	// DANIClaims with a hardware fingerprint (the registry column is NOT NULL)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	cert, err := ctrl.CA.IssueNodeCert(ctx, ca.NodeCertParams{
		NodeUUID: "n-raft", SiteOU: "site-r", PubDER: pubDER,
		Claims: dani.DANIClaims{SchemaVersion: 1, Roles: []string{"worker"}, Classification: "restricted",
			HardwareFprint: []byte{0xaa}},
		NotAfter: time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctrl.Enroll.OnApprove("n-raft", cert, []string{"worker"}, "restricted", "site-r", []byte(`{}`))
	deadline := time.Now().Add(5 * time.Second)
	for {
		if row, err := ctrl.Registry.Get(ctx, "n-raft"); err == nil && row.Class == "restricted" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("raft-applied admission never landed in the registry")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// the renewal hook bumps generation through the same path
	ctrl.Enroll.OnRenew("n-raft", cert, 7)
	deadline = time.Now().Add(5 * time.Second)
	for {
		if row, _ := ctrl.Registry.Get(ctx, "n-raft"); row != nil && row.Generation == 7 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("raft-applied renewal never landed")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestClusterApplyForwarding(t *testing.T) {
	ctx := context.Background()
	leader, err := Genesis(ctx, "TestOrg", "dep-f", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	node := bootCluster(t, leader, "ctrl-001")
	leader.Cluster = node
	applyAddr, err := leader.ServeClusterApply("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	// a FOLLOWER controller (same CA via bundle) forwards a mutation to the leader's endpoint
	b, _ := leader.ExportBundle()
	follower, err := NewFromBundle(ctx, b, "ctrl-002", "site-b", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	fwd := follower.Forwarder(map[string]string{"ctrl-001": "https://" + applyAddr + "/cluster/apply"})
	rec := registry.NodeRecord{UUID: "n-fwd", CertSerial: "01", NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		Generation: 1, HardwareFprint: []byte{0xbb}, Roles: []string{"worker"}, Class: "restricted"}
	data, err := cluster.EncodeUpsert(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := fwd("ctrl-001", "", data); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if row, err := leader.Registry.Get(ctx, "n-fwd"); err == nil && row.UUID == "n-fwd" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("forwarded mutation never applied on the leader")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// forwarding errors: unknown leader id, dead URL, non-2xx (endpoint without a cluster)
	if err := fwd("ghost", "", data); err == nil {
		t.Fatal("unknown leader must error")
	}
	if err := fwd("ctrl-001", "", data); err != nil { // idempotent re-apply is fine
		t.Fatal(err)
	}
	dead := follower.Forwarder(map[string]string{"ctrl-001": "https://127.0.0.1:1/cluster/apply"})
	if err := dead("ctrl-001", "", data); err == nil {
		t.Fatal("dead leader URL must error")
	}
	// an apply endpoint on a controller WITHOUT a cluster -> 503 -> forwarder error
	solo, _ := Genesis(ctx, "TestOrg", "dep-s", ":memory:")
	soloB, _ := solo.ExportBundle()
	soloPeer, _ := NewFromBundle(ctx, soloB, "ctrl-009", "site-x", ":memory:")
	soloAddr, err := solo.ServeClusterApply("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fwd2 := soloPeer.Forwarder(map[string]string{"ctrl-001": "https://" + soloAddr + "/cluster/apply"})
	if err := fwd2("ctrl-001", "", data); err == nil || !strings.Contains(err.Error(), "no cluster") {
		t.Fatalf("clusterless apply must 503: %v", err)
	}
	// a NON-fleet client (self-signed) is refused by mutual mTLS
	rogue := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if _, err := rogue.Post("https://"+applyAddr+"/cluster/apply", "application/octet-stream", nil); err == nil {
		t.Fatal("client without a fleet cert must be refused")
	}
	// bad bind addr
	if _, err := leader.ServeClusterApply("999.999.999.999:0"); err == nil {
		t.Fatal("bad bind must error")
	}
}
