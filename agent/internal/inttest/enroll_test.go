// Package inttest holds integration tests that exercise the real binary's components together
// (controller + node) over a real TLS socket — the closest local proxy to the Azure deployment.
package inttest

import (
	"context"
	"net"
	"testing"
	"time"

	"dani.local/agent/internal/ca"
	"dani.local/agent/internal/controller"
	"dani.local/agent/internal/enrollment"
	"dani.local/agent/internal/node"
)

func TestEnrollOverMTLS(t *testing.T) {
	ctx := context.Background()
	ctrl, err := controller.Genesis(ctx, "AcmeBank", "dep-1", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := ctrl.Serve(lis)
	defer srv.Stop()
	addr := lis.Addr().String()

	token, _, err := enrollment.IssueToken(ctx, ctrl.KS, "dep-1", []string{"worker"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// node enrolls in the background (it polls for approval)
	type result struct {
		id  *node.Identity
		err error
	}
	done := make(chan result, 1)
	go func() {
		id, err := node.Enroll(ctx, node.EnrollParams{
			Addr: addr, TrustRoot: ctrl.CA.Root, Token: token,
			NodeUUID: "worker-1", Roles: []string{"worker"}, Class: "restricted",
			Timeout: 10 * time.Second,
		})
		done <- result{id, err}
	}()

	// wait until the node is queued, then approve it (Mode 2 batch-confirm)
	deadline := time.Now().Add(8 * time.Second)
	var reqID string
	for {
		if w := ctrl.Enroll.Waiting(); len(w) == 1 {
			reqID = w[0]
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("node never reached the pending-join queue")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := ctrl.Enroll.Approve(ctx, reqID, []string{"worker"}, "restricted", "site-hq"); err != nil {
		t.Fatalf("approve: %v", err)
	}

	res := <-done
	if res.err != nil {
		t.Fatalf("node enrollment failed: %v", res.err)
	}
	// the node holds a real cert that chains to the controller's CA and carries the assigned claims
	if err := ctrl.CA.Verify(res.id.Cert); err != nil {
		t.Fatalf("issued cert does not chain to CA: %v", err)
	}
	cl, err := ca.Claims(res.id.Cert)
	if err != nil {
		t.Fatal(err)
	}
	if cl.Classification != "restricted" || cl.Roles[0] != "worker" || cl.SiteTag != "site-hq" {
		t.Fatalf("unexpected claims on the issued cert: %+v", cl)
	}
	if res.id.Cert.Subject.CommonName != "worker-1" {
		t.Fatalf("cert CN = %s, want worker-1", res.id.Cert.Subject.CommonName)
	}
	// the admission was persisted into the real SQLite Node Registry via the OnApprove hook
	if n, err := ctrl.Registry.Count(ctx); err != nil || n != 1 {
		t.Fatalf("registry count after enroll = %d (err %v), want 1", n, err)
	}
	row, err := ctrl.Registry.Get(ctx, "worker-1")
	if err != nil {
		t.Fatalf("registry Get: %v", err)
	}
	if row.Lifecycle != "active" || row.Class != "restricted" || row.Generation != 1 {
		t.Fatalf("unexpected registry row after enroll: %+v", row)
	}
}

func TestEnrollBadTokenOverMTLS(t *testing.T) {
	ctx := context.Background()
	ctrl, err := controller.Genesis(ctx, "AcmeBank", "dep-1", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := ctrl.Serve(lis)
	defer srv.Stop()

	_, err = node.Enroll(ctx, node.EnrollParams{
		Addr: lis.Addr().String(), TrustRoot: ctrl.CA.Root, Token: []byte("garbage"),
		NodeUUID: "x", Roles: []string{"worker"}, Class: "unrestricted", Timeout: 3 * time.Second,
	})
	if err == nil {
		t.Fatal("expected enrollment with a bad token to fail at EnrollBegin")
	}
}

// mustEnroll enrolls "worker-1" and approves it (Mode 2), returning the installed identity.
func mustEnroll(t *testing.T, ctx context.Context, ctrl *controller.Controller, addr string) *node.Identity {
	t.Helper()
	token, _, err := enrollment.IssueToken(ctx, ctrl.KS, "dep-1", []string{"worker"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	type res struct {
		id  *node.Identity
		err error
	}
	done := make(chan res, 1)
	go func() {
		id, err := node.Enroll(ctx, node.EnrollParams{
			Addr: addr, TrustRoot: ctrl.CA.Root, Token: token,
			NodeUUID: "worker-1", Roles: []string{"worker"}, Class: "restricted", Timeout: 10 * time.Second,
		})
		done <- res{id, err}
	}()
	deadline := time.Now().Add(8 * time.Second)
	for {
		if w := ctrl.Enroll.Waiting(); len(w) == 1 {
			if _, err := ctrl.Enroll.Approve(ctx, w[0], []string{"worker"}, "restricted", "site-hq"); err != nil {
				t.Fatal(err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("node never reached the queue")
		}
		time.Sleep(50 * time.Millisecond)
	}
	r := <-done
	if r.err != nil {
		t.Fatalf("enroll: %v", r.err)
	}
	return r.id
}

func TestRenewOverMTLS(t *testing.T) {
	ctx := context.Background()
	ctrl, err := controller.Genesis(ctx, "AcmeBank", "dep-1", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := ctrl.Serve(lis)
	defer srv.Stop()
	addr := lis.Addr().String()

	id := mustEnroll(t, ctx, ctrl, addr)

	// routine renewal over mutual mTLS — no token, no human
	newCert, err := node.Renew(ctx, addr, ctrl.CA.Root, id)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if err := ctrl.CA.Verify(newCert); err != nil {
		t.Fatalf("renewed cert does not chain: %v", err)
	}
	if newCert.Subject.CommonName != id.Cert.Subject.CommonName {
		t.Fatal("CN must be preserved across renewal")
	}
	if newCert.SerialNumber.Cmp(id.Cert.SerialNumber) == 0 {
		t.Fatal("serial should change on renewal")
	}
	// the renewal was persisted: generation bumped and serial tracks the new cert (OnRenew hook)
	row, err := ctrl.Registry.Get(ctx, id.Cert.Subject.CommonName)
	if err != nil {
		t.Fatalf("registry Get after renew: %v", err)
	}
	if row.Generation != 2 {
		t.Fatalf("registry generation after renew = %d, want 2", row.Generation)
	}

	// revocation -> renewal refused (broken trust funnels to full re-enrollment)
	ctrl.Enroll.Revoke(id.Cert.Subject.CommonName)
	if _, err := node.Renew(ctx, addr, ctrl.CA.Root, id); err == nil {
		t.Fatal("expected renewal to be refused after revocation")
	}
}

func TestRenewUnknownNodeRejected(t *testing.T) {
	ctx := context.Background()
	ctrl, _ := controller.Genesis(ctx, "AcmeBank", "dep-1", ":memory:")
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := ctrl.Serve(lis)
	defer srv.Stop()
	addr := lis.Addr().String()

	// enroll one node, then try to renew using its identity but for a node the controller never
	// admitted is impossible (CN is bound to the cert); instead, a controller with no enrolled
	// node rejects renewal. Enroll, drop the registry entry by revoking is covered above; here we
	// renew against a FRESH controller that has never seen this identity.
	id := mustEnroll(t, ctx, ctrl, addr)

	other, _ := controller.Genesis(ctx, "AcmeBank", "dep-1", ":memory:")
	lis2, _ := net.Listen("tcp", "127.0.0.1:0")
	srv2 := other.Serve(lis2)
	defer srv2.Stop()
	// the other controller's root differs, so the node won't even trust it — which is itself the
	// correct rejection of a renewal against an unknown authority.
	if _, err := node.Renew(ctx, lis2.Addr().String(), other.CA.Root, id); err == nil {
		t.Fatal("expected renewal against an unknown controller to fail")
	}
}
