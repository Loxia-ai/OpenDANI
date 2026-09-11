package node

// In-package live enrollment: a real controller (Genesis + gRPC over TLS) admits this node through
// the full 6-step handshake, then renews over mutual mTLS — Enroll and Renew covered where they live.

import (
	"context"
	"net"
	"testing"
	"time"

	"dani.local/agent/internal/controller"
	"dani.local/agent/internal/enrollment"
)

func liveController(t *testing.T) (*controller.Controller, string) {
	t.Helper()
	ctrl, err := controller.Genesis(context.Background(), "TestOrg", "dep-t", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := ctrl.Serve(lis)
	t.Cleanup(srv.Stop)
	// auto-approve the pending queue (the DEMO drain policy) in the background
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
			for _, reqID := range ctrl.Enroll.Waiting() {
				_, _ = ctrl.Enroll.Approve(context.Background(), reqID, nil, "", "site-t")
			}
		}
	}()
	return ctrl, lis.Addr().String()
}

func TestEnrollAndRenewLive(t *testing.T) {
	ctx := context.Background()
	ctrl, addr := liveController(t)
	token, _, err := enrollment.IssueToken(ctx, ctrl.KS, "dep-t", []string{"worker"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	id, err := Enroll(ctx, EnrollParams{
		Addr: addr, TrustRoot: ctrl.CA.Root, Token: token,
		NodeUUID: "n-live", Roles: []string{"worker"}, Class: "restricted",
		Caps: []byte(`{"engines":["stub"]}`), Timeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if id.Cert.Subject.CommonName != "n-live" || id.Key == nil || len(id.CABundle) == 0 {
		t.Fatalf("identity incomplete: %+v", id.Cert.Subject)
	}
	// the issued cert chains to the controller's root (verifyIssuedCert already ran inside Enroll)
	oldSerial := id.Cert.SerialNumber.String()

	// renewal over mutual mTLS rotates the key + serial and bumps the registry generation
	newCert, err := Renew(ctx, addr, ctrl.CA.Root, id)
	if err != nil {
		t.Fatal(err)
	}
	if newCert.SerialNumber.String() == oldSerial {
		t.Fatal("renewal must issue a new serial")
	}
	if newCert.Subject.CommonName != "n-live" {
		t.Fatal("renewed identity must keep its CN")
	}
	row, err := ctrl.Registry.Get(ctx, "n-live")
	if err != nil || row.Generation != 2 {
		t.Fatalf("registry generation should be 2 after renew: %+v %v", row, err)
	}

	// revoked node: renewal refused end-to-end (broken trust funnels to re-enrollment)
	ctrl.Enroll.Revoke("n-live")
	id.Cert = newCert
	if _, err := Renew(ctx, addr, ctrl.CA.Root, id); err == nil {
		t.Fatal("revoked node's renewal must be refused")
	}
}

func TestEnrollDenials(t *testing.T) {
	ctx := context.Background()
	ctrl, addr := liveController(t)
	// bad token: rejected at EnrollBegin
	if _, err := Enroll(ctx, EnrollParams{
		Addr: addr, TrustRoot: ctrl.CA.Root, Token: []byte("garbage-token"),
		NodeUUID: "n-bad", Roles: []string{"worker"}, Class: "restricted", Timeout: 5 * time.Second,
	}); err == nil {
		t.Fatal("garbage token must be rejected")
	}
	// wrong trust root: the TLS chain verification refuses the controller
	stranger, err := controller.Genesis(ctx, "OtherOrg", "dep-x", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	token, _, _ := enrollment.IssueToken(ctx, ctrl.KS, "dep-t", []string{"worker"}, time.Hour)
	if _, err := Enroll(ctx, EnrollParams{
		Addr: addr, TrustRoot: stranger.CA.Root, Token: token,
		NodeUUID: "n-mitm", Roles: []string{"worker"}, Class: "restricted", Timeout: 5 * time.Second,
	}); err == nil {
		t.Fatal("wrong trust root must refuse the controller")
	}
	// unreachable controller
	if _, err := Enroll(ctx, EnrollParams{
		Addr: "127.0.0.1:1", TrustRoot: ctrl.CA.Root, Token: token,
		NodeUUID: "n-dead", Roles: []string{"worker"}, Class: "restricted", Timeout: 2 * time.Second,
	}); err == nil {
		t.Fatal("unreachable controller must error")
	}
}
