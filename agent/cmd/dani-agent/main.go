// Command dani-agent is the single DANI binary (one per node; role decided by config — DL-R11-01).
// This DEMO scaffold implements the `genesis` ceremony foundation (two-tier CA + KMS); the
// enrollment slice, Link stream, worker runtime, and engine supervision land in subsequent phases
// (see ../../DEMO-SCOPE.md §5).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"time"

	"dani.local/agent/internal/ca"
	"dani.local/agent/internal/hwcaps"
	"dani.local/agent/internal/kms"
	"dani.local/agent/pkg/dani"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "genesis":
		runGenesis(os.Args[2:])
	case "controller":
		runController(os.Args[2:])
	case "worker":
		runWorker(os.Args[2:])
	case "connect":
		// local relay: one fixed loopback /v1 for every app on this machine, identity stamped
		cmdConnect(os.Args[2:])
	case "ingest":
		// node-side ingest agent: push THIS machine's documents into a DANI collection
		cmdIngest(os.Args[2:])
	case "caps":
		// operator probe: what acceleration does THIS box bring? (same detection the worker
		// runs at startup to pick its llama-server offload)
		fmt.Println(hwcaps.Detect().String())
	case "version":
		fmt.Println("dani-agent demo 0.1.0")
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: dani-agent <genesis|controller|worker|caps|version> [flags]")
	os.Exit(2)
}

func runGenesis(args []string) {
	fs := flag.NewFlagSet("genesis", flag.ExitOnError)
	org := fs.String("org", "AcmeBank", "organization name")
	_ = fs.Parse(args)
	ctx := context.Background()

	ks, err := kms.NewSoftware()
	check(err)
	authority, err := ca.Genesis(ctx, ks, *org)
	check(err)
	fmt.Printf("GENESIS %s\n  root:         %s (expires %s, dormant/sealed)\n  intermediate: %s (expires %s, online)\n",
		*org,
		authority.Root.Subject.CommonName, authority.Root.NotAfter.Format("2006-01-02"),
		authority.Intermediate.Subject.CommonName, authority.Intermediate.NotAfter.Format("2006-01-02"))

	// the controller self-issues its own identity (it can refresh, not forge — RR-R11.2-08)
	ctrlPub, _, err := ed25519.GenerateKey(rand.Reader)
	check(err)
	pubDER, err := x509.MarshalPKIXPublicKey(ctrlPub)
	check(err)
	cert, err := authority.IssueNodeCert(ctx, ca.NodeCertParams{
		NodeUUID: "ctrl-001",
		SiteOU:   "site-hq",
		PubDER:   pubDER,
		Claims: dani.DANIClaims{
			SchemaVersion:   1,
			Roles:           []string{"controller"},
			Classification:  "unrestricted",
			AttestationTier: dani.TierAdministrative,
			EnrolledAt:      time.Now().UTC().Format(time.RFC3339),
			SiteTag:         "site-hq",
		},
		NotAfter: time.Now().AddDate(0, 0, 90),
	})
	check(err)
	fmt.Printf("  controller cert: CN=%s serial=%x\n", cert.Subject.CommonName, cert.SerialNumber)

	if err := authority.Verify(cert); err != nil {
		fmt.Printf("  chain verify: FAIL: %v\n", err)
		os.Exit(1)
	}
	cl, err := ca.Claims(cert)
	check(err)
	fmt.Printf("  chain verify: OK — claims roles=%v class=%s tier=%d\n", cl.Roles, cl.Classification, cl.AttestationTier)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
