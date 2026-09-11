// Package controller wires the control-plane services and serves the Enrollment gRPC API over TLS.
// Per DL-R11.2-04 the enrollment handshake runs over a controller-AUTHENTICATED TLS channel (the
// node has no cert yet); renewal runs over mutual mTLS. So the server presents its identity cert
// and verifies a client cert only if one is given (VerifyClientCertIfGiven).
package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"dani.local/agent/internal/ca"
	"dani.local/agent/internal/cluster"
	"dani.local/agent/internal/enrollment"
	pb "dani.local/agent/internal/gen/enrollmentv1"
	"dani.local/agent/internal/kms"
	"dani.local/agent/internal/registry"
	"dani.local/agent/pkg/dani"
)

// Controller holds the genesis control plane: KMS, two-tier CA, the enrollment service, and the
// controller's own identity cert/key (used as the TLS server credential).
type Controller struct {
	KS           ca.KeyStore // software (Exportable, HA-bundle) or remote HSM/cloud-KMS (D-28)
	CA           *ca.CA
	Enroll       *enrollment.Service
	Registry     *registry.Registry
	Cert         *x509.Certificate
	Key          ed25519.PrivateKey
	DeploymentID string
	ID           string
	Cluster      *cluster.Node // nil = standalone; set by EnableCluster (multi-controller HA)
}

// wireRegistryHooks points the enrollment service's admission/renewal callbacks at a registry sink —
// either the local registry (standalone) or the Raft cluster (HA). Centralizing this keeps the two
// paths identical except for where the durable write lands.
func wireRegistryHooks(svc *enrollment.Service, upsert func(registry.NodeRecord) error,
	renew func(uuid, serial string, nb, na time.Time, gen int) error) {
	svc.OnApprove = func(uuid string, c *x509.Certificate, roles []string, class, site string, caps []byte) {
		var hw []byte
		if cl, err := ca.Claims(c); err == nil {
			hw = cl.HardwareFprint
		}
		_ = upsert(registry.NodeRecord{
			UUID: uuid, CertSerial: c.SerialNumber.String(), NotBefore: c.NotBefore, NotAfter: c.NotAfter,
			Generation: 1, HardwareFprint: hw, Roles: roles, Class: class, Site: site,
			Tier: int(dani.TierAdministrative), CapabilitiesJSON: caps,
		})
	}
	svc.OnRenew = func(uuid string, c *x509.Certificate, gen int) {
		_ = renew(uuid, c.SerialNumber.String(), c.NotBefore, c.NotAfter, gen)
	}
}

// localHooks wires admissions/renewals straight to a local registry (standalone controller).
func localHooks(svc *enrollment.Service, reg *registry.Registry) {
	wireRegistryHooks(svc,
		func(r registry.NodeRecord) error { return reg.UpsertEnrolled(context.Background(), r) },
		func(uuid, serial string, nb, na time.Time, gen int) error {
			return reg.Renew(context.Background(), uuid, serial, nb, na, gen)
		})
}

// EnableCluster makes this controller part of a Raft cluster: admissions/renewals now replicate
// through the cluster (leader applies, all replicas converge) instead of writing only locally.
func (c *Controller) EnableCluster(node *cluster.Node) {
	c.Cluster = node
	wireRegistryHooks(c.Enroll, node.ApplyUpsert,
		func(uuid, serial string, nb, na time.Time, gen int) error {
			return node.ApplyRenew(cluster.RenewArgs{UUID: uuid, Serial: serial, NotBefore: nb, NotAfter: na, Generation: gen})
		})
}

// Bundle is the shared-CA material that provisions an HA peer controller identically to the genesis
// controller (same root + intermediate + KMS keys) so ANY controller can issue/verify/renew and be
// the Raft leader. Carried over a private mTLS share at deploy time.
type Bundle struct {
	KMSExport    []byte `json:"kms"`
	RootDER      []byte `json:"root"`
	InterDER     []byte `json:"inter"`
	Org          string `json:"org"`
	DeploymentID string `json:"deployment_id"`
}

// ExportBundle serializes this controller's CA + KMS for HA provisioning.
func (c *Controller) ExportBundle() (*Bundle, error) {
	exporter, ok := c.KS.(interface{ Export() ([]byte, error) })
	if !ok {
		return nil, fmt.Errorf("controller: this KMS backend is not exportable (a remote HSM is the shared authority; peers point at the same endpoint, not a CA bundle)")
	}
	ex, err := exporter.Export()
	if err != nil {
		return nil, err
	}
	return &Bundle{KMSExport: ex, RootDER: c.CA.Root.Raw, InterDER: c.CA.Intermediate.Raw, Org: c.CA.Org(), DeploymentID: c.DeploymentID}, nil
}

// NewFromBundle builds a peer controller from a shared CA bundle: it imports the identical CA + KMS,
// issues its OWN identity cert (controllerID/site) from the shared intermediate, and opens its local
// registry replica. Hooks default to local; call EnableCluster to replicate through Raft.
func NewFromBundle(ctx context.Context, b *Bundle, controllerID, site, registryDSN string) (*Controller, error) {
	ks, err := kms.ImportSoftware(b.KMSExport)
	if err != nil {
		return nil, err
	}
	authority, err := ca.Load(ks, b.Org, b.RootDER, b.InterDER)
	if err != nil {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	cert, err := authority.IssueNodeCert(ctx, ca.NodeCertParams{
		NodeUUID: controllerID, SiteOU: site, PubDER: pubDER,
		Claims: dani.DANIClaims{
			SchemaVersion: 1, Roles: []string{"controller"}, Classification: "unrestricted",
			AttestationTier: dani.TierAdministrative, EnrolledAt: time.Now().UTC().Format(time.RFC3339), SiteTag: site,
		},
		NotAfter: time.Now().AddDate(0, 0, 90),
	})
	if err != nil {
		return nil, err
	}
	reg, err := registry.Open(ctx, registryDSN)
	if err != nil {
		return nil, err
	}
	svc := enrollment.New(ks, authority, b.DeploymentID)
	localHooks(svc, reg)
	return &Controller{KS: ks, CA: authority, Enroll: svc, Registry: reg, Cert: cert, Key: priv, DeploymentID: b.DeploymentID, ID: controllerID}, nil
}

// GenesisOrResume makes a STANDALONE controller restart-survivable (SPEC-FINDINGS D-14 #2): on
// first boot it runs the genesis ceremony and persists the CA+KMS bundle to statePath (0600, same
// serialization the HA path shares between peers); on restart it reloads that SAME authority, so
// enrolled workers' certs, outstanding bootstrap tokens, and audit-chain anchors all stay valid.
// Returns resumed=true when the authority came from disk. A corrupt state file is an error, never
// a silent re-genesis — minting a fresh CA over live workers is exactly the failure this prevents.
func GenesisOrResume(ctx context.Context, org, deploymentID, registryDSN, statePath, controllerID, site string) (c *Controller, resumed bool, err error) {
	if data, rerr := os.ReadFile(statePath); rerr == nil {
		var b Bundle
		if err := json.Unmarshal(data, &b); err != nil {
			return nil, false, fmt.Errorf("controller state %s is corrupt (refusing to re-genesis over a live deployment): %w", statePath, err)
		}
		c, err = NewFromBundle(ctx, &b, controllerID, site, registryDSN)
		return c, true, err
	}
	if c, err = Genesis(ctx, org, deploymentID, registryDSN); err != nil {
		return nil, false, err
	}
	// Materialize every long-lived signing key BEFORE export (DEKs are lazy): a resumed controller
	// must reuse them, or old audit anchors / model signatures would verify against nothing.
	for _, p := range []dani.KeyPurpose{dani.PurposeAuditChainSigning,
		dani.PurposeModelSignSecurity, dani.PurposeModelSignGovernance, dani.PurposeModelSignAdmin} {
		if _, err := c.KS.GetPublicKey(ctx, p); err != nil {
			return nil, false, err
		}
	}
	b, err := c.ExportBundle()
	if err != nil {
		return nil, false, err
	}
	data, _ := json.Marshal(b)
	if err := os.WriteFile(statePath, data, 0o600); err != nil {
		return nil, false, fmt.Errorf("persist controller state: %w", err)
	}
	return c, false, nil
}

// Genesis runs the bootstrap ceremony on a fresh software KMS and issues the controller's own
// identity cert. registryDSN is a SQLite path (use ":memory:" for ephemeral / tests).
func Genesis(ctx context.Context, org, deploymentID, registryDSN string) (*Controller, error) {
	ks, err := kms.NewSoftware()
	if err != nil {
		return nil, err
	}
	return GenesisWithKMS(ctx, ks, org, deploymentID, registryDSN)
}

// GenesisWithKMS runs the bootstrap ceremony on an INJECTED KeyStore — a software keystore (the
// default) or a remote HSM/cloud-KMS (D-28), so the CA/enrollment/audit keys can live in hardware.
// With a remote KMS the issuing key never enters DANI; the bundle-based HA (--state, ExportBundle) is
// unavailable (the HSM is the shared authority — peers point at the same endpoint).
func GenesisWithKMS(ctx context.Context, ks ca.KeyStore, org, deploymentID, registryDSN string) (*Controller, error) {
	authority, err := ca.Genesis(ctx, ks, org)
	if err != nil {
		return nil, err
	}
	// Materialize the enrollment-signing key NOW (DEKs are created lazily on first use) so it is
	// captured by ExportBundle and shared identically with HA peer controllers — otherwise each
	// controller would lazily mint its own and reject the others' bootstrap tokens.
	if _, err := ks.GetPublicKey(ctx, dani.PurposeEnrollmentSigning); err != nil {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	cert, err := authority.IssueNodeCert(ctx, ca.NodeCertParams{
		NodeUUID: "ctrl-001", SiteOU: "site-hq", PubDER: pubDER,
		Claims: dani.DANIClaims{
			SchemaVersion: 1, Roles: []string{"controller"}, Classification: "unrestricted",
			AttestationTier: dani.TierAdministrative, EnrolledAt: time.Now().UTC().Format(time.RFC3339), SiteTag: "site-hq",
		},
		NotAfter: time.Now().AddDate(0, 0, 90),
	})
	if err != nil {
		return nil, err
	}
	reg, err := registry.Open(ctx, registryDSN)
	if err != nil {
		return nil, err
	}
	svc := enrollment.New(ks, authority, deploymentID)
	localHooks(svc, reg) // persist admissions + renewals into the local Node Registry (real SQLite)
	return &Controller{
		KS: ks, CA: authority, Enroll: svc, Registry: reg,
		Cert: cert, Key: priv, DeploymentID: deploymentID, ID: "ctrl-001",
	}, nil
}

// ServerTLSConfig builds the TLS config for the enrollment gRPC server.
func (c *Controller) ServerTLSConfig() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(c.CA.Root)
	pool.AddCert(c.CA.Intermediate)
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{c.Cert.Raw, c.CA.Intermediate.Raw}, // leaf + intermediate
			PrivateKey:  c.Key,
			Leaf:        c.Cert,
		}},
		ClientAuth: tls.VerifyClientCertIfGiven, // handshake: none; renewal: mutual mTLS
		ClientCAs:  pool,
		MinVersion: tls.VersionTLS12,
	}
}

// Serve registers the EnrollmentService on a TLS gRPC server and starts serving on lis.
func (c *Controller) Serve(lis net.Listener) *grpc.Server {
	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(c.ServerTLSConfig())))
	pb.RegisterEnrollmentServiceServer(s, c.Enroll)
	go func() { _ = s.Serve(lis) }()
	return s
}
