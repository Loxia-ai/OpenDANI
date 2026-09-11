package controller

// Inter-controller transport for Raft write-forwarding. A follower that receives an enrollment
// admission/renewal can't apply it locally (only the leader appends to the Raft log), so it forwards
// the encoded mutation to the leader's /cluster/apply endpoint over MUTUAL mTLS (controllers trust
// each other via the shared CA). The leader applies and replication fans out to every controller.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

func (c *Controller) clusterPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.CA.Root)
	pool.AddCert(c.CA.Intermediate)
	return pool
}

func (c *Controller) clusterServerTLS() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{c.Cert.Raw, c.CA.Intermediate.Raw}, PrivateKey: c.Key, Leaf: c.Cert}},
		ClientAuth:   tls.RequireAndVerifyClientCert, // controllers only (mutual mTLS)
		ClientCAs:    c.clusterPool(),
		MinVersion:   tls.VersionTLS12,
	}
}

func (c *Controller) clusterClientTLS() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{c.Cert.Raw, c.CA.Intermediate.Raw}, PrivateKey: c.Key, Leaf: c.Cert}},
		// identity is by CHAIN, not DNS (DL-R11-08): controllers dial each other by IP, so skip
		// hostname verification and verify the chain to the shared root ourselves.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: c.verifyPeerChain,
		MinVersion:            tls.VersionTLS12,
	}
}

// verifyPeerChain checks a presented cert chains to the shared CA root (no hostname check).
func (c *Controller) verifyPeerChain(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("cluster: no peer certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}
	inter := x509.NewCertPool()
	inter.AddCert(c.CA.Intermediate)
	for _, r := range rawCerts[1:] {
		if cc, e := x509.ParseCertificate(r); e == nil {
			inter.AddCert(cc)
		}
	}
	roots := x509.NewCertPool()
	roots.AddCert(c.CA.Root)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter})
	return err
}

// ServeClusterApply starts the mTLS endpoint that applies a forwarded mutation on THIS node (valid
// only while it's the leader). Non-blocking; returns the bound address.
func (c *Controller) ServeClusterApply(addr string) (string, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/cluster/apply", func(rw http.ResponseWriter, r *http.Request) {
		if c.Cluster == nil {
			http.Error(rw, "no cluster", http.StatusServiceUnavailable)
			return
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(rw, "read", http.StatusBadRequest)
			return
		}
		if err := c.Cluster.LocalApplyRaw(data); err != nil {
			http.Error(rw, err.Error(), http.StatusServiceUnavailable) // e.g. leadership moved
			return
		}
		rw.WriteHeader(http.StatusNoContent)
	})
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	srv := &http.Server{Handler: mux, TLSConfig: c.clusterServerTLS()}
	go func() { _ = srv.ServeTLS(lis, "", "") }()
	log.Printf("controller %s: cluster apply endpoint on %s (mTLS)", c.ID, lis.Addr())
	return lis.Addr().String(), nil
}

// Forwarder returns a cluster.Node.Forward implementation that POSTs a mutation to the current
// leader's /cluster/apply (looked up by leader id). applyURLByID maps controller id -> apply URL.
func (c *Controller) Forwarder(applyURLByID map[string]string) func(leaderID, leaderRaftAddr string, data []byte) error {
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: c.clusterClientTLS()}}
	return func(leaderID, leaderRaftAddr string, data []byte) error {
		url := applyURLByID[leaderID]
		if url == "" {
			return fmt.Errorf("cluster: no apply URL for leader %q", leaderID)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			b, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("cluster: forward to leader %s failed: %s: %s", leaderID, resp.Status, string(b))
		}
		return nil
	}
}
