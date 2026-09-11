package serving

// Production transport security for the EXTERNAL gateway (the console, the OpenAI /v1 API, and the
// operator/OIDC auth endpoints). The control plane (enrollment / link / dispatch) has always been
// mutual-TLS; this closes the customer-facing surface, which otherwise carries bearer tokens and
// prompts in cleartext (PRODUCTION-READINESS P0-1).
//
// Two modes: a MOUNTED certificate (the production path — a real cert from your ingress/ACME/secret
// store, PEM files) or a SELF-SIGNED cert generated in memory (dev/air-gapped bring-up, so HTTPS is
// on even before a real cert is provisioned). When TLS is on, responses carry HSTS.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"time"
)

// GatewayTLS configures HTTPS for the external gateway. When Enabled and CertFile/KeyFile are set,
// the mounted PEM pair is used; when Enabled with no files, a self-signed cert is generated.
type GatewayTLS struct {
	Enabled  bool
	CertFile string
	KeyFile  string
	Hosts    []string // SANs for the self-signed cert (default: localhost + 127.0.0.1)
}

// tlsConfig builds the *tls.Config for the gateway, loading the mounted cert or minting a self-signed
// one. It reports which path was taken so the boot log is honest about the cert's provenance.
func (g *GatewayTLS) tlsConfig() (*tls.Config, string, error) {
	if g.CertFile != "" && g.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(g.CertFile, g.KeyFile)
		if err != nil {
			return nil, "", fmt.Errorf("gateway TLS: load cert %s / key %s: %w", g.CertFile, g.KeyFile, err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, "mounted certificate", nil
	}
	hosts := g.Hosts
	if len(hosts) == 0 {
		hosts = []string{"localhost"}
	}
	cert, err := selfSignedCert(hosts)
	if err != nil {
		return nil, "", err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, "self-signed certificate (provide --gateway-tls-cert/-key for production)", nil
}

// selfSignedCert mints an in-memory ECDSA server cert valid for the given hosts.
func selfSignedCert(hosts []string) (tls.Certificate, error) {
	certPEM, keyPEM, err := selfSignedPEM(hosts)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// selfSignedPEM returns a fresh self-signed ECDSA server cert + key as PEM (1-year). IPs among the
// hosts land in IPAddresses; names in DNSNames.
func selfSignedPEM(hosts []string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "DANI gateway (self-signed)", Organization: []string{"DANI"}},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key) // self-signed
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// hstsHandler adds Strict-Transport-Security to every response (only mounted when TLS is on, so we
// never advertise HSTS over a plaintext listener).
func hstsHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next.ServeHTTP(rw, r)
	})
}
