package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "dani.local/agent/internal/gen/enrollmentv1"
)

// Renew performs routine lightweight renewal over MUTUAL mTLS (DL-R11.2-05): the node presents its
// current identity cert (proving key possession) and gets a fresh cert with the same attributes. No
// token, no human. The node key is re-used.
func Renew(ctx context.Context, addr string, trustRoot *x509.Certificate, id *Identity) (*x509.Certificate, error) {
	roots := x509.NewCertPool()
	roots.AddCert(trustRoot)

	// present our current identity: leaf + intermediate so the controller can build the chain.
	chain := [][]byte{id.Cert.Raw}
	for _, c := range id.CABundle {
		if !bytes.Equal(c.Raw, trustRoot.Raw) { // the intermediate (everything but the root)
			chain = append(chain, c.Raw)
		}
	}
	tlsCfg := &tls.Config{
		Certificates:       []tls.Certificate{{Certificate: chain, PrivateKey: id.Key, Leaf: id.Cert}},
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyServerChain(rawCerts, roots)
		},
		MinVersion: tls.VersionTLS12,
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	cl := pb.NewEnrollmentServiceClient(conn)

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: id.Cert.Subject.CommonName}}, id.Key)
	if err != nil {
		return nil, err
	}
	resp, err := cl.RenewCert(ctx, &pb.RenewRequest{NodeUuid: id.Cert.Subject.CommonName, CsrDer: csrDER})
	if err != nil {
		return nil, fmt.Errorf("RenewCert: %w", err)
	}
	newCert, err := x509.ParseCertificate(resp.NodeCert)
	if err != nil {
		return nil, err
	}
	if err := verifyIssuedCert(newCert, id.CABundle, trustRoot); err != nil {
		return nil, fmt.Errorf("renewed cert chain verify: %w", err)
	}
	return newCert, nil
}
