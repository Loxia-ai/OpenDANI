package kms

// Open is the config-driven KMS provider (generalizes the reviewer-signer factory to the whole
// KeyStore, ROADMAP §2). An operator picks the controller's key backend by spec:
//
//	software            in-memory software keystore (DEMO default; fresh master KEK)
//	software-file:<p>   persisted software keystore at <p> (created on first use)
//	remote:<url>        external HSM / cloud-KMS signing service (RemoteKeyStore) — keys never in DANI
//
// The returned value satisfies ca.KeyStore (dani.KeyStore + Signer), so it can back the CA, audit
// chain, and enrollment keys. A remote keystore yields an HSM-backed CA: the issuing key lives in the
// HSM. NOTE: a remote keystore cannot Export (that's the point — no private material to export), so
// HA peers share the SAME HSM endpoint rather than the shared-CA bundle; genesis still runs (it reads
// the intermediate public key and asks the HSM to wrap the dormant root).

import (
	"context"
	"crypto"
	"fmt"
	"os"
	"strings"

	"dani.local/agent/pkg/dani"
)

// Provider is a constructed KeyStore plus whether it supports Export (software does; remote does not).
type Provider struct {
	KeyStore   *SoftwareKeyStore // non-nil for software backends (supports Export/HA bundle)
	Remote     *RemoteKeyStore   // non-nil for the remote/HSM backend
	Exportable bool
}

// Open builds a KMS backend from spec. purposes are materialized eagerly for software backends so the
// HA bundle captures them (mirrors the genesis behavior).
func Open(spec string) (*Provider, error) {
	spec = strings.TrimSpace(spec)
	switch {
	case spec == "" || spec == "software":
		ks, err := NewSoftware()
		if err != nil {
			return nil, err
		}
		return &Provider{KeyStore: ks, Exportable: true}, nil

	case strings.HasPrefix(spec, "software-file:"):
		path := strings.TrimPrefix(spec, "software-file:")
		if path == "" {
			return nil, fmt.Errorf("kms: software-file spec needs a path")
		}
		if data, err := os.ReadFile(path); err == nil {
			ks, err := ImportSoftware(data)
			if err != nil {
				return nil, fmt.Errorf("kms: load %s: %w", path, err)
			}
			return &Provider{KeyStore: ks, Exportable: true}, nil
		}
		ks, err := NewSoftware()
		if err != nil {
			return nil, err
		}
		// Materialize every long-lived purpose key BEFORE export (DEKs are created lazily) so a reload
		// from the file yields the SAME keys, not freshly-generated ones.
		for _, p := range allPurposes {
			if _, err := ks.GetPublicKey(context.Background(), p); err != nil {
				return nil, err
			}
		}
		data, err := ks.Export()
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return nil, fmt.Errorf("kms: persist %s: %w", path, err)
		}
		return &Provider{KeyStore: ks, Exportable: true}, nil

	case strings.HasPrefix(spec, "remote:"):
		url := strings.TrimPrefix(spec, "remote:")
		if url == "" {
			return nil, fmt.Errorf("kms: remote spec needs a URL")
		}
		return &Provider{Remote: &RemoteKeyStore{BaseURL: url}, Exportable: false}, nil

	default:
		return nil, fmt.Errorf("kms: unknown backend spec %q (want software | software-file:<path> | remote:<url>)", spec)
	}
}

// KS returns the constructed keystore as the ca.KeyStore-shaped value (dani.KeyStore + Signer): the
// remote HSM backend when present, otherwise the software backend. Both concrete types implement
// Signer, so the caller can hand it straight to controller.GenesisWithKMS.
func (p *Provider) KS() interface {
	dani.KeyStore
	Signer(dani.KeyPurpose) (crypto.Signer, error)
} {
	if p.Remote != nil {
		return p.Remote
	}
	return p.KeyStore
}

// allPurposes are the long-lived purpose keys a controller uses; materialized when persisting.
var allPurposes = []dani.KeyPurpose{
	dani.PurposeCASigning, dani.PurposeConfigSigning, dani.PurposeAuditChainSigning,
	dani.PurposeRevocationSigning, dani.PurposeEnrollmentSigning, dani.PurposeDataAtRest,
	dani.PurposeModelSignSecurity, dani.PurposeModelSignGovernance, dani.PurposeModelSignAdmin,
}
