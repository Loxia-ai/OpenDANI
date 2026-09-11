// Package signerprovider is the config-driven KMS-provider factory for the three reviewer signers
// (ROADMAP §2). An operator picks each role's backend by a spec string — no code change — so the
// three-party control from D-19 can be backed by three DIFFERENT custodians:
//
//	kms            the controller's shared software KMS (DEMO default; all roles distinct purposes)
//	file:<path>    a per-role persisted software keystore (three independent software custodians)
//	remote:<url>   an EXTERNAL signing service (the officer's own HSM / cloud-KMS) — key never in DANI
//
// This is the seam an enterprise deployment uses to put each officer's approval key in their own HSM
// while DANI holds only public halves. The full-KeyStore provider for the OTHER key purposes
// (CA/audit/enrollment going to HSM) remains the broader Phase-1 item; this covers reviewer signing.
package signerprovider

import (
	"context"
	"fmt"
	"os"
	"strings"

	"dani.local/agent/internal/kms"
	"dani.local/agent/internal/modelreg"
	"dani.local/agent/pkg/dani"
)

// Build constructs one reviewer role's RoleSigner from a spec. sharedKS backs the "kms" spec (the
// controller's own keystore); purpose is the role's KeyPurpose (used by the kms/file backends).
func Build(spec string, purpose dani.KeyPurpose, sharedKS dani.KeyStore) (modelreg.RoleSigner, error) {
	spec = strings.TrimSpace(spec)
	switch {
	case spec == "" || spec == "kms":
		if sharedKS == nil {
			return nil, fmt.Errorf("signerprovider: %q backend requires a shared keystore", "kms")
		}
		return modelreg.KMSRoleSigner{KS: sharedKS, Purpose: purpose}, nil

	case strings.HasPrefix(spec, "remote:"):
		url := strings.TrimPrefix(spec, "remote:")
		if url == "" {
			return nil, fmt.Errorf("signerprovider: remote spec needs a URL")
		}
		return modelreg.RemoteRoleSigner{BaseURL: url}, nil

	case strings.HasPrefix(spec, "file:"):
		path := strings.TrimPrefix(spec, "file:")
		if path == "" {
			return nil, fmt.Errorf("signerprovider: file spec needs a path")
		}
		ks, err := loadOrCreateSoftware(path, purpose)
		if err != nil {
			return nil, err
		}
		return modelreg.KMSRoleSigner{KS: ks, Purpose: purpose}, nil

	default:
		return nil, fmt.Errorf("signerprovider: unknown signer spec %q (want kms | file:<path> | remote:<url>)", spec)
	}
}

// BuildAll builds the three reviewer signers from a role→spec map. Every reviewer role must be
// present; a missing or empty spec falls back to the shared KMS so partial config is still valid.
func BuildAll(specs map[modelreg.Role]string, sharedKS dani.KeyStore) (map[modelreg.Role]modelreg.RoleSigner, error) {
	out := map[modelreg.Role]modelreg.RoleSigner{}
	for role, purpose := range modelreg.RolePurposes() {
		s, err := Build(specs[role], purpose, sharedKS)
		if err != nil {
			return nil, fmt.Errorf("signerprovider: role %q: %w", role, err)
		}
		out[role] = s
	}
	return out, nil
}

// ParseSpecMap parses "security=remote:https://a,governance=file:/k/gov,admin=kms" into a role→spec
// map. Blank input yields an empty map (all roles fall back to the shared KMS). Unknown role names
// are an error so a typo can't silently drop an officer to the default backend.
func ParseSpecMap(s string) (map[modelreg.Role]string, error) {
	out := map[modelreg.Role]string{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 || strings.TrimSpace(kv[0]) == "" || strings.TrimSpace(kv[1]) == "" {
			return nil, fmt.Errorf("signerprovider: bad signer entry %q (want role=spec)", part)
		}
		role, ok := resolveRole(strings.TrimSpace(kv[0]))
		if !ok {
			return nil, fmt.Errorf("signerprovider: unknown reviewer role %q", kv[0])
		}
		out[role] = strings.TrimSpace(kv[1])
	}
	return out, nil
}

// roleAliases maps friendly CLI names (and the canonical role values) to reviewer roles.
var roleAliases = map[string]modelreg.Role{
	"security":           modelreg.RoleSecurity,
	"security-officer":   modelreg.RoleSecurity,
	"governance":         modelreg.RoleGovernance,
	"governance-officer": modelreg.RoleGovernance,
	"admin":              modelreg.RoleAdmin,
	"administrator":      modelreg.RoleAdmin,
}

// resolveRole maps a CLI role token (alias or canonical) to a reviewer Role.
func resolveRole(s string) (modelreg.Role, bool) {
	r, ok := roleAliases[strings.ToLower(s)]
	return r, ok
}

// loadOrCreateSoftware returns a persisted software keystore at path, creating + sealing it (0600) on
// first use and materializing the purpose key so its public half is available immediately.
func loadOrCreateSoftware(path string, purpose dani.KeyPurpose) (*kms.SoftwareKeyStore, error) {
	if data, err := os.ReadFile(path); err == nil {
		ks, err := kms.ImportSoftware(data)
		if err != nil {
			return nil, fmt.Errorf("signerprovider: load %s: %w", path, err)
		}
		return ks, nil
	}
	ks, err := kms.NewSoftware()
	if err != nil {
		return nil, err
	}
	if _, err := ks.GetPublicKey(context.Background(), purpose); err != nil {
		return nil, err
	}
	data, err := ks.Export()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return nil, fmt.Errorf("signerprovider: persist %s: %w", path, err)
	}
	return ks, nil
}
