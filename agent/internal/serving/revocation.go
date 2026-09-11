package serving

// Cert-revocation DISTRIBUTION (PRODUCTION-READINESS P1-4, closes D-29's honest gap): revoking a
// node used to refuse its renewals and evict it from routing, but its still-valid certificate kept
// working against every OTHER verifier until expiry. Now the controller publishes a signed
// revocation list on the mTLS Link; every worker polls it and rejects revoked peers at the TLS
// layer — a revoked node is refused fleet-wide within one poll interval, not at cert expiry.
//
// The list is signed with the controller's own Ed25519 identity key and carries its cert chain, so
// a verifier re-checks BOTH the transport (mTLS) and the document (signature by a cert that chains
// to the deployment root and carries the controller role) — the same defense-in-depth shape as the
// artifact pull path (DP13).

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"dani.local/agent/internal/ca"
)

// RevocationList is the fleet-wide CRL document.
type RevocationList struct {
	Seq      int64    `json:"seq"`      // monotonically increasing; replay of an older list is rejected
	Revoked  []string `json:"revoked"`  // node UUIDs (certificate CNs), sorted
	IssuedBy string   `json:"issuedBy"` // controller CN
	IssuedAt string   `json:"issuedAt"` // RFC3339 (informational; freshness is transport+seq)
	Sig      string   `json:"sig"`      // base64 Ed25519 over canonicalCRL(seq, revoked)
	Chain    []string `json:"chain"`    // base64 DER: signer leaf + issuing intermediate
}

// canonicalCRL is the exact byte string the signature covers.
func canonicalCRL(seq int64, revoked []string) []byte {
	return []byte("dani-crl.v1|" + strconv.FormatInt(seq, 10) + "|" + strings.Join(revoked, ","))
}

// buildRevocationList snapshots + signs the plane's revocation state.
func (p *Plane) buildRevocationList() (RevocationList, error) {
	p.mu.RLock()
	revoked := make([]string, 0, len(p.revoked))
	for uuid := range p.revoked {
		revoked = append(revoked, uuid)
	}
	seq := p.revSeq
	p.mu.RUnlock()
	sort.Strings(revoked)
	key, ok := p.id.Key.(ed25519.PrivateKey)
	if !ok {
		return RevocationList{}, fmt.Errorf("revocations: controller key is not ed25519")
	}
	sig := ed25519.Sign(key, canonicalCRL(seq, revoked))
	return RevocationList{
		Seq: seq, Revoked: revoked, IssuedBy: p.id.UUID,
		IssuedAt: time.Now().UTC().Format(time.RFC3339),
		Sig:      base64.StdEncoding.EncodeToString(sig),
		Chain: []string{
			base64.StdEncoding.EncodeToString(p.id.LeafRaw),
			base64.StdEncoding.EncodeToString(p.id.InterRaw),
		},
	}, nil
}

// handleRevocations serves the signed CRL on the mTLS Link (nodes poll it).
func (p *Plane) handleRevocations(rw http.ResponseWriter, _ *http.Request) {
	rl, err := p.buildRevocationList()
	if err != nil {
		writeErr(rw, http.StatusInternalServerError, err)
		return
	}
	writeJSON(rw, http.StatusOK, rl)
}

// Revoked reports whether a node UUID (cert CN) is on the revocation list — the TLS-layer check
// verifiers plug into serverTLS.
func (p *Plane) Revoked(cn string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.revoked[cn]
}

// VerifyRevocationList checks a CRL document end to end: the signer chain parses and verifies to
// the trust root, the signer's DANIClaims carry the controller role (a worker cannot mint
// revocations), issuedBy matches the signer CN, and the Ed25519 signature covers exactly
// (seq, revoked). Returns the revoked set.
func VerifyRevocationList(rl RevocationList, trustRoot *x509.Certificate) (map[string]bool, error) {
	if len(rl.Chain) == 0 {
		return nil, fmt.Errorf("revocations: no signer chain")
	}
	ders := make([][]byte, 0, len(rl.Chain))
	for _, b := range rl.Chain {
		der, err := base64.StdEncoding.DecodeString(b)
		if err != nil {
			return nil, fmt.Errorf("revocations: bad chain encoding: %w", err)
		}
		ders = append(ders, der)
	}
	leaf, err := x509.ParseCertificate(ders[0])
	if err != nil {
		return nil, fmt.Errorf("revocations: bad signer leaf: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(trustRoot)
	inters := x509.NewCertPool()
	for _, der := range ders[1:] {
		if c, err := x509.ParseCertificate(der); err == nil {
			inters.AddCert(c)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, fmt.Errorf("revocations: signer chain: %w", err)
	}
	claims, err := ca.Claims(leaf)
	if err != nil {
		return nil, fmt.Errorf("revocations: signer claims: %w", err)
	}
	isController := false
	for _, r := range claims.Roles {
		if r == "controller" {
			isController = true
		}
	}
	if !isController {
		return nil, fmt.Errorf("revocations: signer %q lacks the controller role", leaf.Subject.CommonName)
	}
	if leaf.Subject.CommonName != rl.IssuedBy {
		return nil, fmt.Errorf("revocations: issuedBy %q != signer CN %q", rl.IssuedBy, leaf.Subject.CommonName)
	}
	sig, err := base64.StdEncoding.DecodeString(rl.Sig)
	if err != nil {
		return nil, fmt.Errorf("revocations: bad signature encoding: %w", err)
	}
	pub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("revocations: signer key is not ed25519")
	}
	if !ed25519.Verify(pub, canonicalCRL(rl.Seq, rl.Revoked), sig) {
		return nil, fmt.Errorf("revocations: signature does not verify")
	}
	set := make(map[string]bool, len(rl.Revoked))
	for _, u := range rl.Revoked {
		set[u] = true
	}
	return set, nil
}

// marshalRL is a tiny helper for tests/logging.
func marshalRL(rl RevocationList) string { b, _ := json.Marshal(rl); return string(b) }

// revocationPoller keeps a node's local copy of the fleet CRL fresh: poll the controller's mTLS
// Link, verify the document (chain + role + signature), refuse sequence rollback, swap the set.
// Shared by Worker and TrainerNode — every mTLS server in the fleet consults it.
type revocationPoller struct {
	mu     sync.RWMutex
	set    map[string]bool
	seq    int64
	client *http.Client
	base   string // controller Link base URL
	root   *x509.Certificate
	every  time.Duration
	uuid   string // this node (log attribution)
}

func newRevocationPoller(uuid, base string, client *http.Client, root *x509.Certificate, every time.Duration) *revocationPoller {
	if every <= 0 {
		every = 5 * time.Second
	}
	return &revocationPoller{set: map[string]bool{}, client: client, base: base, root: root, every: every, uuid: uuid, seq: -1}
}

// isRevoked is the TLS-layer check (safe for nil pollers via the callers' wrappers).
func (rp *revocationPoller) isRevoked(cn string) bool {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return rp.set[cn]
}

// refresh pulls + verifies one CRL. Returns false when nothing changed (same seq).
func (rp *revocationPoller) refresh(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rp.base+"/link/revocations", nil)
	if err != nil {
		return false
	}
	resp, err := rp.client.Do(req)
	if err != nil {
		return false // controller unreachable — keep the last verified set (fail-static, not fail-open)
	}
	defer resp.Body.Close()
	var rl RevocationList
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&rl) != nil {
		return false
	}
	set, err := VerifyRevocationList(rl, rp.root)
	if err != nil {
		log.Printf("node %s: REJECTED revocation list: %v", rp.uuid, err)
		return false
	}
	rp.mu.Lock()
	defer rp.mu.Unlock()
	if rl.Seq < rp.seq {
		log.Printf("node %s: REJECTED revocation list rollback (seq %d < %d)", rp.uuid, rl.Seq, rp.seq)
		return false
	}
	changed := rl.Seq > rp.seq
	rp.set, rp.seq = set, rl.Seq
	if changed && len(set) > 0 {
		log.Printf("node %s: revocation list seq %d — %d revoked node(s) now refused at TLS", rp.uuid, rl.Seq, len(set))
	}
	return changed
}

// run polls until ctx is done.
func (rp *revocationPoller) run(ctx context.Context) {
	t := time.NewTicker(rp.every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rp.refresh(ctx)
		}
	}
}
