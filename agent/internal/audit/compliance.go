package audit

// Compliance & Archived tiers (Architecture §6.15, §6.17.7). The Active tier (audit.go) is the live
// hash chain. This file adds the two long-term tiers as the spec describes them:
//
//   - COMPLIANCE export: a self-contained, offline-verifiable bundle of the ENTIRE chain (every
//     event + every signed head) with a final KMS signature over the whole bundle. A regulator can
//     verify it with VerifyBundle WITHOUT the database or the live controller — the export stands on
//     its own as tamper-evident evidence.
//   - ARCHIVED seal: Export writes that bundle to a file (cold storage); the sealed segment is what
//     an operator rotates off the hot SQLite store for retention. (Pruning the hot store after a seal
//     is a v1.0 operational policy; the seal itself — the durable, verifiable artifact — is here.)

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"os"
	"time"

	"dani.local/agent/pkg/dani"
)

// ComplianceBundle is a portable, independently-verifiable snapshot of the audit chain.
type ComplianceBundle struct {
	Deployment string  `json:"deployment"`
	ExportedAt string  `json:"exportedAt"`
	Events     []Event `json:"events"`
	Heads      []Head  `json:"heads"`
	BundleSig  []byte  `json:"bundleSig"` // KMS signature over bundleDigest(Events, Heads)
	BundlePub  []byte  `json:"bundlePub"` // SPKI of the audit-chain-signing key (self-describing)
}

// bundleDigest is the canonical bytes the bundle signature covers: the deployment id followed by the
// full event and head sets. Any change to any exported record changes this digest.
func bundleDigest(deployment string, events []Event, heads []Head) []byte {
	h := sha256.New()
	b, _ := json.Marshal(struct {
		D string  `json:"d"`
		E []Event `json:"e"`
		H []Head  `json:"h"`
	}{deployment, events, heads})
	h.Write(b)
	sum := h.Sum(nil)
	return sum
}

// Export seals the entire chain into a signed ComplianceBundle. deployment labels the evidence.
func (l *Log) Export(ctx context.Context, deployment string) (*ComplianceBundle, error) {
	events, err := l.allEvents(ctx)
	if err != nil {
		return nil, err
	}
	heads, err := l.allHeads(ctx)
	if err != nil {
		return nil, err
	}
	digest := bundleDigest(deployment, events, heads)
	sig, err := l.ks.Sign(ctx, dani.PurposeAuditChainSigning, digest)
	if err != nil {
		return nil, err
	}
	pub, err := l.ks.GetPublicKey(ctx, dani.PurposeAuditChainSigning)
	if err != nil {
		return nil, err
	}
	return &ComplianceBundle{
		Deployment: deployment, ExportedAt: nowFn().UTC().Format(time.RFC3339Nano),
		Events: events, Heads: heads, BundleSig: sig, BundlePub: pub,
	}, nil
}

// ExportFile seals the chain and writes the bundle JSON to path (the Archived-tier cold artifact).
func (l *Log) ExportFile(ctx context.Context, deployment, path string) (*ComplianceBundle, error) {
	b, err := l.Export(ctx, deployment)
	if err != nil {
		return nil, err
	}
	data, _ := json.MarshalIndent(b, "", "  ")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return nil, err
	}
	return b, nil
}

// VerifyBundle re-verifies an exported bundle OFFLINE (no DB): it replays the hash chain, re-checks
// every signed head, and checks the outer bundle signature. This is what an auditor runs on the
// evidence file. It mirrors Log.Verify's chain logic exactly, so the two can never diverge in intent.
func VerifyBundle(b *ComplianceBundle) (Integrity, error) {
	prev := genesisHash
	var n int64
	hashAtSeq := map[int64]string{}
	for _, e := range b.Events {
		n++
		if e.Seq != n {
			return Integrity{Records: n, BrokenAt: e.Seq, Why: "sequence gap (record deleted?)"}, nil
		}
		if e.PrevHash != prev {
			return Integrity{Records: n, BrokenAt: e.Seq, Why: "prev-hash break (chain re-ordered?)"}, nil
		}
		if hashRecord(e.Seq, e.At.UTC().Format(time.RFC3339Nano), e.Type, []byte(e.Payload), e.PrevHash) != e.Hash {
			return Integrity{Records: n, BrokenAt: e.Seq, Why: "record hash mismatch (content tampered)"}, nil
		}
		prev = e.Hash
		hashAtSeq[e.Seq] = e.Hash
	}
	signed := 0
	for _, h := range b.Heads {
		if hashAtSeq[h.Seq] != h.Head {
			return Integrity{Records: n, SignedHeads: signed, BrokenAt: h.Seq, Why: "signed head does not match chain (history rewritten)"}, nil
		}
		pubAny, err := x509.ParsePKIXPublicKey(h.Pub)
		if err != nil {
			return Integrity{Records: n, SignedHeads: signed, BrokenAt: h.Seq, Why: "unparseable head signature key"}, nil
		}
		edPub, ok := pubAny.(ed25519.PublicKey)
		if !ok || !ed25519.Verify(edPub, headMsg(h.Seq, h.Head), h.Sig) {
			return Integrity{Records: n, SignedHeads: signed, BrokenAt: h.Seq, Why: "head signature invalid"}, nil
		}
		signed++
	}
	// outer bundle signature: proves the export AS A WHOLE was sealed by the audit-chain key
	pubAny, err := x509.ParsePKIXPublicKey(b.BundlePub)
	if err != nil {
		return Integrity{Records: n, SignedHeads: signed, Why: "unparseable bundle key"}, nil
	}
	edPub, ok := pubAny.(ed25519.PublicKey)
	if !ok || !ed25519.Verify(edPub, bundleDigest(b.Deployment, b.Events, b.Heads), b.BundleSig) {
		return Integrity{Records: n, SignedHeads: signed, Why: "bundle signature invalid (export tampered)"}, nil
	}
	return Integrity{OK: true, Records: n, SignedHeads: signed}, nil
}

// allEvents reads the whole chain oldest-first (for export).
func (l *Log) allEvents(ctx context.Context) ([]Event, error) {
	rows, err := l.db.QueryContext(ctx, `SELECT seq, at, type, payload, prev_hash, hash FROM audit_events ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var at, payload string
		if err := rows.Scan(&e.Seq, &at, &e.Type, &payload, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		e.At, _ = time.Parse(time.RFC3339Nano, at)
		e.Payload = json.RawMessage(payload)
		out = append(out, e)
	}
	return out, rows.Err()
}

// allHeads reads every signed head anchor (for export).
func (l *Log) allHeads(ctx context.Context) ([]Head, error) {
	rows, err := l.db.QueryContext(ctx, `SELECT seq, at, head, sig, pub FROM audit_heads ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Head
	for rows.Next() {
		var h Head
		var at string
		if err := rows.Scan(&h.Seq, &at, &h.Head, &h.Sig, &h.Pub); err != nil {
			return nil, err
		}
		h.At, _ = time.Parse(time.RFC3339Nano, at)
		out = append(out, h)
	}
	return out, rows.Err()
}
