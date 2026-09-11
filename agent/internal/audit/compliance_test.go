package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func seedChain(t *testing.T, l *Log) {
	t.Helper()
	ctx := context.Background()
	for i, typ := range []string{"genesis", "node.enrolled", "training.completed", "model.approved", "policy.deny"} {
		if err := l.Emit(typ, map[string]any{"i": i}); err != nil {
			t.Fatal(err)
		}
		if i%2 == 0 { // anchor some heads
			if err := l.SignHead(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// TestComplianceBundleOfflineVerify: an exported bundle verifies STANDALONE (no DB) — the whole
// point of the Compliance tier. Both the chain and the outer bundle signature check out.
func TestComplianceBundleOfflineVerify(t *testing.T) {
	fixedClock(t)
	l, _ := openLog(t)
	seedChain(t, l)
	b, err := l.Export(context.Background(), "dep-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Events) != 5 || len(b.Heads) == 0 {
		t.Fatalf("bundle must carry the whole chain: %d events, %d heads", len(b.Events), len(b.Heads))
	}
	integ, err := VerifyBundle(b)
	if err != nil || !integ.OK || integ.Records != 5 {
		t.Fatalf("clean bundle must verify offline: %+v %v", integ, err)
	}
}

// TestComplianceBundleTamperDetection: tampering with any part of an exported bundle is detected
// offline — event content, a signed head, or the bundle signature itself.
func TestComplianceBundleTamperDetection(t *testing.T) {
	fixedClock(t)
	l, _ := openLog(t)
	seedChain(t, l)
	ctx := context.Background()

	// tamper an event payload
	b1, _ := l.Export(ctx, "dep-1")
	b1.Events[2].Payload = json.RawMessage(`{"i":999}`)
	if integ, _ := VerifyBundle(b1); integ.OK {
		t.Fatal("tampered event must break the bundle")
	}

	// delete an event (sequence gap)
	b2, _ := l.Export(ctx, "dep-1")
	b2.Events = append(b2.Events[:1], b2.Events[2:]...)
	if integ, _ := VerifyBundle(b2); integ.OK {
		t.Fatal("deleted event must break the bundle")
	}

	// forge a signed head
	b3, _ := l.Export(ctx, "dep-1")
	b3.Heads[0].Head = "deadbeef"
	if integ, _ := VerifyBundle(b3); integ.OK {
		t.Fatal("rewritten head must break the bundle")
	}

	// tamper the bundle signature (chain intact, outer seal broken)
	b4, _ := l.Export(ctx, "dep-1")
	b4.BundleSig = append([]byte{}, b4.BundleSig...)
	b4.BundleSig[0] ^= 0xff
	if integ, _ := VerifyBundle(b4); integ.OK {
		t.Fatal("tampered bundle signature must be detected")
	}

	// change the deployment label (covered by the bundle digest)
	b5, _ := l.Export(ctx, "dep-1")
	b5.Deployment = "dep-evil"
	if integ, _ := VerifyBundle(b5); integ.OK {
		t.Fatal("relabeled bundle must be detected")
	}

	// prev-hash break (seq contiguous, but a record's prev pointer rewritten)
	bp, _ := l.Export(ctx, "dep-1")
	bp.Events[2].PrevHash = "deadbeef"
	if integ, _ := VerifyBundle(bp); integ.OK || integ.Why != "prev-hash break (chain re-ordered?)" {
		t.Fatalf("prev-hash break must be detected: %+v", integ)
	}

	// head with a matching root but a corrupted SIGNATURE (distinct from a rewritten head)
	bs, _ := l.Export(ctx, "dep-1")
	bs.Heads[0].Sig = append([]byte{}, bs.Heads[0].Sig...)
	bs.Heads[0].Sig[0] ^= 0xff
	if integ, _ := VerifyBundle(bs); integ.OK || integ.Why != "head signature invalid" {
		t.Fatalf("invalid head signature must be detected: %+v", integ)
	}

	// unparseable head key
	b6, _ := l.Export(ctx, "dep-1")
	b6.Heads[0].Pub = []byte("not-a-key")
	if integ, _ := VerifyBundle(b6); integ.OK {
		t.Fatal("bad head key must break the bundle")
	}

	// unparseable bundle key
	b7, _ := l.Export(ctx, "dep-1")
	b7.BundlePub = []byte("not-a-key")
	if integ, _ := VerifyBundle(b7); integ.OK {
		t.Fatal("bad bundle key must break the bundle")
	}
}

// TestExportFile: the Archived-tier cold artifact round-trips from disk and verifies.
func TestExportFile(t *testing.T) {
	fixedClock(t)
	l, _ := openLog(t)
	seedChain(t, l)
	path := filepath.Join(t.TempDir(), "audit-seal.json")
	if _, err := l.ExportFile(context.Background(), "dep-1", path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var b ComplianceBundle
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatal(err)
	}
	if integ, _ := VerifyBundle(&b); !integ.OK {
		t.Fatalf("sealed file must verify: %+v", integ)
	}
	// unwritable path -> error
	if _, err := l.ExportFile(context.Background(), "dep-1", filepath.Join(t.TempDir(), "no-dir", "x.json")); err == nil {
		t.Fatal("unwritable seal path must error")
	}
}
