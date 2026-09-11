package audit

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dani.local/agent/internal/kms"
	"dani.local/agent/pkg/dani"
)

func openLog(t *testing.T) (*Log, *kms.SoftwareKeyStore) {
	t.Helper()
	ks, err := kms.NewSoftware()
	if err != nil {
		t.Fatal(err)
	}
	l, err := Open(context.Background(), ":memory:", ks)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, ks
}

func fixedClock(t *testing.T) {
	t.Helper()
	orig := nowFn
	n := time.Unix(1700000000, 0)
	nowFn = func() time.Time { n = n.Add(time.Second); return n }
	t.Cleanup(func() { nowFn = orig })
}

func TestChainAppendsAndVerifies(t *testing.T) {
	fixedClock(t)
	l, _ := openLog(t)
	ctx := context.Background()
	for i, typ := range []string{"genesis", "node.enrolled", "training.start", "model.approved"} {
		if err := l.Emit(typ, map[string]any{"i": i}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.SignHead(ctx); err != nil {
		t.Fatal(err)
	}
	l.Emit("rag.denied", map[string]any{"user": "carol"})
	if err := l.SignHead(ctx); err != nil {
		t.Fatal(err)
	}
	in, err := l.Verify(ctx)
	if err != nil || !in.OK || in.Records != 5 || in.SignedHeads != 2 {
		t.Fatalf("verify: %+v err=%v", in, err)
	}
	rec, err := l.Recent(ctx, 3)
	if err != nil || len(rec) != 3 || rec[2].Type != "rag.denied" || rec[0].Seq != 3 {
		t.Fatalf("recent wrong: %+v err=%v", rec, err)
	}
	records, head, heads, err := l.Stats(ctx)
	if err != nil || records != 5 || head == genesisHash || heads != 2 {
		t.Fatalf("stats wrong: %d %s %d %v", records, head, heads, err)
	}
	// default limit path
	if all, _ := l.Recent(ctx, 0); len(all) != 5 {
		t.Fatal("default Recent limit should return all 5")
	}
}

func TestTamperDetection(t *testing.T) {
	fixedClock(t)
	ctx := context.Background()

	t.Run("content tampered", func(t *testing.T) {
		l, _ := openLog(t)
		l.Emit("a", map[string]any{"v": 1})
		l.Emit("b", map[string]any{"v": 2})
		if _, err := l.db.Exec(`UPDATE audit_events SET payload='{"v":999}' WHERE seq=1`); err != nil {
			t.Fatal(err)
		}
		in, _ := l.Verify(ctx)
		if in.OK || in.BrokenAt != 1 || !strings.Contains(in.Why, "tampered") {
			t.Fatalf("tamper not detected: %+v", in)
		}
	})
	t.Run("record deleted", func(t *testing.T) {
		l, _ := openLog(t)
		l.Emit("a", nil)
		l.Emit("b", nil)
		l.Emit("c", nil)
		l.db.Exec(`DELETE FROM audit_events WHERE seq=2`)
		in, _ := l.Verify(ctx)
		if in.OK || !strings.Contains(in.Why, "sequence gap") {
			t.Fatalf("deletion not detected: %+v", in)
		}
	})
	t.Run("chain re-linked", func(t *testing.T) {
		l, _ := openLog(t)
		l.Emit("a", nil)
		l.Emit("b", nil)
		l.db.Exec(`UPDATE audit_events SET prev_hash='deadbeef' WHERE seq=2`)
		in, _ := l.Verify(ctx)
		if in.OK || !strings.Contains(in.Why, "prev-hash break") {
			t.Fatalf("re-link not detected: %+v", in)
		}
	})
	t.Run("history rewritten under a signed head", func(t *testing.T) {
		l, _ := openLog(t)
		l.Emit("a", nil)
		l.SignHead(ctx)
		// a consistent-looking chain replacement: rewrite record 1 AND its hash so the chain itself
		// verifies — the SIGNED HEAD still catches it
		at := nowFn().UTC().Format(time.RFC3339Nano)
		h := hashRecord(1, at, "forged", []byte(`{}`), genesisHash)
		l.db.Exec(`UPDATE audit_events SET at=?, type='forged', payload='{}', prev_hash=?, hash=? WHERE seq=1`, at, genesisHash, h)
		l.seq, l.head = 1, h // attacker also fixes in-memory state in this simulation
		in, _ := l.Verify(ctx)
		if in.OK || !strings.Contains(in.Why, "history rewritten") {
			t.Fatalf("head anchor did not catch the rewrite: %+v", in)
		}
	})
	t.Run("forged head signature", func(t *testing.T) {
		l, _ := openLog(t)
		l.Emit("a", nil)
		l.SignHead(ctx)
		l.db.Exec(`UPDATE audit_heads SET sig=x'00'`)
		in, _ := l.Verify(ctx)
		if in.OK || !strings.Contains(in.Why, "signature invalid") {
			t.Fatalf("forged sig not detected: %+v", in)
		}
	})
	t.Run("garbage head key", func(t *testing.T) {
		l, _ := openLog(t)
		l.Emit("a", nil)
		l.SignHead(ctx)
		l.db.Exec(`UPDATE audit_heads SET pub=x'00'`)
		in, _ := l.Verify(ctx)
		if in.OK || !strings.Contains(in.Why, "unparseable") {
			t.Fatalf("garbage key not detected: %+v", in)
		}
	})
}

func TestResumeFromDisk(t *testing.T) {
	fixedClock(t)
	ctx := context.Background()
	ks, _ := kms.NewSoftware()
	dsn := filepath.Join(t.TempDir(), "audit.db")
	l1, err := Open(ctx, dsn, ks)
	if err != nil {
		t.Fatal(err)
	}
	l1.Emit("a", nil)
	l1.Emit("b", nil)
	l1.Close()
	// reopen: seq/head resume, the chain stays continuous
	l2, err := Open(ctx, dsn, ks)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	l2.Emit("c", nil)
	in, err := l2.Verify(ctx)
	if err != nil || !in.OK || in.Records != 3 {
		t.Fatalf("resume broke the chain: %+v err=%v", in, err)
	}
}

type failKS struct {
	dani.KeyStore
	failSign, failPub bool
}

func (f failKS) Sign(ctx context.Context, p dani.KeyPurpose, b []byte) ([]byte, error) {
	if f.failSign {
		return nil, errors.New("sign boom")
	}
	return f.KeyStore.Sign(ctx, p, b)
}
func (f failKS) GetPublicKey(ctx context.Context, p dani.KeyPurpose) ([]byte, error) {
	if f.failPub {
		return nil, errors.New("pub boom")
	}
	return f.KeyStore.GetPublicKey(ctx, p)
}

func TestSignHeadErrorsAndEmptyChain(t *testing.T) {
	ctx := context.Background()
	base, _ := kms.NewSoftware()
	for _, ks := range []dani.KeyStore{failKS{KeyStore: base, failSign: true}, failKS{KeyStore: base, failPub: true}} {
		l, err := Open(ctx, ":memory:", ks)
		if err != nil {
			t.Fatal(err)
		}
		l.Emit("a", nil)
		if err := l.SignHead(ctx); err == nil {
			t.Fatal("KMS failure must surface")
		}
		l.Close()
	}
	// empty chain: SignHead is a no-op
	l, _ := openLog(t)
	if err := l.SignHead(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, heads, _ := l.Stats(ctx); heads != 0 {
		t.Fatal("empty chain must not be anchored")
	}
}

func TestStartSigningTicks(t *testing.T) {
	l, _ := openLog(t)
	l.Emit("a", nil)
	ctx, cancel := context.WithCancel(context.Background())
	l.StartSigning(ctx, 20*time.Millisecond)
	deadline := time.Now().Add(15 * time.Second) // generous: CI runners under -race are slow
	for {
		if _, _, heads, _ := l.Stats(context.Background()); heads >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("StartSigning never anchored")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	time.Sleep(50 * time.Millisecond) // drain the signing goroutine before other tests swap nowFn
}

func TestClosedLogSurfacesStoreErrors(t *testing.T) {
	ks, _ := kms.NewSoftware()
	l, err := Open(context.Background(), ":memory:", ks)
	if err != nil {
		t.Fatal(err)
	}
	l.Emit("a", nil)
	l.SignHead(context.Background())
	l.Close()
	ctx := context.Background()
	if err := l.Emit("b", nil); err == nil {
		t.Fatal("Emit on a closed store must error")
	}
	if _, err := l.Verify(ctx); err == nil {
		t.Fatal("Verify on a closed store must error")
	}
	if _, err := l.Recent(ctx, 5); err == nil {
		t.Fatal("Recent on a closed store must error")
	}
	if _, _, _, err := l.Stats(ctx); err == nil {
		t.Fatal("Stats on a closed store must error")
	}
	if err := l.SignHead(ctx); err == nil {
		t.Fatal("SignHead insert on a closed store must error")
	}
}

func TestOpenErrors(t *testing.T) {
	ks, _ := kms.NewSoftware()
	// a directory path as DSN → open/schema fails
	if _, err := Open(context.Background(), filepath.Join(t.TempDir(), "no-such-dir", "x.db"), ks); err == nil {
		t.Fatal("unopenable DSN must error")
	}
}
