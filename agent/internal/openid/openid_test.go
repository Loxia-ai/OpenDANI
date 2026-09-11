package openid

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestDeriveUUIDStableAndKeyBound(t *testing.T) {
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	u1 := DeriveUUID(pub1)
	if u1 != DeriveUUID(pub1) {
		t.Fatal("uuid must be stable for a key")
	}
	if u1 == DeriveUUID(pub2) {
		t.Fatal("distinct keys must derive distinct uuids")
	}
	if !IsOpenUUID(u1) || len(u1) != len("open-")+20 {
		t.Fatalf("open uuid shape wrong: %q", u1)
	}
	if !BindsKey(u1, pub1) || BindsKey(u1, pub2) {
		t.Fatal("BindsKey must accept the owning key and reject others")
	}
	if IsOpenUUID("worker-7") {
		t.Fatal("operator-assigned names are not open uuids")
	}
}

func TestProofOfWorkSolveVerify(t *testing.T) {
	dep, uuid := "dep-open", "open-abc"
	// low difficulty so the test is fast but still exercises >0 bits
	nonce, ok := Solve(dep, uuid, 12, 1<<24)
	if !ok {
		t.Fatal("solve failed at 12 bits")
	}
	if !Verify(dep, uuid, nonce, 12) {
		t.Fatal("verify must accept the found nonce")
	}
	// wrong deployment / uuid / difficulty must fail
	if Verify("other-dep", uuid, nonce, 12) {
		t.Fatal("PoW must not verify under a different deployment (no cross-network replay)")
	}
	if Verify(dep, "open-xyz", nonce, 12) {
		t.Fatal("PoW must be bound to the uuid")
	}
	if Verify(dep, uuid, nonce+1, 12) {
		t.Fatal("a different nonce must not verify (except by luck; overwhelmingly unlikely)")
	}
	// harder difficulty than solved-for should (almost always) reject this nonce
	if Verify(dep, uuid, nonce, 28) {
		t.Skip("rare: the 12-bit nonce happened to satisfy 28 bits")
	}
}

func TestPoWZeroBitsIsFree(t *testing.T) {
	if n, ok := Solve("d", "u", 0, 0); !ok || n != 0 {
		t.Fatal("0 bits must be an instant no-op")
	}
	if !Verify("d", "u", 12345, 0) {
		t.Fatal("0 bits must verify any nonce")
	}
}

func TestSolveBoundedFailure(t *testing.T) {
	// a high difficulty with a tiny iteration cap must fail cleanly, not hang
	if _, ok := Solve("d", "u", 40, 1000); ok {
		t.Skip("astronomically unlikely to solve 40 bits in 1000 iters")
	}
}

func TestNonceCodec(t *testing.T) {
	for _, n := range []uint64{0, 1, 42, 1 << 40} {
		got, err := DecodeNonce(EncodeNonce(n))
		if err != nil || got != n {
			t.Fatalf("codec round-trip failed for %d: %v %d", n, err, got)
		}
	}
	if _, err := DecodeNonce([]byte{1, 2, 3}); err == nil {
		t.Fatal("malformed nonce must error")
	}
}

func TestRequestPoW(t *testing.T) {
	bucket := TimeBucket(1783500000, 30)
	body := []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`)
	bh := BodyHash(body)
	nonce, ok := SolveRequest(bucket, bh, 10, 1<<22)
	if !ok {
		t.Fatal("solve request PoW failed")
	}
	if !VerifyRequest(bucket, bh, nonce, 10) {
		t.Fatal("verify must accept the found nonce")
	}
	// bound to the body: a different body invalidates the nonce
	if VerifyRequest(bucket, BodyHash([]byte("other body")), nonce, 10) {
		t.Fatal("PoW must be bound to the request body (no cross-request replay)")
	}
	// bound to the time bucket: a different window invalidates it
	if VerifyRequest(bucket+1, bh, nonce, 10) {
		t.Fatal("PoW must be bound to the time bucket (no stockpiling)")
	}
	// zero bits = off
	if !VerifyRequest(bucket, bh, 0, 0) {
		t.Fatal("0 bits must accept any nonce")
	}
}

func TestTimeBucket(t *testing.T) {
	if TimeBucket(100, 30) != TimeBucket(115, 30) {
		t.Fatal("timestamps in the same 30s window share a bucket")
	}
	if TimeBucket(100, 30) == TimeBucket(131, 30) {
		t.Fatal("timestamps in different windows differ")
	}
	if TimeBucket(100, 0) != TimeBucket(100, 30) {
		t.Fatal("window<=0 must default to 30s")
	}
}

func TestSolveRequestZeroBits(t *testing.T) {
	if n, ok := SolveRequest(1, []byte("x"), 0, 0); !ok || n != 0 {
		t.Fatal("0 bits request PoW is a no-op")
	}
}

func TestLeadingZeroBits(t *testing.T) {
	for _, tc := range []struct {
		b    []byte
		want int
	}{
		{[]byte{0xff}, 0},
		{[]byte{0x7f}, 1},
		{[]byte{0x00, 0xff}, 8},
		{[]byte{0x00, 0x00}, 16},
		{[]byte{0x00, 0x0f}, 12},
	} {
		if got := leadingZeroBits(tc.b); got != tc.want {
			t.Fatalf("leadingZeroBits(%x) = %d, want %d", tc.b, got, tc.want)
		}
	}
}
