// Package openid is Open-DANI's permissionless join primitive: a self-certifying identity derived
// from a node's own public key, plus a proof-of-work speed bump so mass-Sybil enrollment costs real
// CPU. No operator, no bootstrap token. Enterprise DANI does not use this — it keeps signed tokens.
//
// The identity is bound to the key: you cannot claim an identity whose key you do not hold, and a
// new identity cannot be minted for free (each needs its own PoW). This is a FUNNEL-grade anti-Sybil
// measure, not full Byzantine resistance (that is a product, not a marketing network) — reputation
// (increment B) is the second line.
package openid

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
)

// DeriveUUID maps an Ed25519 public key to a stable, self-certifying node id.
func DeriveUUID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "open-" + hex.EncodeToString(h[:])[:20]
}

// leadingZeroBits counts the high zero bits of a digest (the PoW difficulty metric).
func leadingZeroBits(b []byte) int {
	n := 0
	for _, x := range b {
		if x == 0 {
			n += 8
			continue
		}
		for bit := 7; bit >= 0; bit-- {
			if x&(1<<uint(bit)) == 0 {
				n++
			} else {
				return n
			}
		}
		return n
	}
	return n
}

// challenge is the bytes the PoW hashes: deployment || uuid || nonce. Binding the deployment id
// stops one network's PoW from being replayed at another; binding the uuid ties the work to the
// identity (and thus, via EnrollProof, to the keypair).
func challenge(deployment, uuid string, nonce uint64) []byte {
	var nb [8]byte
	binary.BigEndian.PutUint64(nb[:], nonce)
	buf := make([]byte, 0, len(deployment)+1+len(uuid)+1+8)
	buf = append(buf, deployment...)
	buf = append(buf, 0)
	buf = append(buf, uuid...)
	buf = append(buf, 0)
	buf = append(buf, nb[:]...)
	return buf
}

// Solve finds a nonce whose challenge digest has >= bits leading zeros. maxIters bounds the search
// (0 = unbounded). Returns the nonce and whether it succeeded.
func Solve(deployment, uuid string, bits, maxIters int) (uint64, bool) {
	if bits <= 0 {
		return 0, true
	}
	var nonce uint64
	for i := 0; maxIters == 0 || i < maxIters; i++ {
		h := sha256.Sum256(challenge(deployment, uuid, nonce))
		if leadingZeroBits(h[:]) >= bits {
			return nonce, true
		}
		nonce++
	}
	return 0, false
}

// Verify checks that nonce solves the PoW for (deployment, uuid) at the given difficulty.
func Verify(deployment, uuid string, nonce uint64, bits int) bool {
	if bits <= 0 {
		return true
	}
	h := sha256.Sum256(challenge(deployment, uuid, nonce))
	return leadingZeroBits(h[:]) >= bits
}

// IsOpenUUID reports whether an id was minted by the open path (vs an operator-assigned name).
func IsOpenUUID(uuid string) bool { return strings.HasPrefix(uuid, "open-") }

// BindsKey reports whether uuid is the self-certifying id of pub — the check that ties a claimed
// open identity to the key that proved possession in the CSR.
func BindsKey(uuid string, pub ed25519.PublicKey) bool {
	return uuid == DeriveUUID(pub)
}

// ---- request proof-of-work (NAT-agnostic API admission) --------------------------------------
// Rather than rate-limit by IP (wrong behind NAT: shared-IP users throttle each other, and an
// attacker rotates IPs for pennies), price each REQUEST in CPU. The challenge binds a coarse TIME
// BUCKET (can't stockpile solutions) and the REQUEST BODY hash (can't precompute or replay across
// requests), so a solved nonce is good for exactly one request within one window.

// TimeBucket maps a unix-second timestamp to a window index (windowSec-wide).
func TimeBucket(unixSec, windowSec int64) int64 {
	if windowSec <= 0 {
		windowSec = 30
	}
	return unixSec / windowSec
}

func requestChallenge(bucket int64, bodyHash []byte, nonce uint64) []byte {
	var bb, nb [8]byte
	binary.BigEndian.PutUint64(bb[:], uint64(bucket))
	binary.BigEndian.PutUint64(nb[:], nonce)
	buf := make([]byte, 0, 8+len(bodyHash)+8)
	buf = append(buf, bb[:]...)
	buf = append(buf, bodyHash...)
	buf = append(buf, nb[:]...)
	return buf
}

// SolveRequest finds a nonce so sha256(bucket||bodyHash||nonce) has >= bits leading zeros.
func SolveRequest(bucket int64, bodyHash []byte, bits, maxIters int) (uint64, bool) {
	if bits <= 0 {
		return 0, true
	}
	var nonce uint64
	for i := 0; maxIters == 0 || i < maxIters; i++ {
		h := sha256.Sum256(requestChallenge(bucket, bodyHash, nonce))
		if leadingZeroBits(h[:]) >= bits {
			return nonce, true
		}
		nonce++
	}
	return 0, false
}

// VerifyRequest checks a request-PoW nonce for the given bucket + body hash + difficulty.
func VerifyRequest(bucket int64, bodyHash []byte, nonce uint64, bits int) bool {
	if bits <= 0 {
		return true
	}
	h := sha256.Sum256(requestChallenge(bucket, bodyHash, nonce))
	return leadingZeroBits(h[:]) >= bits
}

// BodyHash is the sha256 of a request body (bound into the request PoW).
func BodyHash(body []byte) []byte {
	h := sha256.Sum256(body)
	return h[:]
}

// EncodeNonce/DecodeNonce carry the PoW solution over the existing enrollment `token` wire field, so
// open enrollment needs no protobuf change — the controller reads `token` as a nonce in open mode.
func EncodeNonce(nonce uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], nonce)
	return b[:]
}

func DecodeNonce(b []byte) (uint64, error) {
	if len(b) != 8 {
		return 0, errors.New("open enrollment: malformed proof-of-work nonce")
	}
	return binary.BigEndian.Uint64(b), nil
}
