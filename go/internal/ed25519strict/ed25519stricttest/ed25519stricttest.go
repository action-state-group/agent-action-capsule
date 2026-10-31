// SPDX-License-Identifier: BSD-3-Clause

// Package ed25519stricttest builds, over any message, the two kinds of
// signature in checkpointed-local-log's ed25519-vectors.json that
// ed25519.Verify accepts and strict Ed25519 refuses: a small-order key A
// ("small-order A identity") and a small-order R ("identity R"). Tests of a
// verify path use them to show the path is strict; nothing else imports it.
package ed25519stricttest

import (
	"crypto/ed25519"
	"crypto/sha512"
	"math/big"
)

// IdentityKey is the identity point, the small-order A of the
// "small-order A identity" case.
var IdentityKey = ed25519.PublicKey(append([]byte{1}, make([]byte, 31)...))

// IdentityKeyForgery is R the identity and S = 0: under IdentityKey it
// satisfies the cofactorless equation over any message, so anyone can make it.
func IdentityKeyForgery() []byte {
	return append(append([]byte(nil), IdentityKey...), make([]byte, 32)...)
}

var groupOrder, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

func littleEndian(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

// IdentityR signs message under key with R the identity point, as the
// "identity R" case does: S = k·a mod L with k = SHA-512(R || A || M) and a
// the key's scalar. Then [S]B = [k]A = R + [k]A, so ed25519.Verify accepts
// it, but R has small order. Only the key's holder can make it.
func IdentityR(key ed25519.PrivateKey, message []byte) []byte {
	h := sha512.Sum512(key.Seed())
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	a := littleEndian(h[:32])
	r := append([]byte{1}, make([]byte, 31)...)
	digest := sha512.New()
	digest.Write(r)
	digest.Write(key.Public().(ed25519.PublicKey))
	digest.Write(message)
	k := littleEndian(digest.Sum(nil))
	s := new(big.Int).Mod(new(big.Int).Mul(k, a), groupOrder)
	be := s.FillBytes(make([]byte, 32))
	out := append([]byte(nil), r...)
	for i := 31; i >= 0; i-- {
		out = append(out, be[i])
	}
	return out
}
