// SPDX-License-Identifier: BSD-3-Clause
package witness

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
)

// smallOrderY are the y coordinates, little-endian, of the eight small-order
// points of edwards25519: order 4 (0), the identity (1), order 2 (p - 1) and
// order 8 (Y8, p - Y8). Either sign of x gives the same set.
var smallOrderY = func() [][]byte {
	var ys [][]byte
	for _, y := range []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000000",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	} {
		raw, _ := hex.DecodeString(y)
		ys = append(ys, raw)
	}
	return ys
}()

// ed25519L is the group order L, little-endian.
var ed25519L, _ = hex.DecodeString("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")

// canonicalPoint reports whether a 32-byte point encoding has y < p
// (RFC 8032 section 5.1.3).
func canonicalPoint(encoded []byte) bool {
	return !(encoded[0] >= 0xed && bytes.Count(encoded[1:31], []byte{0xff}) == 30 && encoded[31]&0x7f == 0x7f)
}

// smallOrder reports whether a canonical point encoding names a point of
// small order.
func smallOrder(encoded []byte) bool {
	y := append([]byte(nil), encoded...)
	y[31] &= 0x7f
	for _, small := range smallOrderY {
		if bytes.Equal(y, small) {
			return true
		}
	}
	return false
}

// belowL reports whether a little-endian scalar is less than L.
func belowL(s []byte) bool {
	for i := 31; i >= 0; i-- {
		if s[i] != ed25519L[i] {
			return s[i] < ed25519L[i]
		}
	}
	return false
}

// verifyEd25519Strict is Ed25519 verification as checkpointed-local-log's
// ed25519-vectors.json pins it: A and R canonical (y < p) and not of small
// order, S < L, then the cofactorless equation. ed25519.Verify alone accepts
// a small-order A, and a small-order A verifies a forged signature over any
// message.
func verifyEd25519Strict(public ed25519.PublicKey, message, signature []byte) bool {
	if len(public) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	r, s := signature[:32], signature[32:]
	if !canonicalPoint(public) || !canonicalPoint(r) || smallOrder(public) || smallOrder(r) || !belowL(s) {
		return false
	}
	return ed25519.Verify(public, message, signature)
}
