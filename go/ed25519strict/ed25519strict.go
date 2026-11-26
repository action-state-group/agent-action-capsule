// SPDX-License-Identifier: BSD-3-Clause

// Package ed25519strict is the public form of the strict Ed25519 rule this
// module verifies with: A and R canonical (y < p) and not of small order,
// S < L, then the cofactorless equation, as checkpointed-local-log's
// ed25519-vectors.json pins it. crypto/ed25519.Verify alone accepts a
// small-order A, and a small-order A verifies a forged signature over any
// message. A verifier outside this module uses it so that it applies the same
// rule, not a copy of it.
package ed25519strict

import (
	"crypto/ed25519"

	"github.com/action-state-group/agent-action-capsule/go/internal/ed25519strict"
)

// Verify reports whether signature is a strict Ed25519 signature by public
// over message. A key or signature of the wrong length never verifies.
func Verify(public ed25519.PublicKey, message, signature []byte) bool {
	return ed25519strict.Verify(public, message, signature)
}
