// SPDX-License-Identifier: Apache-2.0

package evidencerequest

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/action-state-group/agent-action-capsule/go/internal/ed25519strict"
)

// CLLCheckpoint is a decoded cll-checkpoint statement (profile §6.2.1 step
// 7): the COSE_Sign1 octets a log signs over its commitment. Decoding reads
// the form only; VerifySignature checks the signature under the log key the
// statement names.
type CLLCheckpoint struct {
	// Key is the log's Ed25519 public key (the statement's kid).
	Key []byte
	// Iss and Sub are the CWT_Claims iss and sub of the protected header,
	// as decoded: the log identity a relying party resolves the key for.
	Iss, Sub any
	// IssuedAt is the statement's issued_at, an RFC 3339 text string.
	IssuedAt string
	// LogSize is the log_size claim.
	LogSize uint64
	// Commitment is the peaks the statement commits to.
	Commitment [][]byte

	cp *cllCheckpoint
}

// ErrCheckpointNotChecked marks a well-formed checkpoint whose signature
// this revision does not check (step 8): not EdDSA, or carrying crit. It is
// returned wrapped together with ErrInvalid.
var ErrCheckpointNotChecked = errors.New("evidencerequest: only EdDSA (-8) checkpoint signatures with no crit are checked")

// DecodeCLLCheckpoint decodes cll-checkpoint octets as step 7 does. It
// accepts only an EdDSA (-8) statement with no crit, whose kid is a 32-octet
// Ed25519 key, as step 8 and step 9 require before a signature is checked.
// A statement that fails only step 8 is ErrCheckpointNotChecked.
func DecodeCLLCheckpoint(octets []byte) (*CLLCheckpoint, error) {
	cp, err := decodeCLLCheckpoint(octets)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if alg, ok := cp.alg.(int64); !ok || alg != -8 || cp.crit {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, ErrCheckpointNotChecked)
	}
	kid, ok := cp.kid.([]byte)
	if !ok || len(kid) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: kid is not a 32-octet Ed25519 public key", ErrInvalid)
	}
	return &CLLCheckpoint{Key: kid, Iss: cp.iss, Sub: cp.sub, IssuedAt: cp.issuedAt, LogSize: cp.logSize, Commitment: cp.commitment, cp: cp}, nil
}

// VerifySignature checks the statement's COSE_Sign1 signature (step 10)
// under the kid of its protected header. The value must come from
// DecodeCLLCheckpoint.
func (c *CLLCheckpoint) VerifySignature() error {
	if c == nil || c.cp == nil {
		return errors.Join(ErrInvalid, errors.New("the checkpoint was not decoded"))
	}
	kid, _ := c.cp.kid.([]byte)
	if len(c.cp.signature) != ed25519.SignatureSize || len(kid) != ed25519.PublicKeySize ||
		!ed25519strict.Verify(kid, sigStructure(c.cp.protected, c.cp.payload), c.cp.signature) {
		return errors.Join(ErrInvalid, errors.New("the checkpoint's COSE_Sign1 signature does not verify"))
	}
	return nil
}
