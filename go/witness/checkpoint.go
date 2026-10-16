// SPDX-License-Identifier: BSD-3-Clause
package witness

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/action-state-group/checkpointed-local-log/go/checkpoint"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// SignedCheckpoint is a CLL checkpoint's fields as its signed COSE statement
// states them. PrevRoot is empty when PrevSize is 0. Timestamp is the
// statement's issued_at text exactly as signed.
type SignedCheckpoint struct {
	LogID     string
	MMRSize   uint64
	Root      string
	KeyID     string
	Timestamp string
	PrevSize  uint64
	PrevRoot  string
}

// ParseSignedCheckpoint reads a CLL COSE checkpoint statement and verifies it
// under its own key (the protected kid). It proves which key signed the
// statement, not who holds that key.
func ParseSignedCheckpoint(statement []byte) (SignedCheckpoint, error) {
	record, err := checkpoint.ParseRecord(statement)
	if err != nil {
		return SignedCheckpoint{}, err
	}
	if err := record.VerifySignature(); err != nil {
		return SignedCheckpoint{}, err
	}
	// Record.Timestamp is a parsed time; the signed text is what other
	// verifiers compare, so read issued_at from the signed claims.
	var message cose.Sign1Message
	if err := message.UnmarshalCBOR(statement); err != nil {
		return SignedCheckpoint{}, fmt.Errorf("decode checkpoint statement: %w", err)
	}
	var claims struct {
		IssuedAt string `cbor:"issued_at"`
	}
	if err := cbor.Unmarshal(message.Payload, &claims); err != nil || claims.IssuedAt == "" {
		return SignedCheckpoint{}, fmt.Errorf("checkpoint issued_at is unreadable")
	}
	return SignedCheckpoint{
		LogID: record.LogID, MMRSize: record.MMRSize, Root: record.Root, KeyID: record.KeyID,
		Timestamp: claims.IssuedAt, PrevSize: record.PrevSize, PrevRoot: record.PrevRoot,
	}, nil
}

// CheckpointDigest is CLL's checkpoint digest: the SHA-256 of the checkpoint
// signing body, the JSON object of v (1), kind (mmr_checkpoint) and the
// signed fields, keys sorted, no whitespace, non-ASCII escaped as \uXXXX.
// It is written by hand because encoding/json escapes HTML characters and
// writes non-ASCII text unescaped.
func CheckpointDigest(signed SignedCheckpoint) [sha256.Size]byte {
	var body strings.Builder
	body.WriteString(`{"key_id":`)
	body.WriteString(pyJSONString(signed.KeyID, true))
	body.WriteString(`,"kind":"mmr_checkpoint","log_id":`)
	body.WriteString(pyJSONString(signed.LogID, true))
	body.WriteString(`,"mmr_size":`)
	body.WriteString(strconv.FormatUint(signed.MMRSize, 10))
	body.WriteString(`,"prev_root":`)
	body.WriteString(pyJSONString(signed.PrevRoot, true))
	body.WriteString(`,"prev_size":`)
	body.WriteString(strconv.FormatUint(signed.PrevSize, 10))
	body.WriteString(`,"root":`)
	body.WriteString(pyJSONString(signed.Root, true))
	body.WriteString(`,"timestamp":`)
	body.WriteString(pyJSONString(signed.Timestamp, true))
	body.WriteString(`,"v":1}`)
	return sha256.Sum256([]byte(body.String()))
}

// pyJSONString writes s as Python's json.dumps does: the short escapes for
// '"', '\\', \b, \f, \n, \r and \t, \u00XX for the other control characters
// and, with ensureASCII, \uXXXX (lowercase hex, UTF-16 surrogate pairs) for
// everything outside printable ASCII, including DEL.
func pyJSONString(s string, ensureASCII bool) string {
	var out strings.Builder
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			switch {
			case r < 0x20:
				fmt.Fprintf(&out, `\u%04x`, r)
			case !ensureASCII || (r >= 0x20 && r <= 0x7e):
				out.WriteRune(r)
			case r > 0xffff:
				high, low := utf16.EncodeRune(r)
				fmt.Fprintf(&out, `\u%04x\u%04x`, high, low)
			default:
				fmt.Fprintf(&out, `\u%04x`, r)
			}
		}
	}
	out.WriteByte('"')
	return out.String()
}
