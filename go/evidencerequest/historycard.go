// SPDX-License-Identifier: Apache-2.0

package evidencerequest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"slices"

	"github.com/action-state-group/agent-action-capsule/go/internal/ed25519strict"
)

// DerivationHistoryCard2 is the bounded history card of ER -03 §8.1.2.
const DerivationHistoryCard2 = "history_card/2"

// MaxHistoryWindow is the largest window a history_card/2 may state (ER -03
// §8.1.2).
const MaxHistoryWindow = 64

// History card findings, in the order CheckHistoryCard2 checks them. The
// names are those of vectors/evidence-request/history-card-2.json.
const (
	FindingCardMalformed      = "card_malformed"
	FindingWindowOutOfRange   = "window_out_of_range"
	FindingPositionsOrder     = "positions_not_increasing_from_zero"
	FindingPositionMissing    = "position_missing"
	FindingPositionUnexpected = "position_unexpected"
	FindingCheckpointInvalid  = "checkpoint_invalid"
	FindingNotFirstCheckpoint = "first_checkpoint_has_predecessor"
	FindingCheckpointShrinks  = "checkpoint_shrinks"
	FindingProofInvalid       = "proof_invalid"
	FindingReceiptInvalid     = "receipt_invalid"
	FindingAnchorMismatch     = "anchor_mismatch"
)

// HistoryCardFindings lists the findings in check order.
var HistoryCardFindings = []string{
	FindingCardMalformed, FindingWindowOutOfRange, FindingPositionsOrder, FindingPositionMissing,
	FindingPositionUnexpected, FindingCheckpointInvalid, FindingNotFirstCheckpoint, FindingCheckpointShrinks, FindingProofInvalid,
	FindingReceiptInvalid, FindingAnchorMismatch,
}

// HistoryPositions is P(n, W) of ER -03 §8.1.2: 0, n - 2^k for every
// 2^k <= n, and max(0, n - W + 1) through n, ascending, each once.
func HistoryPositions(n, window uint64) []uint64 {
	set := map[uint64]bool{0: true}
	for step := uint64(1); step <= n && step != 0; step <<= 1 {
		set[n-step] = true
	}
	start := uint64(0)
	if window <= n {
		start = n - window + 1
	}
	for p := start; p <= n; p++ {
		set[p] = true
		if p == n {
			break
		}
	}
	out := make([]uint64, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

type cardEntry struct {
	position   uint64
	checkpoint []byte
	receipts   []any
	proof      []byte
	hasProof   bool
}

func lowerHex(v any) ([]byte, bool) {
	s, ok := v.(string)
	if !ok || len(s)%2 != 0 {
		return nil, false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil, false
		}
	}
	b, err := hex.DecodeString(s)
	return b, err == nil
}

// readCard is the card's window and entries, and false when the card or an
// entry is not the maps and types of ER -03 §8.1.2. Members a profile adds
// are ignored.
func readCard(card any) (uint64, []cardEntry, bool) {
	m, ok := card.(map[string]any)
	if !ok {
		return 0, nil, false
	}
	window, ok := UintValue(m["window"])
	history, isList := m["history"].([]any)
	if !ok || !isList {
		return 0, nil, false
	}
	entries := make([]cardEntry, 0, len(history))
	for _, raw := range history {
		e, ok := raw.(map[string]any)
		if !ok {
			return 0, nil, false
		}
		for _, member := range []string{"position", "checkpoint", "receipts", "consistency_from_previous"} {
			if _, present := e[member]; !present {
				return 0, nil, false
			}
		}
		var entry cardEntry
		var okPosition, okCheckpoint, okReceipts bool
		entry.position, okPosition = UintValue(e["position"])
		entry.checkpoint, okCheckpoint = lowerHex(e["checkpoint"])
		entry.receipts, okReceipts = e["receipts"].([]any)
		if !okPosition || !okCheckpoint || !okReceipts {
			return 0, nil, false
		}
		if e["consistency_from_previous"] != nil {
			proof, ok := lowerHex(e["consistency_from_previous"])
			if !ok {
				return 0, nil, false
			}
			entry.proof, entry.hasProof = proof, true
		}
		entries = append(entries, entry)
	}
	return window, entries, true
}

// receiptCovers is whether r is a {checkpoint, witness, sig} receipt over
// SHA-256 of checkpoint, signed by witness over UTF-8 of JCS of
// {checkpoint, witness}: the form history-card-2.json fixes.
func receiptCovers(r any, checkpoint []byte) bool {
	m, ok := r.(map[string]any)
	if !ok || len(m) != 3 {
		return false
	}
	covered, ok1 := m["checkpoint"].(string)
	key, ok2 := lowerHex(m["witness"])
	sig, ok3 := lowerHex(m["sig"])
	if !ok1 || !ok2 || !ok3 || covered != Digest(checkpoint) || len(key) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	body, err := EncodeJCS(map[string]any{"checkpoint": covered, "witness": m["witness"]})
	return err == nil && ed25519strict.Verify(key, body, sig)
}

// CheckHistoryCard2 checks card, the decoded result map of a history_card/2
// in Checkpointed Local Log form (profile §6.2.1: hex cll-checkpoint
// statements and cll-consistency-proof octets), against anchor, SHA-256 of
// the octets of the checkpoint the response resolved, and the log keys the
// requester accepts for the stream (lowercase hex). It returns "" when every
// check of ER -03 §8.1.2 "Verifying" passes, else the first finding:
// card_malformed, then checks 1 to 7 in order.
func CheckHistoryCard2(card any, anchor string, logKeys []string) string {
	window, entries, ok := readCard(card)
	if !ok {
		return FindingCardMalformed
	}
	if window < 1 || window > MaxHistoryWindow {
		return FindingWindowOutOfRange
	}
	if len(entries) == 0 || entries[0].position != 0 {
		return FindingPositionsOrder
	}
	listed := make([]uint64, len(entries))
	for i, e := range entries {
		if i > 0 && e.position <= entries[i-1].position {
			return FindingPositionsOrder
		}
		listed[i] = e.position
	}
	expected := HistoryPositions(listed[len(listed)-1], window)
	for _, p := range expected {
		if !slices.Contains(listed, p) {
			return FindingPositionMissing
		}
	}
	if len(listed) != len(expected) {
		return FindingPositionUnexpected
	}

	checkpoints := make([]*CLLCheckpoint, len(entries))
	for i, e := range entries {
		cp, err := DecodeCLLCheckpoint(e.checkpoint)
		if err != nil || !slices.Contains(logKeys, hex.EncodeToString(cp.Key)) || cp.VerifySignature() != nil {
			return FindingCheckpointInvalid
		}
		if i == 0 && cp.cp.prevSize != 0 {
			return FindingNotFirstCheckpoint
		}
		if i > 0 && cp.LogSize < checkpoints[i-1].LogSize {
			return FindingCheckpointShrinks
		}
		checkpoints[i] = cp
	}

	for i, e := range entries {
		if i == 0 {
			if e.hasProof {
				return FindingProofInvalid
			}
			continue
		}
		prev, cur := checkpoints[i-1], checkpoints[i]
		if !e.hasProof || !proofSpans(e.proof, prev.LogSize, cur.LogSize) ||
			VerifyCLLConsistency(prev.Commitment, cur.Commitment, e.proof) != nil {
			return FindingProofInvalid
		}
	}

	for _, e := range entries {
		for _, r := range e.receipts {
			if !receiptCovers(r, e.checkpoint) {
				return FindingReceiptInvalid
			}
		}
	}

	last := sha256.Sum256(entries[len(entries)-1].checkpoint)
	if hex.EncodeToString(last[:]) != anchor {
		return FindingAnchorMismatch
	}
	return ""
}

// proofSpans is whether cll-consistency-proof octets are a four-element
// array whose tree sizes are the two checkpoints' log sizes, so the proof
// checked is the one for this pair.
func proofSpans(octets []byte, from, to uint64) bool {
	v, err := DecodeCBOR(octets)
	parts, ok := v.([]any)
	if err != nil || !ok || len(parts) != 4 {
		return false
	}
	a, ok1 := UintValue(parts[0])
	b, ok2 := UintValue(parts[1])
	return ok1 && ok2 && a == from && b == to
}
