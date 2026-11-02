// SPDX-License-Identifier: Apache-2.0

package inferencehistory

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A synthetic log signs cll-checkpoint statements, so the paths a real
// card's two entries cannot reach (order, equal size, period boundaries)
// are tested with statements the test controls.

type synthLog struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	enc  cbor.EncMode
}

func newSynthLog(t *testing.T) synthLog {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	enc, err := cbor.CoreDetEncOptions().EncMode()
	require.NoError(t, err)
	return synthLog{pub, priv, enc}
}

func (l synthLog) marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := l.enc.Marshal(v)
	require.NoError(t, err)
	return b
}

// statement signs a checkpoint at logSize whose single peak is seed's hash.
func (l synthLog) statement(t *testing.T, issuedAt string, logSize uint64, seed string) string {
	t.Helper()
	peak := sha256.Sum256([]byte(seed))
	commitment := l.marshal(t, [][]byte{peak[:]})
	protected := l.marshal(t, map[int]any{1: -8, 4: []byte(l.pub), 15: map[int]any{1: "iss", 2: "sub"}})
	payload := l.marshal(t, map[string]any{
		"kind": "cll-checkpoint", "log_size": logSize, "prev_size": uint64(0), "prev_commitment": []byte{},
		"issued_at": issuedAt, "commitment": commitment,
	})
	sigInput := l.marshal(t, []any{"Signature1", protected, []byte{}, payload})
	sign1 := cbor.Tag{Number: 18, Content: []any{protected, map[int]any{}, payload, ed25519.Sign(l.priv, sigInput)}}
	return hex.EncodeToString(l.marshal(t, sign1))
}

func (l synthLog) pins() Pins { return Pins{LogKeys: []string{hex.EncodeToString(l.pub)}} }

func card(entries ...any) map[string]any {
	c := map[string]any{"history": entries}
	return map[string]any{"history_card": c, "history_card_digest": dig(c)}
}

func entry(statement string, proof any) any {
	return map[string]any{"checkpoint": statement, "consistency_from_previous": proof}
}

func envOf(a map[string]any) map[string]any { return map[string]any{"artifact": a} }

func TestCLLCardOrderAndEqualSize(t *testing.T) {
	l := newSynthLog(t)
	first := l.statement(t, "2026-10-02T00:00:00Z", 3, "a")
	check := func(second string) bool {
		a := card(entry(first, nil), entry(second, nil))
		a["anchor"] = "00"
		return cardContentEntries(l.pins(), a)
	}
	// Equal size, a later time, the same commitment and no proof: accepted.
	assert.True(t, check(l.statement(t, "2026-10-03T00:00:00Z", 3, "a")))
	// Equal size with another commitment.
	assert.False(t, check(l.statement(t, "2026-10-03T00:00:00Z", 3, "b")))
	// The time goes backwards, or does not advance.
	assert.False(t, check(l.statement(t, "2026-10-01T00:00:00Z", 3, "a")))
	assert.False(t, check(l.statement(t, "2026-10-02T00:00:00Z", 3, "a")))
	// The size goes down.
	assert.False(t, check(l.statement(t, "2026-10-03T00:00:00Z", 1, "a")))
	// Equal size with a proof.
	a := card(entry(first, nil), entry(l.statement(t, "2026-10-03T00:00:00Z", 3, "a"), "00"))
	assert.False(t, cardContentEntries(l.pins(), a))
	// A larger size needs a proof; none is given.
	assert.False(t, check(l.statement(t, "2026-10-03T00:00:00Z", 7, "b")))
}

// cardContentEntries runs cardContent's per-entry checks over a card whose
// anchor is its last statement.
func cardContentEntries(pins Pins, a map[string]any) bool {
	h := get(a["history_card"], "history").([]any)
	octets, _ := hex.DecodeString(h[len(h)-1].(map[string]any)["checkpoint"].(string))
	sum := sha256.Sum256(octets)
	a["anchor"] = hex.EncodeToString(sum[:])

	a["history_card"].(map[string]any)["anchor"] = a["anchor"]
	a["history_card"].(map[string]any)["derivation"] = "history_card/1"
	a["history_card_digest"] = dig(a["history_card"])
	return cardContent(pins, envOf(a))
}

func TestCLLCardPeriods(t *testing.T) {
	l := newSynthLog(t)
	d := map[string]any{"period_policy": policy()}
	pc := func(periods ...any) map[string]any {
		return map[string]any{"policy": dig(policy()), "periods": append([]any{}, periods...)}
	}
	day1 := period("2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z")
	build := func(counts map[string]any, entries ...any) map[string]any {
		a := card(entries...)
		a["period_counts"] = counts
		return envOf(a)
	}
	boundary := entry(l.statement(t, "2026-10-02T00:00:00Z", 3, "a"), nil)
	off := entry(l.statement(t, "2026-10-02T06:00:00Z", 3, "a"), nil)
	empty := entry(l.statement(t, "2026-10-02T00:00:00Z", 0, "a"), nil)

	assert.True(t, anchorOK(d, build(pc(day1), boundary)))
	assert.True(t, periodsOK(d, build(pc(day1), boundary)))
	assert.True(t, periodsOK(d, build(pc(), empty)))
	// An anchor off a period boundary fails period_anchor.
	assert.False(t, anchorOK(d, build(pc(day1), off)))
	// A period that starts after the first checkpoint that commits a record.
	late := period("2026-10-02T00:00:00Z", "2026-10-03T00:00:00Z")
	assert.False(t, periodsOK(d, build(pc(late),
		entry(l.statement(t, "2026-10-01T12:00:00Z", 2, "a"), nil),
		entry(l.statement(t, "2026-10-03T00:00:00Z", 2, "a"), nil))))
	// A statement that cannot be read gives no time.
	assert.False(t, anchorOK(d, build(pc(day1), map[string]any{"checkpoint": "zz"})))
}
