// SPDX-License-Identifier: Apache-2.0

package inferencehistory

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/evidencerequest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// realEnv is the artifact of testdata/real-history-card.json as an envelope
// map, with the pins of its log; each call returns a fresh copy to mutate.
func realEnv(t *testing.T) (Pins, map[string]any) {
	t.Helper()
	data, err := os.ReadFile("testdata/real-history-card.json")
	require.NoError(t, err)
	var fx struct {
		LogKey string `json:"log_key"`
		Reply  string `json:"reply"`
	}
	require.NoError(t, json.Unmarshal(data, &fx))
	reply, err := evidencerequest.DecodeJSON([]byte(fx.Reply))
	require.NoError(t, err)
	octets, err := base64.StdEncoding.DecodeString(get(reply, "artifact").(string))
	if err != nil {
		octets, err = base64.RawStdEncoding.DecodeString(get(reply, "artifact").(string))
	}
	require.NoError(t, err)
	return Pins{LogKeys: []string{fx.LogKey}}, map[string]any{"artifact": artifactValue(octets)}
}

// reseal re-derives the card digest after a mutation, so a test
// fails on the mutation itself and not on the digest over it.
func reseal(env map[string]any) {
	a := env["artifact"].(map[string]any)
	a["history_card_digest"] = dig(a["history_card"])
}

func entries(env map[string]any) []any {
	return get(get(env["artifact"], "history_card"), "history").([]any)
}

func TestCLLCardContent(t *testing.T) {
	pins, env := realEnv(t)
	assert.True(t, cardContent(pins, env))
	assert.False(t, cardContent(Pins{LogKeys: []string{"00"}}, env))

	mutate := map[string]func(env map[string]any){
		"signature bit flipped": func(env map[string]any) {
			h := entries(env)[1].(map[string]any)
			octets, _ := hex.DecodeString(h["checkpoint"].(string))
			octets[len(octets)-1] ^= 1
			h["checkpoint"] = hex.EncodeToString(octets)
		},
		"consistency proof dropped": func(env map[string]any) {
			entries(env)[1].(map[string]any)["consistency_from_previous"] = nil
		},
		"consistency proof tampered": func(env map[string]any) {
			h := entries(env)[1].(map[string]any)
			octets, _ := hex.DecodeString(h["consistency_from_previous"].(string))
			octets[len(octets)-1] ^= 1
			h["consistency_from_previous"] = hex.EncodeToString(octets)
		},
		"first entry carries a proof": func(env map[string]any) {
			entries(env)[0].(map[string]any)["consistency_from_previous"] = entries(env)[1].(map[string]any)["consistency_from_previous"]
		},
		"entries swapped": func(env map[string]any) {
			h := entries(env)
			h[0], h[1] = h[1], h[0]
		},
		"last entry dropped (anchor no longer ends the card)": func(env map[string]any) {
			card := get(env["artifact"], "history_card").(map[string]any)
			card["history"] = entries(env)[:len(entries(env))-1]
		},
		"receipts member": func(env map[string]any) {
			entries(env)[1].(map[string]any)["receipts"] = []any{}
		},
		"not hex": func(env map[string]any) {
			entries(env)[1].(map[string]any)["checkpoint"] = "zz"
		},
		"mixed with a JSON-form checkpoint": func(env map[string]any) {
			entries(env)[1].(map[string]any)["checkpoint"] = map[string]any{"key_id": "00"}
		},
	}
	for name, f := range mutate {
		_, env := realEnv(t)
		f(env)
		reseal(env)
		assert.False(t, cardContent(pins, env), name)
	}
}

func TestCLLCardTimes(t *testing.T) {
	_, env := realEnv(t)
	h := entries(env)
	at, size, ok := cutOf(h[len(h)-1])
	require.True(t, ok)
	assert.NotNil(t, mustWhen(at))
	assert.NotZero(t, size)
	_, _, ok = cutOf(map[string]any{"checkpoint": "zz"})
	assert.False(t, ok)
	_, _, ok = cutOf(map[string]any{"checkpoint": uint64(1)})
	assert.False(t, ok)
}
