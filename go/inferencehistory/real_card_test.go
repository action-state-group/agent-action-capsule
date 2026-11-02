// SPDX-License-Identifier: Apache-2.0

package inferencehistory_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/evidencerequest"
	"github.com/action-state-group/agent-action-capsule/go/inferencehistory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testdata/real-history-card.json is a History a real evidencebook v0.13.2
// Book answered: its history_card/1 carries each checkpoint as a hex
// cll-checkpoint statement with a consistency proof from the one before
// (ER §8.1), not the vectors' JSON form.

type realCard struct {
	ResponderKey   string          `json:"responder_key"`
	LogKey         string          `json:"log_key"`
	EvaluationTime string          `json:"evaluation_time"`
	Definition     json.RawMessage `json:"definition"`
	Contract       map[string]any  `json:"contract"`
	Request        string          `json:"request"`
	Reply          string          `json:"reply"`
}

func loadReal(t *testing.T) realCard {
	t.Helper()
	data, err := os.ReadFile("testdata/real-history-card.json")
	require.NoError(t, err)
	var c realCard
	require.NoError(t, json.Unmarshal(data, &c))
	return c
}

func (c realCard) evaluate(t *testing.T, logKey string, reply []byte) inferencehistory.Result {
	t.Helper()
	v, err := evidencerequest.NewVerifier(evidencerequest.TrustPolicy{ResponderKeys: []string{c.ResponderKey}},
		evidencerequest.VerificationPolicy{ProfilesImplemented: []string{"evidence-interop/0"}, KindsImplemented: evidencerequest.CLLKinds},
		c.EvaluationTime, c.Contract)
	require.NoError(t, err)
	r, err := inferencehistory.Evaluate(v, inferencehistory.Pins{LogKeys: []string{logKey}}, decode(t, c.Definition),
		inferencehistory.Exchange{
			Request: evidencerequest.Message{Octets: []byte(c.Request), MediaType: "application/json"},
			Reply:   evidencerequest.Message{Octets: reply, MediaType: "application/json"},
		}, nil)
	require.NoError(t, err)
	return r
}

func TestRealHistoryCardPasses(t *testing.T) {
	c := loadReal(t)
	r := c.evaluate(t, c.LogKey, []byte(c.Reply))
	for _, p := range []string{"history_card_content", "period_alignment", "period_anchor", "period_floor", "units", "labels",
		"artifact_form", "definition_form", "definition_binding"} {
		assert.Equal(t, evidencerequest.StatusPass, r.Properties[p], p)
	}
	assert.True(t, r.Accepted)
	assert.Equal(t, inferencehistory.WitnessShown{Checkpoints: r.Witness.Checkpoints}, r.Witness)
	assert.Positive(t, r.Witness.Checkpoints)
}

func TestRealHistoryCardNeedsThePinnedLogKey(t *testing.T) {
	c := loadReal(t)
	other := c.LogKey[:len(c.LogKey)-1] + map[bool]string{true: "1", false: "0"}[c.LogKey[len(c.LogKey)-1] == '0']
	r := c.evaluate(t, other, []byte(c.Reply))
	assert.Equal(t, evidencerequest.StatusFail, r.Properties["history_card_content"])
}
