// SPDX-License-Identifier: Apache-2.0

package standardhistory_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/standardhistory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every case of vectors/standard-history-v0 runs from its inputs alone and
// is compared with the case's whole expected block, as
// python/tests/test_standard_history_v0_vectors.py compares the Python
// reference. Every fully checked standard card is also rebuilt by Derive.

type vectorCase struct {
	ID     string `json:"id"`
	Inputs struct {
		Card   json.RawMessage         `json:"card"`
		Policy *standardhistory.Policy `json:"policy"`
		AsOf   *standardhistory.AsOf   `json:"as_of"`
		Deals  []standardhistory.Deal  `json:"deals"`
	} `json:"inputs"`
	Expected struct {
		Properties map[string]string `json:"properties"`
		Standard   bool              `json:"standard"`
		Fails      []string          `json:"fails"`
	} `json:"expected"`
}

type corpus struct {
	Spec       string       `json:"spec"`
	Properties []string     `json:"properties"`
	Count      int          `json:"count"`
	Cases      []vectorCase `json:"cases"`
}

func load(t *testing.T) corpus {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "vectors", "standard-history-v0", "vectors.json"))
	require.NoError(t, err)
	var c corpus
	require.NoError(t, json.Unmarshal(data, &c))
	require.Len(t, c.Cases, c.Count)
	return c
}

func TestCorpusHeader(t *testing.T) {
	c := load(t)
	assert.Equal(t, "spec/standard-history-v0.md", c.Spec)
	assert.Equal(t, standardhistory.Properties, c.Properties)
}

func TestVectors(t *testing.T) {
	for _, tc := range load(t).Cases {
		t.Run(tc.ID, func(t *testing.T) {
			got, err := standardhistory.Check(tc.Inputs.Card, tc.Inputs.Policy, tc.Inputs.AsOf, tc.Inputs.Deals)
			require.NoError(t, err)
			assert.Equal(t, tc.Expected.Properties, got)
			assert.Equal(t, tc.Expected.Standard, standardhistory.IsStandard(got))
			var fails []string
			for _, k := range standardhistory.Properties {
				if got[k] == standardhistory.Fail {
					fails = append(fails, k)
				}
			}
			if len(tc.Expected.Fails) == 0 {
				assert.Empty(t, fails)
			} else {
				assert.Equal(t, tc.Expected.Fails, fails)
			}
			if !tc.Expected.Standard || tc.Inputs.Policy == nil || tc.Inputs.AsOf == nil || tc.Inputs.Deals == nil {
				return
			}
			var card map[string]any
			require.NoError(t, json.Unmarshal(tc.Inputs.Card, &card))
			derived, err := standardhistory.Derive(card["holder_kind"].(string), card["controller_class"].(string),
				*tc.Inputs.AsOf, *tc.Inputs.Policy, tc.Inputs.Deals)
			require.NoError(t, err)
			assert.JSONEq(t, string(tc.Inputs.Card), string(derived))
		})
	}
}

func baseCase(t *testing.T) vectorCase {
	t.Helper()
	return load(t).Cases[0]
}

func TestCountsIntegralReadsTheValue(t *testing.T) {
	tc := baseCase(t)
	var card map[string]any
	require.NoError(t, json.Unmarshal(tc.Inputs.Card, &card))
	for value, want := range map[string]string{
		"3.0": standardhistory.Pass, "9007199254740992": standardhistory.Fail, "-1": standardhistory.Fail,
		"1e400": standardhistory.Fail,
	} {
		card["outcomes"].(map[string]any)["held"] = json.RawMessage(value)
		octets, err := json.Marshal(card)
		require.NoError(t, err)
		got, err := standardhistory.Check(octets, nil, nil, nil)
		require.NoError(t, err)
		assert.Equal(t, want, got["counts_integral"], value)
	}
}

func TestCardFormRejectsABooleanCount(t *testing.T) {
	tc := baseCase(t)
	var card map[string]any
	require.NoError(t, json.Unmarshal(tc.Inputs.Card, &card))
	card["roles"].(map[string]any)["bought"] = true
	octets, err := json.Marshal(card)
	require.NoError(t, err)
	got, err := standardhistory.Check(octets, nil, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, standardhistory.Fail, got["card_form"])
}

func TestMalformedInputIsAnError(t *testing.T) {
	tc := baseCase(t)
	deals := append([]standardhistory.Deal(nil), tc.Inputs.Deals...)
	deals[0].CounterpartyClass = "a_shop"
	_, err := standardhistory.Check(tc.Inputs.Card, tc.Inputs.Policy, tc.Inputs.AsOf, deals)
	require.Error(t, err)

	var d standardhistory.Deal
	require.Error(t, json.Unmarshal([]byte(`{"deal":"d","counterparty_class":null}`), &d))
	require.Error(t, json.Unmarshal([]byte(`{"months":0}`), new(standardhistory.Window)))
}
