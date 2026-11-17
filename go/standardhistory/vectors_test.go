// SPDX-License-Identifier: Apache-2.0

package standardhistory_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/standardhistory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every case of vectors/standard-history-v0 runs from its inputs alone and
// is compared with the case's whole expected block, as
// python/tests/test_standard_history_v0_vectors.py compares the Python
// reference. Every fully checked standard card is also rebuilt by DeriveAs.
// vectors.json holds the standard_history/1 cases, vectors-2.json the
// standard_history/2 ones and vectors-3.json the standard_history/3 ones
// (SH §11), each naming the token it is checked under.

type vectorCase struct {
	ID     string `json:"id"`
	Inputs struct {
		Card   json.RawMessage         `json:"card"`
		Policy *standardhistory.Policy `json:"policy"`
		AsOf   *standardhistory.AsOf   `json:"as_of"`
		Deals  []standardhistory.Deal  `json:"deals"`
		// Derivation is the token the card is checked under; empty is /1.
		Derivation string `json:"derivation"`
	} `json:"inputs"`
	Expected struct {
		Properties map[string]string `json:"properties"`
		Standard   bool              `json:"standard"`
		Fails      []string          `json:"fails"`
	} `json:"expected"`
}

func (tc vectorCase) derivation() string {
	if tc.Inputs.Derivation == "" {
		return standardhistory.Derivation
	}
	return tc.Inputs.Derivation
}

type corpus struct {
	Spec       string       `json:"spec"`
	Derivation string       `json:"derivation"`
	Properties []string     `json:"properties"`
	Count      int          `json:"count"`
	Cases      []vectorCase `json:"cases"`
}

func load(t *testing.T) corpus {
	t.Helper()
	return loadFile(t, "vectors.json")
}

func loadFile(t *testing.T, name string) corpus {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "vectors", "standard-history-v0", name))
	require.NoError(t, err)
	var c corpus
	require.NoError(t, json.Unmarshal(data, &c))
	require.Len(t, c.Cases, c.Count)
	return c
}

func TestCorpusHeader(t *testing.T) {
	for _, c := range []corpus{load(t), loadFile(t, "vectors-2.json"), loadFile(t, "vectors-3.json")} {
		assert.Equal(t, "spec/standard-history-v0.md", c.Spec)
		assert.Equal(t, standardhistory.Properties, c.Properties)
	}
	assert.Equal(t, standardhistory.Derivation2, loadFile(t, "vectors-2.json").Derivation)
	assert.Equal(t, standardhistory.Derivation3, loadFile(t, "vectors-3.json").Derivation)
}

func TestVectors(t *testing.T) {
	all := append(load(t).Cases, loadFile(t, "vectors-2.json").Cases...)
	all = append(all, loadFile(t, "vectors-3.json").Cases...)
	for _, tc := range all {
		t.Run(tc.ID, func(t *testing.T) {
			got, err := standardhistory.CheckAs(tc.derivation(), tc.Inputs.Card, tc.Inputs.Policy, tc.Inputs.AsOf,
				tc.Inputs.Deals)
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
			derived, err := standardhistory.DeriveAs(tc.derivation(), card["holder_kind"].(string),
				card["controller_class"].(string), *tc.Inputs.AsOf, *tc.Inputs.Policy, tc.Inputs.Deals)
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

func TestIsStandardNeedsEveryProperty(t *testing.T) {
	p := map[string]string{}
	for k, v := range baseCase(t).Expected.Properties {
		p[k] = v
	}
	p["counts_recompute"] = "INCONCLUSIVE"
	assert.False(t, standardhistory.IsStandard(p))
	delete(p, "counts_recompute")
	assert.False(t, standardhistory.IsStandard(p))
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
	unknown := "a_shop"
	deals[0].CounterpartyClass = &unknown
	_, err := standardhistory.Check(tc.Inputs.Card, tc.Inputs.Policy, tc.Inputs.AsOf, deals)
	require.Error(t, err)

	var d standardhistory.Deal
	require.Error(t, json.Unmarshal([]byte(`{"deal":"d","counterparty_class":null}`), &d))
	require.Error(t, json.Unmarshal([]byte(`{"months":0}`), new(standardhistory.Window)))
	require.Error(t, json.Unmarshal([]byte(`{"deal":"d","amount":{"value":"1","assetCode":"USD","assetScale":"2"}}`), &d))
	require.Error(t, json.Unmarshal([]byte(`{"deal":"d","amount":{"value":"1","assetCode":"USD","assetScale":2.0}}`), &d))
	// -0 is the integer 0, as Python's json reads it.
	require.NoError(t, json.Unmarshal([]byte(`{"deal":"d","amount":{"value":"1","assetCode":"USD","assetScale":-0}}`), &d))
	assert.Equal(t, 0, d.Amount.AssetScale)
}

// A Deal built in code, not decoded, is counted by its CounterpartyClass
// alone: a shop purchase set in a struct literal is not counted.
func TestDealBuiltInCode(t *testing.T) {
	shop := "shop_preauth"
	deal := standardhistory.Deal{Deal: "d", AgreedAt: "2026-10-01T00:00:00Z", CounterpartyClass: &shop,
		Role: "bought", Amount: standardhistory.Amount{Value: "500", AssetCode: "USD", AssetScale: 2},
		Outcome: "held", Happened: "receipt_only", Disputes: []standardhistory.Dispute{}}
	asOf := standardhistory.AsOf{Anchor: strings.Repeat("a", 64), AnchorTime: "2026-10-28T00:00:00Z",
		FirstCheckpointTime: "2026-01-01T00:00:00Z"}
	policy := standardhistory.Policy{Digest: strings.Repeat("b", 64), Window: standardhistory.Window{Months: 3}}
	octets, err := standardhistory.Derive("person", "person_declared", asOf, policy, []standardhistory.Deal{deal})
	require.NoError(t, err)
	var card map[string]any
	require.NoError(t, json.Unmarshal(octets, &card))
	assert.Equal(t, map[string]any{"of": 1.0, "counted": 0.0, "not_counted": 1.0}, card["in_window"])

	// A card of JSON null has no numbers, as in Python; octets that are not
	// JSON fail it.
	got, err := standardhistory.Check([]byte("null"), nil, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, standardhistory.Pass, got["counts_integral"])
	got, err = standardhistory.Check([]byte("{"), nil, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, standardhistory.Fail, got["counts_integral"])
}

// SH §3, §5.2: a standard_history/1 deal entry needs an amount, so a /1 card
// over an unpriced deal cannot be built or recomputed; the same entries build
// the /2 card.
func TestV1CannotCountAnUnpricedDeal(t *testing.T) {
	var tc vectorCase
	for _, c := range loadFile(t, "vectors-2.json").Cases {
		if c.ID == "unpriced-counted" {
			tc = c
		}
	}
	require.Equal(t, "unpriced-counted", tc.ID)
	_, err := standardhistory.Derive("person", "person_declared", *tc.Inputs.AsOf, *tc.Inputs.Policy, tc.Inputs.Deals)
	require.Error(t, err)
	_, err = standardhistory.Check(baseCase(t).Inputs.Card, tc.Inputs.Policy, tc.Inputs.AsOf, tc.Inputs.Deals)
	require.Error(t, err)
	_, err = standardhistory.DeriveAs(standardhistory.Derivation2, "person", "person_declared", *tc.Inputs.AsOf,
		*tc.Inputs.Policy, tc.Inputs.Deals)
	require.NoError(t, err)
}

func TestUnpricedDealDecoding(t *testing.T) {
	var d standardhistory.Deal
	require.NoError(t, json.Unmarshal([]byte(`{"deal":"d"}`), &d))
	assert.True(t, d.Unpriced)
	require.Error(t, json.Unmarshal([]byte(`{"deal":"d","amount":null}`), &d))
	require.Error(t, json.Unmarshal([]byte(`{"deal":"d","amount":"500"}`), &d))
	require.NoError(t, json.Unmarshal([]byte(`{"deal":"d","amount":{"value":"1","assetCode":"USD","assetScale":2}}`), &d))
	assert.False(t, d.Unpriced)

	// Every deal entry of the vectors reads back as itself after a round
	// trip, an Unpriced one without an amount.
	for _, tc := range loadFile(t, "vectors-2.json").Cases {
		for _, deal := range tc.Inputs.Deals {
			octets, err := json.Marshal(deal)
			require.NoError(t, err)
			assert.Equal(t, deal.Unpriced, !strings.Contains(string(octets), `"amount"`), string(octets))
			var back standardhistory.Deal
			require.NoError(t, json.Unmarshal(octets, &back))
			assert.Equal(t, deal, back)
		}
	}
}

func TestUnknownTokenIsAnError(t *testing.T) {
	_, err := standardhistory.CheckAs("standard_history/4", baseCase(t).Inputs.Card, nil, nil, nil)
	require.Error(t, err)
	_, err = standardhistory.DeriveAs("standard_history/4", "person", "person_declared", standardhistory.AsOf{},
		standardhistory.Policy{}, nil)
	require.Error(t, err)
}

func v3Case(t *testing.T, id string) vectorCase {
	t.Helper()
	for _, c := range loadFile(t, "vectors-3.json").Cases {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no case %s", id)
	return vectorCase{}
}

// SH §11.3, §11.4: every pair of well-formed row results falls in exactly one
// line, and a did_not_hold deal in exactly one part.
func TestV3LinesCoverEveryRowResult(t *testing.T) {
	var results []standardhistory.Row
	for _, s := range []string{"not_reached", "not_due", "no_statement", "in_disagreement", "in_dispute"} {
		results = append(results, standardhistory.Row{Status: s})
	}
	for _, v := range []string{"met", "not_met"} {
		results = append(results, standardhistory.Row{Status: "waiting", Value: v})
	}
	for _, s := range []string{"uncontested", "agreed_so_far", "agreed"} {
		results = append(results, standardhistory.Row{Status: s, Value: "met"},
			standardhistory.Row{Status: s, Value: "not_met", Remedy: "none"},
			standardhistory.Row{Status: s, Value: "not_met", Remedy: "made"})
	}
	for _, v := range []string{"met", "not_met"} {
		for _, r := range []string{"none", "due", "made", "not_honoured"} {
			results = append(results, standardhistory.Row{Status: "ruled", Value: v, Remedy: r})
		}
	}
	var rows []standardhistory.Row
	for _, o := range []string{"holder", "counterparty"} {
		for _, r := range results {
			r.OwedBy = o
			rows = append(rows, r)
		}
	}
	lines := []string{"ruling_not_honoured", "undecided", "did_not_hold", "held_so_far", "held"}
	parts := []string{"not_remedied", "remedy_pending", "remedied", "other_side"}
	for _, a := range rows {
		for _, b := range rows {
			line, part := standardhistory.Line([]standardhistory.Row{a, b})
			assert.Contains(t, lines, line)
			if line == "did_not_hold" {
				assert.Contains(t, parts, part)
			} else {
				assert.Empty(t, part)
			}
		}
	}
}

// SH §11.4: two unmet rows the holder owed compete for parts; the first part
// that applies wins, whatever the order of the rows.
func TestV3SplitOrder(t *testing.T) {
	for _, c := range []struct {
		remedies [2]string
		part     string
	}{{[2]string{"none", "due"}, "not_remedied"}, {[2]string{"due", "made"}, "remedy_pending"},
		{[2]string{"made", "made"}, "remedied"}} {
		a := standardhistory.Row{OwedBy: "holder", Status: "ruled", Value: "not_met", Remedy: c.remedies[0]}
		b := standardhistory.Row{OwedBy: "holder", Status: "ruled", Value: "not_met", Remedy: c.remedies[1]}
		refund := standardhistory.Row{OwedBy: "holder", Status: "agreed", Value: "not_met", Remedy: "made"}
		for _, rows := range [][]standardhistory.Row{{a, b}, {b, a}, {refund, a, b}} {
			line, part := standardhistory.Line(rows)
			assert.Equal(t, "did_not_hold", line)
			assert.Equal(t, c.part, part, c.remedies)
		}
	}
}

// A /1 or /2 entry reads as it always has: members that only /3 reads do not
// stop it, whatever their values.
func TestV3MembersDoNotChangeV1Decoding(t *testing.T) {
	tc := baseCase(t)
	octets, err := json.Marshal(tc.Inputs.Deals[0])
	require.NoError(t, err)
	var entry map[string]any
	require.NoError(t, json.Unmarshal(octets, &entry))
	entry["left_out"] = nil
	entry["rows"] = "opaque"
	octets, err = json.Marshal(entry)
	require.NoError(t, err)
	var d standardhistory.Deal
	require.NoError(t, json.Unmarshal(octets, &d))
	deals := append([]standardhistory.Deal{d}, tc.Inputs.Deals[1:]...)
	got, err := standardhistory.Check(tc.Inputs.Card, tc.Inputs.Policy, tc.Inputs.AsOf, deals)
	require.NoError(t, err)
	assert.Equal(t, tc.Expected.Properties, got)
}

// SH §11.1: deals with no new fact move line when the anchor moves.
func TestV3QuietDealMovesLine(t *testing.T) {
	a := v3Case(t, "lines-and-split").Inputs.Deals
	b := v3Case(t, "quiet-deals-later-anchor").Inputs.Deals
	require.Len(t, b, len(a))
	moved := map[string][2]string{}
	for i := range a {
		la, _ := standardhistory.Line(a[i].Rows)
		lb, _ := standardhistory.Line(b[i].Rows)
		if la != lb {
			moved[a[i].Deal] = [2]string{la, lb}
		}
	}
	assert.Equal(t, map[string][2]string{"deal-302": {"held_so_far", "undecided"}, "deal-314": {"held_so_far", "held"}},
		moved)
}

func TestMalformedV3DealEntryIsAnError(t *testing.T) {
	tc := v3Case(t, "lines-and-split")
	for _, change := range []string{
		`{"outcome":"held"}`,
		`{"rows":[]}`,
		`{"rows":null}`,
		`{"rows":[{"owed_by":"holder","status":"agreed"}]}`,
		`{"rows":[{"owed_by":"holder","status":"not_due","value":"met"}]}`,
		`{"rows":[{"owed_by":"holder","status":"ruled","value":"met"}]}`,
		`{"rows":[{"owed_by":"seller","status":"not_due"}]}`,
		`{"left_out":"late"}`,
		`{"rows":[{"owed_by":"holder","status":"agreed","value":"not_met"}]}`,
		`{"rows":[{"owed_by":"holder","status":"agreed","value":"not_met","remedy":"due"}]}`,
		`{"rows":[{"owed_by":"holder","status":"not_due","local":false}]}`,
		`{"rows":[{"owed_by":"holder","status":"not_due","value":""}]}`,
		`{"rows":[{"owed_by":"holder","status":"agreed","value":"met","remedy":""}]}`,
		`{"outcome":""}`,
	} {
		octets, err := json.Marshal(tc.Inputs.Deals[0])
		require.NoError(t, err)
		var entry map[string]any
		require.NoError(t, json.Unmarshal(octets, &entry))
		var patch map[string]any
		require.NoError(t, json.Unmarshal([]byte(change), &patch))
		for k, v := range patch {
			entry[k] = v
		}
		octets, err = json.Marshal(entry)
		require.NoError(t, err)
		var d standardhistory.Deal
		if json.Unmarshal(octets, &d) != nil {
			continue // refused while decoding
		}
		deals := append([]standardhistory.Deal{d}, tc.Inputs.Deals[1:]...)
		_, err = standardhistory.CheckAs(standardhistory.Derivation3, tc.Inputs.Card, tc.Inputs.Policy, tc.Inputs.AsOf,
			deals)
		assert.Error(t, err, change)
	}
}
