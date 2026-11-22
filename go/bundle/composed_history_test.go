// SPDX-License-Identifier: BSD-3-Clause
package bundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type historyCase struct {
	ID        string                 `json:"id"`
	Options   map[string]interface{} `json:"options"`
	Container map[string]interface{} `json:"container"`
	Expect    map[string]interface{} `json:"expect"`
}

// historyCases reads vectors/bundle/composed-history/vectors.json (numbers
// kept as json.Number).
func historyCases(t *testing.T) []historyCase {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "vectors", "bundle", "composed-history", "vectors.json"))
	require.NoError(t, err)
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	var file struct {
		Count json.Number   `json:"count"`
		Cases []historyCase `json:"cases"`
	}
	require.NoError(t, decoder.Decode(&file))
	require.Equal(t, json.Number("30"), file.Count)
	require.Len(t, file.Cases, 30)
	return file.Cases
}

func historyOptions(t *testing.T, c historyCase) Options {
	switch named := c.Options["history_signature"]; named {
	case nil:
		return Options{}
	case "evidence-interop/0":
		return Options{HistorySignature: EvidenceInteropSignature}
	default:
		t.Fatalf("%s: unknown history_signature %v", c.ID, named)
	}
	return Options{}
}

func textValues(values []interface{}) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = v.(string)
	}
	return out
}

// TestComposedHistoryVectors checks VerifyComposed against every expected
// result in vectors/bundle/composed-history (bundle -03, "History Members").
func TestComposedHistoryVectors(t *testing.T) {
	for _, c := range historyCases(t) {
		t.Run(c.ID, func(t *testing.T) {
			want := c.Expect
			got := VerifyComposed(composedBlockOf(c.Container), historyOptions(t, c))
			require.Equal(t, want["status"], got.Status)
			findings := got.Findings
			if findings == nil {
				findings = []string{}
			}
			require.Equal(t, textValues(want["findings"].([]interface{})), findings)
			if want["malformed"] == true {
				require.True(t, got.Malformed)
				return
			}
			require.Equal(t, want["composed_digest"], got.ComposedDigest.Recomputed)
			require.True(t, got.ComposedDigest.Matches)
			preimage, err := ComposedDigestPreimage(composedBlockOf(c.Container))
			require.NoError(t, err)
			require.Equal(t, want["canonical_preimage"], string(preimage))

			members := want["members"].(map[string]interface{})
			require.Len(t, got.Members, len(members))
			for _, m := range got.Members {
				w := members[m.ID].(map[string]interface{})
				require.Equal(t, w["outcome"], m.Outcome, m.ID)
				require.Equal(t, w["body"], m.Body, m.ID)
				require.Equal(t, w["digest"], m.Digest, m.ID)
				if form, ok := w["form"]; ok {
					require.Equal(t, form, m.Form, m.ID)
				}
				if w["form"] == FormHistory && w["body"] == "carried" {
					require.Equal(t, w["history_signature"], m.HistorySignature, m.ID)
					require.Equal(t, w["anchor_checkpoint"], m.AnchorCheckpoint, m.ID)
					require.Equal(t, w["anchor_time"], m.AnchorTime, m.ID)
					memberFindings := m.Findings
					if memberFindings == nil {
						memberFindings = []string{}
					}
					require.Equal(t, textValues(w["findings"].([]interface{})), memberFindings, m.ID)
				}
				if claims, ok := w["claims"].(map[string]interface{}); ok {
					require.NotNil(t, m.Bundle, m.ID)
					require.Equal(t, claims["graph_closure"], m.Bundle.GraphClosure.Status, m.ID)
					require.Equal(t, claims["interval_coverage"], m.Bundle.IntervalCoverage.Status, m.ID)
					require.Equal(t, claims["per_record_membership"], m.Bundle.PerRecordMembership.Status, m.ID)
				}
			}

			closure := want["composition_closure"].(map[string]interface{})
			require.Equal(t, closure["status"], got.CompositionClosure.Status)
			missing := got.CompositionClosure.Missing
			if missing == nil {
				missing = []string{}
			}
			require.Equal(t, textValues(closure["missing"].([]interface{})), missing)

			joins := want["joins"].([]interface{})
			require.Len(t, got.Joins, len(joins))
			for i, raw := range joins {
				w := raw.(map[string]interface{})
				j := got.Joins[i]
				require.Equal(t, textValues(w["members"].([]interface{})), []string{j.Members[0], j.Members[1]})
				require.Equal(t, w["declared"], j.Declared)
				require.Equal(t, w["derived"], j.Derived)
				require.Equal(t, w["result"], j.Result)
				joinFindings := j.Findings
				if joinFindings == nil {
					joinFindings = []string{}
				}
				require.Equal(t, textValues(w["findings"].([]interface{})), joinFindings)
			}

			corroborations := want["corroboration"].([]interface{})
			require.Len(t, got.Corroboration, len(corroborations))
			for i, raw := range corroborations {
				w := raw.(map[string]interface{})
				r := got.Corroboration[i]
				require.Equal(t, textValues(w["members"].([]interface{})), []string{r.Members[0], r.Members[1]})
				require.Equal(t, w["result"], r.Result)
				if reasons, ok := w["reasons"]; ok {
					require.Equal(t, textValues(reasons.([]interface{})), r.Reasons)
					require.Equal(t, "redundant, not corroborating", r.Report)
				}
				if qualifier, ok := w["qualifier"]; ok {
					require.Equal(t, qualifier, r.Qualifier)
				}
			}

			related := []RelatedHistories{}
			for _, raw := range want["related_histories"].([]interface{}) {
				w := raw.(map[string]interface{})
				histories, halves := textValues(w["histories"].([]interface{})), textValues(w["halves"].([]interface{}))
				related = append(related, RelatedHistories{
					Histories: [2]string{histories[0], histories[1]},
					Halves:    [2]string{halves[0], halves[1]},
					Pointer:   w["pointer"].(string),
				})
			}
			gotRelated := got.RelatedHistories
			require.Equal(t, related, gotRelated)
		})
	}
}

// TestComposedHistoryThroughVerifyBundle runs the staple through the Bundle
// verifier, as a relying party would: the block's result is the extension's.
func TestComposedHistoryThroughVerifyBundle(t *testing.T) {
	var staple historyCase
	for _, c := range historyCases(t) {
		if c.ID == "history-staple" {
			staple = c
		}
	}
	require.Equal(t, "history-staple", staple.ID)
	composed := composedResultOf(t, VerifyBundleWithOptions(staple.Container, historyOptions(t, staple)))
	require.Equal(t, "pass", composed.Status)
	require.Len(t, composed.RelatedHistories, 1)
	require.Equal(t, [2]string{"history-a", "history-b"}, composed.RelatedHistories[0].Histories)
}
