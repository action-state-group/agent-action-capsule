// SPDX-License-Identifier: BSD-3-Clause

package evidenceresult

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const vectorsDir = "../../vectors/evidence-result"

// crossElementNegatives are the negatives the schema accepts and the
// cross-element rules refuse (the Python reference's LINK_NEGATIVES,
// COVERAGE_NEGATIVES and REVISION_NEGATIVES), each with the finding of the
// rule its mutant switches off there. Every other negative is one of its
// NEGATIVES, which the schema refuses.
var crossElementNegatives = map[string]string{
	"neg-close-agreed-relabelled-contested":   "asserted AGREED but the cited Close's counterparty links read CONTESTED",
	"neg-close-agreed-self-acknowledged":      "asserted AGREED but the cited Close's counterparty links read UNILATERAL",
	"neg-close-ref-not-in-evidence":           "close.close_ref (761923a4e7b9...) does not resolve inside the claim's evidence[]",
	"neg-close-peer-ref-not-in-evidence":      "close.peer_close_ref (a6747053e3fe...) does not resolve inside the claim's evidence[]",
	"neg-close-agreed-third-book":             "asserted AGREED but the cited Close's counterparty links read UNILATERAL",
	"neg-close-agreed-bookless-close":         "asserted AGREED but the cited Close's counterparty links read UNILATERAL",
	"neg-coverage-correlated-counted-as-met":  "req-claim-1: independence.met is true but 1 producer(s) against 2 required",
	"neg-coverage-summary-does-not-recompute": "does not recompute",
	"neg-out-of-scope-listed-in-met":          "claim-2 (out_of_scope) is in buckets [met]",
	"neg-later-claim-in-bucket":               "claim-2 is not yet in force but is in buckets [not_met]",
	"neg-switch-disagrees-in-row":             "req-claim-1: its claims disagree on out_of_scope_allowed",
	"neg-applies-from-disagrees-in-row":       "req-claim-1: its claims disagree on applies_from",
	"neg-later-claim-in-population":           "evaluated_population 5, but 2 in-force claim(s)",
	"neg-later-unknown-counted":               "unknown_count 1, but 0 in-force UNKNOWN claim(s)",
	"neg-not-yet-in-force-absent":             "not_yet_in_force <nil>, but 3 later claim(s)",
	"neg-not-yet-in-force-wrong":              "not_yet_in_force 2, but 3 later claim(s)",
	"neg-generated-at-unparseable":            `generated_at "2026-09-22" is not an RFC 3339 date-time`,
	"neg-applies-from-not-a-date":             `applies_from "2027-02-30" is not a calendar date`,
	"neg-generated-at-impossible":             `generated_at "2026-02-30T00:00:00Z" is not an RFC 3339 date-time`,
	"neg-generated-at-without-seconds":        `generated_at "2026-09-22T10:00+00:00" is not an RFC 3339 date-time`,
	"neg-not-yet-in-force-without-later":      "not_yet_in_force is present, but no claim is later",
	"neg-requirements-covered-omits-claimed":  "req-claim-2: a claim cites it, but requirements_covered does not list it",
	"neg-requirements-covered-unaccounted":    "requirements_covered lists 1 requirement(s) no claim cites, but excluded_not_applicable is 0",
}

// vectorCases lists the cases of vectors/evidence-result: every .json file
// but the .records.json sidecars, which belong to the case of the same name.
func vectorCases(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(vectorsDir)
	require.NoError(t, err)
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".records.json") {
			names = append(names, strings.TrimSuffix(name, ".json"))
		}
	}
	sort.Strings(names)
	return names
}

func load(t *testing.T, name string) (map[string]interface{}, []map[string]interface{}) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorsDir, name+".json"))
	require.NoError(t, err)
	doc, err := Decode(raw)
	require.NoError(t, err)
	var records []map[string]interface{}
	if raw, err := os.ReadFile(filepath.Join(vectorsDir, name+".records.json")); err == nil {
		records, err = DecodeRecords(raw)
		require.NoError(t, err)
	} else {
		require.True(t, errors.Is(err, os.ErrNotExist), err)
	}
	return doc, records
}

// TestVectorsParity runs every case with the Python reference's verdict,
// and with its stage: the schema refuses exactly the schema negatives.
func TestVectorsParity(t *testing.T) {
	positives, negatives, sidecars := 0, 0, 0
	for _, name := range vectorCases(t) {
		doc, records := load(t, name)
		if records != nil {
			sidecars++
		}
		claims, err := Check(doc, records)
		switch {
		case strings.HasPrefix(name, "pos-"):
			positives++
			assert.NoError(t, err, name)
			assert.NotEmpty(t, claims, name)
		case strings.HasPrefix(name, "neg-"):
			negatives++
			var refused *Error
			if !assert.ErrorAs(t, err, &refused, name) {
				continue
			}
			finding, cross := crossElementNegatives[name]
			assert.Equal(t, !cross, refused.Schema, "%s refused by the wrong stage: %v", name, err)
			if cross {
				assert.Contains(t, err.Error(), finding, name)
			}
		default:
			t.Errorf("%s is neither pos- nor neg-", name)
		}
	}
	assert.Equal(t, 20, positives)
	assert.Equal(t, 55, negatives)
	assert.Equal(t, 14, sidecars)
	for name := range crossElementNegatives {
		_, err := os.Stat(filepath.Join(vectorsDir, name+".json"))
		assert.NoError(t, err, "cross-element negative %s has no vector", name)
	}
}

func TestSchemaIsTheRepositorys(t *testing.T) {
	want, err := os.ReadFile("../../schemas/evidence-result-v0.json")
	require.NoError(t, err)
	require.Equal(t, string(want), string(Schema()), "go/evidenceresult/evidence-result-v0.json must be a byte copy of schemas/evidence-result-v0.json")
}

func TestCheckReturnsTheClaims(t *testing.T) {
	doc, records := load(t, "pos-example-org-applicability-result")
	claims, err := Check(doc, records)
	require.NoError(t, err)
	inForce := map[string]bool{}
	for _, claim := range claims {
		inForce[claim.ID] = claim.InForce
	}
	assert.Equal(t, map[string]bool{"claim-1": true, "claim-2": false, "claim-3": true, "claim-4": false, "claim-5": false}, inForce)

	doc, records = load(t, "pos-example-org-close-agreed-result")
	claims, err = Check(doc, records)
	require.NoError(t, err)
	require.Len(t, claims, 2)
	assert.Equal(t, TypeRequirement, claims[0].Type)
	assert.Nil(t, claims[0].Close)
	require.NotNil(t, claims[1].Close)
	assert.Equal(t, "AGREED", claims[1].Close.State)
	assert.Equal(t, "example-org-sor", claims[1].Close.Peer)
	assert.Contains(t, claims[1].Evidence, claims[1].Close.Ref)
	assert.Contains(t, claims[1].Evidence, claims[1].Close.PeerRef)

	doc, records = load(t, "pos-example-org-reconcile-result")
	claims, err = Check(doc, records)
	require.NoError(t, err)
	require.NotNil(t, claims[1].Reconcile)
	assert.Equal(t, "408", claims[1].Reconcile.Tallies["matched"].String())
}

// A close claim is never accepted unchecked: without the records it cites,
// its state cannot be recomputed.
func TestCloseClaimNeedsItsRecords(t *testing.T) {
	doc, _ := load(t, "pos-example-org-close-agreed-result")
	_, err := Check(doc, nil)
	var refused *Error
	require.ErrorAs(t, err, &refused)
	assert.False(t, refused.Schema)
	assert.Contains(t, err.Error(), "close_ref names no record")
}

// Section 4: claim ids are unique within a Result. The schema cannot say so.
func TestDuplicateClaimID(t *testing.T) {
	doc, _ := load(t, "pos-example-org-claims-result")
	claims := doc["claims"].([]interface{})
	claims[1].(map[string]interface{})["id"] = claims[0].(map[string]interface{})["id"]
	_, err := Check(doc, nil)
	var refused *Error
	require.ErrorAs(t, err, &refused)
	assert.False(t, refused.Schema)
	assert.Contains(t, err.Error(), `claims[1].id "claim-1" duplicates claims[0]`)
}

// Counts compare by value, as the Python reference compares them.
func TestCountsCompareByValue(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorsDir, "pos-example-org-claims-result.json"))
	require.NoError(t, err)
	spelled := strings.Replace(string(raw), `"evaluated_population": 3`, `"evaluated_population": 3.0`, 1)
	require.NotEqual(t, string(raw), spelled)
	doc, err := Decode([]byte(spelled))
	require.NoError(t, err)
	_, err = Check(doc, nil)
	assert.NoError(t, err)
}

func TestDecode(t *testing.T) {
	doc, err := Decode([]byte(`{"claims":[{"n":8}]}`))
	require.NoError(t, err)
	assert.Equal(t, json.Number("8"), doc["claims"].([]interface{})[0].(map[string]interface{})["n"])
	for name, raw := range map[string]string{
		"not JSON":       `{"claims":`,
		"trailing data":  `{} {}`,
		"an array":       `[{}]`,
		"invalid UTF-8":  "{\"a\":\"\xff\"}",
		"lone surrogate": `{"a":"\ud800"}`,
	} {
		_, err := Decode([]byte(raw))
		assert.Error(t, err, name)
	}
	_, err = DecodeRecords([]byte(`{}`))
	assert.Error(t, err)
	_, err = DecodeRecords([]byte(`[1]`))
	assert.Error(t, err)
	records, err := DecodeRecords([]byte(`[{"seq":1}]`))
	require.NoError(t, err)
	assert.Len(t, records, 1)
}

// The date grammar, case by case, as the Python reference's own table pins
// it (check_evidence_result_examples.py) and the TypeScript reader's tests
// (ts/test/result-revision.test.ts).
func TestDateGrammar(t *testing.T) {
	for stamp, want := range map[string]string{
		"2026-09-22T23:30:00-05:00":    "2026-09-23",
		"2026-09-22t23:30:00-05:00":    "2026-09-23",
		"2026-09-22T00:30:00+01:00":    "2026-09-21",
		"2026-09-22T10:00:00.123Z":     "2026-09-22",
		"2026-02-30T00:00:00Z":         "",
		"2026-09-22T24:00:00Z":         "",
		"2026-09-22T23:59:60Z":         "",
		"2026-09-22T10:00+00:00":       "",
		"2026-09-22X00:00:00+00:00":    "",
		"2026-09-22T00:00:00+00:00:30": "",
		"2026-09-22":                   "",
		"٢٠٢٦-09-22T00:00:00Z":         "",
		"0001-01-01T00:00:00+01:00":    "",
		"9999-12-31T23:00:00-05:00":    "",
		"2026-09-22T00:00:00Z\n":       "",
	} {
		got, ok := utcDate(stamp)
		if want == "" {
			assert.False(t, ok, stamp)
			continue
		}
		expected, _ := calendarDate(want)
		assert.True(t, ok, stamp)
		assert.Equal(t, expected, got, stamp)
	}
	for value, ok := range map[string]bool{
		"0099-01-01": true, "2024-02-29": true, "0000-01-01": false, "2027-02-30": false,
		"٢٠٢٦-09-22": false, "2026-09-22\n": false,
	} {
		_, got := calendarDate(value)
		assert.Equal(t, ok, got, value)
	}
}

// A tally is read exactly, whatever its size or spelling.
func TestTalliesAreExact(t *testing.T) {
	doc, _ := load(t, "pos-example-org-reconcile-result")
	tallies := doc["claims"].([]interface{})[1].(map[string]interface{})["reconcile"].(map[string]interface{})["tallies"].(map[string]interface{})
	tallies["matched"] = json.Number("9223372036854775808")
	tallies["a_only"] = json.Number("2.0")
	claims, err := Check(doc, nil)
	require.NoError(t, err)
	assert.Equal(t, "9223372036854775808", claims[1].Reconcile.Tallies["matched"].String())
	assert.Equal(t, "2", claims[1].Reconcile.Tallies["a_only"].String())
}

// Schema patterns are ECMA-262's: \s is Unicode whitespace, and $ matches
// only at the end of the text.
func TestPatternsReadAsECMA262(t *testing.T) {
	for name, mutate := range map[string]func(claim map[string]interface{}){
		"no-break space in contract_ref": func(claim map[string]interface{}) { claim["contract_ref"] = "ec:\u00a0example@1" },
		"line separator in contract_ref": func(claim map[string]interface{}) { claim["contract_ref"] = "ec:\u2028example@1" },
		"newline after a digest": func(claim map[string]interface{}) {
			ref := claim["evidence"].([]interface{})[0].(map[string]interface{})
			ref["digest"] = ref["digest"].(string) + "\n"
		},
	} {
		doc, _ := load(t, "pos-example-org-claims-result")
		mutate(doc["claims"].([]interface{})[0].(map[string]interface{}))
		_, err := Check(doc, nil)
		var refused *Error
		if assert.ErrorAs(t, err, &refused, name) {
			assert.True(t, refused.Schema, name)
		}
	}
	re, err := ecmaRegexp(`^[^@\s]+@\S+$`)
	require.NoError(t, err)
	assert.True(t, re.MatchString("a@b"))
	assert.False(t, re.MatchString("a\u3000x@b"))
	assert.False(t, re.MatchString("a@b\ufeff"))
	_, err = ecmaRegexp(`[\S]`)
	assert.Error(t, err)
}
