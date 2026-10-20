// SPDX-License-Identifier: BSD-3-Clause
package bundle_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	stdstrings "strings"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/bundle"
	"github.com/stretchr/testify/require"
)

// Evidence Bundle -02: vectors/bundle/non-record-leaves,
// vectors/bundle/certificate-mode and vectors/bundle/category-coverage.

type bundle02Case struct {
	ID      string                 `json:"id"`
	Options map[string]interface{} `json:"options"`
	Bundle  interface{}            `json:"bundle"`
	Expect  map[string]interface{} `json:"expect"`
}

func loadBundle02(t *testing.T, directory string) []bundle02Case {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "vectors", "bundle", directory, "vectors.json"))
	require.NoError(t, err)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var vectors struct {
		Cases []bundle02Case `json:"cases"`
	}
	require.NoError(t, decoder.Decode(&vectors))
	require.NotEmpty(t, vectors.Cases)
	return vectors.Cases
}

// bundle02Bundle returns a fresh copy of the named case's Bundle.
func bundle02Bundle(t *testing.T, directory, id string) map[string]interface{} {
	t.Helper()
	for _, c := range loadBundle02(t, directory) {
		if c.ID == id {
			return c.Bundle.(map[string]interface{})
		}
	}
	t.Fatalf("no case %s in %s", id, directory)
	return nil
}

func TestBundle02CertificateVectors(t *testing.T) {
	for _, directory := range []string{"non-record-leaves", "certificate-mode"} {
		for _, c := range loadBundle02(t, directory) {
			t.Run(directory+"/"+c.ID, func(t *testing.T) {
				require.Equal(t, map[string]interface{}{"require_signature": false, "witness_directory": false}, c.Options)
				expect := map[string]interface{}{"kind_ok": true}
				for name, value := range c.Expect {
					expect[name] = value
				}
				require.Equal(t, expect, observed(bundle.VerifyStrict(c.Bundle, bundle.StrictOptions{})))
			})
		}
	}
}

// coverageOptions reads a category-coverage case's options.
func coverageOptions(t *testing.T, options map[string]interface{}) bundle.Options {
	t.Helper()
	var opts bundle.Options
	if sets, ok := options["category_sets"].(map[string]interface{}); ok {
		opts.CategorySets = map[string][]string{}
		for set, names := range sets {
			opts.CategorySets[set] = []string{}
			for _, name := range names.([]interface{}) {
				opts.CategorySets[set] = append(opts.CategorySets[set], name.(string))
			}
		}
	}
	if request, ok := options["category_request"].(string); ok {
		opts.CategoryRequest = []byte(request)
	}
	if assigned, ok := options["record_categories"].(map[string]interface{}); ok {
		opts.RecordCategories = map[string]*string{}
		for id, category := range assigned {
			var value *string
			if text, isString := category.(string); isString {
				value = &text
			}
			opts.RecordCategories[id] = value
		}
	}
	return opts
}

func coverageValue(properties []bundle.CategoryProperty) interface{} {
	if properties == nil {
		return nil
	}
	out := map[string]interface{}{}
	for _, property := range properties {
		out[property.Name] = property.Value
	}
	return out
}

func TestBundle02CategoryCoverageVectors(t *testing.T) {
	for _, c := range loadBundle02(t, "category-coverage") {
		t.Run(c.ID, func(t *testing.T) {
			result := bundle.VerifyStrict(c.Bundle, bundle.StrictOptions{Options: coverageOptions(t, c.Options)})
			require.Equal(t, c.Expect, map[string]interface{}{"verdict": result.Verdict, "category_coverage": coverageValue(result.CategoryCoverage)})
			// The claims are the base Bundle's: the member changes none of them.
			for _, claim := range result.Claims {
				require.Equal(t, "pass", claim.Status, claim.Name)
			}
			if result.CategoryCoverage != nil {
				names := []string{}
				for _, property := range result.CategoryCoverage {
					names = append(names, property.Name)
				}
				require.Equal(t, bundle.CategoryCoverageProperties, names, "report order")
			}
		})
	}
}

func TestCategoryCoverageIsReportedInPlainMode(t *testing.T) {
	for _, c := range loadBundle02(t, "category-coverage") {
		if c.ID != "neg-consistency-absent-with-record" {
			continue
		}
		result := bundle.VerifyBundleWithOptions(c.Bundle, coverageOptions(t, c.Options))
		require.Equal(t, c.Expect["category_coverage"], coverageValue(result.CategoryCoverage))
		return
	}
	t.Fatal("case not found")
}

func plainClaims(value interface{}) [2]bundle.ClaimResult {
	result := bundle.VerifyBundle(value)
	return [2]bundle.ClaimResult{result.IntervalCoverage, result.PerRecordMembership}
}

func claim(status string, findings ...string) bundle.ClaimResult {
	return bundle.ClaimResult{Status: status, Findings: findings}
}

func TestPlainProducerSelected(t *testing.T) {
	selected := func() map[string]interface{} {
		return bundle02Bundle(t, "certificate-mode", "incomplete-producer-selected-padded-log")
	}
	notCheckable := claim("withheld", "selection_not_checkable")
	require.Equal(t, [2]bundle.ClaimResult{notCheckable, claim("pass")}, plainClaims(selected()))

	unsigned := selected()
	delete(unsigned["checkpoint"].(map[string]interface{}), "cose")
	require.Equal(t, claim("pass", "checkpoint_unverified"), plainClaims(unsigned)[1])

	badCose := selected()
	cose := badCose["checkpoint"].(map[string]interface{})["cose"].(string)
	badCose["checkpoint"].(map[string]interface{})["cose"] = cose[:len(cose)-4] + "AAAA"
	require.Equal(t, claim("fail", "checkpoint_authentication_invalid"), plainClaims(badCose)[1])

	tampered := bundle02Bundle(t, "certificate-mode", "neg-producer-selected-padded-log-tampered")
	require.Equal(t, claim("fail", "membership_proof_invalid:"+tampered["root"].(string)), plainClaims(tampered)[1])

	otherRoot := selected()
	delete(otherRoot["checkpoint"].(map[string]interface{}), "cose")
	otherRoot["checkpoint"].(map[string]interface{})["root"] = "0000000000000000000000000000000000000000000000000000000000000000"
	require.Equal(t, claim("fail", "completeness_certificate_invalid"), plainClaims(otherRoot)[1])

	noLogID := selected()
	delete(noLogID["checkpoint"].(map[string]interface{}), "cose")
	delete(noLogID["completeness_certificate"].(map[string]interface{}), "log_id")
	require.Equal(t, claim("fail", "completeness_certificate_invalid"), plainClaims(noLogID)[1])

	// A checkpoint root of another JSON type is refused, never a panic.
	objectRoot := selected()
	objectRoot["checkpoint"].(map[string]interface{})["root"] = map[string]interface{}{}
	objectRoot["completeness_certificate"].(map[string]interface{})["range_root"] = map[string]interface{}{}
	require.Equal(t, claim("fail", "completeness_certificate_invalid"), plainClaims(objectRoot)[1])

	negativeSize := selected()
	delete(negativeSize["checkpoint"].(map[string]interface{}), "cose")
	negativeSize["checkpoint"].(map[string]interface{})["mmr_size"] = json.Number("-1")
	require.Equal(t, "fail", plainClaims(negativeSize)[1].Status)
}

func TestPlainUnknownModeIsWithheld(t *testing.T) {
	unsupported := claim("withheld", bundle.CertificateModeUnsupported)
	for _, value := range []interface{}{"x-sampled", json.Number("7"), "", map[string]interface{}{"mode": "producer-selected"}, nil} {
		b := bundle02Bundle(t, "certificate-mode", "incomplete-producer-selected-padded-log")
		b["completeness"].(map[string]interface{})["selection"] = value
		require.Equal(t, [2]bundle.ClaimResult{unsupported, unsupported}, plainClaims(b), "%v", value)
	}
	null := bundle02Bundle(t, "certificate-mode", "incomplete-certificate-mode-null")
	require.Equal(t, [2]bundle.ClaimResult{unsupported, unsupported}, plainClaims(null))
	delete(null["completeness"].(map[string]interface{}), "selection")
	require.Equal(t, [2]bundle.ClaimResult{claim("pass"), claim("pass")}, plainClaims(null))
}

func TestPlainPaddedRange(t *testing.T) {
	require.Equal(t, [2]bundle.ClaimResult{claim("pass"), claim("pass")}, plainClaims(bundle02Bundle(t, "non-record-leaves", "pos-padded-whole-log")))
	unknown := bundle02Bundle(t, "non-record-leaves", "incomplete-unknown-leaf-type")
	require.Equal(t, claim("withheld", "non_record_leaf_type_unsupported:20"), plainClaims(unknown)[1])
	delete(unknown["checkpoint"].(map[string]interface{}), "cose")
	require.Equal(t, claim("withheld", "non_record_leaf_type_unsupported:20", "checkpoint_unverified"), plainClaims(unknown)[1])

	member := bundle02Bundle(t, "non-record-leaves", "neg-non-record-leaves-on-producer-selected")
	require.Equal(t, claim("fail", "completeness_certificate_invalid"), plainClaims(member)[1])
	delete(member["checkpoint"].(map[string]interface{}), "cose")
	strict := bundle.VerifyStrict(member, bundle.StrictOptions{})
	require.Equal(t, claim("fail", "completeness_certificate_invalid"), *strict.Claim("per_record_membership"))
	require.Equal(t, bundle.VerdictInvalid, strict.Verdict)
}

func TestUnknownCertificateMembersAreIgnored(t *testing.T) {
	b := bundle02Bundle(t, "non-record-leaves", "pos-padded-whole-log")
	certificate := b["completeness_certificate"].(map[string]interface{})
	certificate["x-note"] = map[string]interface{}{"anything": []interface{}{json.Number("1"), json.Number("2")}}
	certificate["non_record_leaves"].([]interface{})[0].(map[string]interface{})["x-note"] = "ignored"
	require.Equal(t, bundle.VerdictValid, bundle.VerifyStrict(b, bundle.StrictOptions{}).Verdict)
}

func coverageProperty(result []bundle.CategoryProperty, name string) string {
	for _, property := range result {
		if property.Name == name {
			return property.Value
		}
	}
	return ""
}

func TestCategoryCoverageNonCanonicalRootFailsTheSignature(t *testing.T) {
	for _, root := range []interface{}{json.Number("1.5"), json.Number("1152921504606846976")} {
		b := bundle02Bundle(t, "category-coverage", "pos-all-six-statuses")
		b["root"] = root
		plain := bundle.VerifyBundle(b)
		require.Equal(t, bundle.CoverageFail, coverageProperty(plain.CategoryCoverage, "category_coverage_signature"))
		strict := bundle.VerifyStrict(b, bundle.StrictOptions{})
		require.Equal(t, bundle.CoverageFail, coverageProperty(strict.CategoryCoverage, "category_coverage_signature"))
		require.Equal(t, bundle.VerdictInvalid, strict.Verdict)
	}
}

func TestCategoryCoverageIgnoredMemberDoesNotFailTheForm(t *testing.T) {
	b := bundle02Bundle(t, "category-coverage", "unsigned-member")
	b["category_coverage"].(map[string]interface{})["x-note"] = map[string]interface{}{"weight": json.Number("0.5")}
	require.Equal(t, bundle.CoveragePass, coverageProperty(bundle.VerifyBundle(b).CategoryCoverage, "category_coverage_form"))
}

func TestCategoryCoverageRequestIsReadStrictly(t *testing.T) {
	b := bundle02Bundle(t, "category-coverage", "request-without-categories")
	request := func(text string) string {
		result := bundle.VerifyBundleWithOptions(b, bundle.Options{CategoryRequest: []byte(text)})
		return coverageProperty(result.CategoryCoverage, "category_coverage_request")
	}
	for _, text := range []string{
		`{"categories": NaN}`,
		`{"categories": Infinity}`,
		`{"a": {"b": 1, "b": 2}}`,
		`[{"x": 1, "x": 1}]`,
		`{"categories": {"set": "example-set", "names": ["messages"]}} {}`,
		"{\"categories\": \"\xff\"}",
		`[]`,
		``,
	} {
		require.Equal(t, bundle.CoverageNotChecked, request(text), text)
	}
	// The same member name in two objects is no repeat.
	require.Equal(t, bundle.CoverageNotPresent, request(`{"a": {"x": 1}, "b": {"x": [{"x": 2}]}, "x": 3}`))
	// An unpaired surrogate escape is refused wherever it is; a pair, and
	// escapes that only look like one, are read.
	for _, text := range []string{`{"x": "\ud800"}`, `{"x": "\udc00"}`, `{"\ud800": 1}`, `["a\ud800b"]`, `{"x": "\ud800\u0041"}`, `{"x": "\ud800\ud800"}`, `{"x": "\udc00\ud800"}`} {
		require.Equal(t, bundle.CoverageNotChecked, request(text), text)
	}
	for _, text := range []string{`{"x": "\ud83d\ude00"}`, `{"x": "\\ud800"}`, `{"x": "\"\ud83d\ude00"}`, `{"x": "\u00e9"}`} {
		require.Equal(t, bundle.CoverageNotPresent, request(text), text)
	}
	// A number beyond float64 does not end the scan before a repeat.
	require.Equal(t, bundle.CoverageNotChecked, request(`{"pad": 1e400, "categories": {"set": "example-set", "names": ["messages"]}, "categories": {"set": "example-set", "names": ["messages"]}}`))
	require.Equal(t, bundle.CoverageNotChecked, request(`{"categories": {"set": "example-set", "names": ["messages", "messages"]}}`))
	require.Equal(t, bundle.CoverageNotChecked, request(`{"categories": {"set": "example-set", "names": []}}`))
	require.Equal(t, bundle.CoverageNotChecked, request(`{"categories": {"set": 1, "names": ["messages"]}}`))
}

func TestCategoryCoverageRefusesASmallOrderKey(t *testing.T) {
	// The identity point: it "verifies" a signature whose R is the identity
	// and S is zero over any message, under crypto/ed25519.
	identity := "0100000000000000000000000000000000000000000000000000000000000000"
	signature := "0100000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000"
	b := bundle02Bundle(t, "category-coverage", "pos-no-inputs")
	member := b["category_coverage"].(map[string]interface{})
	member["signer"] = map[string]interface{}{"key_id": identity}
	member["signature"] = signature
	require.Equal(t, bundle.CoverageFail, coverageProperty(bundle.VerifyBundle(b).CategoryCoverage, "category_coverage_signature"))
}

// Cases the vectors leave out, each pinned to what the Python reference
// reports for the same edit.

func TestNonRecordLeafBelowTheInterval(t *testing.T) {
	b := bundle02Bundle(t, "non-record-leaves", "pos-padded-suffix")
	certificate := b["completeness_certificate"].(map[string]interface{})
	leaves := certificate["non_record_leaves"].([]interface{})
	certificate["non_record_leaves"] = append(leaves, map[string]interface{}{"seq": json.Number("5"), "content": leaves[0].(map[string]interface{})["content"]})
	strict := bundle.VerifyStrict(b, bundle.StrictOptions{})
	require.Equal(t, claim("fail", "non_record_leaf_seq_invalid:56"), *strict.Claim("per_record_membership"))
}

func TestNonRecordLeafCapsuleIDInUppercase(t *testing.T) {
	b := bundle02Bundle(t, "non-record-leaves", "pos-padded-whole-log")
	content := b["completeness_certificate"].(map[string]interface{})["non_record_leaves"].([]interface{})[0].(map[string]interface{})["content"].(map[string]interface{})
	content["capsule_id"] = stdstrings.ToUpper(content["capsule_id"].(string))
	strict := bundle.VerifyStrict(b, bundle.StrictOptions{})
	require.Equal(t, claim("fail", "non_record_leaf_malformed:6"), *strict.Claim("per_record_membership"))
}

func TestCategoryCoverageFormEdges(t *testing.T) {
	for name, edit := range map[string]func(member map[string]interface{}){
		"empty set": func(m map[string]interface{}) { m["set"] = "" },
		"empty name": func(m map[string]interface{}) {
			m["categories"].(map[string]interface{})[""] = map[string]interface{}{"status": "AVAILABLE"}
		},
		"policy_uri not a string": func(m map[string]interface{}) {
			m["categories"].(map[string]interface{})["messages"].(map[string]interface{})["policy_uri"] = []interface{}{"https://example.com/policy"}
		},
		"key_id in uppercase": func(m map[string]interface{}) {
			signer := m["signer"].(map[string]interface{})
			signer["key_id"] = stdstrings.ToUpper(signer["key_id"].(string))
		},
		"signature one digit short": func(m map[string]interface{}) { m["signature"] = m["signature"].(string)[1:] },
		"signature without signer":  func(m map[string]interface{}) { delete(m, "signer") },
	} {
		b := bundle02Bundle(t, "category-coverage", "pos-no-inputs")
		edit(b["category_coverage"].(map[string]interface{}))
		require.Equal(t, bundle.CoverageFail, coverageProperty(bundle.VerifyBundle(b).CategoryCoverage, "category_coverage_form"), name)
	}
}

func TestCategoryCoverageRequestNameNotUTF8(t *testing.T) {
	b := bundle02Bundle(t, "category-coverage", "request-without-categories")
	request := func(text string) string {
		return coverageProperty(bundle.VerifyBundleWithOptions(b, bundle.Options{CategoryRequest: []byte(text)}).CategoryCoverage, "category_coverage_request")
	}
	require.Equal(t, bundle.CoverageNotChecked, request("{\"categories\": {\"set\": \"example-set\", \"names\": [\"\xff\"]}}"))
	require.Equal(t, bundle.CoverageFail, request(`{"categories": {"set": "example-set", "names": ["nope"]}}`))
}

func TestNonRecordLeafWithAFifthMember(t *testing.T) {
	b := bundle02Bundle(t, "non-record-leaves", "pos-padded-whole-log")
	content := b["completeness_certificate"].(map[string]interface{})["non_record_leaves"].([]interface{})[0].(map[string]interface{})["content"].(map[string]interface{})
	content["zz"] = json.Number("1") // sorts after every padding member
	strict := bundle.VerifyStrict(b, bundle.StrictOptions{})
	require.Equal(t, claim("fail", "non_record_leaf_malformed:6"), *strict.Claim("per_record_membership"))
}

func TestNonRecordLeafRecordTypeNotAString(t *testing.T) {
	b := bundle02Bundle(t, "non-record-leaves", "pos-padded-whole-log")
	content := b["completeness_certificate"].(map[string]interface{})["non_record_leaves"].([]interface{})[0].(map[string]interface{})["content"].(map[string]interface{})
	content["record_type"] = json.Number("7")
	strict := bundle.VerifyStrict(b, bundle.StrictOptions{})
	require.Equal(t, claim("fail", "non_record_leaf_malformed:6"), *strict.Claim("per_record_membership"))
}
