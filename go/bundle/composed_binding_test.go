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

type bindingCase struct {
	ID                 string                   `json:"id"`
	Container          map[string]interface{}   `json:"container"`
	ControllerBindings []map[string]interface{} `json:"controller_bindings"`
	BindingRevocations []map[string]interface{} `json:"binding_revocations"`
	Expect             map[string]interface{}   `json:"expect"`
}

// bindingCases reads vectors/bundle/composed-controller-binding/vectors.json.
func bindingCases(t *testing.T) map[string]bindingCase {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "vectors", "bundle", "composed-controller-binding", "vectors.json"))
	require.NoError(t, err)
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	var file struct {
		Count json.Number   `json:"count"`
		Cases []bindingCase `json:"cases"`
	}
	require.NoError(t, decoder.Decode(&file))
	require.Equal(t, json.Number("8"), file.Count)
	cases := map[string]bindingCase{}
	for _, c := range file.Cases {
		cases[c.ID] = c
	}
	require.Len(t, cases, 8)
	return cases
}

func bindingOptions(c bindingCase) Options {
	return Options{ControllerBindings: c.ControllerBindings, BindingRevocations: c.BindingRevocations}
}

func TestComposedControllerBindingVectors(t *testing.T) {
	for id, c := range bindingCases(t) {
		c := c
		t.Run(id, func(t *testing.T) {
			block := composedBlockOf(c.Container)
			preimage, err := ComposedDigestPreimage(block)
			require.NoError(t, err)
			require.Equal(t, c.Expect["canonical_preimage"], string(preimage))

			composed := verifyBlock(t, c.Container, bindingOptions(c))
			require.Equal(t, c.Expect["status"], composed.Status, composed.Findings)
			want := map[string]interface{}{}
			for key, value := range c.Expect {
				if key != "canonical_preimage" {
					want[key] = value
				}
			}
			require.Equal(t, want, expectShape(composed))
		})
	}
}

// Without the delivered records, every controller_binding join is
// not_derivable: the basis never derives from the block alone.
func TestComposedControllerBindingNeedsTheDeliveredRecord(t *testing.T) {
	for id, c := range bindingCases(t) {
		composed := verifyBlock(t, c.Container, Options{})
		require.Equal(t, "not_derivable", composed.Joins[0].Result, id)
		require.Equal(t, "not_applicable", composed.Corroboration[0].Result, id)
	}
}

// A binding the verifier received but cannot read under the join's keys is
// unjoined, never corroborating, whichever way it fails.
func TestComposedControllerBindingFailuresNeverCorroborate(t *testing.T) {
	c := bindingCases(t)["controller-binding-linked"]
	mutations := map[string]func(record map[string]interface{}){
		"second signature from the first key": func(r map[string]interface{}) {
			sigs := r["sigs"].([]interface{})
			sigs[1].(map[string]interface{})["sig"] = sigs[0].(map[string]interface{})["sig"]
		},
		"one signature": func(r map[string]interface{}) { r["sigs"] = r["sigs"].([]interface{})[:1] },
		"third signature": func(r map[string]interface{}) {
			r["sigs"] = append(r["sigs"].([]interface{}), r["sigs"].([]interface{})[0])
		},
		"sigs out of key order": func(r map[string]interface{}) {
			sigs := r["sigs"].([]interface{})
			r["sigs"] = []interface{}{sigs[1], sigs[0]}
		},
	}
	for name, mutate := range mutations {
		record := cloneJSON(t, c.ControllerBindings[0])
		mutate(record)
		composed := verifyBlock(t, c.Container, Options{ControllerBindings: []map[string]interface{}{record}})
		require.Equal(t, "unjoined", composed.Joins[0].Derived, name)
		require.Equal(t, "join_state_mismatch", composed.Joins[0].Result, name)
		require.Equal(t, "not_applicable", composed.Corroboration[0].Result, name)
	}
}

// A revocation statement that does not apply (another binding, a key that is
// not bound, a bad signature, a time after both records) leaves the link.
func TestComposedControllerBindingRevocationMustApply(t *testing.T) {
	cases := bindingCases(t)
	linked, revoked := cases["controller-binding-linked"], cases["controller-binding-revoked-declared-agree"]
	statement := revoked.BindingRevocations[0]
	mutations := map[string]func(s map[string]interface{}){
		"another binding": func(s map[string]interface{}) { s["binding"] = strings.Repeat("0", 64) },
		"unbound key":     func(s map[string]interface{}) { s["key_id"] = strings.Repeat("1", 64) },
		"bad signature":   func(s map[string]interface{}) { s["sig"] = strings.Repeat("0", 128) },
		"after both":      func(s map[string]interface{}) { s["revoked_at"] = "2026-10-03T00:00:00Z" },
	}
	for name, mutate := range mutations {
		s := cloneJSON(t, statement)
		mutate(s)
		composed := verifyBlock(t, linked.Container, Options{
			ControllerBindings: linked.ControllerBindings,
			BindingRevocations: []map[string]interface{}{s},
		})
		require.Equal(t, "agree", composed.Joins[0].Derived, name)
		require.Equal(t, "redundant", composed.Corroboration[0].Result, name)
	}
}

func cloneJSON(t *testing.T, value map[string]interface{}) map[string]interface{} {
	t.Helper()
	data, err := json.Marshal(value)
	require.NoError(t, err)
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	var out map[string]interface{}
	require.NoError(t, decoder.Decode(&out))
	return out
}

// A root record's timestamp may carry fractional seconds; the window compares
// instants. The edit breaks the member digest, not the join's derivation.
func TestComposedControllerBindingFractionalRecordTime(t *testing.T) {
	c := bindingCases(t)["controller-binding-linked"]
	for stamp, derived := range map[string]string{
		"2026-10-02T12:10:00.5Z":    "agree",
		"2027-09-30T23:59:59.999Z":  "agree",
		"2027-10-01T00:00:00.0Z":    "unjoined",
		"2026-09-30T23:59:59.9Z":    "unjoined",
		"2026-10-02T12:10:00+00:00": "unjoined",
	} {
		container := cloneJSON(t, c.Container)
		member := composedBlockOf(container)["members"].([]interface{})[0].(map[string]interface{})
		member["bundle"].(map[string]interface{})["records"].([]interface{})[0].(map[string]interface{})["timestamp"] = stamp
		composed := verifyBlock(t, container, bindingOptions(c))
		require.Equal(t, derived, composed.Joins[0].Derived, stamp)
	}
}
