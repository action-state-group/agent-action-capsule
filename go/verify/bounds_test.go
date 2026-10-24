// SPDX-License-Identifier: BSD-3-Clause
package verify_test

// Verify does bounded work on hostile numbers (#383, the #381 shape). A wide
// array under a long key used to make the walk build a full path for every
// member and keep a finding per failing number: about 125 GB for a 1 MB
// record. The shared fixture pins the same findings for every implementation.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/verify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func numberFindings(res verify.VerificationResult) []verify.Finding {
	var out []verify.Finding
	for _, f := range res.Findings {
		if f.Code == "float_in_digest_field" || f.Code == "unsafe_integer_in_digest_field" {
			out = append(out, f)
		}
	}
	return out
}

func TestNumberFindingsMatchTheSharedFixture(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "vectors", "cross-language", "verify-number-findings.json"))
	require.NoError(t, err)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var fixture struct {
		Record   map[string]interface{} `json:"record"`
		Expected []struct {
			Code string `json:"code"`
			Path string `json:"path"`
		} `json:"expected"`
	}
	require.NoError(t, decoder.Decode(&fixture))

	found := numberFindings(verify.Verify(fixture.Record, nil, nil))
	require.Len(t, found, len(fixture.Expected))
	for i, e := range fixture.Expected {
		assert.Equal(t, e.Code, found[i].Code, i)
		assert.Contains(t, found[i].Detail, " at "+e.Path, i)
	}
}

// wideRecord is a well-formed record with 250,000 copies of value in one
// array under a 500 KB key: a little over 1 MB of JSON. The same shape as
// Rust's tests/verify_bounds.rs.
func wideRecord(value interface{}) map[string]interface{} {
	items := make([]interface{}, 250_000)
	for i := range items {
		items[i] = value
	}
	record := map[string]interface{}{
		"spec_version":        "draft-mih-scitt-agent-action-capsule-05",
		"format_version":      "4",
		"canonicalization_id": "jcs",
		"action_id":           "wide",
		"action_type":         "fyi",
		"operator":            "op",
		"developer":           "dev@v1",
		"timestamp":           "2026-09-29T00:00:00Z",
		"model_attestation":   map[string]interface{}{strings.Repeat("k", 500_000): items},
	}
	id, err := canonical.ComputeCapsuleID(record)
	if err != nil {
		id = ""
	}
	record["capsule_id"] = id
	return record
}

func TestWideArrayUnderALongKeyIsBounded(t *testing.T) {
	cases := map[string]interface{}{
		"zeros":   json.Number("0"),
		"objects": map[string]interface{}{},
		"floats":  json.Number("0.5"),
		"unsafe":  json.Number("9007199254740993"),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			record := wideRecord(value)
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			start := time.Now()
			res := verify.Verify(record, nil, nil)
			elapsed := time.Since(start)
			runtime.ReadMemStats(&after)

			assert.Less(t, elapsed, 10*time.Second)
			// Total bytes allocated, not the peak. The identity check
			// re-canonicalizes the record; before #383 the floats shape
			// needed about 125 GB.
			assert.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(64<<20))
			found := numberFindings(res)
			if name == "zeros" || name == "objects" {
				assert.True(t, res.OK, res.Findings)
				assert.Empty(t, found)
				return
			}
			assert.False(t, res.OK)
			require.Len(t, found, 64)
			assert.Contains(t, found[0].Detail, " at model_attestation."+strings.Repeat("k", 256-len("model_attestation."))+"...")
			for _, f := range found {
				assert.Less(t, len(f.Detail), 600)
			}
		})
	}
}
