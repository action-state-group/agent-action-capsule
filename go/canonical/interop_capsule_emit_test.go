// SPDX-License-Identifier: BSD-3-Clause
package canonical_test

// Cross-library interop regression: capsule-emit producer -> AAC Go verifier.
//
// Guards the capsule_id preimage contract across the two libraries. capsule-emit
// attaches the COSE_Sign1 producer envelope (signature) and its signing key_id
// to each ledger line AFTER it computes the capsule_id — so those fields are
// excluded from the id's preimage (see capsule-emit _LOCAL_ONLY_FIELDS and AAC
// canonical.LocalOnlyFields / Python canonical.LOCAL_ONLY_FIELDS).
//
// If ComputeCapsuleID excludes only capsule_id (the pre-fix bug), it hashes
// signature + key_id into the preimage the producer did not, so EVERY emitted
// capsule fails with capsule_id_mismatch. This test recomputes the id over a
// REAL capsule-emit-produced ledger and asserts every capsule verifies.
//
// The fixture is the SAME committed ledger the Python interop test uses
// (python/tests/fixtures/capsule_emit_ledger.jsonl): real format-4 capsule-emit
// capsules carrying signature/key_id, plus one chained "confirms" capsule. It is
// referenced by relative path so both runtimes share one source of truth; keep
// the two interop tests in sync when the wire format changes.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/stretchr/testify/require"
)

func loadCapsuleEmitLedger(t *testing.T) []map[string]interface{} {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	// go/canonical/ -> repo root -> python/tests/fixtures/…; shared fixture.
	path := filepath.Join(
		filepath.Dir(filename), "..", "..",
		"python", "tests", "fixtures", "capsule_emit_ledger.jsonl",
	)
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var capsules []map[string]interface{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		decoder := json.NewDecoder(strings.NewReader(line))
		decoder.UseNumber()
		var capsule map[string]interface{}
		require.NoError(t, decoder.Decode(&capsule))
		capsules = append(capsules, capsule)
	}
	require.NoError(t, scanner.Err())
	return capsules
}

// TestFixtureIsRealCapsuleEmitOutput is the sanity check mirroring the Python
// test_fixture_is_real_capsule_emit_output: the fixture carries the envelope
// fields the bug tripped over (signature + key_id) and at least one chained
// capsule.
func TestFixtureIsRealCapsuleEmitOutput(t *testing.T) {
	capsules := loadCapsuleEmitLedger(t)
	require.GreaterOrEqual(t, len(capsules), 3)
	hasChain := false
	for _, c := range capsules {
		require.Equal(t, "jcs", c["canonicalization_id"])
		_, hasSig := c["signature"]
		_, hasKeyID := c["key_id"]
		require.True(t, hasSig, "capsule missing signature")
		require.True(t, hasKeyID, "capsule missing key_id")
		if _, ok := c["chain"]; ok {
			hasChain = true
		}
	}
	require.True(t, hasChain, "no chained capsule in fixture")
}

// TestRecomputedCapsuleIDMatchesProducer mirrors the Python
// test_recomputed_capsule_id_matches_producer: AAC recomputes the SAME
// capsule_id capsule-emit committed, for every capsule including the chained
// one. RED before the LocalOnlyFields fix (signature/key_id would be hashed in).
func TestRecomputedCapsuleIDMatchesProducer(t *testing.T) {
	for _, capsule := range loadCapsuleEmitLedger(t) {
		want, ok := capsule["capsule_id"].(string)
		require.True(t, ok, "capsule_id is not a string")

		got, err := canonical.ComputeCapsuleID(capsule)
		require.NoError(t, err)
		require.Equalf(t, want, got,
			"capsule_id_mismatch: AAC recomputed %s != producer %s (action_id=%v)",
			got, want, capsule["action_id"],
		)
	}
}
