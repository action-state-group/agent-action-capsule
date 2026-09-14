// SPDX-License-Identifier: BSD-3-Clause
package disclosure_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/disclosure"
	"github.com/action-state-group/agent-action-capsule/go/registries"
	"github.com/stretchr/testify/require"
)

func builderCapsule(t *testing.T) map[string]interface{} {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "vectors", "capsule", "pos-executed-confirmed", "input.json"))
	require.NoError(t, err)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var capsule map[string]interface{}
	require.NoError(t, decoder.Decode(&capsule))
	capsule["spec_version"] = "draft-mih-scitt-agent-action-capsule-04"
	capsule["format_version"] = "4"
	capsule["canonicalization_id"] = canonical.CanonicalizationJCS
	return capsule
}

func TestBuildDisclosureEnvelopeNestedRoundTripAndTampering(t *testing.T) {
	capsule := builderCapsule(t)
	value := map[string]interface{}{
		"outer": map[string]interface{}{
			"items": []interface{}{
				map[string]interface{}{"nested": map[string]interface{}{"value": "one"}},
				map[string]interface{}{"nested": map[string]interface{}{"value": "two"}},
			},
		},
	}
	digest, err := canonical.JSONDigest(value)
	require.NoError(t, err)
	capsule["model_attestation"] = map[string]interface{}{
		"compute_attestation": map[string]interface{}{"agent_input_digest": digest},
	}
	capsuleID, err := canonical.ComputeCapsuleID(capsule)
	require.NoError(t, err)
	capsule["capsule_id"] = capsuleID

	envelope, err := disclosure.Build(capsule, map[string]interface{}{"agent_input": value})
	require.NoError(t, err)
	regs, err := registries.LoadAuthoritative()
	require.NoError(t, err)
	require.True(t, disclosure.Verify(envelope, regs).OK())

	envelope["disclosures"].(map[string]interface{})["agent_input"] = map[string]interface{}{
		"outer": map[string]interface{}{"items": []interface{}{map[string]interface{}{"nested": map[string]interface{}{"value": "tampered"}}}},
	}
	result := disclosure.Verify(envelope, regs)
	require.False(t, result.OK())
	require.Equal(t, disclosure.Mismatch, result.DisclosureFindings[0].Code)
}

func TestBuildDisclosureEnvelopeRejectsInvalidMembers(t *testing.T) {
	capsule := builderCapsule(t)
	_, err := disclosure.Build(capsule, map[string]interface{}{"not_eligible": "value"})
	require.ErrorContains(t, err, disclosure.Ineligible)
	_, err = disclosure.Build(capsule, map[string]interface{}{"agent_input": "value"})
	require.ErrorContains(t, err, disclosure.NoCommittedDigest)
	value := map[string]interface{}{"nested": map[string]interface{}{"value": "committed"}}
	digest, err := canonical.JSONDigest(value)
	require.NoError(t, err)
	capsule["model_attestation"] = map[string]interface{}{
		"compute_attestation": map[string]interface{}{"agent_input_digest": digest},
	}
	_, err = disclosure.Build(capsule, map[string]interface{}{
		"agent_input": map[string]interface{}{"nested": map[string]interface{}{"value": "different"}},
	})
	require.ErrorContains(t, err, disclosure.Mismatch)
}
