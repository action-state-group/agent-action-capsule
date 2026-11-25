// SPDX-License-Identifier: BSD-3-Clause
package verify_test

import (
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/verify"
	"github.com/stretchr/testify/require"
)

// The §5.4.4 deferral binding rule through Verify's own store argument. The
// capsule corpus reaches it only through VerifyStore; these cover an id-only
// store and a forged parent copy.

func bindingCodes(result verify.VerificationResult) []string {
	codes := make([]string, 0, len(result.Findings))
	for _, f := range result.Findings {
		codes = append(codes, f.Code+"/"+f.Severity)
	}
	return codes
}

func TestDeferralBindingIDOnlyStoreIsNotEvaluated(t *testing.T) {
	ledger := loadCapsule(t, "neg-supersedes-action-mismatch")["ledger"].([]interface{})
	parent := ledger[0].(map[string]interface{})
	child := ledger[1]
	result := verify.Verify(child, []interface{}{parent["capsule_id"]}, nil)
	require.True(t, result.OK)
	require.Contains(t, bindingCodes(result), "deferral_binding_not_evaluated/info")
	require.NotContains(t, bindingCodes(result), "supersedes_action_mismatch/error")
}

func TestDeferralBindingForgedParentCopyDoesNotCapture(t *testing.T) {
	ledger := loadCapsule(t, "neg-supersedes-action-mismatch")["ledger"].([]interface{})
	parent := ledger[0].(map[string]interface{})
	child := ledger[1].(map[string]interface{})
	forged := make(map[string]interface{}, len(parent))
	for k, v := range parent {
		forged[k] = v
	}
	forged["action_id"] = child["action_id"]
	result := verify.Verify(child, []interface{}{forged, parent, child}, nil)
	require.False(t, result.OK)
	require.Contains(t, bindingCodes(result), "supersedes_action_mismatch/error")
}
