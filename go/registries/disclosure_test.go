// SPDX-License-Identifier: BSD-3-Clause
package registries_test

import (
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/registries"
	"github.com/stretchr/testify/require"
)

func TestDisclosureEligibilityTable(t *testing.T) {
	require.Equal(t, map[string]string{
		"agent_input":  "model_attestation.compute_attestation.agent_input_digest",
		"agent_output": "model_attestation.compute_attestation.agent_output_digest",
	}, registries.DisclosureEligibleFields)
}
