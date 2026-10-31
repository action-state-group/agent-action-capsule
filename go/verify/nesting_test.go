// SPDX-License-Identifier: BSD-3-Clause
package verify_test

import (
	"strings"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/verify"
	"github.com/stretchr/testify/require"
)

// DecodeCapsuleJSON refuses text nested past the shared limit, as the Rust and
// TypeScript readers do (vectors/json-nesting/).
func TestDecodeCapsuleJSONRefusesPastTheNestingLimit(t *testing.T) {
	n := canonical.MaxNestingDepth
	_, err := verify.DecodeCapsuleJSON([]byte(strings.Repeat("[", n) + strings.Repeat("]", n)))
	require.NoError(t, err)
	_, err = verify.DecodeCapsuleJSON([]byte(strings.Repeat("[", n+1) + strings.Repeat("]", n+1)))
	require.Error(t, err)
}
