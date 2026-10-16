// SPDX-License-Identifier: BSD-3-Clause
package canonical_test

import (
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/stretchr/testify/require"
)

func TestTooDeep(t *testing.T) {
	build := func(levels int) interface{} {
		var value interface{} = "leaf"
		for i := range levels {
			if i%2 == 0 {
				value = []interface{}{value}
			} else {
				value = map[string]interface{}{"k": value}
			}
		}
		return value
	}
	require.False(t, canonical.TooDeep("scalar"))
	require.False(t, canonical.TooDeep(build(canonical.MaxNestingDepth)))
	require.True(t, canonical.TooDeep(build(canonical.MaxNestingDepth+1)))

	// A value that contains itself is infinitely deep, and still answered.
	cycle := map[string]interface{}{}
	cycle["self"] = cycle
	require.True(t, canonical.TooDeep(cycle))
}
