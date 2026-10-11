// SPDX-License-Identifier: BSD-3-Clause
package canonical_test

import (
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/stretchr/testify/require"
)

func TestCheckJSONTextAcceptsWellFormedStrings(t *testing.T) {
	for _, text := range []string{
		`{"a":"plain"}`,
		`{"a":"😀"}`,
		`{"a":"é \\u not an escape \"quoted\""}`,
		`["é", "\n"]`,
	} {
		require.NoError(t, canonical.CheckJSONText([]byte(text)), text)
	}
}

func TestCheckJSONTextRejectsRepairedStrings(t *testing.T) {
	for _, text := range []string{
		`{"a":"\ud800"}`,
		`{"a":"\udc00"}`,
		`{"a":"\ud800x"}`,
		`{"a":"\ud800A"}`,
		`{"a":"\ud800𐀀"}`,
		"{\"a\":\"\xff\"}",
	} {
		require.Error(t, canonical.CheckJSONText([]byte(text)), text)
	}
}
