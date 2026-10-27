// SPDX-License-Identifier: BSD-3-Clause
package bundle

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeKeepsNumbersAndRefusesWhatIsNotOneObject(t *testing.T) {
	value, err := Decode([]byte(`{"root":"a","checkpoint":{"mmr_size":8}}`))
	require.NoError(t, err)
	require.Equal(t, json.Number("8"), value["checkpoint"].(map[string]interface{})["mmr_size"])
	for name, raw := range map[string]string{
		"not JSON":       `{"root":`,
		"trailing data":  `{"root":"a"} {}`,
		"trailing text":  `{"root":"a"} garbage`,
		"an array":       `[{"root":"a"}]`,
		"a string":       `"bundle"`,
		"invalid UTF-8":  "{\"root\":\"\xff\"}",
		"lone surrogate": `{"root":"\ud800"}`,
	} {
		_, err := Decode([]byte(raw))
		require.Error(t, err, name)
		require.True(t, strings.HasPrefix(err.Error(), "bundle "), "%s: %q", name, err)
	}
}

func TestPublicVerifierURLTakesAFragment(t *testing.T) {
	fragment, err := EncodeFragment(map[string]interface{}{"root": "a"})
	require.NoError(t, err)
	link := PublicVerifierURL + "#" + fragment
	decoded, err := DecodeFragment(strings.SplitN(link, "#", 2)[1])
	require.NoError(t, err)
	require.Equal(t, "a", decoded.(map[string]interface{})["root"])
}
