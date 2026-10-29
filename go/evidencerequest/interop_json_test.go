// SPDX-License-Identifier: Apache-2.0

package evidencerequest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The received JSON reader keeps an unpaired surrogate as itself: as a key
// it is not the U+FFFD key a foreign-object path names, so the object is
// not found there, as the reference finds none.
func TestReceivedJSONKeepsAnUnpairedSurrogate(t *testing.T) {
	v := decodeArtifactJSON([]byte(`{"\ud800":"x.y.z","pair":"😀"}`))
	m, ok := v.(map[string]any)
	require.True(t, ok)
	_, repaired := m["�"]
	assert.False(t, repaired)
	assert.Len(t, m, 2)
	assert.Equal(t, "\U0001F600", m["pair"], "a surrogate pair is one character")
	assert.Nil(t, jcsOrNil(m), "JCS has no form for a lone surrogate")
	assert.False(t, strictEqual(map[string]any{"�": "x.y.z"}, map[string]any{}))
	report := (&Verifier{}).nativeCheck([]byte(`{"\ud800":"x.y.z"}`), ForeignObject{Path: "�", MediaType: "application/jose"})
	assert.Equal(t, StatusNotPresent, report.Status)
}

func TestReceivedJSONReadsTheReferenceGrammar(t *testing.T) {
	for text, want := range map[string]struct{ ok, dup, bad bool }{
		`{"a":1,"a":2}`:    {true, true, false},
		`{"a":-0}`:         {true, false, true},
		`{"a":1.5}`:        {true, false, true},
		`{"a":1e3}`:        {true, false, true},
		`{"a":NaN}`:        {true, false, true},
		`[Infinity]`:       {true, false, true},
		`{"a":01}`:         {false, false, false},
		"{\"a\":\"\x01\"}": {false, false, false},
		`{"a":1} x`:        {false, false, false},
		`{"a":"\q"}`:       {false, false, false},
		` {"a" : [ ] } `:   {true, false, false},
	} {
		_, dup, bad, err := parseReceivedJSON([]byte(text))
		assert.Equal(t, want.ok, err == nil, text)
		if err == nil {
			assert.Equal(t, want.dup, dup, text)
			assert.Equal(t, want.bad, bad, text)
		}
	}
}
