// SPDX-License-Identifier: BSD-3-Clause
package registries

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadAuthoritative(t *testing.T) {
	known, err := LoadAuthoritative()
	require.NoError(t, err)
	assert.True(t, known["effect.type"]["write_order"])
	assert.True(t, known["citation_purpose"]["responds_to"])
}

func TestEmbeddedAuthoritativeRegistryMatchesSpec(t *testing.T) {
	expected, err := os.ReadFile("../../spec/REGISTRY.md")
	if os.IsNotExist(err) {
		t.Skip("spec/REGISTRY.md is unavailable outside the source checkout")
	}
	require.NoError(t, err)
	assert.Equal(t, expected, authoritativeRegistry, "run go generate ./registries after changing spec/REGISTRY.md")
}
