package registries

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProvisionalSnapshotMatchesPython(t *testing.T) {
	expected, err := os.ReadFile("../../python/agent_action_capsule/data/cpb_provisional.json")
	require.NoError(t, err)
	assert.Equal(t, expected, cpbSnapshot, "refresh the vendored snapshot from Python when its provenance changes")
	values, err := ProvisionalValues()
	require.NoError(t, err)
	assert.Equal(t, "mesh-inference-exchange", values["effect.type"]["inference_completion"])
	assert.Empty(t, values["effect.type"]["future-effect"])
	values["effect.type"]["inference_completion"] = "caller mutation"
	fresh, err := ProvisionalValues()
	require.NoError(t, err)
	assert.Equal(t, "mesh-inference-exchange", fresh["effect.type"]["inference_completion"])
}

func TestLoadOlderRegistrySnapshot(t *testing.T) {
	current, err := os.ReadFile("../../spec/REGISTRY.md")
	require.NoError(t, err)
	older, _, found := strings.Cut(string(current), "\n## 11.")
	require.True(t, found)
	path := filepath.Join(t.TempDir(), "REGISTRY.md")
	require.NoError(t, os.WriteFile(path, []byte(older), 0600))
	known, err := Load(path)
	require.NoError(t, err)
	assert.True(t, known["chain.relation"]["confirms"])
	assert.Empty(t, known["citation_purpose"])
}
