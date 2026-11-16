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
	assert.Empty(t, values, "the mesh-inference-exchange values are registered, so the snapshot lists none")
}

func TestProvisionalValuesAreCallerOwned(t *testing.T) {
	snapshot := []byte(`{"provisional_artifact_types": {"example-class": {"capsule_field_values": {"effect.type": ["future-effect"]}}}}`)
	values, err := parseProvisional(snapshot)
	require.NoError(t, err)
	assert.Equal(t, "example-class", values["effect.type"]["future-effect"])
	values["effect.type"]["future-effect"] = "caller mutation"
	fresh, err := parseProvisional(snapshot)
	require.NoError(t, err)
	assert.Equal(t, "example-class", fresh["effect.type"]["future-effect"])
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
