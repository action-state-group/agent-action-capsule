// SPDX-License-Identifier: BSD-3-Clause
package presentation

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const unilateral = `{"spec_version":"aac.presentation-manifest/v0","id":"org.example.unilateral/v0",
"presentation_api":"aac.presentation-api/v0","runtime_min":"0.1.0","trust_class":"trusted-executable",
"requires":{"bundle_kind":"evidence-bundle/v2","profiles":["spec_version:org.example.exchange/v0"]},
"audiences":["*"],"formats":["html"],"fallback":false,"priority":PRIORITY,
"executable":{"carrier":"core-runtime"}EXTRA}`

func manifestJSON(priority, extra string) []byte {
	return []byte(strings.NewReplacer("PRIORITY", priority, "EXTRA", extra).Replace(unilateral))
}

func TestParseManifestAcceptsAnIntegralPriorityWrittenAsAFraction(t *testing.T) {
	manifest, err := ParseManifest(manifestJSON("1.0", ""))
	require.NoError(t, err)
	require.Equal(t, int64(1), *manifest.Priority)
	require.Empty(t, manifest.Problems())
}

// Unknown members are reported in the order JavaScript enumerates them:
// array-index names ascending, then the rest in source order.
func TestUnknownMembersInJavaScriptOrder(t *testing.T) {
	_, err := ParseManifest(manifestJSON("1", `,"zeta":1,"10":1,"alpha":1,"2":1`))
	var registration *RegistrationError
	require.ErrorAs(t, err, &registration)
	require.Equal(t, []string{
		`unknown member "2"`, `unknown member "10"`, `unknown member "zeta"`, `unknown member "alpha"`,
	}, registration.Problems)
}

// Shapes the TypeScript registry cannot express (it would throw reading
// them) are problems here, reported after the registry's own.
func TestWrongShapesAreProblems(t *testing.T) {
	data := []byte(strings.Replace(string(manifestJSON("1", "")),
		`"profiles":["spec_version:org.example.exchange/v0"]`, `"profiles":"spec_version:x"`, 1))
	_, err := ParseManifest(data)
	var registration *RegistrationError
	require.ErrorAs(t, err, &registration)
	require.Equal(t, []string{"requires.profiles is not a list"}, registration.Problems)

	_, err = ParseManifest([]byte(`[]`))
	require.ErrorAs(t, err, &registration)
	require.Equal(t, "manifest undefined refused: manifest is not an object", err.Error())
}

func TestResolveWithAsksCanRenderOnlyAfterTheTierIsDecided(t *testing.T) {
	registry, err := NewBuiltinRegistry(ReferenceRuntime())
	require.NoError(t, err)
	kind := "evidence-bundle/v2"
	graph := Descriptor{Verified: true, BundleKind: &kind, Profiles: []string{"spec_version:evaluation-summary/v1"}}
	var asked []string
	resolution, err := registry.ResolveWith(graph, "owner", FormatEmbedded, func(m Manifest) bool {
		asked = append(asked, m.ID)
		return m.ID != "aac.builtin.evaluation-summary-graph/v0"
	})
	require.NoError(t, err)
	require.Equal(t, []string{"aac.builtin.evaluation-summary-graph/v0", "aac.builtin.no-aggregate/v0"}, asked)
	require.Equal(t, "aac.builtin.no-aggregate/v0", resolution.Manifest.ID)

	resolution, err = registry.Resolve(graph, "owner", FormatEmbedded)
	require.NoError(t, err)
	require.Equal(t, "aac.builtin.evaluation-summary-graph/v0", resolution.Manifest.ID)
}
