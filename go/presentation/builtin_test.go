// SPDX-License-Identifier: BSD-3-Clause
package presentation

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The embedded page manifests are the contract's files, byte for byte.
func TestBuiltinManifestsAreTheContractFiles(t *testing.T) {
	dir := filepath.Join(vectorsDir(t), "..", "schemas", "examples", "presentation-manifest-v0")
	for _, name := range builtinPageFiles {
		want, err := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, err)
		got, err := builtinFiles.ReadFile("builtin/" + name)
		require.NoError(t, err)
		require.Equal(t, string(want), string(got), name)
	}
}

func TestBuiltinRegistries(t *testing.T) {
	pages, err := NewBuiltinRegistry(ReferenceRuntime())
	require.NoError(t, err)
	require.Len(t, pages.List(), 6)
	require.Empty(t, pages.Refused())
	sections, err := NewSectionRegistry(ReferenceRuntime())
	require.NoError(t, err)
	require.Len(t, sections.List(), 1)

	// Under a runtime that implements no presentation API, every built-in is
	// refused, none is selectable, and resolution names what it matched.
	refusing, err := NewBuiltinRegistry(Runtime{RuntimeVersion: "0.1.0"})
	require.NoError(t, err)
	require.Empty(t, refusing.List())
	require.Len(t, refusing.Refused(), 6)
	kind := "evidence-bundle/v2"
	resolution, err := refusing.Resolve(Descriptor{Verified: true, BundleKind: &kind, Profiles: []string{"spec_version:report/v1"}}, "*", FormatHTML)
	require.NoError(t, err)
	require.Equal(t, ResolutionNone, resolution.Kind)
	require.Len(t, resolution.Refused, 2)
	require.Equal(t,
		"Presentation module aac.builtin.report-rows/v0 was not used: it needs presentation API aac.presentation-api/v0, which this viewer does not implement",
		RefusalLine(resolution.Refused[0]))

	// The composition section in the page registry is refused by section 4.5.
	manifests, err := BuiltinManifests()
	require.NoError(t, err)
	section, err := BuiltinSectionManifests()
	require.NoError(t, err)
	registry := NewRegistry(ReferenceRuntime())
	for _, m := range manifests {
		_, err := registry.Register(m)
		require.NoError(t, err)
	}
	_, err = registry.Register(section[0])
	var ambiguity *AmbiguityError
	require.ErrorAs(t, err, &ambiguity)
}
