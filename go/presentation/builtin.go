// SPDX-License-Identifier: BSD-3-Clause
package presentation

import (
	"embed"
	"fmt"
)

// The built-in manifests, embedded byte for byte. The six page manifests are
// copies of schemas/examples/presentation-manifest-v0/builtin-*.json (the
// tests compare the bytes); the section manifest has no file in the contract
// and equals the TypeScript constant BUILTIN_MANIFEST_COMPOSED (the tests
// compare it with the shared vectors' copy of that constant).
//
//go:embed builtin/*.json
var builtinFiles embed.FS

// builtinPageFiles is appendix A's table order, an order that decides nothing.
var builtinPageFiles = []string{
	"builtin-report-rows.json",
	"builtin-result-outcome-report.json",
	"builtin-result-compliance.json",
	"builtin-result.json",
	"builtin-evaluation-summary-graph.json",
	"builtin-no-aggregate.json",
}

var builtinSectionFiles = []string{"section-composed.json"}

func loadBuiltins(names []string) ([]Manifest, error) {
	out := make([]Manifest, 0, len(names))
	for _, name := range names {
		data, err := builtinFiles.ReadFile("builtin/" + name)
		if err != nil {
			return nil, err
		}
		manifest, err := ParseManifest(data)
		if err != nil {
			return nil, fmt.Errorf("built-in %s: %w", name, err)
		}
		out = append(out, manifest)
	}
	return out, nil
}

// BuiltinManifests is the six built-in page manifests of the contract's
// appendix A. Precedence between them is stated in their forbids.
func BuiltinManifests() ([]Manifest, error) { return loadBuiltins(builtinPageFiles) }

// BuiltinSectionManifests is the built-in section manifests: the composition
// section (aac.builtin.composed/v0), resolved in its own registry after the
// page, because one descriptor matches it together with each specific page
// manifest.
func BuiltinSectionManifests() ([]Manifest, error) { return loadBuiltins(builtinSectionFiles) }

// BuiltinManifestJSON is the embedded bytes of a built-in manifest, page or
// section, by id.
func BuiltinManifestJSON(id string) ([]byte, bool) {
	for _, name := range append(append([]string{}, builtinPageFiles...), builtinSectionFiles...) {
		data, err := builtinFiles.ReadFile("builtin/" + name)
		if err != nil {
			continue
		}
		if manifest, err := ParseManifest(data); err == nil && manifest.ID == id {
			return data, true
		}
	}
	return nil, false
}

func registryOf(runtime Runtime, manifests []Manifest, err error) (*Registry, error) {
	if err != nil {
		return nil, err
	}
	registry := NewRegistry(runtime)
	for _, manifest := range manifests {
		if _, err := registry.Register(manifest); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

// NewBuiltinRegistry is a registry for runtime holding the six built-in page
// manifests (the TypeScript createPresentationRegistry, under any runtime).
func NewBuiltinRegistry(runtime Runtime) (*Registry, error) {
	manifests, err := BuiltinManifests()
	return registryOf(runtime, manifests, err)
}

// NewSectionRegistry is a registry for runtime holding the built-in section
// manifests (the TypeScript createSectionRegistry). It is resolved after the
// page registry, only for a verified bundle whose page resolved; a section
// ambiguity is the page's refusal too.
func NewSectionRegistry(runtime Runtime) (*Registry, error) {
	manifests, err := BuiltinSectionManifests()
	return registryOf(runtime, manifests, err)
}
