// SPDX-License-Identifier: BSD-3-Clause
package presentation

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// The shared resolution vectors (vectors/presentation-resolution/), generated
// by the TypeScript registry and normative for this package too. Each runs
// here exactly as ts/test/presentation-resolution-vectors.test.ts runs it.

func vectorsDir(t *testing.T) string {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "vectors")
}

func readVector(t *testing.T, path string, into interface{}) {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	require.NoError(t, decoder.Decode(into))
}

// sameJSON compares a Go value with an expected JSON value, both as plain
// decoded JSON.
func sameJSON(t *testing.T, expected json.RawMessage, actual interface{}, label string) {
	t.Helper()
	encoded, err := json.Marshal(actual)
	require.NoError(t, err)
	var left, right interface{}
	require.NoError(t, json.Unmarshal(expected, &left))
	require.NoError(t, json.Unmarshal(encoded, &right))
	require.Equal(t, left, right, label)
}

type wireRefusal struct {
	Refusal
	RowCovered   string `json:"row_covered"`
	RowUncovered string `json:"row_uncovered"`
	Line         string `json:"line"`
}

func toWireRefusal(r Refusal) wireRefusal {
	return wireRefusal{Refusal: r, RowCovered: RefusalRow(r, true), RowUncovered: RefusalRow(r, false), Line: RefusalLine(r)}
}

func wireRefusals(list []Refusal) []wireRefusal {
	out := []wireRefusal{}
	for _, r := range list {
		out = append(out, toWireRefusal(r))
	}
	return out
}

type wireError struct {
	Kind    string   `json:"kind"`
	IDs     []string `json:"ids,omitempty"`
	Message string   `json:"message"`
}

func toWireError(t *testing.T, err error) wireError {
	t.Helper()
	var ambiguity *AmbiguityError
	if errors.As(err, &ambiguity) {
		return wireError{Kind: "ambiguity", IDs: ambiguity.IDs, Message: ambiguity.Error()}
	}
	var registration *RegistrationError
	require.ErrorAs(t, err, &registration)
	return wireError{Kind: "registration", Message: registration.Error()}
}

type wireResolution struct {
	Kind    string         `json:"kind"`
	Module  string         `json:"module,omitempty"`
	Refused *[]wireRefusal `json:"refused,omitempty"`
}

func resolveWire(
	t *testing.T,
	manifests []Manifest,
	d Descriptor,
	audience string,
	format Format,
	declines []string,
	refuse func(Manifest) (Refusal, bool),
) interface{} {
	t.Helper()
	resolution, err := ResolveManifests(manifests, d, audience, format, func(m Manifest) bool {
		return !contains(declines, m.ID)
	}, refuse)
	if err != nil {
		return toWireError(t, err)
	}
	out := wireResolution{Kind: string(resolution.Kind)}
	if resolution.Kind != ResolutionRefusal {
		refused := wireRefusals(resolution.Refused)
		out.Refused = &refused
	}
	if resolution.Manifest != nil {
		out.Module = resolution.Manifest.ID
	}
	return out
}

type probe struct {
	Descriptor Descriptor      `json:"descriptor"`
	Audience   string          `json:"audience"`
	Format     Format          `json:"format"`
	Declines   []string        `json:"declines"`
	Expect     json.RawMessage `json:"expect"`
}

type registered struct {
	manifests []Manifest
	refusals  map[string]Refusal
	registry  *Registry
	outcomes  []interface{}
	err       error
}

func (r registered) refuse(m Manifest) (Refusal, bool) {
	refusal, ok := r.refusals[m.ID]
	return refusal, ok
}

// registerAll parses and registers each manifest in order, stopping at the
// first error, as the TypeScript runner does.
func registerAll(manifests []json.RawMessage, rt Runtime) registered {
	out := registered{refusals: map[string]Refusal{}, registry: NewRegistry(rt), outcomes: []interface{}{}}
	for _, data := range manifests {
		manifest, err := ParseManifest(data)
		if err == nil {
			var registration Registration
			registration, err = out.registry.Register(manifest)
			if err == nil {
				out.manifests = append(out.manifests, manifest)
				if registration.Refused {
					out.refusals[manifest.ID] = registration.Refusal
					out.outcomes = append(out.outcomes, map[string]interface{}{
						"status": "refused", "refusal": toWireRefusal(registration.Refusal),
					})
				} else {
					out.outcomes = append(out.outcomes, map[string]string{"status": "registered"})
				}
				continue
			}
		}
		out.err = err
		return out
	}
	return out
}

func builtinRaw(t *testing.T, ids ...string) []json.RawMessage {
	t.Helper()
	var out []json.RawMessage
	for _, id := range ids {
		data, ok := BuiltinManifestJSON(id)
		require.True(t, ok, id)
		out = append(out, data)
	}
	return out
}

func manifestIDs(t *testing.T, manifests []Manifest, err error) []string {
	t.Helper()
	require.NoError(t, err)
	var ids []string
	for _, m := range manifests {
		ids = append(ids, m.ID)
	}
	return ids
}

func TestTableVectors(t *testing.T) {
	var file struct {
		Runtime Runtime `json:"runtime"`
		Count   int     `json:"count"`
		Cases   []probe `json:"cases"`
	}
	readVector(t, filepath.Join(vectorsDir(t), "presentation-resolution", "table.json"), &file)
	require.Equal(t, 1536, file.Count)
	require.Len(t, file.Cases, 1536)
	builtins, err := BuiltinManifests()
	built := registerAll(builtinRaw(t, manifestIDs(t, builtins, err)...), file.Runtime)
	require.NoError(t, built.err)
	for i, c := range file.Cases {
		actual := resolveWire(t, built.manifests, c.Descriptor, c.Audience, c.Format, c.Declines, built.refuse)
		sameJSON(t, c.Expect, actual, label(file.Cases[i].Descriptor))
	}
}

func TestRegistrationVectors(t *testing.T) {
	var file struct {
		Cases []struct {
			ID        string            `json:"id"`
			Runtime   Runtime           `json:"runtime"`
			Register  bool              `json:"register"`
			Manifests []json.RawMessage `json:"manifests"`
			Expect    json.RawMessage   `json:"expect"`
			Probes    []probe           `json:"probes"`
		} `json:"cases"`
	}
	readVector(t, filepath.Join(vectorsDir(t), "presentation-resolution", "registration.json"), &file)
	require.NotEmpty(t, file.Cases)
	reasons := map[RefusalReason]bool{}
	errorKinds := map[string]bool{}
	for _, c := range file.Cases {
		var manifests []Manifest
		var refuse func(Manifest) (Refusal, bool)
		if c.Register {
			built := registerAll(c.Manifests, c.Runtime)
			expect := map[string]interface{}{"registrations": built.outcomes, "error": nil, "list": nil, "refused": nil}
			if built.err != nil {
				wire := toWireError(t, built.err)
				expect["error"] = wire
				errorKinds[wire.Kind] = true
			} else {
				ids := []string{}
				for _, m := range built.registry.List() {
					ids = append(ids, m.ID)
				}
				expect["list"] = ids
				expect["refused"] = wireRefusals(built.registry.Refused())
				for _, r := range built.registry.Refused() {
					reasons[r.Reason] = true
				}
			}
			sameJSON(t, c.Expect, expect, c.ID)
			manifests, refuse = built.manifests, built.refuse
		} else {
			for _, data := range c.Manifests {
				manifest, err := ParseManifest(data)
				require.NoError(t, err, c.ID)
				manifests = append(manifests, manifest)
			}
			rt := c.Runtime
			refuse = func(m Manifest) (Refusal, bool) { return RefusalOf(m, rt) }
		}
		for _, p := range c.Probes {
			actual := resolveWire(t, manifests, p.Descriptor, p.Audience, p.Format, p.Declines, refuse)
			sameJSON(t, p.Expect, actual, c.ID+" "+label(p.Descriptor))
		}
	}
	require.Equal(t, map[RefusalReason]bool{RefusalAPIUnsupported: true, RefusalRuntimeTooOld: true}, reasons)
	require.Equal(t, map[string]bool{"ambiguity": true, "registration": true}, errorKinds)
}

type bundleSource struct {
	Bundle string `json:"bundle"`
	Vector *struct {
		File   string `json:"file"`
		Key    string `json:"key"`
		Case   string `json:"case"`
		Member string `json:"member"`
	} `json:"vector"`
}

// overlayExtensions applies a case's extensions overlay: each member replaces
// that kind in the bundle's extensions object (created when absent), and
// null removes it.
func overlayExtensions(value interface{}, overlay map[string]interface{}) interface{} {
	if overlay == nil {
		return value
	}
	top, _ := value.(map[string]interface{})
	copied := make(map[string]interface{}, len(top))
	for k, v := range top {
		copied[k] = v
	}
	extensions := map[string]interface{}{}
	if existing, ok := copied["extensions"].(map[string]interface{}); ok {
		for k, v := range existing {
			extensions[k] = v
		}
	}
	for kind, block := range overlay {
		if block == nil {
			delete(extensions, kind)
		} else {
			extensions[kind] = block
		}
	}
	copied["extensions"] = extensions
	return copied
}

// TestDescriptorVectors is the parity test: over every real fixture bundle
// in the corpus (and the extension overlays on each verified one), the Go
// verifier and Describe give exactly the descriptor the TypeScript
// describeContext gives, and the built-in page and section registries
// resolve it to the same module.
func TestDescriptorVectors(t *testing.T) {
	var file struct {
		Bundles map[string]interface{} `json:"bundles"`
		Count   int                    `json:"count"`
		Cases   []struct {
			ID         string                 `json:"id"`
			Source     bundleSource           `json:"source"`
			Extensions map[string]interface{} `json:"extensions"`
			Expect     struct {
				Descriptor json.RawMessage `json:"descriptor"`
				Page       json.RawMessage `json:"page"`
				Section    json.RawMessage `json:"section"`
			} `json:"expect"`
		} `json:"cases"`
	}
	dir := vectorsDir(t)
	readVector(t, filepath.Join(dir, "presentation-resolution", "descriptors.json"), &file)
	require.Len(t, file.Cases, file.Count)
	pages, err := BuiltinManifests()
	require.NoError(t, err)
	sections, err := BuiltinSectionManifests()
	require.NoError(t, err)
	none := func(Manifest) (Refusal, bool) { return Refusal{}, false }
	vectorFiles := map[string][]map[string]interface{}{}
	verified := 0
	for _, c := range file.Cases {
		var base interface{}
		if c.Source.Vector == nil {
			var ok bool
			base, ok = file.Bundles[c.Source.Bundle]
			require.True(t, ok, c.ID)
		} else {
			v := c.Source.Vector
			cases, loaded := vectorFiles[v.File]
			if !loaded {
				var other struct {
					Cases []map[string]interface{} `json:"cases"`
				}
				readVector(t, filepath.Join(dir, filepath.FromSlash(v.File)), &other)
				cases = other.Cases
				vectorFiles[v.File] = cases
			}
			for _, other := range cases {
				if other[v.Key] == v.Case {
					base = other[v.Member]
				}
			}
			require.NotNil(t, base, c.ID)
		}
		descriptor, _ := DescribeBundle(overlayExtensions(base, c.Extensions))
		if descriptor.Verified {
			verified++
		}
		sameJSON(t, c.Expect.Descriptor, descriptor, c.ID)
		sameJSON(t, c.Expect.Page, resolveWire(t, pages, descriptor, "*", FormatHTML, nil, none), c.ID)
		sameJSON(t, c.Expect.Section, resolveWire(t, sections, descriptor, "*", FormatHTML, nil, none), c.ID)
	}
	require.Greater(t, verified, 0)
}

func TestCorpusCarriesTheBuiltinManifests(t *testing.T) {
	var file struct {
		BuiltinManifests        []json.RawMessage `json:"builtin_manifests"`
		BuiltinSectionManifests []json.RawMessage `json:"builtin_section_manifests"`
		ReferenceRuntime        Runtime           `json:"reference_runtime"`
	}
	readVector(t, filepath.Join(vectorsDir(t), "presentation-resolution", "manifest.json"), &file)
	require.Equal(t, ReferenceRuntime(), file.ReferenceRuntime)
	for name, pair := range map[string]struct {
		expected []json.RawMessage
		load     func() ([]Manifest, error)
	}{
		"pages":    {file.BuiltinManifests, BuiltinManifests},
		"sections": {file.BuiltinSectionManifests, BuiltinSectionManifests},
	} {
		manifests, err := pair.load()
		require.NoError(t, err)
		require.Len(t, manifests, len(pair.expected), name)
		for i, m := range manifests {
			// The embedded bytes, the TypeScript constant and the parsed value agree.
			data, ok := BuiltinManifestJSON(m.ID)
			require.True(t, ok)
			sameJSON(t, pair.expected[i], json.RawMessage(data), m.ID)
			sameJSON(t, pair.expected[i], m, m.ID)
		}
	}
}

func label(d Descriptor) string {
	data, _ := json.Marshal(d)
	return string(data)
}
