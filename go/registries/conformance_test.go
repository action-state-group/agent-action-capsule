// SPDX-License-Identifier: BSD-3-Clause
package registries

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const conformanceVectors = "../../vectors/registry-conformance"

func readConformanceJSON(t *testing.T, parts ...string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(append([]string{conformanceVectors}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestConformanceAxesAgreeWithLoad: one value set, two readers. The
// conformance axes and the registries the verifier loads must be equal.
func TestConformanceAxesAgreeWithLoad(t *testing.T) {
	axes, err := LoadAxes()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadAuthoritative()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range RegistryNames {
		if !reflect.DeepEqual(axes.Sets[name], loaded[name]) {
			t.Fatalf("%s: conformance axis %v != Load %v", name, axes.Sets[name], loaded[name])
		}
	}
	for alias, target := range axes.Aliases {
		if axes.Sets["chain.relation"][alias] || !axes.Sets["chain.relation"][target] {
			t.Fatalf("legacy alias %s -> %s: alias registered or target unregistered", alias, target)
		}
	}
	if len(axes.Aliases) != 5 {
		t.Fatalf("legacy aliases %v, want the five §6 lists", axes.Aliases)
	}
}

// TestConformanceVectors reads the vectors the Python reference generated and
// requires the same findings, value for value.
func TestConformanceVectors(t *testing.T) {
	axes, err := LoadAxes()
	if err != nil {
		t.Fatal(err)
	}
	manifest := readConformanceJSON(t, "vectors.json")
	cases := manifest["cases"].([]any)
	if len(cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range cases {
		name := c.(map[string]any)["name"].(string)
		t.Run(name, func(t *testing.T) {
			input := readConformanceJSON(t, name, "input.json")
			expected := readConformanceJSON(t, name, "expected.json")
			findings := axes.CheckCapsule(input)
			raw, err := json.Marshal(findings)
			if err != nil {
				t.Fatal(err)
			}
			var got []any
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, expected["findings"]) {
				t.Fatalf("findings\n got %v\nwant %v", got, expected["findings"])
			}
			if Conformant(findings) != expected["conformant"].(bool) {
				t.Fatalf("conformant = %v, want %v", Conformant(findings), expected["conformant"])
			}
			if expected["conformant"].(bool) != strings.HasPrefix(name, "pos-") {
				t.Fatal("a pos- case must conform and a neg- case must not")
			}
		})
	}
}
