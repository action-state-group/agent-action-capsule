// SPDX-License-Identifier: BSD-3-Clause

package registries

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type vendoredCase struct {
	Name        string          `json:"name"`
	Vendored    json.RawMessage `json:"vendored"`
	Registry    string          `json:"registry"`
	RegistryRef string          `json:"registry_ref"`
	Ref         *string         `json:"ref"`
	Expected    json.RawMessage `json:"expected"`
}

// TestVendoredRegistryVectors runs vectors/vendored-registry/cases.json, the
// same cases the Python tests run, and compares the outcome's JSON form.
func TestVendoredRegistryVectors(t *testing.T) {
	dir := filepath.Join("..", "..", "vectors", "vendored-registry")
	data, err := os.ReadFile(filepath.Join(dir, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Cases []vendoredCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range manifest.Cases {
		t.Run(c.Name, func(t *testing.T) {
			registry, err := os.ReadFile(filepath.Join(dir, c.Registry))
			if err != nil {
				t.Fatal(err)
			}
			ref := ""
			if c.Ref != nil {
				ref = *c.Ref
			}
			res := CheckVendored(c.Vendored, registry, c.RegistryRef, ref)
			gotJSON, err := json.Marshal(res)
			if err != nil {
				t.Fatal(err)
			}
			var got, want any
			if err := json.Unmarshal(gotJSON, &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(c.Expected, &want); err != nil {
				t.Fatal(err)
			}
			g, _ := json.Marshal(got)
			w, _ := json.Marshal(want)
			if string(g) != string(w) {
				t.Fatalf("outcome differs\n got  %s\n want %s", g, w)
			}
		})
	}
}

func TestNormalizeRef(t *testing.T) {
	for _, r := range []string{"go/v0.6.0", "v0.6.0", "0.6.0"} {
		if NormalizeRef(r) != "0.6.0" {
			t.Fatalf("NormalizeRef(%q) = %q", r, NormalizeRef(r))
		}
	}
	if NormalizeRef("deadbeef") != "deadbeef" {
		t.Fatal("a commit ref changed")
	}
}

func TestEmbeddedVersionUnknownInDevBuild(t *testing.T) {
	// A test binary of this module is a development build: the embedded copy's
	// version is unknown, so a check against it cannot silently pass.
	if v := EmbeddedVersion(); v != "" {
		t.Fatalf("EmbeddedVersion() = %q in a development build", v)
	}
	res := CheckVendored([]byte(`{"source":{"interim_registry":"(section 17)"},"values":[]}`), EmbeddedRegistry(), EmbeddedVersion(), "v0.7.0")
	if res.OK || res.Problems[0] != ProblemRefUnresolvable {
		t.Fatalf("got %+v", res)
	}
}
