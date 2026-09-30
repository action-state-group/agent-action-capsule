// SPDX-License-Identifier: BSD-3-Clause
package emitter

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A bundle whose root record is a sealed Evidence Result v0 goes through the
// same shell wrapper as any other bundle: this package embeds bytes and knows
// nothing about root families, so its output for the committed sealed
// Result-root fixture must equal the TypeScript emitter's byte for byte.
// ts/test/result-root-emitter.test.ts pins the TypeScript side to the same
// two files.
func TestEmitResultRootHTMLMatchesTypeScript(t *testing.T) {
	input, err := os.ReadFile(filepath.Join("..", "..", "ts", "test", "testdata", "result-root-bundle.sealed.json"))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(input)))
	decoder.UseNumber()
	var bundle map[string]interface{}
	if err := decoder.Decode(&bundle); err != nil {
		t.Fatal(err)
	}

	got, err := EmitEvidenceGraphHTML(bundle, []byte("/*IIFE_MARKER*/"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "expected-result-root.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal([]byte(got), want) {
		t.Fatal("Go HTML for the Result-root bundle differs from TypeScript HTML")
	}
}
