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

func TestShellMatchesTypeScript(t *testing.T) {
	tsShell, err := os.ReadFile(filepath.Join("..", "..", "ts", "src", "emitter-shell.html"))
	if err != nil {
		t.Fatal(err)
	}
	goShell, err := os.ReadFile("shell.html")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tsShell, goShell) {
		t.Fatal("Go and TypeScript emitter shells differ")
	}
}

func TestEmitEvidenceGraphHTMLMatchesTypeScript(t *testing.T) {
	input, err := os.ReadFile(filepath.Join("..", "..", "ts", "test", "testdata", "week-bundle.json"))
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
	want, err := os.ReadFile(filepath.Join("testdata", "expected.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal([]byte(got), want) {
		t.Fatal("Go HTML differs from TypeScript HTML")
	}
}
