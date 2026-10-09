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

func TestEmitEvidenceGraphHTMLEscapesScriptBreakingBundleContent(t *testing.T) {
	payload := "</script><script>window.pwned=1</script>"
	html, err := EmitEvidenceGraphHTML(map[string]interface{}{"payload": payload}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(html, payload) || !strings.Contains(html, `\u003c/script\u003e`) {
		t.Fatal("bundle content can break out of its script element")
	}
}

// A page that fills every optional slot, including a module with stylesheet
// pins, must equal the TypeScript emitter's byte for byte.
// ts/test/emitter-csp.test.ts writes and checks the same golden.
func TestEmitWithModuleStylesMatchesTypeScript(t *testing.T) {
	module := "window.moduleRan=true;"
	got, err := EmitEvidenceGraphHTMLWithOptions(loadWeekBundle(t), []byte("/*IIFE_MARKER*/"), Options{
		Title:             "Module styles",
		ThemeCSS:          ":root{--aac-accent:#123456}",
		CoreRuntimeSHA256: hexPinOf("/*IIFE_MARKER*/"),
		Modules: []Module{{
			Code:        []byte(module),
			SHA256:      hexPinOf(module),
			StyleSHA256: []string{hexPinOf(".m{color:red}"), hexPinOf(".n{color:blue}")},
		}},
		Bootstrap: "window.booted=true;",
	})
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "expected-module-styles.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal([]byte(got), want) {
		t.Fatal("Go HTML with module styles differs from TypeScript HTML")
	}
}
