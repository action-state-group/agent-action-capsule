// SPDX-License-Identifier: BSD-3-Clause
// Go second-runtime conformance vector runner.
//
// Loads test-vectors/vectors.json and asserts every case (positive, negative,
// store-level) against the same frozen expected.json manifest the Python runner
// uses. No shared code paths with the Python implementation: this is an
// independent clean-room verification.
//
// Exit 0 iff all vectors pass. Prints a per-vector PASS/FAIL report and a
// summary line suitable for inclusion in CI logs.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/action-state-group/agent-action-capsule/go/registries"
	"github.com/action-state-group/agent-action-capsule/go/verify"
)

func main() {
	vectorsDir := flag.String("vectors-dir", "", "path to test-vectors/ directory (default: auto-locate)")
	registryPath := flag.String("registry", "", "path to spec/REGISTRY.md (default: AAC_REGISTRY_PATH or auto-locate)")
	flag.Parse()

	vdir, err := resolveVectorsDir(*vectorsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if *registryPath != "" {
		os.Setenv("AAC_REGISTRY_PATH", *registryPath)
	}

	regs, err := registries.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading registries: %v\n", err)
		os.Exit(1)
	}

	manifest, err := loadManifest(filepath.Join(vdir, "vectors.json"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading manifest: %v\n", err)
		os.Exit(1)
	}

	total, pass, fail := 0, 0, 0
	for _, cas := range manifest.Cases {
		name := cas.Name
		total++
		err := runCase(vdir, name, regs)
		if err != nil {
			fmt.Printf("FAIL  %s: %v\n", name, err)
			fail++
		} else {
			fmt.Printf("PASS  %s\n", name)
			pass++
		}
	}

	fmt.Printf("\n--- Go runtime: %d/%d vectors pass, %d fail ---\n", pass, total, fail)
	if fail > 0 {
		os.Exit(1)
	}
}

// manifest is the shape of vectors.json.
type manifest struct {
	Count int    `json:"count"`
	Cases []struct {
		Name string `json:"name"`
		Kind string `json:"kind"`
	} `json:"cases"`
}

func loadManifest(path string) (*manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading vectors.json: %w", err)
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing vectors.json: %w", err)
	}
	return &m, nil
}

// expectedSingle is the shape of a single-capsule expected.json.
type expectedSingle struct {
	OK                bool                   `json:"ok"`
	Derived           map[string]string      `json:"derived"`
	CapsuleIDRecomputed *string              `json:"capsule_id_recomputed"`
	Findings          []expectedFinding      `json:"findings"`
}

// expectedStore is the shape of a store-level expected.json.
type expectedStore struct {
	Results []expectedSingle `json:"results"`
}

type expectedFinding struct {
	Check    *int   `json:"check"`
	Severity string `json:"severity"`
	Code     string `json:"code"`
}

func runCase(vdir, name string, regs map[string]map[string]bool) error {
	caseDir := filepath.Join(vdir, name)

	inputData, err := os.ReadFile(filepath.Join(caseDir, "input.json"))
	if err != nil {
		return fmt.Errorf("reading input.json: %w", err)
	}
	expectedData, err := os.ReadFile(filepath.Join(caseDir, "expected.json"))
	if err != nil {
		return fmt.Errorf("reading expected.json: %w", err)
	}

	input, err := decodeWithNumbers(inputData)
	if err != nil {
		return fmt.Errorf("decoding input.json: %w", err)
	}

	// Dispatch: store (has "ledger" key) vs single capsule.
	if inputMap, ok := input.(map[string]interface{}); ok {
		if ledger, hasLedger := inputMap["ledger"]; hasLedger {
			return runStoreCase(ledger, expectedData, regs)
		}
	}
	return runSingleCase(input, expectedData, regs)
}

func runSingleCase(input interface{}, expectedData []byte, regs map[string]map[string]bool) error {
	var exp expectedSingle
	if err := json.Unmarshal(expectedData, &exp); err != nil {
		return fmt.Errorf("parsing expected.json: %w", err)
	}

	res := verify.Verify(input, nil, regs)
	return assertSingle(res, exp)
}

func runStoreCase(ledgerRaw interface{}, expectedData []byte, regs map[string]map[string]bool) error {
	var expStore expectedStore
	if err := json.Unmarshal(expectedData, &expStore); err != nil {
		return fmt.Errorf("parsing expected.json (store): %w", err)
	}

	ledger, ok := ledgerRaw.([]interface{})
	if !ok {
		return fmt.Errorf("ledger is not an array")
	}

	results := verify.VerifyStore(ledger, regs)
	if len(results) != len(expStore.Results) {
		return fmt.Errorf("result count mismatch: got %d, expected %d", len(results), len(expStore.Results))
	}
	for i, res := range results {
		if err := assertSingle(res, expStore.Results[i]); err != nil {
			return fmt.Errorf("capsule[%d]: %w", i, err)
		}
	}
	return nil
}

func assertSingle(res verify.VerificationResult, exp expectedSingle) error {
	var errs []string

	if res.OK != exp.OK {
		errs = append(errs, fmt.Sprintf("ok: got %v, expected %v", res.OK, exp.OK))
	}

	// Compare derived assurance.
	if len(res.Assurance) != len(exp.Derived) {
		errs = append(errs, fmt.Sprintf("assurance key count: got %d, expected %d", len(res.Assurance), len(exp.Derived)))
	} else {
		for k, v := range exp.Derived {
			if res.Assurance[k] != v {
				errs = append(errs, fmt.Sprintf("assurance.%s: got %q, expected %q", k, res.Assurance[k], v))
			}
		}
	}

	// Compare capsule_id_recomputed.
	switch {
	case res.CapsuleID == nil && exp.CapsuleIDRecomputed != nil:
		errs = append(errs, fmt.Sprintf("capsule_id_recomputed: got null, expected %q", *exp.CapsuleIDRecomputed))
	case res.CapsuleID != nil && exp.CapsuleIDRecomputed == nil:
		errs = append(errs, fmt.Sprintf("capsule_id_recomputed: got %q, expected null", *res.CapsuleID))
	case res.CapsuleID != nil && exp.CapsuleIDRecomputed != nil && *res.CapsuleID != *exp.CapsuleIDRecomputed:
		errs = append(errs, fmt.Sprintf("capsule_id_recomputed: got %q, expected %q", *res.CapsuleID, *exp.CapsuleIDRecomputed))
	}

	// Compare findings as (check, severity, code) tuples in order.
	got := findingKeys(res.Findings)
	want := expectedFindingKeys(exp.Findings)
	if !stringSliceEqual(got, want) {
		errs = append(errs, fmt.Sprintf("findings mismatch:\n  got:  %v\n  want: %v", got, want))
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// findingKey returns a canonical (check,severity,code) string for a Finding.
func findingKey(f verify.Finding) string {
	check := "null"
	if f.Check != nil {
		check = fmt.Sprintf("%d", *f.Check)
	}
	return fmt.Sprintf("(%s,%s,%s)", check, f.Severity, f.Code)
}

func findingKeys(fs []verify.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = findingKey(f)
	}
	return out
}

func expectedFindingKeys(fs []expectedFinding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		check := "null"
		if f.Check != nil {
			check = fmt.Sprintf("%d", *f.Check)
		}
		out[i] = fmt.Sprintf("(%s,%s,%s)", check, f.Severity, f.Code)
	}
	return out
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// decodeWithNumbers decodes JSON preserving integers as json.Number (not float64).
func decodeWithNumbers(data []byte) (interface{}, error) {
	var v interface{}
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// resolveVectorsDir finds the test-vectors/ directory.
// Prefers the flag value, then walks up from CWD looking for test-vectors/vectors.json.
func resolveVectorsDir(flagVal string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	// Check env var.
	if env := os.Getenv("AAC_VECTORS_DIR"); env != "" {
		return env, nil
	}
	// Walk up from CWD.
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := cwd
	for {
		candidate := filepath.Join(dir, "test-vectors", "vectors.json")
		if _, err := os.Stat(candidate); err == nil {
			return filepath.Join(dir, "test-vectors"), nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("test-vectors/vectors.json not found walking up from %s; set AAC_VECTORS_DIR", cwd)
}
