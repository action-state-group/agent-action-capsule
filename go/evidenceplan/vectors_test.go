// SPDX-License-Identifier: BSD-3-Clause

package evidenceplan

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const vectorsDir = "../../vectors/evidence-dataset"

type vectorCase struct {
	Name   string `json:"name"`
	Expect string `json:"expect"`
	Base   string `json:"base"`
}

func loadPart(t *testing.T, name, part string) interface{} {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorsDir, name+"."+part+".json"))
	require.NoError(t, err)
	value, err := Decode(raw)
	require.NoError(t, err)
	return value
}

func cases(t *testing.T) []vectorCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorsDir, "cases.json"))
	require.NoError(t, err)
	var out []vectorCase
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

// TestVectorsParity refuses every negative with the reason the Python
// reference gives, and accepts every positive.
func TestVectorsParity(t *testing.T) {
	reasons := map[string]bool{}
	positives := 0
	for _, c := range cases(t) {
		err := CheckDataset(loadPart(t, c.Name, "plan"), loadPart(t, c.Name, "dataset"), loadPart(t, c.Name, "records"))
		if c.Expect == "valid" {
			positives++
			assert.NoError(t, err, c.Name)
			continue
		}
		var refused *Error
		if assert.True(t, errors.As(err, &refused), "%s: %v", c.Name, err) {
			assert.Equal(t, Reason(c.Expect), refused.Reason, "%s: %v", c.Name, err)
		}
		reasons[c.Expect] = true
	}
	assert.Equal(t, 5, positives)
	for _, r := range []Reason{PlanInvalid, PlanShape, DatasetInvalid, PlanRefMismatch, RecordsInvalid, FieldMissing, FieldType, RowsMismatch} {
		assert.True(t, reasons[string(r)], "no vector refuses with %s", r)
	}
}

// TestBuildReproducesThePositives: Build over a positive's plan and records
// gives its committed dataset, whose digest a Result's dataset_ref names.
func TestBuildReproducesThePositives(t *testing.T) {
	for _, c := range cases(t) {
		if c.Expect != "valid" {
			continue
		}
		built, err := Build(loadPart(t, c.Name, "plan"), loadPart(t, c.Name, "records"))
		require.NoError(t, err, c.Name)
		want, err := canonical.JSONDigest(loadPart(t, c.Name, "dataset"))
		require.NoError(t, err)
		got, err := canonical.JSONDigest(built)
		require.NoError(t, err)
		assert.Equal(t, want, got, c.Name)
	}
}

func TestRunSelectsInLogOrder(t *testing.T) {
	rows, err := Run(loadPart(t, "pos-window-and-exclusion", "plan"), loadPart(t, "pos-window-and-exclusion", "records"))
	require.NoError(t, err)
	var seqs []uint64
	for _, r := range rows {
		seqs = append(seqs, r.Seq)
	}
	// seq 2 and 5 are runs, 3 and 6 events; see generate_dataset_examples.py.
	assert.Equal(t, []uint64{2, 3, 5, 6}, seqs)
}

func TestSchemaIsTheRepositorys(t *testing.T) {
	want, err := os.ReadFile("../../schemas/evidence-plan-ir-v0.json")
	require.NoError(t, err)
	require.Equal(t, string(want), string(schemaBytes), "go/evidenceplan/evidence-plan-ir-v0.json must be a byte copy of schemas/evidence-plan-ir-v0.json")
}
