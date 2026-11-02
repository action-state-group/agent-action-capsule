// SPDX-License-Identifier: BSD-3-Clause
package bundle_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/bundle"
	"github.com/action-state-group/agent-action-capsule/go/witness"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type parentWitnessVectors struct {
	WitnessDirectory interface{} `json:"witness_directory"`
	Cases            []struct {
		ID      string `json:"id"`
		Options struct {
			WitnessDirectory bool `json:"witness_directory"`
		} `json:"options"`
		Bundle interface{}            `json:"bundle"`
		Expect map[string]interface{} `json:"expect"`
	} `json:"cases"`
}

func loadParentWitnessVectors(t *testing.T) parentWitnessVectors {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "vectors", "bundle", "parent-log-witness", "vectors.json"))
	require.NoError(t, err)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var vectors parentWitnessVectors
	require.NoError(t, decoder.Decode(&vectors))
	return vectors
}

// receiptsObserved renders receipts in the strict vectors' receipt shape.
func receiptsObserved(receipts []witness.ReceiptResult) []interface{} {
	out := []interface{}{}
	for _, receipt := range receipts {
		var grade, keyID, registrationTime, registrationTimeReason interface{}
		if receipt.Grade != nil {
			grade = *receipt.Grade
		}
		if receipt.KeyID != nil {
			keyID = *receipt.KeyID
		}
		if receipt.RegistrationTime != nil {
			registrationTime = json.Number(jsonInt(*receipt.RegistrationTime))
		}
		if receipt.RegistrationTimeReason != nil {
			registrationTimeReason = *receipt.RegistrationTimeReason
		}
		out = append(out, map[string]interface{}{
			"ts_url": receipt.TSURL, "binding": receipt.Binding, "status": receipt.Status, "grade": grade,
			"key_id": keyID, "registration_time": registrationTime, "registration_time_reason": registrationTimeReason,
		})
	}
	return out
}

func parentWitnessObserved(result *bundle.ParentWitnessResult) interface{} {
	if result == nil {
		return nil
	}
	var extent interface{}
	if result.Extent != nil {
		extent = map[string]interface{}{
			"entries": json.Number(strconv.FormatUint(result.Extent.Entries, 10)),
			"of":      json.Number(strconv.FormatUint(result.Extent.Of, 10)),
		}
	}
	return map[string]interface{}{
		"status": result.Status, "findings": strings(result.Findings), "extent": extent,
		"receipts": receiptsObserved(result.Receipts),
	}
}

func TestParentWitnessVectors(t *testing.T) {
	vectors := loadParentWitnessVectors(t)
	require.Len(t, vectors.Cases, 36)
	directory := witness.DirectoryFromValue(vectors.WitnessDirectory)
	for _, testCase := range vectors.Cases {
		t.Run(testCase.ID, func(t *testing.T) {
			opts := bundle.StrictOptions{}
			if testCase.Options.WitnessDirectory {
				opts.WitnessDirectory = &directory
			}
			result := bundle.VerifyStrict(testCase.Bundle, opts)
			assert.Equal(t, testCase.Expect["verdict"], result.Verdict)
			expected, present := testCase.Expect["parent_witness"]
			require.True(t, present, "every case states parent_witness")
			assert.Equal(t, expected, parentWitnessObserved(result.ParentWitness))
			if want, given := testCase.Expect["extension_status"]; given {
				var status interface{}
				for _, extension := range result.Extensions {
					if extension.Kind == bundle.ParentLogWitnessKind {
						status = extension.Status
					}
				}
				assert.Equal(t, want, status)
			}
			if want, given := testCase.Expect["witnesses"]; given {
				require.NotNil(t, result.Witnesses)
				assert.Equal(t, want, map[string]interface{}{
					"status": result.Witnesses.Status, "findings": strings(result.Witnesses.Findings),
				})
			}
		})
	}
}

// Plain verification leaves the kind uninterpreted, as for any extension it
// does not implement.
func TestParentWitnessPlainModeUninterpreted(t *testing.T) {
	vectors := loadParentWitnessVectors(t)
	checked := 0
	for _, testCase := range vectors.Cases {
		bundleValue, _ := testCase.Bundle.(map[string]interface{})
		extensions, _ := bundleValue["extensions"].(map[string]interface{})
		if _, present := extensions[bundle.ParentLogWitnessKind]; !present {
			continue
		}
		checked++
		for _, extension := range bundle.VerifyBundle(testCase.Bundle).Extensions {
			if extension.Kind == bundle.ParentLogWitnessKind {
				assert.Equal(t, "uninterpreted", extension.Status, testCase.ID)
			}
		}
	}
	assert.NotZero(t, checked)
}

func TestParentWitnessWithheldWithoutSignedCheckpoint(t *testing.T) {
	result := bundle.VerifyParentLogWitness(map[string]interface{}{}, nil, nil, witness.Directory{})
	assert.Equal(t, "withheld", result.Status)
	assert.Equal(t, []string{"checkpoint_unverified"}, result.Findings)
	assert.Nil(t, result.Extent)
}
