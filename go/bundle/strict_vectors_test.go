// SPDX-License-Identifier: BSD-3-Clause
package bundle_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/bundle"
	"github.com/action-state-group/agent-action-capsule/go/envelope"
	"github.com/action-state-group/agent-action-capsule/go/witness"
	"github.com/stretchr/testify/require"
)

type strictVectors struct {
	WitnessDirectory interface{} `json:"witness_directory"`
	Cases            []struct {
		ID      string `json:"id"`
		Options struct {
			RequireSignature bool `json:"require_signature"`
			WitnessDirectory bool `json:"witness_directory"`
		} `json:"options"`
		Bundle interface{}            `json:"bundle"`
		Expect map[string]interface{} `json:"expect"`
	} `json:"cases"`
	RecordSignatures []struct {
		ID     string      `json:"id"`
		Record interface{} `json:"record"`
		Expect string      `json:"expect"`
	} `json:"record_signatures"`
}

func loadStrictVectors(t *testing.T) strictVectors {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "vectors", "bundle", "strict", "vectors.json"))
	require.NoError(t, err)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var vectors strictVectors
	require.NoError(t, decoder.Decode(&vectors))
	return vectors
}

// observed renders a strict result in the vectors' expect shape, so the
// comparison covers exactly what the README lists.
func observed(result bundle.StrictResult) map[string]interface{} {
	claims := []interface{}{}
	for _, claim := range result.Claims {
		claims = append(claims, map[string]interface{}{"name": claim.Name, "status": claim.Status, "findings": strings(claim.Findings)})
	}
	var witnesses interface{}
	if result.Witnesses != nil {
		receipts := []interface{}{}
		for _, receipt := range result.WitnessReceipts {
			var grade interface{}
			if receipt.Grade != nil {
				grade = *receipt.Grade
			}
			receipts = append(receipts, map[string]interface{}{"ts_url": receipt.TSURL, "binding": receipt.Binding, "status": receipt.Status, "grade": grade})
		}
		witnesses = map[string]interface{}{"status": result.Witnesses.Status, "findings": strings(result.Witnesses.Findings), "receipts": receipts}
	}
	records := []interface{}{}
	for _, record := range result.Records {
		var keyID, seq interface{}
		if record.KeyID != nil {
			keyID = *record.KeyID
		}
		if record.Seq != nil {
			seq = json.Number(jsonInt(*record.Seq))
		}
		records = append(records, map[string]interface{}{
			"capsule_id": record.CapsuleID, "identity_ok": record.IdentityOK, "signature": record.Signature,
			"key_id": keyID, "seq": seq,
		})
	}
	var signerMatches interface{}
	if result.SignerMatchesCheckpoint != nil {
		signerMatches = *result.SignerMatchesCheckpoint
	}
	return map[string]interface{}{
		"verdict":                   result.Verdict,
		"kind_ok":                   result.KindOK,
		"claims":                    claims,
		"witnesses":                 witnesses,
		"records":                   records,
		"checkpoint_authenticated":  result.SignedCheckpoint != nil,
		"signer_matches_checkpoint": signerMatches,
	}
}

func strings(values []string) []interface{} {
	out := []interface{}{}
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

func jsonInt(value int64) string {
	data, _ := json.Marshal(value)
	return string(data)
}

func TestStrictVectors(t *testing.T) {
	vectors := loadStrictVectors(t)
	require.NotEmpty(t, vectors.Cases)
	directory := witness.DirectoryFromValue(vectors.WitnessDirectory)
	for _, testCase := range vectors.Cases {
		t.Run(testCase.ID, func(t *testing.T) {
			opts := bundle.StrictOptions{RequireSignature: testCase.Options.RequireSignature}
			if testCase.Options.WitnessDirectory {
				opts.WitnessDirectory = &directory
			}
			expect := map[string]interface{}{"kind_ok": true}
			for name, value := range testCase.Expect {
				expect[name] = value
			}
			require.Equal(t, expect, observed(bundle.VerifyStrict(testCase.Bundle, opts)))
		})
	}
}

func TestStrictRecordSignatureVectors(t *testing.T) {
	vectors := loadStrictVectors(t)
	require.NotEmpty(t, vectors.RecordSignatures)
	for _, testCase := range vectors.RecordSignatures {
		t.Run(testCase.ID, func(t *testing.T) {
			verdict, messages := envelope.VerifyRecordSignature(testCase.Record)
			require.Equal(t, testCase.Expect, verdict)
			require.Equal(t, verdict == envelope.Invalid, len(messages) != 0)
		})
	}
}

func TestStrictRefusesANonObject(t *testing.T) {
	for _, value := range []interface{}{[]interface{}{json.Number("1")}, nil, "bundle"} {
		result := bundle.VerifyStrict(value, bundle.StrictOptions{})
		require.False(t, result.KindOK)
		require.Equal(t, bundle.VerdictInvalid, result.Verdict)
		require.Equal(t, []bundle.NamedClaim{{Name: "records", ClaimResult: bundle.ClaimResult{Status: "fail", Findings: []string{"not_an_evidence_bundle_v2"}}}}, result.Claims)
		require.Nil(t, result.Witnesses)
	}
}

func TestStrictKeepsThePlainResult(t *testing.T) {
	vectors := loadStrictVectors(t)
	value := vectors.Cases[0].Bundle
	plain := bundle.VerifyBundle(value)
	strict := bundle.VerifyStrict(value, bundle.StrictOptions{})
	require.Equal(t, plain.GraphClosure, strict.GraphClosure)
	require.Equal(t, plain.BundleDigest, strict.BundleDigest)
	require.Equal(t, "pass", strict.Claim("checkpoint").Status)
	require.Nil(t, strict.Claim("disclosures"))
	require.NotNil(t, strict.SignedCheckpoint)
}
