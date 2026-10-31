// SPDX-License-Identifier: BSD-3-Clause
package bundle_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/bundle"
	"github.com/action-state-group/agent-action-capsule/go/canonical"
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
			receipts = append(receipts, map[string]interface{}{
				"ts_url": receipt.TSURL, "binding": receipt.Binding, "status": receipt.Status, "grade": grade,
				"key_id": keyID, "registration_time": registrationTime, "registration_time_reason": registrationTimeReason,
			})
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

// checkpointClaimWith runs the base VALID case with checkpoint.prev_size
// replaced by raw JSON text, decoded with or without UseNumber.
func checkpointClaimWith(t *testing.T, prevSize string, useNumber bool) *bundle.ClaimResult {
	t.Helper()
	vectors := loadStrictVectors(t)
	data, err := json.Marshal(vectors.Cases[0].Bundle)
	require.NoError(t, err)
	var value map[string]interface{}
	if useNumber {
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		require.NoError(t, decoder.Decode(&value))
	} else {
		require.NoError(t, json.Unmarshal(data, &value))
	}
	var replacement interface{}
	decoder := json.NewDecoder(bytes.NewReader([]byte(prevSize)))
	if useNumber {
		decoder.UseNumber()
	}
	require.NoError(t, decoder.Decode(&replacement))
	value["checkpoint"].(map[string]interface{})["prev_size"] = replacement
	return bundle.VerifyStrict(value, bundle.StrictOptions{}).Claim("checkpoint")
}

func TestCheckpointIntegerFieldsRefuseFloats(t *testing.T) {
	require.Equal(t, "pass", checkpointClaimWith(t, "0", true).Status)
	for _, text := range []string{"0.0", "0e0", "0E0", "-0.0", "false", `"0"`} {
		claim := checkpointClaimWith(t, text, true)
		require.Equal(t, "fail", claim.Status, text)
		require.Contains(t, claim.Findings, "checkpoint_field_mismatch:prev_size", text)
	}
	// Standard encoding/json decodes 0.0 and 0 alike to float64, so a float
	// never matches the signed integer; strict callers decode with UseNumber.
	claim := checkpointClaimWith(t, "0.0", false)
	require.Equal(t, "fail", claim.Status)
	require.Contains(t, claim.Findings, "checkpoint_field_mismatch:prev_size")
	require.Contains(t, claim.Findings, "checkpoint_field_mismatch:mmr_size")
}

// nested builds a value n arrays deep around a string.
func nested(n int) interface{} {
	var value interface{} = "leaf"
	for range n {
		value = []interface{}{value}
	}
	return value
}

func TestStrictRefusesValuesNestedTooDeeply(t *testing.T) {
	vectors := loadStrictVectors(t)
	data, err := json.Marshal(vectors.Cases[0].Bundle)
	require.NoError(t, err)
	var value map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	require.NoError(t, decoder.Decode(&value))

	// Far beyond any JSON text, built in Go: refused, not a stack overflow.
	value["extensions"] = map[string]interface{}{"x": nested(2_000_000)}
	result := bundle.VerifyStrict(value, bundle.StrictOptions{})
	require.Equal(t, bundle.VerdictInvalid, result.Verdict)
	require.False(t, result.KindOK)
	malformed := bundle.ClaimResult{Status: "fail", Findings: []string{"bundle_malformed"}}
	require.Equal(t, []bundle.NamedClaim{{Name: "records", ClaimResult: malformed}}, result.Claims)
	require.Equal(t, malformed, result.GraphClosure)

	record := vectors.RecordSignatures[0].Record.(map[string]interface{})
	deep := map[string]interface{}{}
	for name, member := range record {
		deep[name] = member
	}
	deep["action_id"] = nested(2_000_000)
	verdict, messages := envelope.VerifyRecordSignature(deep)
	require.Equal(t, envelope.Invalid, verdict)
	require.NotEmpty(t, messages)
}

// A Bundle nested one level past canonical.MaxNestingDepth is malformed in
// plain and strict mode, as in Python, TypeScript and Rust; one at the limit
// is verified as usual (vectors/json-nesting/).
func TestBundleNestingLimit(t *testing.T) {
	vectors := loadStrictVectors(t)
	data, err := json.Marshal(vectors.Cases[0].Bundle)
	require.NoError(t, err)
	isMalformed := func(c bundle.ClaimResult) bool {
		return c.Status == "fail" && len(c.Findings) == 1 && c.Findings[0] == "bundle_malformed"
	}
	// The Bundle, extensions and x are two levels around x's arrays.
	for arrays, tooDeep := range map[int]bool{canonical.MaxNestingDepth - 2: false, canonical.MaxNestingDepth - 1: true} {
		var value map[string]interface{}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		require.NoError(t, decoder.Decode(&value))
		value["extensions"] = map[string]interface{}{"x": nested(arrays)}
		plain := bundle.VerifyBundle(value)
		strict := bundle.VerifyStrict(value, bundle.StrictOptions{})
		require.Equal(t, tooDeep, isMalformed(plain.GraphClosure), "plain, %d arrays", arrays)
		require.Equal(t, tooDeep, isMalformed(plain.IntervalCoverage), "plain, %d arrays", arrays)
		require.Equal(t, tooDeep, isMalformed(strict.GraphClosure), "strict, %d arrays", arrays)
	}
}

// VerifyCheckpoint is VerifyStrict's checkpoint claim on its own: on every
// strict case it gives the same claim and authenticated checkpoint, and on a
// pass the COSE bytes it returns are the Bundle's checkpoint.cose.
func TestVerifyCheckpointIsTheStrictCheckpointClaim(t *testing.T) {
	for _, c := range loadStrictVectors(t).Cases {
		value, isObject := c.Bundle.(map[string]interface{})
		if !isObject {
			continue
		}
		strict := bundle.VerifyStrict(value, bundle.StrictOptions{})
		claim, signed, cose := bundle.VerifyCheckpoint(value)
		if strict.Claim("checkpoint") == nil {
			continue
		}
		require.Equal(t, *strict.Claim("checkpoint"), claim, c.ID)
		require.Equal(t, strict.SignedCheckpoint, signed, c.ID)
		if claim.Status != "pass" {
			require.Nil(t, cose, c.ID)
			continue
		}
		stated := value["checkpoint"].(map[string]interface{})
		encoded, err := base64.RawURLEncoding.DecodeString(stated["cose"].(string))
		require.NoError(t, err, c.ID)
		require.Equal(t, encoded, cose, c.ID)
	}
}
