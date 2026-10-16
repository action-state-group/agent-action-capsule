// SPDX-License-Identifier: BSD-3-Clause
package settlement_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/settlement"
	"github.com/stretchr/testify/require"
)

func vectorDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "vectors", "settlement")
}

func decode(t *testing.T, path string, into interface{}) {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	require.NoError(t, decoder.Decode(into))
}

type vectorCase struct {
	ID        string                 `json:"id"`
	KeyPolicy map[string]interface{} `json:"key_policy"`
	Records   []struct {
		Label       string                 `json:"label"`
		Capsule     map[string]interface{} `json:"capsule"`
		CapsuleID   *string                `json:"capsule_id"`
		EnvelopeHex string                 `json:"envelope_hex"`
		EnvelopeKid string                 `json:"envelope_kid"`
	} `json:"records"`
	WrappedObjects []struct {
		Digest     string `json:"digest"`
		OctetsB64U string `json:"octets_b64u"`
	} `json:"wrapped_objects"`
	Expect json.RawMessage `json:"expect"`
}

// run maps a case to a Verify call the way python/tests/test_settlement_library.py
// does: each leg carries its envelope as signature/key_id, and capsule IDs in
// the report are mapped back to the case's labels. iso20022 is not carried by
// the vectors. mutate, when set, edits the capsule list before the call.
func run(t *testing.T, c vectorCase, mutate func([]interface{}) []interface{}) map[string]interface{} {
	labels := map[string]string{}
	input := settlement.Input{WrappedObjects: map[string][]byte{}}
	if c.KeyPolicy != nil {
		// A role's keys are one hex key or a list of them.
		input.KeyPolicy = map[string][]string{}
		for role, keys := range c.KeyPolicy {
			switch keys := keys.(type) {
			case string:
				input.KeyPolicy[role] = []string{keys}
			case []interface{}:
				for _, key := range keys {
					input.KeyPolicy[role] = append(input.KeyPolicy[role], key.(string))
				}
			}
		}
	}
	for _, r := range c.Records {
		capsule := map[string]interface{}{}
		for name, value := range r.Capsule {
			capsule[name] = value
		}
		if r.EnvelopeHex != "" {
			capsule["signature"] = r.EnvelopeHex
			capsule["key_id"] = r.EnvelopeKid
		}
		input.Capsules = append(input.Capsules, capsule)
		// A leg that cannot be canonicalized has a null capsule_id, which
		// the report names as nil.
		labels[idKey(r.CapsuleID)] = r.Label
	}
	for _, w := range c.WrappedObjects {
		octets, err := base64.RawURLEncoding.DecodeString(w.OctetsB64U)
		require.NoError(t, err)
		input.WrappedObjects[w.Digest] = octets
	}
	if mutate != nil {
		input.Capsules = mutate(input.Capsules)
	}
	report := settlement.Verify(input)
	relabel := func(entries []settlement.Entry) []settlement.Entry {
		out := []settlement.Entry{}
		for _, entry := range entries {
			records := make([]*string, len(entry.Records))
			for i, id := range entry.Records {
				if label, found := labels[idKey(id)]; found {
					records[i] = &label
				} else {
					records[i] = id
				}
			}
			out = append(out, settlement.Entry{Records: records, Code: entry.Code})
		}
		return out
	}
	settlements := []settlement.Settlement{}
	for _, s := range report.Settlements {
		s.Terms = labels[s.Terms]
		s.ISO20022 = nil
		settlements = append(settlements, s)
	}
	data, err := json.Marshal(map[string]interface{}{
		"conforming": report.Conforming, "failures": relabel(report.Failures),
		"findings": relabel(report.Findings), "settlements": settlements,
	})
	require.NoError(t, err)
	var observed map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &observed))
	return observed
}

func idKey(id *string) string {
	if id == nil {
		return "\x00null"
	}
	return *id
}

func TestSettlementVectors(t *testing.T) {
	var file struct {
		Count int          `json:"count"`
		Cases []vectorCase `json:"cases"`
	}
	decode(t, filepath.Join(vectorDir(), "cases.json"), &file)
	require.Equal(t, file.Count, len(file.Cases))
	require.Equal(t, 19, len(file.Cases))
	for _, c := range file.Cases {
		t.Run(c.ID, func(t *testing.T) {
			var expect map[string]interface{}
			require.NoError(t, json.Unmarshal(c.Expect, &expect))
			require.Equal(t, expect, run(t, c, nil))
		})
	}
}

// A leg nested far deeper than any JSON text, built in Go, is capsule_invalid
// and takes no part: the legs before and after it are read as before.
func TestLegNestedTooDeeplyIsRefused(t *testing.T) {
	var file struct {
		Cases []vectorCase `json:"cases"`
	}
	decode(t, filepath.Join(vectorDir(), "cases.json"), &file)
	c := file.Cases[0]
	require.Equal(t, "pos-x402-two-sided-agreed", c.ID)

	var deep interface{} = "leaf"
	for range 2_000_000 {
		deep = []interface{}{deep}
	}
	deepID := strings.Repeat("d", 64)
	observed := run(t, c, func(capsules []interface{}) []interface{} {
		out := append([]interface{}{map[string]interface{}{"capsule_id": deepID, "action_id": deep}}, capsules[:1]...)
		out = append(out, map[string]interface{}{"capsule_id": json.Number("1"), "action_id": deep})
		return append(out, capsules[1:]...)
	})

	var expect map[string]interface{}
	require.NoError(t, json.Unmarshal(c.Expect, &expect))
	expect["conforming"] = false
	expect["failures"] = []interface{}{
		map[string]interface{}{"records": []interface{}{deepID}, "code": "capsule_invalid"},
		map[string]interface{}{"records": []interface{}{nil}, "code": "capsule_invalid"},
	}
	require.Equal(t, expect, observed)
}

func TestTablesMatchTheDraftRegistry(t *testing.T) {
	var registry struct {
		Version            string            `json:"settlement_version"`
		Legs               []string          `json:"legs"`
		Roles              []string          `json:"sealer_roles"`
		Statuses           []string          `json:"statuses"`
		DeliveryDirections map[string]string `json:"delivery_directions"`
		WrappedTypes       map[string]string `json:"wrapped_types"`
		PaymentRefTypes    map[string]struct {
			Qualifiers []string `json:"qualifiers"`
			ReceiveFee string   `json:"receive_fee"`
		} `json:"payment_ref_types"`
		Members map[string]struct {
			Required []string `json:"required"`
			Optional []string `json:"optional"`
		} `json:"settlement_members"`
	}
	decode(t, filepath.Join(vectorDir(), "registry.json"), &registry)
	require.Equal(t, registry.Version, settlement.Version)
	require.Equal(t, registry.Legs, settlement.Legs)
	require.Equal(t, registry.Roles, settlement.Roles)
	require.Equal(t, registry.Statuses, settlement.Statuses)
	require.Equal(t, registry.DeliveryDirections, settlement.DeliveryDirections)
	require.Equal(t, registry.WrappedTypes, settlement.WrappedTypes)
	require.Len(t, settlement.PaymentRefTypes, len(registry.PaymentRefTypes))
	for name, want := range registry.PaymentRefTypes {
		got, found := settlement.PaymentRefTypes[name]
		require.True(t, found, name)
		require.Equal(t, len(want.Qualifiers), len(got.Qualifiers), name)
		if len(want.Qualifiers) != 0 {
			require.Equal(t, want.Qualifiers, got.Qualifiers, name)
		}
		require.Equal(t, want.ReceiveFee, got.ReceiveFee, name)
	}
	require.Len(t, settlement.Members, len(registry.Members))
	for name, want := range registry.Members {
		got := settlement.Members[name]
		require.Equal(t, want.Required, got.Required, name)
		require.Equal(t, want.Optional, got.Optional, name)
	}
}
