// SPDX-License-Identifier: BSD-3-Clause
package bundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/stretchr/testify/require"
)

type bindingCase struct {
	ID                 string                   `json:"id"`
	Container          map[string]interface{}   `json:"container"`
	ControllerBindings []map[string]interface{} `json:"controller_bindings"`
	BindingRevocations []map[string]interface{} `json:"binding_revocations"`
	Expect             map[string]interface{}   `json:"expect"`
}

// bindingCases reads vectors/bundle/composed-controller-binding/vectors.json.
func bindingCases(t *testing.T) map[string]bindingCase {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "vectors", "bundle", "composed-controller-binding", "vectors.json"))
	require.NoError(t, err)
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	var file struct {
		Count json.Number   `json:"count"`
		Cases []bindingCase `json:"cases"`
	}
	require.NoError(t, decoder.Decode(&file))
	require.Equal(t, json.Number("14"), file.Count)
	cases := map[string]bindingCase{}
	for _, c := range file.Cases {
		cases[c.ID] = c
	}
	require.Len(t, cases, 14)
	return cases
}

func bindingOptions(c bindingCase) Options {
	return Options{ControllerBindings: c.ControllerBindings, BindingRevocations: c.BindingRevocations}
}

func TestComposedControllerBindingVectors(t *testing.T) {
	for id, c := range bindingCases(t) {
		c := c
		t.Run(id, func(t *testing.T) {
			block := composedBlockOf(c.Container)
			preimage, err := ComposedDigestPreimage(block)
			require.NoError(t, err)
			require.Equal(t, c.Expect["canonical_preimage"], string(preimage))

			composed := verifyBlock(t, c.Container, bindingOptions(c))
			require.Equal(t, c.Expect["status"], composed.Status, composed.Findings)
			want := map[string]interface{}{}
			for key, value := range c.Expect {
				if key != "canonical_preimage" {
					want[key] = value
				}
			}
			require.Equal(t, want, expectShape(composed))
		})
	}
}

// Without the delivered records, every controller_binding join is
// not_derivable: the basis never derives from the block alone.
func TestComposedControllerBindingNeedsTheDeliveredRecord(t *testing.T) {
	for id, c := range bindingCases(t) {
		composed := verifyBlock(t, c.Container, Options{})
		require.Equal(t, "not_derivable", composed.Joins[0].Result, id)
		require.Equal(t, "not_applicable", composed.Corroboration[0].Result, id)
	}
}

// A binding the verifier received but cannot read under the join's keys is
// unjoined, never corroborating, whichever way it fails.
func TestComposedControllerBindingFailuresNeverCorroborate(t *testing.T) {
	c := bindingCases(t)["controller-binding-linked"]
	mutations := map[string]func(record map[string]interface{}){
		"second signature from the first key": func(r map[string]interface{}) {
			sigs := r["sigs"].([]interface{})
			sigs[1].(map[string]interface{})["sig"] = sigs[0].(map[string]interface{})["sig"]
		},
		"one signature": func(r map[string]interface{}) { r["sigs"] = r["sigs"].([]interface{})[:1] },
		"third signature": func(r map[string]interface{}) {
			r["sigs"] = append(r["sigs"].([]interface{}), r["sigs"].([]interface{})[0])
		},
		"sigs out of key order": func(r map[string]interface{}) {
			sigs := r["sigs"].([]interface{})
			r["sigs"] = []interface{}{sigs[1], sigs[0]}
		},
	}
	for name, mutate := range mutations {
		record := cloneJSON(t, c.ControllerBindings[0])
		mutate(record)
		composed := verifyBlock(t, c.Container, Options{ControllerBindings: []map[string]interface{}{record}})
		require.Equal(t, "unjoined", composed.Joins[0].Derived, name)
		require.Equal(t, "join_state_mismatch", composed.Joins[0].Result, name)
		require.Equal(t, "not_applicable", composed.Corroboration[0].Result, name)
	}
}

// A revocation statement that does not apply (another binding, a key that is
// not bound, a bad signature, a time after both records) leaves the link.
// Each is signed, so only the condition it names stops it.
func TestComposedControllerBindingRevocationMustApply(t *testing.T) {
	linked := bindingCases(t)["controller-binding-linked"]
	digest := composedBlockOf(linked.Container)["joins"].([]interface{})[0].(map[string]interface{})["identifier_digest"].(string)
	badSignature := signRevocation(t, "responder-b", digest, "2026-10-02T00:00:00Z")
	badSignature["sig"] = strings.Repeat("0", 128)
	statements := map[string]map[string]interface{}{
		"another binding": signRevocation(t, "responder-b", strings.Repeat("0", 64), "2026-10-02T00:00:00Z"),
		"unbound key":     signRevocation(t, "runtime observer", digest, "2026-10-02T00:00:00Z"),
		"bad signature":   badSignature,
		"after both":      signRevocation(t, "responder-b", digest, "2026-10-03T00:00:00Z"),
	}
	for name, statement := range statements {
		composed := verifyBlock(t, linked.Container, Options{
			ControllerBindings: linked.ControllerBindings,
			BindingRevocations: []map[string]interface{}{statement},
		})
		require.Equal(t, "agree", composed.Joins[0].Derived, name)
		require.Equal(t, "redundant", composed.Corroboration[0].Result, name)
	}
}

// A controller_binding join without identifier_digest or pointer names no
// binding record, so it is not derivable, whatever the verifier received.
func TestComposedControllerBindingJoinWithoutDigest(t *testing.T) {
	c := bindingCases(t)["controller-binding-linked"]
	for _, member := range []string{"identifier_digest", "pointer"} {
		container := cloneJSON(t, c.Container)
		block := composedBlockOf(container)
		join := block["joins"].([]interface{})[0].(map[string]interface{})
		delete(join, member)
		join["state"] = "unjoined"
		reseal(t, block)
		composed := verifyBlock(t, container, bindingOptions(c))
		require.Equal(t, "not_derivable", composed.Joins[0].Result, member)
	}
}

func cloneJSON(t *testing.T, value map[string]interface{}) map[string]interface{} {
	t.Helper()
	data, err := json.Marshal(value)
	require.NoError(t, err)
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	var out map[string]interface{}
	require.NoError(t, decoder.Decode(&out))
	return out
}

// A root record's timestamp may carry fractional seconds; the window compares
// instants. The edit breaks the member digest, not the join's derivation.
func TestComposedControllerBindingFractionalRecordTime(t *testing.T) {
	c := bindingCases(t)["controller-binding-linked"]
	for stamp, derived := range map[string]string{
		"2026-10-02T12:10:00.5Z":    "agree",
		"2027-09-30T23:59:59.999Z":  "agree",
		"2027-10-01T00:00:00.0Z":    "unjoined",
		"2026-09-30T23:59:59.9Z":    "unjoined",
		"2026-10-02T12:10:00+00:00": "unjoined",
	} {
		container := cloneJSON(t, c.Container)
		member := composedBlockOf(container)["members"].([]interface{})[0].(map[string]interface{})
		member["bundle"].(map[string]interface{})["records"].([]interface{})[0].(map[string]interface{})["timestamp"] = stamp
		composed := verifyBlock(t, container, bindingOptions(c))
		require.Equal(t, derived, composed.Joins[0].Derived, stamp)
	}
}

// Both root records under one bound key are not the record's two keys.
func TestComposedControllerBindingNeedsBothKeys(t *testing.T) {
	c := bindingCases(t)["controller-binding-linked"]
	container := cloneJSON(t, c.Container)
	members := composedBlockOf(container)["members"].([]interface{})
	first := members[0].(map[string]interface{})["bundle"].(map[string]interface{})["records"].([]interface{})[0].(map[string]interface{})
	second := members[1].(map[string]interface{})["bundle"].(map[string]interface{})["records"].([]interface{})[0].(map[string]interface{})
	second["key_id"] = first["key_id"]
	composed := verifyBlock(t, container, bindingOptions(c))
	require.Equal(t, "unjoined", composed.Joins[0].Derived)
}

// signRevocation signs a revocation statement with the vectors' seed for name.
func signRevocation(t *testing.T, name, binding, revokedAt string) map[string]interface{} {
	t.Helper()
	private := seedKey(t, name)
	statement := map[string]interface{}{
		"revocation_version": "controller-binding-revocation/0", "binding": binding,
		"key_id": hex.EncodeToString(private.Public().(ed25519.PublicKey)), "revoked_at": revokedAt,
	}
	input, err := canonical.JCS(statement)
	require.NoError(t, err)
	statement["sig"] = hex.EncodeToString(ed25519.Sign(private, input))
	return statement
}

// A revocation takes effect at revoked_at: one dated between the two root
// records' times reaches the later one. One signed by a key the binding does
// not bind does not apply.
func TestComposedControllerBindingRevocationTimeAndSigner(t *testing.T) {
	c := bindingCases(t)["controller-binding-linked"]
	digest := composedBlockOf(c.Container)["joins"].([]interface{})[0].(map[string]interface{})["identifier_digest"].(string)
	for _, tc := range []struct {
		signer, at, derived string
	}{
		{"responder-a", "2026-10-02T12:10:30Z", "unjoined"},
		{"responder-b", "2026-10-02T12:11:00Z", "unjoined"},
		{"responder-b", "2026-10-02T12:11:01Z", "agree"},
		{"runtime observer", "2026-10-02T00:00:00Z", "agree"},
	} {
		composed := verifyBlock(t, c.Container, Options{
			ControllerBindings: c.ControllerBindings,
			BindingRevocations: []map[string]interface{}{signRevocation(t, tc.signer, digest, tc.at)},
		})
		require.Equal(t, tc.derived, composed.Joins[0].Derived, tc)
	}
}

// Each form rule of "Controller Binding Records", read on its own.
func TestControllerBindingForm(t *testing.T) {
	base := bindingCases(t)["controller-binding-linked"].ControllerBindings[0]
	require.True(t, bindingForm(cloneJSON(t, base)))
	keys := base["keys"].([]interface{})
	cases := map[string]func(r map[string]interface{}){
		"keys descending":          func(r map[string]interface{}) { r["keys"] = []interface{}{keys[1], keys[0]} },
		"keys equal":               func(r map[string]interface{}) { r["keys"] = []interface{}{keys[0], keys[0]} },
		"one key":                  func(r map[string]interface{}) { r["keys"] = []interface{}{keys[0]} },
		"key not hex":              func(r map[string]interface{}) { r["keys"] = []interface{}{keys[0], strings.ToUpper(keys[1].(string))} },
		"not_before after issued":  func(r map[string]interface{}) { r["not_before"] = "2026-10-01T00:00:01Z" },
		"not_after at issued":      func(r map[string]interface{}) { r["not_after"] = r["issued_at"] },
		"time with offset":         func(r map[string]interface{}) { r["issued_at"] = "2026-10-01T00:00:00+00:00" },
		"time with fraction":       func(r map[string]interface{}) { r["not_after"] = "2027-10-01T00:00:00.5Z" },
		"time not a date":          func(r map[string]interface{}) { r["not_after"] = "2027-02-30T00:00:00Z" },
		"other version":            func(r map[string]interface{}) { r["binding_version"] = "controller-binding/1" },
		"other revocation method":  func(r map[string]interface{}) { r["revocation"] = "x-revocation/0" },
		"empty nonce":              func(r map[string]interface{}) { r["nonce"] = "" },
		"unknown claim":            func(r map[string]interface{}) { r["claim"] = "x-claim" },
		"extra member":             func(r map[string]interface{}) { r["x"] = "y" },
		"missing member":           func(r map[string]interface{}) { delete(r, "nonce") },
		"delegator on other claim": func(r map[string]interface{}) { r["delegator"] = keys[0] },
		"method of another claim":  func(r map[string]interface{}) { r["method"] = "dual_signature_credential/0" },
		"method not a string":      func(r map[string]interface{}) { r["method"] = 1 },
		"sig not hex": func(r map[string]interface{}) {
			r["sigs"].([]interface{})[0].(map[string]interface{})["sig"] = "zz"
		},
		"sigs not an array": func(r map[string]interface{}) { r["sigs"] = "x" },
		"sig entry extra member": func(r map[string]interface{}) {
			r["sigs"].([]interface{})[0].(map[string]interface{})["x"] = "y"
		},
		"delegator not bound": func(r map[string]interface{}) {
			r["claim"], r["delegator"] = "delegated_by", strings.Repeat("1", 64)
		},
		"credential missing digest": func(r map[string]interface{}) {
			r["claim"], r["method"] = "same_organization_credentialed", "dual_signature_credential/0"
			r["credential"] = map[string]interface{}{"issuer": keys[0], "method": "m"}
		},
		"key_types one entry":    func(r map[string]interface{}) { r["key_types"] = []interface{}{"ed25519"} },
		"key_types not strings":  func(r map[string]interface{}) { r["key_types"] = []interface{}{"ed25519", 1} },
		"key_types not an array": func(r map[string]interface{}) { r["key_types"] = "ed25519" },
		"key_types ed25519 sig": func(r map[string]interface{}) {
			r["key_types"] = []interface{}{"ed25519", "ed25519"}
			r["sigs"].([]interface{})[0].(map[string]interface{})["sig"] = "zz"
		},
	}
	// key_types is optional; a type -02 does not define frees sig from its hex form.
	typed := cloneJSON(t, base)
	typed["key_types"] = []interface{}{"ed25519", "x-example-type"}
	typed["sigs"].([]interface{})[1].(map[string]interface{})["sig"] = map[string]interface{}{"x": "y"}
	require.True(t, bindingForm(typed))
	require.False(t, ed25519Keys(typed))
	typed["key_types"] = []interface{}{"ed25519", "ed25519"}
	require.True(t, ed25519Keys(typed))
	for name, mutate := range cases {
		record := cloneJSON(t, base)
		mutate(record)
		require.False(t, bindingForm(record), name)
	}
	for name, mutate := range map[string]func(r map[string]interface{}){
		"undefined method token": func(r map[string]interface{}) { r["method"] = "x-example-method/0" },
		"any method string":      func(r map[string]interface{}) { r["method"] = "x method" },
		"delegated_by":           func(r map[string]interface{}) { r["claim"], r["delegator"] = "delegated_by", keys[1] },
		"same_organization_credentialed": func(r map[string]interface{}) {
			r["claim"], r["method"] = "same_organization_credentialed", "dual_signature_credential/0"
			r["credential"] = map[string]interface{}{"issuer": keys[0], "method": "m", "digest": strings.Repeat("a", 64)}
		},
	} {
		record := cloneJSON(t, base)
		mutate(record)
		require.True(t, bindingForm(record), name)
	}
}

// seedKey returns the vectors' private key for name.
func seedKey(t *testing.T, name string) ed25519.PrivateKey {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "vectors", "bundle", "composed-controller-binding", "vectors.json"))
	require.NoError(t, err)
	var file struct {
		Keys map[string]struct {
			Seed string `json:"seed_hex"`
		} `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(data, &file))
	seed, err := hex.DecodeString(file.Keys[name].Seed)
	require.NoError(t, err)
	return ed25519.NewKeyFromSeed(seed)
}

// resignBinding re-signs record with the named keys in sigs order and points
// the case's join at its new digest.
func resignBinding(t *testing.T, c bindingCase, record map[string]interface{}, signers ...string) map[string]interface{} {
	t.Helper()
	input, ok := signingInput(record, "sigs")
	require.True(t, ok)
	sigs := record["sigs"].([]interface{})
	for i, name := range signers {
		sigs[i].(map[string]interface{})["sig"] = hex.EncodeToString(ed25519.Sign(seedKey(t, name), input))
	}
	container := cloneJSON(t, c.Container)
	block := composedBlockOf(container)
	sum := sha256.Sum256(input)
	block["joins"].([]interface{})[0].(map[string]interface{})["identifier_digest"] = hex.EncodeToString(sum[:])
	reseal(t, block)
	return container
}

// A record both keys signed is still no binding when it is malformed (here,
// keys out of order) or when sigs label the keys out of order: the join is
// derivable and unjoined, never linked.
func TestComposedControllerBindingSignedButMalformed(t *testing.T) {
	c := bindingCases(t)["controller-binding-linked"]
	keys := c.ControllerBindings[0]["keys"].([]interface{})
	sigs := c.ControllerBindings[0]["sigs"].([]interface{})
	first, second := sigs[0].(map[string]interface{}), sigs[1].(map[string]interface{})

	descending := cloneJSON(t, c.ControllerBindings[0])
	descending["keys"] = []interface{}{keys[1], keys[0]}
	descending["sigs"] = []interface{}{cloneJSON(t, second), cloneJSON(t, first)}
	container := resignBinding(t, c, descending, "responder-b", "responder-a")
	composed := verifyBlock(t, container, Options{ControllerBindings: []map[string]interface{}{descending}})
	require.Equal(t, "unjoined", composed.Joins[0].Derived)

	// Each sig made by the right key, under the other key's key_id.
	swapped := cloneJSON(t, c.ControllerBindings[0])
	swapped["sigs"].([]interface{})[0].(map[string]interface{})["key_id"] = keys[1]
	swapped["sigs"].([]interface{})[1].(map[string]interface{})["key_id"] = keys[0]
	composed = verifyBlock(t, c.Container, Options{ControllerBindings: []map[string]interface{}{swapped}})
	require.Equal(t, "unjoined", composed.Joins[0].Derived)
}

// signingInput is the UTF-8 JCS of value without the member named omit.
func signingInput(value map[string]interface{}, omit string) ([]byte, bool) {
	rest := make(map[string]interface{}, len(value))
	for k, v := range value {
		if k != omit {
			rest[k] = v
		}
	}
	data, err := canonical.JCS(rest)
	return data, err == nil
}

// bindingForm reports whether a record is well formed as -02 states it.
func bindingForm(record map[string]interface{}) bool {
	_, wellFormed := bindingReport(record, nil, nil)
	return wellFormed
}

// A sig that cannot be serialized (here a float) is malformed under ed25519
// keys, which -02 holds to sig-hex, and merely not implemented under a key type
// -02 does not define. The record's digest, which leaves sigs out, still
// matches its join.
func TestControllerBindingUnserializableSig(t *testing.T) {
	record := cloneJSON(t, bindingCases(t)["controller-binding-linked"].ControllerBindings[0])
	record["sigs"].([]interface{})[0].(map[string]interface{})["sig"] = 1.5
	require.False(t, bindingForm(record))
	record["key_types"] = []interface{}{"ed25519", "x-example-type"}
	require.True(t, bindingForm(record))
	require.False(t, implemented(record))
}
