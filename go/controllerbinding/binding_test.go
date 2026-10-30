// SPDX-License-Identifier: BSD-3-Clause

package controllerbinding_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	cb "github.com/action-state-group/agent-action-capsule/go/controllerbinding"
	er "github.com/action-state-group/agent-action-capsule/go/evidencerequest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The cases vectors/controller-binding-v0/README.md lists as not covered,
// built from test keys here.

func verifyHex(key, sig string, message []byte) bool {
	raw, err := hex.DecodeString(sig)
	return err == nil && er.VerifySignature(key, message, raw) == nil
}

type testKey struct {
	id   string
	priv ed25519.PrivateKey
}

func newKey(label string) testKey {
	seed := sha256.Sum256([]byte("controllerbinding test " + label))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return testKey{hex.EncodeToString(priv.Public().(ed25519.PublicKey)), priv}
}

func (k testKey) sign(t *testing.T, v map[string]any) string {
	t.Helper()
	data, err := er.EncodeJCS(v)
	require.NoError(t, err)
	return hex.EncodeToString(ed25519.Sign(k.priv, data))
}

func jcs(t *testing.T, v any) []byte {
	t.Helper()
	data, err := er.EncodeJCS(v)
	require.NoError(t, err)
	return data
}

var (
	keyA, keyB, keyC = newKey("a"), newKey("b"), newKey("c")
	during           = []time.Time{time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)}
)

// ordered returns the two keys ascending, as keys must be.
func ordered() (testKey, testKey) {
	if keyA.id < keyB.id {
		return keyA, keyB
	}
	return keyB, keyA
}

// unsigned is a same_controller_asserted record over keyA and keyB, without sigs.
func unsigned() map[string]any {
	first, second := ordered()
	return map[string]any{
		"binding_version": cb.Version, "claim": cb.ClaimSameController, "method": cb.MethodDualSignature,
		"keys": []any{first.id, second.id}, "issued_at": "2026-10-01T00:00:00Z",
		"not_before": "2026-10-01T00:00:00Z", "not_after": "2027-10-01T00:00:00Z",
		"revocation": cb.RevocationMethod, "nonce": "ceremony-1",
	}
}

// signed adds sigs by both bound keys in order.
func signed(t *testing.T, r map[string]any) map[string]any {
	t.Helper()
	first, second := ordered()
	r["sigs"] = []any{
		map[string]any{"key_id": first.id, "sig": first.sign(t, r)},
		map[string]any{"key_id": second.id, "sig": second.sign(t, r)},
	}
	return r
}

func digestOf(t *testing.T, r map[string]any) string {
	t.Helper()
	unsignedRecord := map[string]any{}
	for k, v := range r {
		if k != "sigs" {
			unsignedRecord[k] = v
		}
	}
	return er.Digest(jcs(t, unsignedRecord))
}

func revocationBy(t *testing.T, k testKey, binding, at string) []byte {
	t.Helper()
	s := map[string]any{"revocation_version": cb.RevocationVersion, "binding": binding, "key_id": k.id,
		"revoked_at": at}
	s["sig"] = k.sign(t, s)
	return jcs(t, s)
}

func TestValidBindingApplies(t *testing.T) {
	r := signed(t, unsigned())
	report := cb.Verify(jcs(t, r), during, cb.Options{})
	assert.Equal(t, map[string]string{
		cb.PropertyForm: er.StatusPass, cb.PropertySignatures: er.StatusPass, cb.PropertyWindow: er.StatusPass,
		cb.PropertyRevocation: er.StatusNotChecked,
	}, report.Properties)
	assert.True(t, report.AppliesTo(keyA.id, keyB.id))
	assert.True(t, report.AppliesTo(keyB.id, keyA.id))
	assert.False(t, report.AppliesTo(keyA.id, keyC.id))
	assert.False(t, report.AppliesTo(keyA.id, keyA.id))
	assert.True(t, report.Binds(keyA.id))
	assert.False(t, report.Binds(keyC.id))
	assert.Equal(t, digestOf(t, r), report.BindingDigest)
	assert.Equal(t, cb.ClaimSameController, report.Claim)
	assert.Equal(t, "2026-10-01T00:00:00Z", report.NotBefore)
}

func TestSignatures(t *testing.T) {
	t.Run("out of order", func(t *testing.T) {
		r := signed(t, unsigned())
		sigs := r["sigs"].([]any)
		r["sigs"] = []any{sigs[1], sigs[0]}
		report := cb.Verify(jcs(t, r), during, cb.Options{})
		assert.Equal(t, er.StatusFail, report.Properties[cb.PropertySignatures])
		assert.Empty(t, report.Proves)
		assert.False(t, report.Applies())
	})
	t.Run("key_id labels swapped over signatures in order", func(t *testing.T) {
		r := signed(t, unsigned())
		sigs := r["sigs"].([]any)
		first, second := sigs[0].(map[string]any), sigs[1].(map[string]any)
		first["key_id"], second["key_id"] = second["key_id"], first["key_id"]
		assert.Equal(t, er.StatusFail, cb.Verify(jcs(t, r), during, cb.Options{}).Properties[cb.PropertySignatures])
	})
	t.Run("a third entry", func(t *testing.T) {
		r := signed(t, unsigned())
		r["sigs"] = append(r["sigs"].([]any), map[string]any{"key_id": keyC.id, "sig": keyC.sign(t, unsigned())})
		assert.Equal(t, er.StatusFail, cb.Verify(jcs(t, r), during, cb.Options{}).Properties[cb.PropertySignatures])
	})
	t.Run("one key signs both entries", func(t *testing.T) {
		r := signed(t, unsigned())
		first, _ := ordered()
		sigs := r["sigs"].([]any)
		sigs[1].(map[string]any)["sig"] = first.sign(t, unsigned())
		assert.Equal(t, er.StatusFail, cb.Verify(jcs(t, r), during, cb.Options{}).Properties[cb.PropertySignatures])
	})
	t.Run("a member changed after signing", func(t *testing.T) {
		r := signed(t, unsigned())
		r["nonce"] = "ceremony-2"
		assert.Equal(t, er.StatusFail, cb.Verify(jcs(t, r), during, cb.Options{}).Properties[cb.PropertySignatures])
	})
	t.Run("uppercase hex signature", func(t *testing.T) {
		r := signed(t, unsigned())
		entry := r["sigs"].([]any)[0].(map[string]any)
		entry["sig"] = strings.ToUpper(entry["sig"].(string))
		assert.Equal(t, er.StatusFail, cb.Verify(jcs(t, r), during, cb.Options{}).Properties[cb.PropertySignatures])
	})
}

func TestForm(t *testing.T) {
	malformed := map[string]func(map[string]any){
		"a method of another claim type": func(r map[string]any) { r["method"] = cb.MethodDualSignatureCredit },
		"keys descending": func(r map[string]any) {
			k := r["keys"].([]any)
			r["keys"] = []any{k[1], k[0]}
		},
		"a key bound to itself":   func(r map[string]any) { r["keys"] = []any{keyA.id, keyA.id} },
		"three keys":              func(r map[string]any) { r["keys"] = append(r["keys"].([]any), keyC.id) },
		"a missing member":        func(r map[string]any) { delete(r, "nonce") },
		"an unknown member":       func(r map[string]any) { r["scope"] = "all" },
		"a member of another":     func(r map[string]any) { r["delegator"] = keyA.id },
		"not a calendar date":     func(r map[string]any) { r["issued_at"] = "2026-02-30T00:00:00Z" },
		"a fractional time":       func(r map[string]any) { r["issued_at"] = "2026-10-01T00:00:00.5Z" },
		"not_before after issued": func(r map[string]any) { r["not_before"] = "2026-10-02T00:00:00Z" },
		"not_after at issued":     func(r map[string]any) { r["not_after"] = "2026-10-01T00:00:00Z" },
		"another version":         func(r map[string]any) { r["binding_version"] = "controller-binding/1" },
		"another revocation":      func(r map[string]any) { r["revocation"] = "crl/0" },
		"a numeric nonce":         func(r map[string]any) { r["nonce"] = er.JSONNumber("1") },
		"an unknown claim":        func(r map[string]any) { r["claim"] = "same_person" },
	}
	for name, change := range malformed {
		t.Run(name, func(t *testing.T) {
			r := unsigned()
			change(r)
			report := cb.Verify(jcs(t, signed(t, r)), during, cb.Options{})
			assert.Equal(t, map[string]string{cb.PropertyForm: er.StatusFail}, report.Properties)
			assert.Empty(t, report.Proves)
			assert.False(t, report.Applies())
		})
	}
	t.Run("a duplicate member", func(t *testing.T) {
		text := string(jcs(t, signed(t, unsigned())))
		text = strings.Replace(text, `"nonce":"ceremony-1"`, `"nonce":"ceremony-1","nonce":"ceremony-2"`, 1)
		assert.Equal(t, er.StatusFail, cb.Verify([]byte(text), during, cb.Options{}).Properties[cb.PropertyForm])
	})
	t.Run("not JSON", func(t *testing.T) {
		assert.Equal(t, er.StatusFail, cb.Verify([]byte("{"), during, cb.Options{}).Properties[cb.PropertyForm])
	})
	t.Run("an undefined method is well formed and not checked", func(t *testing.T) {
		r := unsigned()
		r["method"] = "single_signature/0"
		report := cb.Verify(jcs(t, signed(t, r)), during, cb.Options{})
		assert.Equal(t, er.StatusPass, report.Properties[cb.PropertyForm])
		assert.Equal(t, er.StatusNotChecked, report.Properties[cb.PropertySignatures])
		assert.False(t, report.Applies())
	})
}

func TestWindow(t *testing.T) {
	r := jcs(t, signed(t, unsigned()))
	at := func(s string) []time.Time {
		v, err := time.Parse(time.RFC3339, s)
		require.NoError(t, err)
		return []time.Time{v}
	}
	assert.Equal(t, er.StatusFail, cb.Verify(r, at("2026-09-30T23:59:59Z"), cb.Options{}).Properties[cb.PropertyWindow])
	assert.Equal(t, er.StatusPass, cb.Verify(r, at("2026-10-01T00:00:00Z"), cb.Options{}).Properties[cb.PropertyWindow])
	assert.Equal(t, er.StatusFail, cb.Verify(r, at("2027-10-01T00:00:00Z"), cb.Options{}).Properties[cb.PropertyWindow])
	both := append(at("2026-10-15T00:00:00Z"), at("2027-11-01T00:00:00Z")...)
	assert.Equal(t, er.StatusFail, cb.Verify(r, both, cb.Options{}).Properties[cb.PropertyWindow])
}

func TestRevocation(t *testing.T) {
	r := signed(t, unsigned())
	record, digest := jcs(t, r), digestOf(t, r)
	status := func(statements ...[]byte) string {
		return cb.Verify(record, during, cb.Options{Revocations: statements}).Properties[cb.PropertyRevocation]
	}
	assert.Equal(t, er.StatusFail, status(revocationBy(t, keyA, digest, "2026-10-14T00:00:00Z")))
	assert.Equal(t, er.StatusFail, status(revocationBy(t, keyB, digest, "2026-10-15T00:00:00Z")), "at T")
	assert.Equal(t, er.StatusNotChecked, status(revocationBy(t, keyA, digest, "2026-10-16T00:00:00Z")), "after T")
	assert.Equal(t, er.StatusNotChecked, status(revocationBy(t, keyC, digest, "2026-10-14T00:00:00Z")),
		"by a key it does not bind")
	other := strings.Repeat("0", 64)
	assert.Equal(t, er.StatusNotChecked, status(revocationBy(t, keyA, other, "2026-10-14T00:00:00Z")),
		"naming another binding")

	forged := map[string]any{"revocation_version": cb.RevocationVersion, "binding": digest, "key_id": keyA.id,
		"revoked_at": "2026-10-14T00:00:00Z"}
	forged["sig"] = keyC.sign(t, forged)
	assert.Equal(t, er.StatusNotChecked, status(jcs(t, forged)), "a signature that does not verify")
	assert.Equal(t, er.StatusNotChecked, status([]byte("not json")), "unreadable")

	// The digest leaves out sigs, so a re-signed copy is revoked too (CB §4).
	resigned := signed(t, unsigned())
	resigned["sigs"].([]any)[0].(map[string]any)["sig"] = strings.Repeat("0", 128)
	report := cb.Verify(jcs(t, resigned), during,
		cb.Options{Revocations: [][]byte{revocationBy(t, keyA, digest, "2026-10-14T00:00:00Z")}})
	assert.Equal(t, er.StatusFail, report.Properties[cb.PropertyRevocation])

	// Revocation stops a binding from applying; NOT_CHECKED does not.
	assert.False(t, cb.Verify(record, during, cb.Options{Revocations: [][]byte{
		revocationBy(t, keyA, digest, "2026-10-14T00:00:00Z")}}).Applies())
	assert.True(t, cb.Verify(record, during, cb.Options{}).Applies())
}

func credentialed(t *testing.T, credential []byte, method string) []byte {
	t.Helper()
	r := unsigned()
	r["claim"] = cb.ClaimSameOrganization
	r["method"] = cb.MethodDualSignatureCredit
	sum := sha256.Sum256(credential)
	r["credential"] = map[string]any{"issuer": keyC.id, "method": method, "digest": hex.EncodeToString(sum[:])}
	return jcs(t, signed(t, r))
}

func TestCredential(t *testing.T) {
	credential := []byte(`{"opaque":"credential"}`)
	record := credentialed(t, credential, "test/0")
	answer := func(status string) map[string]cb.CredentialVerifier {
		return map[string]cb.CredentialVerifier{"test/0": func([]byte, cb.Credential, [2]string) string { return status }}
	}
	status := func(opts cb.Options) string {
		report := cb.Verify(record, during, opts)
		assert.True(t, report.Applies(), "the credential never decides whether a binding applies")
		return report.Properties[cb.PropertyCredential]
	}
	assert.Equal(t, er.StatusNotPresent, status(cb.Options{CredentialVerifiers: answer(er.StatusPass)}))
	assert.Equal(t, er.StatusNotChecked, status(cb.Options{Credential: credential}))
	assert.Equal(t, er.StatusPass, status(cb.Options{Credential: credential, CredentialVerifiers: answer(er.StatusPass)}))
	assert.Equal(t, er.StatusInconclusive,
		status(cb.Options{Credential: credential, CredentialVerifiers: answer(er.StatusInconclusive)}))
	assert.Equal(t, er.StatusFail, status(cb.Options{Credential: credential, CredentialVerifiers: answer("OK")}),
		"a verifier that returns no §7.1 status")
	assert.Equal(t, er.StatusFail, status(cb.Options{Credential: []byte(`{"other":"credential"}`),
		CredentialVerifiers: answer(er.StatusPass)}), "a credential that does not hash to its digest")

	var got cb.Credential
	var gotKeys [2]string
	cb.Verify(record, during, cb.Options{Credential: credential, CredentialVerifiers: map[string]cb.CredentialVerifier{
		"test/0": func(_ []byte, c cb.Credential, keys [2]string) string {
			got, gotKeys = c, keys
			return er.StatusPass
		}}})
	first, second := ordered()
	assert.Equal(t, keyC.id, got.Issuer)
	assert.Equal(t, [2]string{first.id, second.id}, gotKeys)

	report := cb.Verify(record, during, cb.Options{Credential: credential, CredentialVerifiers: answer(er.StatusPass)})
	assert.Len(t, report.Proves, 3)
}

func TestPairIndependence(t *testing.T) {
	r := signed(t, unsigned())
	applies := cb.Verify(jcs(t, r), during, cb.Options{})
	expired := cb.Verify(jcs(t, r), []time.Time{time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)}, cb.Options{})

	got := cb.PairIndependence(keyA.id, keyB.id, expired, applies)
	assert.Equal(t, er.StatusFail, got.Status)
	assert.Equal(t, "redundant, not corroborating", got.ShownAs)
	require.NotNil(t, got.Reason)
	assert.Equal(t, "controller binding same_controller_asserted "+applies.BindingDigest, *got.Reason)

	got = cb.PairIndependence(keyA.id, keyB.id, expired)
	assert.Equal(t, cb.IssuerIndependence{Status: er.StatusNotChecked, ShownAs: "not corroborating"}, got)
	assert.Equal(t, er.StatusNotChecked, cb.PairIndependence(keyA.id, keyC.id, applies).Status)

	got = cb.PairIndependence(keyA.id, keyA.id)
	require.NotNil(t, got.Reason)
	assert.Equal(t, "same key", *got.Reason)
}
