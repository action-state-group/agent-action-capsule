// SPDX-License-Identifier: BSD-3-Clause
package settlement

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func observedLeg(overrides map[string]interface{}) map[string]interface{} {
	leg := map[string]interface{}{
		"version": "0", "leg": "payer_observed", "sealer_role": "payer", "terms_ref": hex64("0"),
		"amount":      map[string]interface{}{"value": "15", "assetCode": "USD", "assetScale": json.Number("2")},
		"payment_ref": map[string]interface{}{"type": "acp.order_id", "value": "o-1"}, "status": "settled",
		"observed_at": "2026-10-15T00:00:00Z",
	}
	for name, value := range overrides {
		leg[name] = value
	}
	return leg
}

func hex64(digit string) string {
	out := ""
	for range 64 {
		out += digit
	}
	return out
}

func TestStructureFailures(t *testing.T) {
	require.Empty(t, StructureFailures(observedLeg(nil)))
	require.Equal(t, []string{"settlement_malformed"}, StructureFailures(nil))
	require.Equal(t, []string{"leg_role_mismatch", "amount_not_exact"}, StructureFailures(observedLeg(map[string]interface{}{
		"sealer_role": "payee", "amount": map[string]interface{}{"value": "1.5", "assetCode": "USD", "assetScale": json.Number("2")},
	})))
	for name, amount := range map[string]map[string]interface{}{
		"value with newline": {"value": "15\n", "assetCode": "USD", "assetScale": json.Number("2")},
		"float assetScale":   {"value": "1", "assetCode": "USD", "assetScale": json.Number("2.0")},
	} {
		require.Equal(t, []string{"amount_not_exact"}, StructureFailures(observedLeg(map[string]interface{}{"amount": amount})), name)
	}
	wrapped := func(entry map[string]interface{}) map[string]interface{} {
		return observedLeg(map[string]interface{}{"wrapped": []interface{}{entry}})
	}
	for name, leg := range map[string]map[string]interface{}{
		"terms_ref with newline":   observedLeg(map[string]interface{}{"terms_ref": hex64("0") + "\n"}),
		"observed_at with newline": observedLeg(map[string]interface{}{"observed_at": "2026-10-15T00:00:00Z\n"}),
		"non-ASCII digits":         observedLeg(map[string]interface{}{"observed_at": "２０２6-10-15T00:00:00Z"}),
		"null payment_ref":         observedLeg(map[string]interface{}{"payment_ref": nil}),
		"null wrapped":             observedLeg(map[string]interface{}{"wrapped": nil}),
		"unknown member":           observedLeg(map[string]interface{}{"extra": true}),
		"qualifier missing":        observedLeg(map[string]interface{}{"payment_ref": map[string]interface{}{"type": "x402.transaction", "value": "0x1"}}),
		"non-string wrapped type":  wrapped(map[string]interface{}{"type": []interface{}{"x402.offer"}, "digest_alg": "SHA-256", "digest": hex64("0")}),
		"non-string content":       wrapped(map[string]interface{}{"type": "x402.offer", "digest_alg": "SHA-256", "digest": hex64("0"), "content": json.Number("7")}),
		"non-string direction": {"version": "0", "leg": "delivered", "sealer_role": "payer", "terms_ref": hex64("0"),
			"observed_at": "2026-10-15T00:00:00Z", "delivery": map[string]interface{}{"direction": []interface{}{"received"}}},
	} {
		require.Equal(t, []string{"settlement_malformed"}, StructureFailures(leg), name)
	}
	require.Empty(t, StructureFailures(observedLeg(map[string]interface{}{"payment_ref": map[string]interface{}{"type": "x-private", "value": "1", "other": "x"}})),
		"an unregistered type has no qualifier rule")
}

func TestAmountOK(t *testing.T) {
	require.True(t, AmountOK(map[string]interface{}{"value": "0", "assetCode": "X", "assetScale": json.Number("255")}))
	for _, bad := range []map[string]interface{}{
		{"value": "01", "assetCode": "X", "assetScale": json.Number("0")},
		{"value": "1", "assetCode": "", "assetScale": json.Number("0")},
		{"value": "1", "assetCode": "X", "assetScale": json.Number("256")},
		{"value": "1", "assetCode": "X", "assetScale": true},
		{"value": "1", "assetCode": "X", "assetScale": json.Number("0"), "extra": 1},
	} {
		require.False(t, AmountOK(bad), bad)
	}
}

func TestNonObjectInputsAreReportedNotPanics(t *testing.T) {
	report := Verify(Input{Capsules: []interface{}{nil, "x", map[string]interface{}{"capsule_id": json.Number("1")}}})
	require.False(t, report.Conforming)
	require.Equal(t, Entry{Records: []*string{nil}, Code: "capsule_invalid"}, report.Failures[0])
	require.Equal(t, Entry{Records: []*string{nil}, Code: "capsule_invalid"}, report.Failures[1])
	data, err := json.Marshal(report)
	require.NoError(t, err)
	var decoded map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Equal(t, []interface{}{nil}, decoded["failures"].([]interface{})[0].(map[string]interface{})["records"])
	require.Equal(t, false, decoded["key_policy_applied"])
	require.Equal(t, []interface{}{}, decoded["settlements"])
}

func TestWrappedContentIsCanonicalBase64URL(t *testing.T) {
	octets := []byte("hi")
	sum := sha256.Sum256(octets)
	digest := hex.EncodeToString(sum[:])
	leg := func(content string) map[string]interface{} {
		return map[string]interface{}{"sealer_role": "payer", "wrapped": []interface{}{
			map[string]interface{}{"type": "x402.offer", "digest_alg": "SHA-256", "digest": digest, "content": content},
		}}
	}
	require.Empty(t, wrappedFailures(leg(base64.RawURLEncoding.EncodeToString(octets)), "", nil))
	for _, bad := range []string{"aGk=", "aGl", "aG k"} {
		require.Equal(t, []string{"wrapped_digest_mismatch"}, wrappedFailures(leg(bad), "", nil), bad)
	}
}

func TestUndecodableContentMatchesNotEvenTheEmptyDigest(t *testing.T) {
	empty := sha256.Sum256(nil)
	s := map[string]interface{}{"sealer_role": "payer", "wrapped": []interface{}{
		map[string]interface{}{"type": "x402.offer", "digest_alg": "SHA-256", "digest": hex.EncodeToString(empty[:]), "content": "a="},
	}}
	require.Equal(t, []string{"wrapped_digest_mismatch"}, wrappedFailures(s, "", nil))
	s["wrapped"].([]interface{})[0].(map[string]interface{})["content"] = ""
	require.Empty(t, wrappedFailures(s, "", nil), "empty content is the empty bytes")
}

func TestRegisteredQualifiersAreStrings(t *testing.T) {
	ref := func(network interface{}) map[string]interface{} {
		return observedLeg(map[string]interface{}{"payment_ref": map[string]interface{}{"type": "x402.transaction", "value": "0x1", "network": network}})
	}
	require.Empty(t, StructureFailures(ref("eip155:8453")))
	for _, bad := range []interface{}{json.Number("8453"), nil, []interface{}{"eip155:8453"}, true} {
		require.Equal(t, []string{"settlement_malformed"}, StructureFailures(ref(bad)), bad)
	}
}

func TestWrappedResigned(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"scheme":"exact"}`))
	signature := ed25519.Sign(private, []byte(header+"."+payload))
	jws := []byte(header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(signature) + "~")
	sum := sha256.Sum256(jws)
	digest := hex.EncodeToString(sum[:])
	s := map[string]interface{}{"sealer_role": "payer", "wrapped": []interface{}{
		map[string]interface{}{"type": "x402.offer", "digest_alg": "SHA-256", "digest": digest},
	}}
	objects := map[string][]byte{digest: jws}
	require.Equal(t, []string{"wrapped_resigned"}, wrappedFailures(s, hex.EncodeToString(public), objects))
	require.Empty(t, wrappedFailures(s, hex64("a"), objects), "another key")
	// An SD-JWT with a disclosure: only the issuer JWS before the first ~ is signed.
	withDisclosure := append(append([]byte(nil), jws...), "WyJzYWx0IiwiYSIsMV0~"...)
	withSum := sha256.Sum256(withDisclosure)
	withDigest := hex.EncodeToString(withSum[:])
	withS := map[string]interface{}{"sealer_role": "payer", "wrapped": []interface{}{
		map[string]interface{}{"type": "x402.offer", "digest_alg": "SHA-256", "digest": withDigest},
	}}
	require.Equal(t, []string{"wrapped_resigned"}, wrappedFailures(withS, hex.EncodeToString(public), map[string][]byte{withDigest: withDisclosure}))
	require.Equal(t, "exact", x402Scheme([]map[string]interface{}{s}, objects), "a JWS offer's payload")
	require.Nil(t, x402Scheme([]map[string]interface{}{s}, map[string][]byte{digest: jws[:len(jws)-1]}), "octets of another digest")
}

func TestX402Scheme(t *testing.T) {
	offer := []byte(`{"payload":{"scheme":"exact"}}`)
	sum := sha256.Sum256(offer)
	digest := hex.EncodeToString(sum[:])
	s := map[string]interface{}{"wrapped": []interface{}{
		map[string]interface{}{"type": "x402.offer", "digest_alg": "SHA-256", "digest": digest},
	}}
	require.Equal(t, "exact", x402Scheme([]map[string]interface{}{s}, map[string][]byte{digest: offer}))
	require.Nil(t, x402Scheme([]map[string]interface{}{s}, nil), "octets not held")
}

func TestAmountsCompareByValueAcrossScales(t *testing.T) {
	a := map[string]interface{}{"value": "15", "assetCode": "USD", "assetScale": json.Number("1")}
	b := map[string]interface{}{"value": "150", "assetCode": "USD", "assetScale": json.Number("2")}
	require.True(t, amountsEqual(a, b))
	b["assetCode"] = "EUR"
	require.False(t, amountsEqual(a, b))
	require.True(t, jsonEqual(json.Number("1"), json.Number("1.0")))
	require.False(t, jsonEqual(json.Number("1"), "1"))
}

func TestOptionalMembersHaveTheDraftTypes(t *testing.T) {
	delivered := func(delivery map[string]interface{}) map[string]interface{} {
		d := map[string]interface{}{"direction": "sent", "carrier": "post"}
		for name, value := range delivery {
			d[name] = value
		}
		return map[string]interface{}{"version": "0", "leg": "delivered", "sealer_role": "payee", "terms_ref": hex64("0"),
			"observed_at": "2026-10-15T00:00:00Z", "delivery": d}
	}
	require.Empty(t, StructureFailures(delivered(map[string]interface{}{
		"tracking_digest": hex64("a"), "address_digest": hex64("b"), "status": "in_transit",
		"shipped_at": "2026-10-14T00:00:00Z", "delivered_at": "2026-10-15T00:00:00.5Z",
	})))
	for name, delivery := range map[string]map[string]interface{}{
		"carrier not a string":      {"carrier": json.Number("1")},
		"tracking_digest uppercase": {"tracking_digest": hex64("A")},
		"address_digest short":      {"address_digest": "ab"},
		"status unknown":            {"status": "lost"},
		"status not a string":       {"status": []interface{}{"pending"}},
		"shipped_at not UTC":        {"shipped_at": "2026-10-14T00:00:00+01:00"},
		"delivered_at a number":     {"delivered_at": json.Number("1")},
	} {
		require.Equal(t, []string{"settlement_malformed"}, StructureFailures(delivered(delivery)), name)
	}

	terms := map[string]interface{}{"version": "0", "leg": "terms", "sealer_role": "payee",
		"amount": map[string]interface{}{"value": "1", "assetCode": "USD", "assetScale": json.Number("0")}, "valid_until": "2026-10-15T00:00:00Z"}
	require.Empty(t, StructureFailures(terms))
	for _, bad := range []interface{}{"2026-10-15", "2026-10-15T00:00:00Z\n", json.Number("1"), nil} {
		terms["valid_until"] = bad
		require.Equal(t, []string{"settlement_malformed"}, StructureFailures(terms), bad)
	}
}

func TestAmountsOfAnyLengthCompareExactly(t *testing.T) {
	long := "1"
	for range 5000 {
		long += "0"
	}
	amount := func(value string, scale string) map[string]interface{} {
		return map[string]interface{}{"value": value, "assetCode": "X", "assetScale": json.Number(scale)}
	}
	require.True(t, AmountOK(amount(long, "0")))
	require.True(t, amountsEqual(amount(long, "0"), amount(long+"00", "2")))
	require.False(t, amountsEqual(amount(long, "0"), amount(long+"01", "2")))
	payer := map[string]interface{}{"amount": amount(long, "0")}
	nines := ""
	for range 5001 {
		nines += "9"
	}
	payee := map[string]interface{}{"received": amount(nines, "1")}
	require.True(t, amountRuleHolds(payer, payee, amount("1", "1")), "10^5000 = (10^5000 - 0.1) + 0.1")
	require.False(t, amountRuleHolds(payer, payee, amount("2", "1")))
}

func TestDeeplyNestedX402ObjectsFailCleanly(t *testing.T) {
	deep := []byte(`{"payload":` + strings.Repeat("[", 1_000_000) + strings.Repeat("]", 1_000_000) + `}`)
	jws := []byte(base64.RawURLEncoding.EncodeToString([]byte("{}")) + "." + base64.RawURLEncoding.EncodeToString(deep[11:len(deep)-1]) + ".sig")
	for name, octets := range map[string][]byte{"EIP-712 offer": deep, "JWS offer": jws} {
		sum := sha256.Sum256(octets)
		digest := hex.EncodeToString(sum[:])
		for _, kind := range []string{"x402.offer", "x402.payment-payload"} {
			s := map[string]interface{}{"wrapped": []interface{}{
				map[string]interface{}{"type": kind, "digest_alg": "SHA-256", "digest": digest},
			}}
			require.Nil(t, x402Scheme([]map[string]interface{}{s}, map[string][]byte{digest: octets}), name+" "+kind)
		}
	}
}

func TestUTCTimesNameARealInstant(t *testing.T) {
	for _, good := range []string{
		"2026-10-15T00:00:00Z", "2024-02-29T23:59:59Z", "2000-02-29T12:00:00.5Z", "0000-02-29T00:00:00Z",
		"2026-12-31T23:59:59.999999Z", "2026-01-31T00:00:00Z", "2026-04-30T00:00:00Z",
	} {
		require.True(t, utcTimeOK(good), good)
	}
	for _, bad := range []interface{}{
		"2026-13-01T00:00:00Z", "2026-00-01T00:00:00Z", "2026-01-00T00:00:00Z", "2026-02-29T00:00:00Z",
		"1900-02-29T00:00:00Z", "2026-04-31T00:00:00Z", "2026-01-32T00:00:00Z", "2026-10-15T24:00:00Z",
		"2026-10-15T23:60:00Z", "2026-12-31T23:59:60Z", "2026-10-15T00:00:00+00:00", json.Number("1"), nil,
	} {
		require.False(t, utcTimeOK(bad), bad)
	}

	// Each settlement time member holds to it.
	require.Equal(t, []string{"settlement_malformed"}, StructureFailures(observedLeg(map[string]interface{}{"observed_at": "2026-02-30T00:00:00Z"})))
	terms := map[string]interface{}{"version": "0", "leg": "terms", "sealer_role": "payee",
		"amount": map[string]interface{}{"value": "1", "assetCode": "USD", "assetScale": json.Number("0")}, "valid_until": "2026-12-31T23:59:60Z"}
	require.Equal(t, []string{"settlement_malformed"}, StructureFailures(terms))
	for _, name := range []string{"shipped_at", "delivered_at"} {
		leg := map[string]interface{}{"version": "0", "leg": "delivered", "sealer_role": "payee", "terms_ref": hex64("0"),
			"observed_at": "2026-10-15T00:00:00Z", "delivery": map[string]interface{}{"direction": "sent", "carrier": "post", name: "2026-06-31T00:00:00Z"}}
		require.Equal(t, []string{"settlement_malformed"}, StructureFailures(leg), name)
	}
}

// The wrapped_resigned check verifies a wrapped JWS under the leg key with
// strict Ed25519: the identity key's forgery (R the identity, S = 0), which
// ed25519.Verify accepts over any message, and a non-canonical R do not count
// as a signature by that key.
func TestJWSVerifiesIsStrict(t *testing.T) {
	b64 := base64.RawURLEncoding.EncodeToString
	signingInput := b64([]byte(`{"alg":"EdDSA"}`)) + "." + b64([]byte(`{}`))
	compact := func(signature []byte) []byte { return []byte(signingInput + "." + b64(signature)) }

	identity := append([]byte{1}, make([]byte, 31)...)
	forged := append(append([]byte(nil), identity...), make([]byte, 32)...)
	require.True(t, ed25519.Verify(identity, []byte(signingInput), forged))
	require.False(t, jwsVerifies(compact(forged), hex.EncodeToString(identity)))

	_, private, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	keyHex := hex.EncodeToString(private.Public().(ed25519.PublicKey))
	signature := ed25519.Sign(private, []byte(signingInput))
	require.True(t, jwsVerifies(compact(signature), keyHex))
	nonCanonicalR := append(append([]byte{0xef}, []byte(strings.Repeat("\xff", 30))...), 0x7f)
	require.False(t, jwsVerifies(compact(append(nonCanonicalR, signature[32:]...)), keyHex))
}

func TestEnvelopeSignatureIsHexPairs(t *testing.T) {
	for _, bad := range []interface{}{"", " d2", "d2 84", "d", "zz", json.Number("1"), nil} {
		require.Empty(t, envelopeKey(map[string]interface{}{"signature": bad}, hex64("0")), bad)
	}
}
