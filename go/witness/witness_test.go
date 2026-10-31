// SPDX-License-Identifier: BSD-3-Clause
package witness

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/checkpointed-local-log/go/checkpoint"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func TestBindingAndEndpoint(t *testing.T) {
	for url, want := range map[string][2]string{
		"https://w.example/":           {BindingCLL, "https://w.example"},
		"rekor+https://r.example//":    {BindingRekor, "https://r.example"},
		"SCRAPI+https://s.example":     {BindingSCRAPI, "https://s.example"},
		"not a url":                    {BindingCLL, "not a url"},
		"rekorish://x.example":         {BindingCLL, "rekorish://x.example"},
		"scrapi+rekor+https://example": {BindingSCRAPI, "rekor+https://example"},
	} {
		require.Equal(t, want[0], BindingOf(url), url)
		require.Equal(t, want[1], EndpointOf(url), url)
	}
}

func TestParseDirectory(t *testing.T) {
	directory, err := ParseDirectory([]byte(`{"witnesses":[{"name":"a","endpoint":"https://a.example/","key_ids":[]},
		{"name":"r","endpoint":"https://a.example","binding":"rekor","key_ids":[]},
		{"name":"n","endpoint":"https://n.example","binding":null}]}`))
	require.NoError(t, err)
	row, found := directory.RowFor("https://a.example")
	require.True(t, found)
	require.Equal(t, "a", row.Name)
	row, found = RowFor(directory, "rekor+https://a.example/")
	require.True(t, found)
	require.Equal(t, "r", row.Name)
	_, found = directory.RowFor("https://n.example")
	require.False(t, found, "a null binding is not cll")

	bare, err := ParseDirectory([]byte(`[{"endpoint":"https://b.example"}]`))
	require.NoError(t, err)
	_, found = bare.RowFor("https://b.example")
	require.True(t, found)

	for _, bad := range []string{`"x"`, `{"witnesses":[]} {}`, `nope`} {
		_, err := ParseDirectory([]byte(bad))
		require.Error(t, err, bad)
	}
	_, found = Directory{}.RowFor("https://a.example")
	require.False(t, found)
}

func TestRowKeys(t *testing.T) {
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edDER, err := x509.MarshalPKIXPublicKey(edPublic)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecDER, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	require.NoError(t, err)
	ecID := sha256.Sum256(ecDER)
	rawID := hex.EncodeToString(edPublic)
	row := func(fields map[string]interface{}) Row { return Row{raw: fields} }

	keys, err := row(map[string]interface{}{
		"key_ids":     []interface{}{rawID, hex.EncodeToString(ecID[:])},
		"public_keys": []interface{}{base64.StdEncoding.EncodeToString(ecDER), "not base64", 7},
	}).Keys()
	require.NoError(t, err)
	require.Len(t, keys, 2)
	require.Equal(t, ed25519.PublicKey(edPublic), keys[0])
	require.True(t, keys[1].(*ecdsa.PublicKey).Equal(&ecKey.PublicKey))

	// An Ed25519 public_keys entry is named by its raw key too.
	keys, err = row(map[string]interface{}{
		"key_ids": []interface{}{rawID}, "public_keys": []interface{}{base64.StdEncoding.EncodeToString(edDER)},
	}).Keys()
	require.NoError(t, err)
	require.Equal(t, []crypto.PublicKey{edPublic}, keys)

	for name, fields := range map[string]map[string]interface{}{
		"rekor log ID without a key": {"binding": "rekor", "key_ids": []interface{}{rawID}},
		"not hex":                    {"key_ids": []interface{}{"zz"}},
		"short key":                  {"key_ids": []interface{}{"abcd"}},
		"key id not a string":        {"key_ids": []interface{}{7}},
		"key_ids a string":           {"key_ids": rawID},
		"key_ids null":               {"key_ids": nil},
		"public_keys null":           {"key_ids": []interface{}{rawID}, "public_keys": nil},
		"uppercase key id":           {"key_ids": []interface{}{strings.ToUpper(rawID)}},
		"unpadded public key":        {"binding": "rekor", "key_ids": []interface{}{hex.EncodeToString(ecID[:])}, "public_keys": []interface{}{base64.RawStdEncoding.EncodeToString(ecDER)}},
		"non-canonical public key":   {"binding": "rekor", "key_ids": []interface{}{hex.EncodeToString(ecID[:])}, "public_keys": []interface{}{nonCanonicalBase64(t, ecDER)}},
	} {
		_, err := row(fields).Keys()
		require.Error(t, err, name)
	}
	keys, err = row(map[string]interface{}{"key_ids": []interface{}{}}).Keys()
	require.NoError(t, err)
	require.Empty(t, keys)
}

// spki builds a SubjectPublicKeyInfo for algorithm with parameters (an OID,
// or none) and the given key bytes.
func spki(t *testing.T, algorithm asn1.ObjectIdentifier, parameters asn1.ObjectIdentifier, key []byte) []byte {
	t.Helper()
	identifier := pkix.AlgorithmIdentifier{Algorithm: algorithm}
	if parameters != nil {
		encoded, err := asn1.Marshal(parameters)
		require.NoError(t, err)
		identifier.Parameters = asn1.RawValue{FullBytes: encoded}
	}
	der, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{identifier, asn1.BitString{Bytes: key, BitLength: len(key) * 8}})
	require.NoError(t, err)
	return der
}

func mustHex(t *testing.T, text string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(text)
	require.NoError(t, err)
	return raw
}

var (
	oidEC        = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidP256      = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidSecp256k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
	oidBrainpool = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}
)

// The generator points of secp256k1 (SEC 2) and brainpoolP256r1 (RFC 5639).
const (
	secp256k1X = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	secp256k1Y = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
	brainpoolX = "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262"
	brainpoolY = "547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997"
)

func TestOnlyEd25519AndP256DirectoryKeysCount(t *testing.T) {
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edDER, err := x509.MarshalPKIXPublicKey(edPublic)
	require.NoError(t, err)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p256DER, err := x509.MarshalPKIXPublicKey(&p256.PublicKey)
	require.NoError(t, err)
	for name, der := range map[string][]byte{"Ed25519": edDER, "P-256": p256DER} {
		_, err := parsePublicKey(der)
		require.NoError(t, err, name)
	}

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	p384DER, err := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	x25519DER, err := x509.MarshalPKIXPublicKey(x25519.PublicKey())
	require.NoError(t, err)
	point := append(append([]byte{4}, p256.X.FillBytes(make([]byte, 32))...), p256.Y.FillBytes(make([]byte, 32))...)
	offCurve := append([]byte(nil), point...)
	offCurve[len(offCurve)-1] ^= 1

	for name, der := range map[string][]byte{
		"P-384":                 p384DER,
		"secp256k1":             spki(t, oidEC, oidSecp256k1, mustHex(t, "04"+secp256k1X+secp256k1Y)),
		"brainpoolP256r1":       spki(t, oidEC, oidBrainpool, mustHex(t, "04"+brainpoolX+brainpoolY)),
		"RSA":                   rsaDER,
		"X25519":                x25519DER,
		"unknown algorithm OID": spki(t, asn1.ObjectIdentifier{1, 2, 3, 4}, nil, []byte{1, 2, 3}),
		"P-256 point off curve": spki(t, oidEC, oidP256, offCurve),
		"EC without a curve":    spki(t, oidEC, nil, point),
	} {
		_, err := parsePublicKey(der)
		require.ErrorIs(t, err, errNotADirectoryKey, name)
		// In a rekor row a log ID naming only that entry has no key.
		id := sha256.Sum256(der)
		_, err = Row{raw: map[string]interface{}{"binding": "rekor", "key_ids": []interface{}{hex.EncodeToString(id[:])},
			"public_keys": []interface{}{base64.StdEncoding.EncodeToString(der)}}}.Keys()
		require.Error(t, err, name)
		// Elsewhere the key id is read as a raw Ed25519 key instead.
		keys, err := Row{raw: map[string]interface{}{"key_ids": []interface{}{hex.EncodeToString(id[:])},
			"public_keys": []interface{}{base64.StdEncoding.EncodeToString(der)}}}.Keys()
		require.NoError(t, err, name)
		require.Equal(t, []crypto.PublicKey{ed25519.PublicKey(id[:])}, keys, name)
	}
}

func TestPublicKeysThatAreNotSubjectPublicKeyInfoAreSkipped(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	good, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	require.NoError(t, err)
	for name, der := range map[string][]byte{
		"trailing byte": append(append([]byte(nil), good...), 0),
		"not DER":       []byte("not a key"),
		"empty":         {},
	} {
		id := sha256.Sum256(der)
		entry := base64.StdEncoding.EncodeToString(der)
		// In a rekor row the log ID then names no key: the row is unusable.
		_, err := Row{raw: map[string]interface{}{"binding": "rekor", "key_ids": []interface{}{hex.EncodeToString(id[:])}, "public_keys": []interface{}{entry}}}.Keys()
		require.Error(t, err, name)
		// Elsewhere the key id is read as a raw Ed25519 key, as with no entry.
		keys, err := Row{raw: map[string]interface{}{"key_ids": []interface{}{hex.EncodeToString(id[:])}, "public_keys": []interface{}{entry}}}.Keys()
		require.NoError(t, err, name)
		require.Equal(t, []crypto.PublicKey{ed25519.PublicKey(id[:])}, keys, name)
	}
	// The good key beside a skipped entry is still found.
	id := sha256.Sum256(good)
	keys, err := Row{raw: map[string]interface{}{"binding": "rekor", "key_ids": []interface{}{hex.EncodeToString(id[:])},
		"public_keys": []interface{}{base64.StdEncoding.EncodeToString([]byte("not a key")), base64.StdEncoding.EncodeToString(good)}}}.Keys()
	require.NoError(t, err)
	require.Len(t, keys, 1)
}

func TestDeeplyNestedRekorJSONFailsCleanly(t *testing.T) {
	rekorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	checkpointKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	deep := []byte(strings.Repeat("[", 1_000_000) + strings.Repeat("]", 1_000_000))
	signed := SignedCheckpoint{KeyID: hex.EncodeToString(checkpointKey)}

	record := map[string]interface{}{"ts_url": "rekor+https://r.example", "receipt_b64": base64.StdEncoding.EncodeToString(deep)}
	ok, reason, _ := VerifyReceipt(signed, record, &rekorKey.PublicKey, []byte("cose"))
	require.False(t, ok)
	require.Contains(t, reason, "unreadable receipt")

	// A body nested too deep fails after its Signed Entry Timestamp verifies.
	sum := sha256.Sum256([]byte("cose"))
	entry := rekorEntry(t, rekorKey, checkpointKey, map[string]interface{}{"algorithm": "sha256", "value": hex.EncodeToString(sum[:])})
	body := base64.StdEncoding.EncodeToString(deep)
	logID := entry["logID"].(string)
	digest := sha256.Sum256([]byte(`{"body":"` + body + `","integratedTime":1700000000,"logID":"` + logID + `","logIndex":7}`))
	set, err := ecdsa.SignASN1(rand.Reader, rekorKey, digest[:])
	require.NoError(t, err)
	entry["body"] = body
	entry["verification"] = map[string]interface{}{"signedEntryTimestamp": base64.StdEncoding.EncodeToString(set)}
	require.ErrorContains(t, VerifyRekorEntry(entry, []byte("cose"), signed.KeyID, &rekorKey.PublicKey), "unreadable receipt")
}

func TestKeyIDThatIsNotACurvePointVerifiesNothing(t *testing.T) {
	// The all-0xff key is 32 bytes that are not an Ed25519 point.
	raw := bytes.Repeat([]byte{0xff}, 32)
	keys, err := Row{raw: map[string]interface{}{"key_ids": []interface{}{hex.EncodeToString(raw)}}}.Keys()
	require.NoError(t, err)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, err = VerifyCOSEReceipt(buildReceipt(t, []byte("leaf"), receiptSpec{alg: algEdDSA, vds: 1, key: private}), []byte("leaf"), keys[0])
	require.Error(t, err)
}

func TestDecodeStdBase64IsStrict(t *testing.T) {
	_, err := decodeStdBase64("QQ==")
	require.NoError(t, err)
	// QR== and QUJ= set trailing bits that QQ== and QUI= leave zero.
	for _, bad := range []string{"QQ", "QQ=", "Q Q==", "QQ==\n", "-_8=", "QUJD=", "QR==", "QUJ="} {
		_, err := decodeStdBase64(bad)
		require.Error(t, err, bad)
	}
	raw := []byte{1, 2, 3, 4}
	_, err = decodeStdBase64(nonCanonicalBase64(t, raw))
	require.Error(t, err, "non-zero trailing bits")
}

// nonCanonicalBase64 spells raw (whose length is not a multiple of 3) with
// non-zero trailing bits: it decodes to the same bytes under a lenient
// decoder but does not re-encode to itself.
func nonCanonicalBase64(t *testing.T, raw []byte) string {
	t.Helper()
	require.NotZero(t, len(raw)%3)
	canonical := []byte(base64.StdEncoding.EncodeToString(raw))
	last := bytes.IndexByte(canonical, '=') - 1
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	canonical[last] = alphabet[strings.IndexByte(alphabet, canonical[last])+1]
	decoded, err := base64.StdEncoding.DecodeString(string(canonical))
	require.NoError(t, err)
	require.Equal(t, raw, decoded, "same bytes, other spelling")
	return string(canonical)
}

func TestNonCanonicalReceiptBase64Fails(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signed := SignedCheckpoint{LogID: "log:test", MMRSize: 4, Root: hex.EncodeToString(make([]byte, 32)), KeyID: hex.EncodeToString(public), Timestamp: "2026-10-15T00:00:00Z"}
	digest := CheckpointDigest(signed)
	leaf := sha256.Sum256(digest[:])
	receipt := buildReceipt(t, leaf[:], receiptSpec{alg: algEdDSA, vds: 1, key: private})
	if len(receipt)%3 == 0 {
		receipt = buildReceipt(t, leaf[:], receiptSpec{alg: algEdDSA, vds: 1, key: private, grade: "mmr-verified"})
	}
	require.NotZero(t, len(receipt)%3, "a receipt with trailing bits to set")
	record := map[string]interface{}{"ts_url": "https://w.example", "entry_hash": hex.EncodeToString(leaf[:]),
		"receipt_b64": base64.StdEncoding.EncodeToString(receipt)}
	ok, _, _ := VerifyReceipt(signed, record, public, nil)
	require.True(t, ok)
	record["receipt_b64"] = nonCanonicalBase64(t, receipt)
	ok, _, _ = VerifyReceipt(signed, record, public, nil)
	require.False(t, ok)
}

func TestPyJSONString(t *testing.T) {
	require.Equal(t, "\"a\\\"\\\\\\b\\f\\n\\r\\t\\u0001/<&\\u007f\\u00e9\\ud83d\\ude00\"", pyJSONString("a\"\\\b\f\n\r\t\x01/<&\x7f\u00e9\U0001F600", true))
	require.Equal(t, `"\u0001/<&`+"\x7fé😀"+`"`, pyJSONString("\x01/<&\x7fé😀", false))
}

func TestCheckpointDigestMatchesCLL(t *testing.T) {
	signed := SignedCheckpoint{
		LogID: "log:test", MMRSize: 4, Root: hex.EncodeToString(make([]byte, 32)),
		KeyID: hex.EncodeToString(make([]byte, 32)), Timestamp: "2026-10-15T00:00:00Z",
	}
	stamp, err := time.Parse(time.RFC3339, signed.Timestamp)
	require.NoError(t, err)
	want, err := checkpoint.Payload{LogID: signed.LogID, KeyID: signed.KeyID, MMRSize: signed.MMRSize, Root: signed.Root, Timestamp: stamp}.Digest()
	require.NoError(t, err)
	require.Equal(t, want, CheckpointDigest(signed))
}

// receipt builds a COSE Receipt for leaf at index 0 of a two-leaf tree.
type receiptSpec struct {
	alg       int64
	vds       interface{}
	grade     interface{}
	crit      []interface{}
	attached  bool
	extraBlob []byte
	key       crypto.Signer
	signature []byte // used as is, instead of a signature by key
}

func buildReceipt(t *testing.T, leaf []byte, spec receiptSpec) []byte {
	t.Helper()
	other := sha256.Sum256([]byte{0, 'x'})
	leafHash := sha256.Sum256(append([]byte{0}, leaf...))
	root := nodeHash(leafHash[:], other[:])
	protected := map[interface{}]interface{}{int64(1): spec.alg, int64(395): spec.vds}
	if spec.grade != nil {
		protected[int64(labelGrade)] = spec.grade
	}
	if spec.crit != nil {
		protected[int64(2)] = spec.crit
	}
	protectedBytes, err := deterministicEncoding.Marshal(protected)
	require.NoError(t, err)
	proof, err := deterministicEncoding.Marshal([]interface{}{2, 0, []interface{}{other[:]}})
	require.NoError(t, err)
	proofs := []interface{}{proof}
	if spec.extraBlob != nil {
		proofs = append(proofs, spec.extraBlob)
	}
	tbs := sigStructure(protectedBytes, root)
	signature := spec.signature
	switch key := spec.key.(type) {
	case ed25519.PrivateKey:
		signature = ed25519.Sign(key, tbs)
	case *ecdsa.PrivateKey:
		digest := sha256.Sum256(tbs)
		r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
		require.NoError(t, err)
		size := (key.Curve.Params().BitSize + 7) / 8
		signature = append(r.FillBytes(make([]byte, size)), s.FillBytes(make([]byte, size))...)
	}
	var payload interface{}
	if spec.attached {
		payload = root
	}
	data, err := deterministicEncoding.Marshal(cbor.Tag{Number: 18, Content: []interface{}{
		protectedBytes, map[interface{}]interface{}{int64(396): map[interface{}]interface{}{int64(-1): proofs}}, payload, signature,
	}})
	require.NoError(t, err)
	return data
}

func TestVerifyCOSEReceipt(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leaf := []byte("leaf")
	base := receiptSpec{alg: algEdDSA, vds: 1, key: private}

	checked, err := VerifyCOSEReceipt(buildReceipt(t, leaf, base), leaf, public)
	require.NoError(t, err)
	require.Equal(t, int64(2), checked.TreeSize)
	require.Equal(t, int64(0), checked.LeafIndex)
	require.False(t, checked.GradeLabel)
	require.Nil(t, checked.Grade)

	graded := base
	graded.grade = "countersigned-observed"
	checked, err = VerifyCOSEReceipt(buildReceipt(t, leaf, graded), leaf, public)
	require.NoError(t, err)
	require.Equal(t, GradeObservedOnly, *checked.Grade)
	graded.grade = "other"
	checked, err = VerifyCOSEReceipt(buildReceipt(t, leaf, graded), leaf, public)
	require.NoError(t, err)
	require.True(t, checked.GradeLabel)
	require.Nil(t, checked.Grade)

	understood := base
	understood.crit = []interface{}{int64(395)}
	_, err = VerifyCOSEReceipt(buildReceipt(t, leaf, understood), leaf, public)
	require.NoError(t, err)

	es256 := receiptSpec{alg: algES256, vds: 1, key: ecKey}
	_, err = VerifyCOSEReceipt(buildReceipt(t, leaf, es256), leaf, &ecKey.PublicKey)
	require.NoError(t, err)

	// The alg fixes the key type: ES256 is P-256 only, EdDSA is Ed25519.
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	_, err = VerifyCOSEReceipt(buildReceipt(t, leaf, receiptSpec{alg: algES256, vds: 1, key: p384}), leaf, &p384.PublicKey)
	require.ErrorContains(t, err, "P-256", "a P-384 signature that verifies is still refused")
	for name, key := range map[string]crypto.PublicKey{
		"Ed25519 key": public,
		"no key":      nil,
	} {
		_, err = VerifyCOSEReceipt(buildReceipt(t, leaf, es256), leaf, key)
		require.ErrorContains(t, err, "ES256 needs", name)
	}
	_, err = VerifyCOSEReceipt(buildReceipt(t, leaf, base), leaf, &ecKey.PublicKey)
	require.ErrorContains(t, err, "EdDSA needs")

	refused := map[string]struct {
		receipt []byte
		leaf    []byte
		key     crypto.PublicKey
	}{
		"other leaf":                  {buildReceipt(t, leaf, base), []byte("other"), public},
		"other key":                   {buildReceipt(t, leaf, base), leaf, ed25519.PublicKey(make([]byte, 32))},
		"ES256 key for EdDSA":         {buildReceipt(t, leaf, base), leaf, &ecKey.PublicKey},
		"attached payload":            {buildReceipt(t, leaf, receiptSpec{alg: algEdDSA, vds: 1, key: private, attached: true}), leaf, public},
		"vds 2":                       {buildReceipt(t, leaf, receiptSpec{alg: algEdDSA, vds: 2, key: private}), leaf, public},
		"vds true":                    {buildReceipt(t, leaf, receiptSpec{alg: algEdDSA, vds: true, key: private}), leaf, public},
		"alg ES384":                   {buildReceipt(t, leaf, receiptSpec{alg: -35, vds: 1, key: ecKey}), leaf, &ecKey.PublicKey},
		"unknown critical label":      {buildReceipt(t, leaf, receiptSpec{alg: algEdDSA, vds: 1, key: private, crit: []interface{}{int64(labelGrade)}, grade: "mmr-verified"}), leaf, public},
		"critical label absent":       {buildReceipt(t, leaf, receiptSpec{alg: algEdDSA, vds: 1, key: private, crit: []interface{}{int64(15)}}), leaf, public},
		"malformed second proof":      {buildReceipt(t, leaf, receiptSpec{alg: algEdDSA, vds: 1, key: private, extraBlob: []byte{0x80}}), leaf, public},
		"trailing bytes":              {append(buildReceipt(t, leaf, base), 0), leaf, public},
		"empty":                       {nil, leaf, public},
		"non-minimal length encoding": {nonMinimal(t, buildReceipt(t, leaf, base)), leaf, public},
	}
	for name, c := range refused {
		_, err := VerifyCOSEReceipt(c.receipt, c.leaf, c.key)
		require.Error(t, err, name)
	}
}

// nonMinimal re-encodes the receipt's outer array head in a two-byte form.
func nonMinimal(t *testing.T, receipt []byte) []byte {
	require.Equal(t, byte(0xd2), receipt[0])
	require.Equal(t, byte(0x84), receipt[1])
	return append([]byte{0xd2, 0x98, 0x04}, receipt[2:]...)
}

func TestRootFromInclusionProofBounds(t *testing.T) {
	_, ok := rootFromInclusionProof([]byte("x"), 0, maxTreeSize+1, nil)
	require.False(t, ok)
	_, ok = rootFromInclusionProof([]byte("x"), 1, 1, nil)
	require.False(t, ok)
	_, ok = rootFromInclusionProof([]byte("x"), 0, 2, nil)
	require.False(t, ok, "path too short")
	root, ok := rootFromInclusionProof([]byte("x"), 0, 1, nil)
	require.True(t, ok)
	want := sha256.Sum256([]byte{0, 'x'})
	require.Equal(t, want[:], root)
	size, ok := cborInteger(*new(big.Int).SetInt64(5))
	require.True(t, ok)
	require.Equal(t, int64(5), size)
}

func TestVerifyReceiptsWithoutAnchorOrEntries(t *testing.T) {
	status, findings, receipts := VerifyReceipts(nil, &SignedCheckpoint{}, []byte{1}, Directory{})
	require.Equal(t, StatusWithheld, status)
	require.Equal(t, []string{"witness_receipt_absent"}, findings)
	require.Empty(t, receipts)
	status, findings, _ = VerifyReceipts([]interface{}{map[string]interface{}{}}, nil, nil, Directory{})
	require.Equal(t, StatusWithheld, status)
	require.Equal(t, []string{"checkpoint_unverified"}, findings)

	record := map[string]interface{}{"ts_url": "https://w.example", "entry_hash": "ab", "receipt_b64": "AA==", "leaf_index": 0, "tree_size": 1}
	directory := DirectoryFromValue([]interface{}{map[string]interface{}{"endpoint": "https://w.example", "key_ids": []interface{}{"zz"}}})
	status, findings, receipts = VerifyReceipts([]interface{}{record, "junk"}, &SignedCheckpoint{}, []byte{1}, directory)
	require.Equal(t, StatusFail, status, "a malformed entry fails the witnesses")
	require.Equal(t, []string{"witness_receipt_malformed:1", "witness_unverified:https://w.example"}, findings)
	require.Equal(t, StatusWithheld, receipts[0].Status, "an unusable row key is not checked")
}

// A record whose members are present but empty, of another type, or whose
// receipt_b64 is not canonical standard base64 is malformed, with or without
// a directory row for its witness (vectors/bundle/strict/README.md).
func TestVerifyReceiptsFailsAMalformedMember(t *testing.T) {
	good := func() map[string]interface{} {
		return map[string]interface{}{"ts_url": "https://w.example", "entry_hash": "ab", "receipt_b64": "AA==", "leaf_index": 0, "tree_size": 1}
	}
	for name, edit := range map[string]func(map[string]interface{}){
		"ts_url empty":              func(r map[string]interface{}) { r["ts_url"] = "" },
		"entry_hash empty":          func(r map[string]interface{}) { r["entry_hash"] = "" },
		"entry_hash not a string":   func(r map[string]interface{}) { r["entry_hash"] = true },
		"receipt_b64 empty":         func(r map[string]interface{}) { r["receipt_b64"] = "" },
		"receipt_b64 not a string":  func(r map[string]interface{}) { r["receipt_b64"] = 7 },
		"receipt_b64 not base64":    func(r map[string]interface{}) { r["receipt_b64"] = "!" },
		"receipt_b64 unpadded":      func(r map[string]interface{}) { r["receipt_b64"] = "AA" },
		"receipt_b64 trailing bits": func(r map[string]interface{}) { r["receipt_b64"] = "AB==" },
		"a stub, receipt_b64 empty": func(r map[string]interface{}) { r["is_stub"] = true; r["receipt_b64"] = "" },
	} {
		record := good()
		edit(record)
		status, findings, receipts := VerifyReceipts([]interface{}{record}, &SignedCheckpoint{}, []byte{1}, Directory{})
		require.Equal(t, StatusFail, status, name)
		require.Equal(t, []string{"witness_receipt_malformed:0"}, findings, name)
		require.Empty(t, receipts, name)
	}
	status, findings, _ := VerifyReceipts([]interface{}{good()}, &SignedCheckpoint{}, []byte{1}, Directory{})
	require.Equal(t, StatusWithheld, status)
	require.Equal(t, []string{"witness_unverified:https://w.example"}, findings)
}

// rekorEntry builds a Rekor dsse entry logging a checkpoint under
// checkpointKey with the given payloadHash, and its Signed Entry Timestamp
// under rekorKey.
func rekorEntry(t *testing.T, rekorKey *ecdsa.PrivateKey, checkpointKey ed25519.PublicKey, payloadHash map[string]interface{}) map[string]interface{} {
	t.Helper()
	pemText, err := ed25519PEM(hex.EncodeToString(checkpointKey))
	require.NoError(t, err)
	body, err := json.Marshal(map[string]interface{}{"kind": "dsse", "spec": map[string]interface{}{
		"payloadHash": payloadHash,
		"signatures":  []interface{}{map[string]interface{}{"verifier": base64.StdEncoding.EncodeToString(append(pemText, '\n'))}},
	}})
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&rekorKey.PublicKey)
	require.NoError(t, err)
	logIDSum := sha256.Sum256(der)
	logID := hex.EncodeToString(logIDSum[:])
	encodedBody := base64.StdEncoding.EncodeToString(body)
	signed := `{"body":"` + encodedBody + `","integratedTime":1700000000,"logID":"` + logID + `","logIndex":7}`
	digest := sha256.Sum256([]byte(signed))
	set, err := ecdsa.SignASN1(rand.Reader, rekorKey, digest[:])
	require.NoError(t, err)
	return map[string]interface{}{
		"body": encodedBody, "integratedTime": json.Number("1700000000"), "logID": logID, "logIndex": json.Number("7"),
		"verification": map[string]interface{}{"signedEntryTimestamp": base64.StdEncoding.EncodeToString(set)},
	}
}

func TestVerifyRekorEntryPayloadHash(t *testing.T) {
	rekorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	checkpointKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	cose := []byte("checkpoint statement")
	sum := sha256.Sum256(cose)
	value := hex.EncodeToString(sum[:])
	keyID := hex.EncodeToString(checkpointKey)

	good := rekorEntry(t, rekorKey, checkpointKey, map[string]interface{}{"algorithm": "sha256", "value": value})
	require.NoError(t, VerifyRekorEntry(good, cose, keyID, &rekorKey.PublicKey))
	require.Error(t, VerifyRekorEntry(good, []byte("other"), keyID, &rekorKey.PublicKey))

	for name, payloadHash := range map[string]map[string]interface{}{
		"no algorithm":        {"value": value},
		"another algorithm":   {"algorithm": "sha512", "value": value},
		"algorithm uppercase": {"algorithm": "SHA256", "value": value},
		"algorithm not text":  {"algorithm": 256, "value": value},
	} {
		entry := rekorEntry(t, rekorKey, checkpointKey, payloadHash)
		require.Error(t, VerifyRekorEntry(entry, cose, keyID, &rekorKey.PublicKey), name)
	}

	// Body, Signed Entry Timestamp and verifier must be canonical base64.
	canonicalBody := good["body"].(string)
	bodyBytes, err := base64.StdEncoding.DecodeString(canonicalBody)
	require.NoError(t, err)
	tampered := map[string]interface{}{}
	for name, value := range good {
		tampered[name] = value
	}
	tampered["body"] = nonCanonicalBase64(t, bodyBytes)
	require.Error(t, VerifyRekorEntry(tampered, cose, keyID, &rekorKey.PublicKey))
}

func TestRekorKeyMustBeP256(t *testing.T) {
	checkpointKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	cose := []byte("checkpoint statement")
	sum := sha256.Sum256(cose)
	payloadHash := map[string]interface{}{"algorithm": "sha256", "value": hex.EncodeToString(sum[:])}
	keyID := hex.EncodeToString(checkpointKey)

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	entry := rekorEntry(t, p384, checkpointKey, payloadHash)
	err = VerifyRekorEntry(entry, cose, keyID, &p384.PublicKey)
	require.ErrorContains(t, err, "P-256")

	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	entry = rekorEntry(t, p256, checkpointKey, payloadHash)
	require.NoError(t, VerifyRekorEntry(entry, cose, keyID, &p256.PublicKey))
	require.ErrorContains(t, VerifyRekorEntry(entry, cose, keyID, checkpointKey), "P-256")
}

// singleLeafReceipt signs a COSE Receipt for a one-leaf tree whose vdp
// carries proof as given, byte for byte.
func singleLeafReceipt(t *testing.T, private ed25519.PrivateKey, leaf, proof []byte) []byte {
	t.Helper()
	protected, err := deterministicEncoding.Marshal(map[interface{}]interface{}{int64(1): int64(algEdDSA), int64(395): 1})
	require.NoError(t, err)
	root := sha256.Sum256(append([]byte{0}, leaf...))
	data, err := deterministicEncoding.Marshal(cbor.Tag{Number: 18, Content: []interface{}{
		protected, map[interface{}]interface{}{int64(396): map[interface{}]interface{}{int64(-1): []interface{}{proof}}},
		nil, ed25519.Sign(private, sigStructure(protected, root[:])),
	}})
	require.NoError(t, err)
	return data
}

func TestInclusionProofBlobIsDecodedLeniently(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	leaf := []byte("leaf")
	// [1, 0, []] in shortest form, then with one-byte heads for 1 and 0: the
	// scitt-cose verifiers accept both, refusing only trailing bytes.
	for _, blob := range []string{"83010080", "831801180080"} {
		checked, err := VerifyCOSEReceipt(singleLeafReceipt(t, private, leaf, mustHex(t, blob)), leaf, public)
		require.NoError(t, err, blob)
		require.Equal(t, int64(1), checked.TreeSize, blob)
	}
	_, err = VerifyCOSEReceipt(singleLeafReceipt(t, private, leaf, mustHex(t, "8301008000")), leaf, public)
	require.Error(t, err, "trailing bytes after the proof")
	// The envelope itself stays strict: a widened head there is refused.
	receipt := singleLeafReceipt(t, private, leaf, mustHex(t, "83010080"))
	require.Equal(t, byte(0x84), receipt[1])
	_, err = VerifyCOSEReceipt(append([]byte{0xd2, 0x98, 0x04}, receipt[2:]...), leaf, public)
	require.Error(t, err)
}

// The registration-time edges no shared vector reaches: a negative or text
// iat, and claims without one.
func TestRegistrationTimeEdges(t *testing.T) {
	claims := func(value interface{}) map[interface{}]interface{} {
		return map[interface{}]interface{}{uint64(labelCWTClaims): value}
	}
	for name, test := range map[string]struct {
		protected map[interface{}]interface{}
		want      *int64
		reason    string
	}{
		"no claims":     {map[interface{}]interface{}{}, nil, ReasonIatAbsent},
		"empty claims":  {claims(map[interface{}]interface{}{}), nil, ReasonIatAbsent},
		"other claim":   {claims(map[interface{}]interface{}{uint64(1): "issuer"}), nil, ReasonIatAbsent},
		"negative iat":  {claims(map[interface{}]interface{}{uint64(cwtIat): int64(-1)}), nil, ReasonIatInvalid},
		"text iat":      {claims(map[interface{}]interface{}{uint64(cwtIat): "1792022400"}), nil, ReasonIatInvalid},
		"largest iat":   {claims(map[interface{}]interface{}{uint64(cwtIat): uint64(maxIat)}), ptr(int64(maxIat)), ""},
		"zero iat":      {claims(map[interface{}]interface{}{uint64(cwtIat): uint64(0)}), ptr(int64(0)), ""},
		"claims a list": {claims([]interface{}{}), nil, ReasonIatInvalid},
	} {
		got, reason := registrationTime(test.protected)
		require.Equal(t, test.want, got, name)
		require.Equal(t, test.reason, reason, name)
	}
}

func ptr[T any](value T) *T { return &value }

func TestParseDirectoryRefusesPastTheNestingLimit(t *testing.T) {
	n := canonical.MaxNestingDepth
	_, err := ParseDirectory([]byte("[" + strings.Repeat("[", n-1) + strings.Repeat("]", n-1) + "]"))
	require.NoError(t, err)
	_, err = ParseDirectory([]byte("[" + strings.Repeat("[", n) + strings.Repeat("]", n) + "]"))
	require.Error(t, err)
}
