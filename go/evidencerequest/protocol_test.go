// SPDX-License-Identifier: Apache-2.0

package evidencerequest_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"testing"
	"time"

	er "github.com/action-state-group/agent-action-capsule/go/evidencerequest"
	"github.com/action-state-group/checkpointed-local-log/go/mmr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func digestOf(s string) string { return er.Digest([]byte(s)) }

func sizeFloor(n uint64) *er.Freshness { return &er.Freshness{Size: &n} }

func encodeRequest(t *testing.T, req er.Request, mediaType string) er.Message {
	t.Helper()
	octets, err := er.EncodeRequest(req, mediaType)
	require.NoError(t, err)
	return er.Message{Octets: octets, MediaType: mediaType}
}

// The request reader's refusals, from evidencebook's responder tests: the
// first failing rule of profile §6.1 decides the reason.
func TestParseRequestReasons(t *testing.T) {
	record, pin := digestOf("record"), digestOf("anchor")
	subject := `"subject":{"record":"` + record + `"}`
	coverage := `"coverage":{"expected_pin":"` + pin + `"}`
	cases := []struct{ name, octets, reason string }{
		{"malformed JSON", `{"subject":`, er.ReasonRequestMalformed},
		{"trailing bytes", `{` + subject + `,` + coverage + `} {}`, er.ReasonRequestMalformed},
		{"duplicate member", `{` + subject + `,` + subject + `,` + coverage + `}`, er.ReasonRequestMalformed},
		{"case-variant member is not the member", `{"SUBJECT":{"record":"` + record + `"},` + coverage + `}`, er.ReasonRequestMalformed},
		{"old subject shape", `{"subject":{"kind":"record","digest":"` + record + `"},` + coverage + `}`, er.ReasonRequestMalformed},
		{"deadline not a time", `{` + subject + `,` + coverage + `,"deadline":"whenever"}`, er.ReasonRequestMalformed},
		{"deadline with an offset", `{` + subject + `,` + coverage + `,"deadline":"2026-01-01T00:00:00+01:00"}`, er.ReasonRequestMalformed},
		{"nonce not text", `{` + subject + `,` + coverage + `,"nonce":7}`, er.ReasonRequestMalformed},
		{"range above 2^53-1", `{"subject":{"range":[0,9007199254740992]},` + coverage + `}`, er.ReasonRequestMalformed},
		{"range negative", `{"subject":{"range":[-1,2]},` + coverage + `}`, er.ReasonRequestMalformed},
		{"empty correlation", `{"subject":{"correlation":""},` + coverage + `}`, er.ReasonRequestMalformed},
		{"invalid UTF-8", "{\"subject\":{\"correlation\":\"\xff\"}," + coverage + "}", er.ReasonRequestMalformed},
		{"unpaired surrogate in a value", `{"subject":{"correlation":"c-\ud800"},` + coverage + `}`, er.ReasonRequestMalformed},
		{"unpaired surrogate in a key", `{` + subject + `,` + coverage + `,"x\udc00":1}`, er.ReasonRequestMalformed},
		{"paired surrogates", `{"subject":{"correlation":"c-\ud83d\ude00"},` + coverage + `}`, ""},
		{"both coverage members", `{` + subject + `,"coverage":{"expected_pin":"` + pin + `","min_freshness":1}}`, er.ReasonCoverageUnsatisfiable},
		{"no coverage member", `{` + subject + `,"coverage":{}}`, er.ReasonCoverageUnsatisfiable},
		{"coverage missing", `{` + subject + `}`, er.ReasonCoverageUnsatisfiable},
		{"unknown profile", `{` + subject + `,` + coverage + `,"profile":"evidence-interop/9"}`, er.ReasonRequestMalformed},
		{"pin alone", `{` + subject + `,` + coverage + `}`, ""},
		{"unknown member is ignored", `{` + subject + `,` + coverage + `,"page":{"size":10,"x":-1.5}}`, ""},
		{"fractional deadline", `{` + subject + `,` + coverage + `,"deadline":"2026-01-01T00:00:00.5Z"}`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := er.ParseRequest(er.Message{Octets: []byte(c.octets), MediaType: er.MediaTypeJSON})
			assert.Equal(t, c.reason, got.Reason, got.Why)
		})
	}
	unknown := er.ParseRequest(er.Message{Octets: []byte(`{` + subject + `,` + coverage + `,"profile":"evidence-interop/9"}`), MediaType: er.MediaTypeJSON})
	assert.Equal(t, "profiles supported: evidence-interop/0, evidence-interop/1", unknown.Detail,
		"an unknown profile's refusal lists the ones supported")
	plain := er.ParseRequest(er.Message{Octets: []byte(`{` + subject + `,` + coverage + `}`), MediaType: er.MediaTypeJSON})
	assert.Equal(t, er.ProfileID, plain.Request.Profile, "a request without a profile asks for evidence-interop/0 (v1 §3.3 step 2)")
	assert.Empty(t, plain.Detail)
	v1 := er.ParseRequest(er.Message{Octets: []byte(`{` + subject + `,` + coverage + `,"profile":"evidence-interop/1"}`), MediaType: er.MediaTypeJSON})
	assert.Empty(t, v1.Reason, v1.Why)
	assert.Equal(t, er.ProfileIDv1, v1.Request.Profile)
}

// A request round-trips through either encoding, and Request.Value refuses
// one a responder would refuse.
func TestEncodeRequest(t *testing.T) {
	requests := []er.Request{
		{Subject: er.Subject{Kind: er.SubjectFullHistory}, Coverage: er.Coverage{MinFreshness: sizeFloor(3)}, Derivation: er.DerivationHistoryCard, Profile: er.ProfileID},
		{Subject: er.Subject{Kind: er.SubjectRecord, Digest: digestOf("r")}, Coverage: er.Coverage{ExpectedPin: digestOf("a")}, Nonce: "n", Route: "https://a.example/?x=<1>&y=2", Profile: er.ProfileID},
		{Subject: er.Subject{Kind: er.SubjectRange, Range: [2]uint64{1, 4}}, Coverage: er.Coverage{MinFreshness: &er.Freshness{Time: "2026-01-01T00:00:00Z"}}, Deadline: "2026-01-02T00:00:00Z", Profile: er.ProfileID},
		{Subject: er.Subject{Kind: er.SubjectCorrelation, Correlation: "c-1"}, Coverage: er.Coverage{ExpectedPin: digestOf("a")}, Derivation: digestOf("def"), Profile: er.ProfileID},
		{Subject: er.Subject{Kind: er.SubjectExchange, Digest: digestOf("half")}, Coverage: er.Coverage{ExpectedPin: digestOf("half")}, Profile: er.ProfileID},
		{Subject: er.Subject{Kind: er.SubjectCheckpoints}, Coverage: er.Coverage{ExpectedPin: digestOf("a")}, Profile: er.ProfileID},
	}
	for _, req := range requests {
		for _, mediaType := range []string{er.MediaTypeJSON, er.MediaTypeCBOR} {
			m := encodeRequest(t, req, mediaType)
			got := er.ParseRequest(m)
			require.Empty(t, got.Reason, got.Why)
			assert.Equal(t, req, got.Request, "%s %s", req.Subject.Kind, mediaType)
			again, err := er.EncodeRequest(got.Request, mediaType)
			require.NoError(t, err)
			assert.Equal(t, m.Octets, again, "the encoding is deterministic")
		}
	}
	jcs := encodeRequest(t, requests[1], er.MediaTypeJSON)
	assert.Contains(t, string(jcs.Octets), `"route":"https://a.example/?x=<1>&y=2"`, "JCS does not escape HTML characters")

	invalid := map[string]er.Request{
		"no subject":            {Coverage: er.Coverage{ExpectedPin: digestOf("a")}},
		"record without digest": {Subject: er.Subject{Kind: er.SubjectRecord}, Coverage: er.Coverage{ExpectedPin: digestOf("a")}},
		"reversed range":        {Subject: er.Subject{Kind: er.SubjectRange, Range: [2]uint64{4, 1}}, Coverage: er.Coverage{ExpectedPin: digestOf("a")}},
		"two forms":             {Subject: er.Subject{Kind: er.SubjectFullHistory, Digest: digestOf("r")}, Coverage: er.Coverage{ExpectedPin: digestOf("a")}},
		"both coverage members": {Subject: er.Subject{Kind: er.SubjectCheckpoints}, Coverage: er.Coverage{ExpectedPin: digestOf("a"), MinFreshness: sizeFloor(1)}},
		"no coverage member":    {Subject: er.Subject{Kind: er.SubjectCheckpoints}},
		"pin not a digest":      {Subject: er.Subject{Kind: er.SubjectCheckpoints}, Coverage: er.Coverage{ExpectedPin: "abc"}},
		"floor size and time":   {Subject: er.Subject{Kind: er.SubjectCheckpoints}, Coverage: er.Coverage{MinFreshness: &er.Freshness{Size: new(uint64), Time: "2026-01-01T00:00:00Z"}}},
		"floor time malformed":  {Subject: er.Subject{Kind: er.SubjectCheckpoints}, Coverage: er.Coverage{MinFreshness: &er.Freshness{Time: "yesterday"}}},
		"derivation malformed":  {Subject: er.Subject{Kind: er.SubjectCheckpoints}, Coverage: er.Coverage{ExpectedPin: digestOf("a")}, Derivation: "History_Card"},
		"deadline malformed":    {Subject: er.Subject{Kind: er.SubjectCheckpoints}, Coverage: er.Coverage{ExpectedPin: digestOf("a")}, Deadline: "soon"},
	}
	for name, req := range invalid {
		_, err := er.EncodeRequest(req, er.MediaTypeJSON)
		assert.ErrorIs(t, err, er.ErrInvalid, name)
	}
	_, err := er.EncodeRequest(requests[0], "application/cbor; charset=x")
	assert.ErrorIs(t, err, er.ErrInvalid, "a media type is compared exactly")
}

// A request in deterministic CBOR is digested as received: a
// non-deterministic encoding of the same map is the same request with a
// different digest, never re-canonicalized. Octets that are not one
// well-formed map are request_malformed.
func TestCBORRequestDigestedAsReceived(t *testing.T) {
	req := er.Request{Subject: er.Subject{Kind: er.SubjectRecord, Digest: digestOf("r")}, Coverage: er.Coverage{ExpectedPin: digestOf("a")}, Nonce: "n", Profile: er.ProfileID}
	deterministic := encodeRequest(t, req, er.MediaTypeCBOR)
	// The same map with a non-minimal length head for its first key.
	loose := append([]byte{deterministic.Octets[0], 0x78, deterministic.Octets[1] - 0x60}, deterministic.Octets[2:]...)
	got := er.ParseRequest(er.Message{Octets: loose, MediaType: er.MediaTypeCBOR})
	require.Empty(t, got.Reason, got.Why)
	assert.Equal(t, req, got.Request)
	assert.NotEqual(t, er.Digest(deterministic.Octets), er.Digest(loose))

	for name, octets := range map[string][]byte{
		"trailing byte":   append(slices.Clone(deterministic.Octets), 0x00),
		"duplicate key":   duplicateFirstKey(deterministic.Octets),
		"not a map":       {0x80},
		"truncated":       deterministic.Octets[:len(deterministic.Octets)-1],
		"integer map key": {0xa1, 0x01, 0x01},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, er.ReasonRequestMalformed, er.ParseRequest(er.Message{Octets: octets, MediaType: er.MediaTypeCBOR}).Reason)
		})
	}
	_, err := er.Decode(er.Message{Octets: deterministic.Octets, MediaType: "application/cbor; charset=x"})
	assert.ErrorIs(t, err, er.ErrInvalid, "a media type is compared exactly")
	assert.Equal(t, er.ReasonRequestMalformed, er.ParseRequest(er.Message{Octets: deterministic.Octets, MediaType: "application/CBOR"}).Reason)
}

// duplicateFirstKey repeats the first member of a deterministic CBOR map of
// fewer than 23 members whose first member is a short text key and a short
// text value.
func duplicateFirstKey(m []byte) []byte {
	count := m[0] & 0x1f
	keyLen := int(m[1] & 0x1f)
	first := m[1 : 1+1+keyLen]
	value := m[1+1+keyLen:]
	valueLen := 1 + int(value[0]&0x1f)
	member := append(slices.Clone(first), value[:valueLen]...)
	out := []byte{0xa0 | (count + 1)}
	out = append(out, member...)
	return append(out, m[1:]...)
}

// EncodeJCS is RFC 8785: its §3.2.3 example string, with every escaping rule
// in it, comes out byte for byte, and members sort by key. Integers within
// 2^53-1 are plain decimals; a float or a larger integer is refused.
func TestEncodeJCS(t *testing.T) {
	decoded, err := er.DecodeJSON([]byte(`{"numbers":[0,100,9007199254740991],"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/","literals":[null,true,false]}`))
	require.NoError(t, err)
	got, err := er.EncodeJCS(decoded)
	require.NoError(t, err)
	assert.Equal(t, `{"literals":[null,true,false],"numbers":[0,100,9007199254740991],"string":"€$\u000f\nA'B\"\\\\\"/"}`, string(got))
	for _, refused := range []string{`[4.50]`, `[1E2]`, `[9007199254740993]`} {
		decoded, err := er.DecodeJSON([]byte(refused))
		require.NoError(t, err)
		_, err = er.EncodeJCS(decoded)
		assert.Error(t, err, "%s: a number outside the integer profile is refused", refused)
	}
	_, err = er.EncodeJCS(map[string]any{"n": uint64(er.MaxSafeInteger + 1)})
	assert.ErrorIs(t, err, er.ErrInvalid)
	_, err = er.EncodeCBOR(map[string]any{"n": uint64(er.MaxSafeInteger + 1)})
	assert.ErrorIs(t, err, er.ErrInvalid)
	_, err = er.EncodeCBOR(map[string]any{"f": 1.5})
	assert.ErrorIs(t, err, er.ErrInvalid)
	bin, err := er.EncodeJCS(map[string]any{"b": []byte{0xfb, 0xff}})
	require.NoError(t, err)
	assert.Equal(t, `{"b":"-_8"}`, string(bin), "bytes are base64url without padding in JSON")

	deep := bytes.Repeat([]byte("["), 40)
	_, err = er.DecodeJSON(append(deep, bytes.Repeat([]byte("]"), 40)...))
	assert.Error(t, err, "nesting is bounded")
}

func TestTimes(t *testing.T) {
	for s, ok := range map[string]bool{
		"2026-01-01T00:00:00Z": true, "2026-01-01T00:00:00.123Z": true,
		"2026-01-01T00:00:00.123456789Z": true, "2026-01-01T00:00:00.1234567891Z": false,
		"2026-01-01T00:00:00.Z":     false,
		"2026-01-01T00:00:00+00:00": false, "2026-01-01t00:00:00z": false, "2026-13-01T00:00:00Z": false,
	} {
		_, got := er.ParseRequestTime(s)
		assert.Equal(t, ok, got, s)
	}
	_, ok := er.ParseProfileTime("2026-01-01T00:00:00.5Z")
	assert.False(t, ok, "the profile's time form has no fraction")
	assert.Equal(t, "2026-01-01T00:00:01Z", er.ProfileTime(time.Date(2026, 1, 1, 0, 0, 1, 999, time.FixedZone("x", 0))))
}

func signer(t *testing.T, seed byte) (seededSigner, string) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	return seededSigner{key}, hex.EncodeToString(key.Public().(ed25519.PublicKey))
}

// The refusal signature covers exactly request_digest, reason and
// issued_at in JCS, so changing any of them, or the key, breaks it.
func TestRefusalSignatureCoversReasonAndTime(t *testing.T) {
	s, keyID := signer(t, 1)
	original, err := er.Refusal{RequestDigest: digestOf("req"), Reason: er.ReasonRequestMalformed, IssuedAt: "2026-09-28T00:00:00Z", KeyID: keyID, Detail: "outside the signature"}.Sign(context.Background(), s)
	require.NoError(t, err)
	require.NoError(t, original.Verify())
	require.NoError(t, original.VerifyFor(keyID, digestOf("req")))
	body, err := original.SigningBody()
	require.NoError(t, err)
	assert.Equal(t, `{"issued_at":"2026-09-28T00:00:00Z","reason":"request_malformed","request_digest":"`+digestOf("req")+`"}`, string(body))
	_, otherKey := signer(t, 9)
	for name, mutate := range map[string]func(r *er.Refusal){
		"reason":  func(r *er.Refusal) { r.Reason = er.ReasonPolicyDeclined },
		"time":    func(r *er.Refusal) { r.IssuedAt = "2020-01-01T00:00:00Z" },
		"request": func(r *er.Refusal) { r.RequestDigest = digestOf("other") },
		"key":     func(r *er.Refusal) { r.KeyID = otherKey },
		"sig case": func(r *er.Refusal) {
			r.Sig = string(bytes.ToUpper([]byte(r.Sig)))
		},
	} {
		forged := original
		mutate(&forged)
		assert.Error(t, forged.Verify(), "a refusal with a changed %s verifies", name)
	}
	detail := original
	detail.Detail = "other prose"
	assert.NoError(t, detail.Verify(), "detail is outside the signature")
	assert.Error(t, original.VerifyFor(otherKey, digestOf("req")), "another responder's key")
	assert.Error(t, original.VerifyFor(keyID, digestOf("other")), "another request")
	unregistered, err := er.Refusal{RequestDigest: digestOf("req"), Reason: "no_such_record", IssuedAt: "2026-09-28T00:00:00Z", KeyID: keyID}.Sign(context.Background(), s)
	require.NoError(t, err)
	assert.NoError(t, unregistered.Verify(), "the signature alone does not judge the reason")
	assert.False(t, unregistered.Conforming())
	assert.Error(t, unregistered.VerifyFor(keyID, digestOf("req")))
	capacity, err := er.Refusal{RequestDigest: digestOf("req"), Reason: er.ReasonCapacityExceeded, IssuedAt: "2026-09-28T00:00:00Z", KeyID: keyID}.Sign(context.Background(), s)
	require.NoError(t, err)
	assert.Error(t, capacity.VerifyFor(keyID, digestOf("req")), "capacity_exceeded is unregistered under evidence-interop/0")
	assert.NoError(t, capacity.VerifyForProfile(er.ProfileIDv1, keyID, digestOf("req")), "and registered under /1")
	assert.Error(t, capacity.VerifyForProfile(er.ProfileIDv1, otherKey, digestOf("req")), "another responder's key")

	for _, mediaType := range []string{er.MediaTypeJSON, er.MediaTypeCBOR} {
		reply, err := er.EncodeReply(mediaType, nil, &original)
		require.NoError(t, err)
		parsed, err := er.ParseReply(reply.Message)
		require.NoError(t, err)
		require.NotNil(t, parsed.Refusal)
		assert.Equal(t, original, *parsed.Refusal)
		check := er.CheckRefusal(reply.Message)
		assert.Equal(t, er.RefusalCheck{SignatureValid: true, ReasonRegistered: true, Conformant: true}, check)
	}
}

// An envelope round-trips through either encoding and verifies; a changed
// artifact, verification item or signed member does not.
func TestEnvelope(t *testing.T) {
	s, keyID := signer(t, 2)
	size := uint64(42)
	artifact := []byte(`{"records":[]}`)
	material := [][]byte{[]byte("checkpoint"), []byte("proof")}
	unsigned := er.Envelope{
		Profile: er.ProfileID, RequestDigest: digestOf("req"), Subject: er.Subject{Kind: er.SubjectRange, Range: [2]uint64{0, 2}},
		Anchor: er.Anchor{Digest: digestOf("anchor"), FreshnessSize: &size}, ArtifactDigest: er.Digest(artifact),
		Verification: []er.VerificationEntry{{Kind: er.KindCLLCheckpoint, Digest: er.Digest(material[0])}, {Kind: er.KindCLLInclusionProof, Digest: er.Digest(material[1])}},
		Responder:    keyID, IssuedAt: "2026-09-28T00:00:00Z", Artifact: artifact, VerificationContent: material,
	}
	e, err := unsigned.Sign(context.Background(), s)
	require.NoError(t, err)
	require.NoError(t, e.Verify())
	for _, mediaType := range []string{er.MediaTypeJSON, er.MediaTypeCBOR} {
		reply, err := er.EncodeReply(mediaType, &e, nil)
		require.NoError(t, err)
		parsed, err := er.ParseReply(reply.Message)
		require.NoError(t, err)
		require.NotNil(t, parsed.Envelope)
		assert.Equal(t, e, *parsed.Envelope)
		assert.NoError(t, parsed.Envelope.Verify())
	}
	jsonReply, err := er.EncodeReply(er.MediaTypeJSON, &e, nil)
	require.NoError(t, err)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(jsonReply.Octets, &raw))
	_, isText := raw["artifact"].(string)
	assert.True(t, isText, "in JSON the artifact is base64url text")

	for name, mutate := range map[string]func(e *er.Envelope){
		"artifact":     func(e *er.Envelope) { e.Artifact = []byte(`{}`) },
		"material":     func(e *er.Envelope) { e.VerificationContent = [][]byte{material[0], []byte("other")} },
		"missing item": func(e *er.Envelope) { e.VerificationContent = material[:1] },
		"subject":      func(e *er.Envelope) { e.Subject.Range[1] = 3 },
		"anchor":       func(e *er.Envelope) { e.Anchor.FreshnessSize = nil },
		"derivation":   func(e *er.Envelope) { e.Derivation = er.DerivationHistoryCard },
	} {
		forged := e
		mutate(&forged)
		assert.ErrorIs(t, forged.Verify(), er.ErrInvalid, name)
	}
	_, err = er.EncodeReply(er.MediaTypeJSON, &e, &er.Refusal{})
	assert.ErrorIs(t, err, er.ErrInvalid, "a reply is exactly one of an envelope or a refusal")
}

// ParseReply refuses what it cannot authenticate as exactly one reply.
func TestParseReplyRefuses(t *testing.T) {
	for name, octets := range map[string]string{
		"both":              `{"artifact_digest":"x","reason":"no_such_subject"}`,
		"neither":           `{"error":"timeout"}`,
		"not a map":         `[]`,
		"duplicate":         `{"reason":"a","reason":"b"}`,
		"reason not text":   `{"request_digest":"a","reason":["a"],"issued_at":"t","key_id":"k","sig":"s"}`,
		"refusal missing":   `{"reason":"no_such_subject"}`,
		"anchor extra":      `{"profile":"p","request_digest":"a","artifact_digest":"b","responder":"r","issued_at":"t","sig":"s","subject":{"checkpoints":null},"anchor":{"digest":"d","x":1},"artifact":""}`,
		"empty derivation":  `{"profile":"p","request_digest":"a","artifact_digest":"b","responder":"r","issued_at":"t","sig":"s","derivation":"","subject":{"checkpoints":null},"anchor":{"digest":"d"},"artifact":""}`,
		"artifact not b64":  `{"profile":"p","request_digest":"a","artifact_digest":"b","responder":"r","issued_at":"t","sig":"s","subject":{"checkpoints":null},"anchor":{"digest":"d"},"artifact":"a="}`,
		"bad verification":  `{"profile":"p","request_digest":"a","artifact_digest":"b","responder":"r","issued_at":"t","sig":"s","subject":{"checkpoints":null},"anchor":{"digest":"d"},"artifact":"","verification":[{"kind":"k"}]}`,
		"envelope subject":  `{"profile":"p","request_digest":"a","artifact_digest":"b","responder":"r","issued_at":"t","sig":"s","subject":{"kind":"record"},"anchor":{"digest":"d"},"artifact":""}`,
		"freshness invalid": `{"profile":"p","request_digest":"a","artifact_digest":"b","responder":"r","issued_at":"t","sig":"s","subject":{"checkpoints":null},"anchor":{"digest":"d","freshness":-1},"artifact":""}`,
		// Present and empty: the signer would have covered it, SigningBody omits it.
		"empty verification": `{"profile":"p","request_digest":"a","artifact_digest":"b","responder":"r","issued_at":"t","sig":"s","subject":{"checkpoints":null},"anchor":{"digest":"d"},"artifact":"","verification":[]}`,
	} {
		_, err := er.ParseReply(er.Message{Octets: []byte(octets), MediaType: er.MediaTypeJSON})
		assert.ErrorIs(t, err, er.ErrInvalid, name)
	}
}

// testView is a log of records at positions 0..n-1, every record servable
// unless listed in hidden, with anchors at the given entry counts.
type testView struct {
	records     []string
	hidden      map[uint64]bool
	anchors     []er.AnchorView
	correlation map[string][]uint64
	citations   map[string][]uint64
	lapsed      map[er.Subject]bool
}

func (v testView) Anchors() []er.AnchorView { return v.anchors }
func (v testView) LogEntries() uint64       { return uint64(len(v.records)) }
func (v testView) LeafOf(d string) (uint64, bool) {
	i := slices.Index(v.records, d)
	return uint64(i), i >= 0 && v.Servable(uint64(i))
}
func (v testView) Servable(leaf uint64) bool {
	return leaf < uint64(len(v.records)) && !v.hidden[leaf]
}
func (v testView) Correlated(id string) []uint64         { return v.correlation[id] }
func (v testView) Citing(half string) []uint64           { return v.citations[half] }
func (v testView) Lapsed(s er.Subject, _ time.Time) bool { return v.lapsed[s] }
func anchorAt(entries uint64, issued time.Time) er.AnchorView {
	return er.AnchorView{Digest: digestOf(string(rune('a' + entries))), Entries: entries, IssuedAt: issued}
}

// Decide's ordering and resolution, from evidencebook's responder tests.
func TestDecide(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	records := []string{digestOf("r0"), digestOf("r1"), digestOf("r2"), digestOf("r3"), digestOf("r4")}
	half := digestOf("half")
	view := testView{
		records: records, hidden: map[uint64]bool{3: true},
		anchors:     []er.AnchorView{anchorAt(2, now.Add(-2*time.Hour)), anchorAt(4, now.Add(-time.Hour))},
		correlation: map[string][]uint64{"c-1": {1, 0}, "c-late": {4}},
		citations:   map[string][]uint64{half: {1}},
		lapsed:      map[er.Subject]bool{{Kind: er.SubjectRecord, Digest: digestOf("gone")}: true},
	}
	pin := view.anchors[1].Digest
	record := func(i int) er.Subject { return er.Subject{Kind: er.SubjectRecord, Digest: records[i]} }
	byPin := func(s er.Subject) er.Request { return er.Request{Subject: s, Coverage: er.Coverage{ExpectedPin: pin}} }
	registered := func(name string) ([]er.SubjectKind, bool) {
		if name == "count/1" {
			return []er.SubjectKind{er.SubjectFullHistory}, true
		}
		return nil, false
	}
	cases := []struct {
		name   string
		req    er.Request
		policy er.Policy
		reason string
		anchor int
		leaves []uint64
	}{
		{name: "record under the pin", req: byPin(record(1)), anchor: 1, leaves: []uint64{1}},
		{name: "record beyond the anchor is coverage, not absence", req: er.Request{Subject: record(2), Coverage: er.Coverage{ExpectedPin: view.anchors[0].Digest}}, reason: er.ReasonCoverageUnsatisfiable},
		{name: "unanchored record is coverage", req: er.Request{Subject: record(4), Coverage: er.Coverage{ExpectedPin: pin}}, reason: er.ReasonCoverageUnsatisfiable},
		{name: "hidden record is not held", req: byPin(record(3)), reason: er.ReasonNoSuchSubject},
		{name: "lapsed commitment", req: byPin(er.Subject{Kind: er.SubjectRecord, Digest: digestOf("gone")}), reason: er.ReasonRetentionExpired},
		{name: "full history skips the hidden", req: byPin(er.Subject{Kind: er.SubjectFullHistory}), anchor: 1, leaves: []uint64{0, 1, 2}},
		{name: "checkpoints", req: byPin(er.Subject{Kind: er.SubjectCheckpoints}), anchor: 1},
		{name: "range", req: byPin(er.Subject{Kind: er.SubjectRange, Range: [2]uint64{1, 3}}), anchor: 1, leaves: []uint64{1, 2}},
		{name: "range past the anchor inside the log", req: byPin(er.Subject{Kind: er.SubjectRange, Range: [2]uint64{1, 4}}), reason: er.ReasonCoverageUnsatisfiable},
		{name: "range past the log", req: byPin(er.Subject{Kind: er.SubjectRange, Range: [2]uint64{1, 9}}), reason: er.ReasonNoSuchSubject},
		{name: "range of hidden only", req: byPin(er.Subject{Kind: er.SubjectRange, Range: [2]uint64{3, 3}}), reason: er.ReasonNoSuchSubject},
		{name: "correlation sorted", req: byPin(er.Subject{Kind: er.SubjectCorrelation, Correlation: "c-1"}), anchor: 1, leaves: []uint64{0, 1}},
		{name: "correlation beyond the anchor", req: byPin(er.Subject{Kind: er.SubjectCorrelation, Correlation: "c-late"}), reason: er.ReasonCoverageUnsatisfiable},
		{name: "correlation case-folded", req: byPin(er.Subject{Kind: er.SubjectCorrelation, Correlation: "C-1"}), reason: er.ReasonNoSuchSubject},
		{name: "exchange pinned by its own half", req: er.Request{Subject: er.Subject{Kind: er.SubjectExchange, Digest: half}, Coverage: er.Coverage{ExpectedPin: half}}, anchor: 0, leaves: []uint64{1}},
		{name: "exchange half not cited", req: er.Request{Subject: er.Subject{Kind: er.SubjectExchange, Digest: digestOf("x")}, Coverage: er.Coverage{ExpectedPin: digestOf("x")}}, reason: er.ReasonNoSuchSubject},
		{name: "size floor met by the newest", req: er.Request{Subject: record(0), Coverage: er.Coverage{MinFreshness: sizeFloor(2)}}, anchor: 1, leaves: []uint64{0}},
		{name: "size floor beyond the log", req: er.Request{Subject: record(0), Coverage: er.Coverage{MinFreshness: sizeFloor(9)}}, policy: er.Policy{MayIssue: true}, reason: er.ReasonCoverageUnsatisfiable},
		{name: "time floor in the future", req: er.Request{Subject: record(0), Coverage: er.Coverage{MinFreshness: &er.Freshness{Time: "2026-09-29T00:00:00Z"}}}, policy: er.Policy{MayIssue: true}, reason: er.ReasonCoverageUnsatisfiable},
		{name: "deadline passed", req: er.Request{Subject: record(0), Coverage: er.Coverage{ExpectedPin: pin}, Deadline: "2026-09-28T12:00:00Z"}, reason: er.ReasonDeadlineUnmet},
		{name: "history card for a record", req: er.Request{Subject: record(0), Coverage: er.Coverage{ExpectedPin: pin}, Derivation: er.DerivationHistoryCard}, policy: er.Policy{Uniform: true}, reason: er.ReasonNoSuchSubject},
		{name: "derivation unsupported", req: er.Request{Subject: record(0), Coverage: er.Coverage{ExpectedPin: pin}, Derivation: "other/1"}, policy: er.Policy{Derivation: registered}, reason: er.ReasonDerivationUnsupported},
		{name: "derivation not for this form", req: er.Request{Subject: record(0), Coverage: er.Coverage{ExpectedPin: pin}, Derivation: "count/1"}, policy: er.Policy{Derivation: registered}, reason: er.ReasonNoSuchSubject},
		{name: "derivation for this form", req: er.Request{Subject: er.Subject{Kind: er.SubjectFullHistory}, Coverage: er.Coverage{ExpectedPin: pin}, Derivation: "count/1"}, policy: er.Policy{Derivation: registered}, anchor: 1, leaves: []uint64{0, 1, 2}},
		{name: "not authorized", req: byPin(record(0)), policy: er.Policy{Authorize: func(er.Request) bool { return false }}, reason: er.ReasonNotAuthorized},
		{name: "not authorized, uniform", req: byPin(record(0)), policy: er.Policy{Uniform: true, Authorize: func(er.Request) bool { return false }}, reason: er.ReasonPolicyDeclined},
		{name: "derivation unsupported before authorization", req: er.Request{Subject: record(0), Coverage: er.Coverage{ExpectedPin: pin}, Derivation: "other/1"}, policy: er.Policy{Authorize: func(er.Request) bool { return false }}, reason: er.ReasonDerivationUnsupported},
		{name: "uniform hides absence", req: byPin(record(3)), policy: er.Policy{Uniform: true}, reason: er.ReasonPolicyDeclined},
		{name: "uniform keeps retention_expired", req: byPin(er.Subject{Kind: er.SubjectRecord, Digest: digestOf("gone")}), policy: er.Policy{Uniform: true}, reason: er.ReasonRetentionExpired},
		{name: "unanchored mechanism", req: byPin(record(0)), policy: er.Policy{Unanchored: true}, reason: er.ReasonCoverageUnsatisfiable},
		{name: "unpositioned range", req: byPin(er.Subject{Kind: er.SubjectRange, Range: [2]uint64{0, 1}}), policy: er.Policy{Unpositioned: true}, reason: er.ReasonCoverageUnsatisfiable},
		{name: "unpositioned record", req: byPin(record(0)), policy: er.Policy{Unpositioned: true}, anchor: 1, leaves: []uint64{0}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := er.Decide(view, c.req, c.policy, now)
			assert.False(t, got.NeedAnchor)
			assert.Equal(t, c.reason, got.Reason)
			if c.reason == "" {
				assert.Equal(t, c.anchor, got.Anchor)
				assert.Equal(t, c.leaves, got.Leaves)
			}
		})
	}

	// A floor no anchor meets yet but the log can: the responder that may
	// issue is asked to; one that may not refuses.
	floor := er.Request{Subject: record(4), Coverage: er.Coverage{MinFreshness: sizeFloor(5)}}
	assert.True(t, er.Decide(view, floor, er.Policy{MayIssue: true}, now).NeedAnchor)
	assert.Equal(t, er.ReasonCoverageUnsatisfiable, er.Decide(view, floor, er.Policy{}, now).Reason)
	grown := view
	grown.anchors = append(slices.Clone(view.anchors), anchorAt(5, now))
	assert.Equal(t, []uint64{4}, er.Decide(grown, floor, er.Policy{MayIssue: true}, now).Leaves)
	timed := er.Request{Subject: record(0), Coverage: er.Coverage{MinFreshness: &er.Freshness{Time: er.ProfileTime(now.Add(-90 * time.Minute))}}}
	assert.Equal(t, 1, er.Decide(view, timed, er.Policy{}, now).Anchor, "the newest anchor issued no earlier than the floor")
	assert.True(t, er.AnchorMeets(er.AnchorView{IssuedAt: now.Add(500 * time.Millisecond)}, &er.Freshness{Time: er.ProfileTime(now)}, now), "issued_at is compared at seconds precision")
}

func TestPolicyDisclose(t *testing.T) {
	for _, reason := range er.RefusalReasons {
		assert.Equal(t, reason, er.Policy{}.Disclose(reason))
		want := reason
		if slices.Contains([]string{er.ReasonNotAuthorized, er.ReasonNoSuchSubject, er.ReasonCoverageUnsatisfiable}, reason) {
			want = er.ReasonPolicyDeclined
		}
		assert.Equal(t, want, er.Policy{Uniform: true}.Disclose(reason))
	}
}

// The MMR helpers and the CLL material checks agree with the Checkpointed
// Local Log's own tree: every leaf's inclusion proof reaches a peak, every
// consistency proof reaches the later peaks, and a changed octet fails.
func TestCLLMaterialAgainstTheLogTree(t *testing.T) {
	tree, err := mmr.New(nil)
	require.NoError(t, err)
	var entries [][]byte
	var sizes []uint64
	for i := range 13 {
		entry := sha256.Sum256([]byte{byte(i)})
		entries = append(entries, entry[:])
		_, err := tree.Append(entry[:])
		require.NoError(t, err)
		sizes = append(sizes, tree.Size())
	}
	for _, size := range sizes {
		peaks, err := tree.PeakHashesAt(size)
		require.NoError(t, err)
		require.Len(t, er.MMRPeaks(size-1), len(peaks))
		leaves := uint64(0)
		for i := range size {
			if er.MMRIndexHeight(i) == 0 {
				leaves++
			}
		}
		for leaf := range leaves {
			proof, err := tree.InclusionProofAt(leaf, size)
			require.NoError(t, err)
			assert.Equal(t, uint64(0), er.MMRIndexHeight(er.MMRLeafIndex(leaf)))
			octets, err := er.EncodeCLLInclusionProof(leaf, proof.Witness)
			require.NoError(t, err)
			require.NoError(t, er.VerifyCLLInclusion(peaks, entries[leaf], octets), "leaf %d at size %d", leaf, size)
			other := slices.Clone(entries[leaf])
			other[0] ^= 1
			assert.ErrorIs(t, er.VerifyCLLInclusion(peaks, other, octets), er.ErrInvalid)
			if len(proof.Witness) > 0 {
				tampered := slices.Clone(octets)
				tampered[len(tampered)-1] ^= 1
				assert.ErrorIs(t, er.VerifyCLLInclusion(peaks, entries[leaf], tampered), er.ErrInvalid)
			}
		}
	}
	for i, oldSize := range sizes {
		for _, newSize := range sizes[i:] {
			proof, err := tree.ConsistencyProofAt(oldSize, newSize)
			require.NoError(t, err)
			roots := er.MMRConsistentRoots(oldSize-1, proof.OldPeaks, proof.Witness)
			require.LessOrEqual(t, len(roots), len(proof.NewPeaks))
			right := proof.NewPeaks[len(roots):]
			octets, err := er.EncodeCLLConsistencyProof(oldSize, newSize, proof.Witness, right)
			require.NoError(t, err)
			require.NoError(t, er.VerifyCLLConsistency(proof.OldPeaks, proof.NewPeaks, octets), "%d to %d", oldSize, newSize)
			changed := slices.Clone(proof.OldPeaks)
			changed[0] = make([]byte, sha256.Size)
			assert.ErrorIs(t, er.VerifyCLLConsistency(changed, proof.NewPeaks, octets), er.ErrInvalid)
		}
	}
	for name, octets := range map[string][]byte{
		"not CBOR":    {0xff},
		"not a pair":  {0x80},
		"not a leaf":  mustCBOR(t, []any{uint64(2), []any{}}),
		"short node":  mustCBOR(t, []any{uint64(0), []any{[]byte{1}}}),
		"index float": {0x82, 0xf9, 0x3c, 0x00, 0x80},
	} {
		assert.ErrorIs(t, er.VerifyCLLInclusion(nil, entries[0], octets), er.ErrInvalid, name)
	}
	assert.ErrorIs(t, er.VerifyCLLConsistency(nil, nil, mustCBOR(t, []any{uint64(0), uint64(1), []any{}, []any{}})), er.ErrInvalid, "size 0")

	// Paths too long for any MMR are refused before a position can overflow.
	node := make([]byte, sha256.Size)
	long := func(n int) []any { return byteStringList(slices.Repeat([][]byte{node}, n)) }
	for _, n := range []int{53, 64} {
		assert.ErrorIs(t, er.VerifyCLLInclusion(nil, entries[0], mustCBOR(t, []any{uint64(0), long(n)})), er.ErrInvalid, "%d siblings", n)
		assert.ErrorIs(t, er.VerifyCLLConsistency([][]byte{node}, [][]byte{node}, mustCBOR(t, []any{uint64(1), uint64(1), []any{long(n)}, []any{}})), er.ErrInvalid, "%d siblings", n)
	}
	assert.ErrorIs(t, er.VerifyCLLInclusion(nil, entries[0], mustCBOR(t, []any{uint64(0), long(52)})), er.ErrInvalid, "a 52-sibling path is followed and reaches no peak")
	tall := mustCBOR(t, []any{uint64(er.MaxSafeInteger), uint64(er.MaxSafeInteger), []any{long(52)}, []any{}})
	assert.NotPanics(t, func() {
		_ = er.VerifyCLLConsistency(slices.Repeat([][]byte{node}, len(er.MMRPeaks(er.MaxSafeInteger-1))), nil, tall)
	})
}

func byteStringList(nodes [][]byte) []any {
	out := make([]any, len(nodes))
	for i, n := range nodes {
		out[i] = n
	}
	return out
}

func mustCBOR(t *testing.T, v any) []byte {
	t.Helper()
	octets, err := er.EncodeCBOR(v)
	require.NoError(t, err)
	return octets
}

// A retention commitment names a record, an exchange or a range, in either
// encoding.
func TestParseRetentionCommitment(t *testing.T) {
	value := map[string]any{"evidence_stream": "s", "subject": er.Subject{Kind: er.SubjectRange, Range: [2]uint64{1, 2}}.Value(), "until": "2027-01-01T00:00:00Z"}
	for _, mediaType := range []string{er.MediaTypeJSON, er.MediaTypeCBOR} {
		octets, err := er.Encode(mediaType, value)
		require.NoError(t, err)
		c, err := er.ParseRetentionCommitment(er.Message{Octets: octets, MediaType: mediaType})
		require.NoError(t, err)
		assert.Equal(t, er.RetentionCommitment{EvidenceStream: "s", Subject: er.Subject{Kind: er.SubjectRange, Range: [2]uint64{1, 2}}, Until: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}, c)
	}
	for name, octets := range map[string]string{
		"reversed range": `{"evidence_stream":"s","subject":{"range":[3,2]},"until":"2027-01-01T00:00:00Z"}`,
		"prefix digest":  `{"evidence_stream":"s","subject":{"record":"abc"},"until":"2027-01-01T00:00:00Z"}`,
		"two forms":      `{"evidence_stream":"s","subject":{"record":"` + digestOf("r") + `","range":[1,2]},"until":"2027-01-01T00:00:00Z"}`,
		"no stream":      `{"subject":{"record":"` + digestOf("r") + `"},"until":"2027-01-01T00:00:00Z"}`,
		"until offset":   `{"evidence_stream":"s","subject":{"record":"` + digestOf("r") + `"},"until":"2027-01-01T00:00:00+00:00"}`,
	} {
		_, err := er.ParseRetentionCommitment(er.Message{Octets: []byte(octets), MediaType: er.MediaTypeJSON})
		assert.ErrorIs(t, err, er.ErrInvalid, name)
	}
}

// The three-state discipline holds for every reason and window, beyond the
// cases the vectors enumerate.
func TestObservationState(t *testing.T) {
	for _, open := range []bool{true, false} {
		for _, conformant := range []bool{true, false} {
			state := er.Observation{Received: er.ReceivedRefusal, Refusal: er.RefusalCheck{SignatureValid: true, ReasonRegistered: true, Conformant: conformant}, WindowOpen: open}.State()
			assert.NotContains(t, []string{er.StateRecordedAbsence, er.StatePending}, state, "a signed refusal is never an absence")
		}
		state := er.Observation{Received: er.ReceivedRefusal, Refusal: er.RefusalCheck{ReasonRegistered: true}, WindowOpen: open}.State()
		assert.Equal(t, er.StateRefusalSignatureInvalid, state)
		for _, silence := range []er.Received{er.ReceivedNothing, er.ReceivedTransportError, er.ReceivedSubprotocolNotOffered} {
			want := er.StateRecordedAbsence
			if open {
				want = er.StatePending
			}
			assert.Equal(t, want, er.Observation{Received: silence, WindowOpen: open}.State())
		}
	}
	assert.Equal(t, er.RetentionNoCommitment, er.ClassifyRefusal(er.CommitmentNone, er.ReasonNoSuchSubject))
	assert.Equal(t, er.AbsenceAttemptOnly, er.ClassifyAbsence(er.CommitmentLapsed))
	assert.Equal(t, er.InvarianceHolds, er.CompareAnswers(nil))
}
