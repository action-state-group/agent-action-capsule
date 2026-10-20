// SPDX-License-Identifier: Apache-2.0

package evidencerequest_test

import (
	"context"
	"strings"
	"testing"

	er "github.com/action-state-group/agent-action-capsule/go/evidencerequest"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Verifier's paths the conformance vectors do not reach: malformed
// replies, CBOR, key windows, the online resolver, contracts and content
// evaluation.

const anchorPin = "1111111111111111111111111111111111111111111111111111111111111111"

var interopContract = map[string]any{
	"id": "C", "version": "1",
	"requirements": []any{map[string]any{"id": "r", "profile": "outcome", "statement": "s"}},
}

type answered struct {
	request  er.Message
	envelope er.Envelope
	reply    er.Message
	key      string
}

// answer builds a request for a correlation subject under expected_pin and
// an envelope answering it, signed by the key seeded with seed, carried in
// mediaType.
func answer(t *testing.T, seed byte, mediaType string) answered {
	t.Helper()
	s, key := signer(t, seed)
	req := er.Request{Subject: er.Subject{Kind: er.SubjectCorrelation, Correlation: "deal-a"}, Coverage: er.Coverage{ExpectedPin: anchorPin}, Nonce: "n", Profile: er.ProfileID}
	octets, err := er.EncodeRequest(req, mediaType)
	require.NoError(t, err)
	artifact := []byte(`{"records":[]}`)
	env, err := er.Envelope{
		Profile: er.ProfileID, RequestDigest: er.Digest(octets), Subject: req.Subject, Anchor: er.Anchor{Digest: anchorPin},
		ArtifactDigest: er.Digest(artifact), Responder: key, IssuedAt: "2026-10-15T00:00:00Z", Artifact: artifact,
	}.Sign(context.Background(), s)
	require.NoError(t, err)
	reply, err := er.EncodeReply(mediaType, &env, nil)
	require.NoError(t, err)
	return answered{request: er.Message{Octets: octets, MediaType: mediaType}, envelope: env, reply: reply.Message, key: key}
}

func verifierFor(t *testing.T, trust er.TrustPolicy, policy er.VerificationPolicy) *er.Verifier {
	t.Helper()
	if policy.ProfilesImplemented == nil {
		policy = er.VerificationPolicyFromPin(map[string]any{"online": policy.Online})
		policy.KeyStatus = nil
	}
	v, err := er.NewVerifier(trust, policy, "2026-10-16T00:00:00Z", interopContract)
	require.NoError(t, err)
	return v
}

func verifyOne(t *testing.T, v *er.Verifier, request, reply er.Message) *er.ReplyResult {
	t.Helper()
	res, err := v.Verify([]er.Exchange{{Request: request, Replies: []er.Message{reply}}}, er.VerifyOptions{})
	require.NoError(t, err)
	return res.Exchanges[0].Replies[0]
}

func TestVerifierAcceptsAWellFormedEnvelopeInBothEncodings(t *testing.T) {
	for _, mediaType := range []string{er.MediaTypeJSON, er.MediaTypeCBOR} {
		a := answer(t, 1, mediaType)
		r := verifyOne(t, verifierFor(t, er.TrustPolicy{ResponderKeys: []string{a.key}}, er.VerificationPolicy{}), a.request, a.reply)
		assert.Equal(t, "envelope", r.MessageType, mediaType)
		for _, p := range []string{"profile_version", "envelope_signature", "responder_trust", "issued_at_form", "request_binding", "subject_binding", "artifact_digest", "anchor_match"} {
			assert.Equal(t, er.StatusPass, r.Status(p), "%s %s", mediaType, p)
		}
		assert.Equal(t, er.StatusNotPresent, r.Status("verification_binding"))
		assert.Equal(t, er.StatusNotChecked, r.Status("anchor_inclusion"), "a correlation subject has no CLL method")
		assert.Equal(t, er.StatusNotChecked, r.Status("responder_key_current"))
		assert.Equal(t, "envelope-4", r.Requirements["r"].Row)
		assert.Equal(t, []byte(`{"records":[]}`), r.Artifact)
	}
}

// A duplicate member or an out-of-range number leaves the reply classified
// by its members, but not well formed: its signature cannot pass (§5.2).
func TestVerifierFailsTheSignatureOfAReplyThatIsNotWellFormed(t *testing.T) {
	a := answer(t, 1, er.MediaTypeJSON)
	v := verifierFor(t, er.TrustPolicy{ResponderKeys: []string{a.key}}, er.VerificationPolicy{})
	text := string(a.reply.Octets)
	for name, mutated := range map[string]string{
		"duplicate member": strings.Replace(text, `{"anchor"`, `{"issued_at":"2026-10-15T00:00:00Z","anchor"`, 1),
		"float":            strings.Replace(text, `{"anchor"`, `{"x":1.5,"anchor"`, 1),
		"negative":         strings.Replace(text, `{"anchor"`, `{"x":-1,"anchor"`, 1),
		"above 2^53-1":     strings.Replace(text, `{"anchor"`, `{"x":9007199254740992,"anchor"`, 1),
	} {
		require.NotEqual(t, text, mutated, name)
		r := verifyOne(t, v, a.request, er.Message{Octets: []byte(mutated), MediaType: er.MediaTypeJSON})
		assert.Equal(t, "envelope", r.MessageType, name)
		assert.Equal(t, er.StatusFail, r.Status("envelope_signature"), name)
		assert.Equal(t, er.StatusPass, r.Status("request_binding"), name)
		assert.Equal(t, "envelope-2", r.Requirements["r"].Row, name)
	}
}

func TestVerifierClassifiesWhatIsNotAnEnvelope(t *testing.T) {
	a := answer(t, 1, er.MediaTypeJSON)
	v := verifierFor(t, er.TrustPolicy{ResponderKeys: []string{a.key}}, er.VerificationPolicy{})
	for octets, want := range map[string]string{
		`not json`:                             "not_a_response",
		`[1,2]`:                                "not_a_response",
		`{"other":1}`:                          "not_a_response",
		`{"artifact_digest":"x","reason":"y"}`: "received_and_failed",
	} {
		r := verifyOne(t, v, a.request, er.Message{Octets: []byte(octets), MediaType: er.MediaTypeJSON})
		assert.Equal(t, want, r.MessageType, octets)
	}
	r := verifyOne(t, v, a.request, er.Message{Octets: a.reply.Octets, MediaType: "text/plain"})
	assert.Equal(t, "not_a_response", r.MessageType)
	res, err := v.Verify([]er.Exchange{{Request: a.request, Replies: []er.Message{{Octets: []byte(`[`), MediaType: er.MediaTypeJSON}}}}, er.VerifyOptions{})
	require.NoError(t, err)
	assert.True(t, res.Exchanges[0].Pending(), "a transport condition leaves the request pending")
	assert.Empty(t, res.Exchanges[0].Replies[0].Requirements)
}

func TestVerifierRefusesARequestThatIsNotAMap(t *testing.T) {
	v := verifierFor(t, er.TrustPolicy{}, er.VerificationPolicy{})
	_, err := v.Verify([]er.Exchange{{Request: er.Message{Octets: []byte(`{"a":1,"a":2}`), MediaType: er.MediaTypeJSON}}}, er.VerifyOptions{})
	assert.ErrorIs(t, err, er.ErrInvalid)
}

func TestVerifierTrustsAKeyOnlyInsideItsWindow(t *testing.T) {
	a := answer(t, 1, er.MediaTypeJSON)
	trust, err := er.TrustPolicyFromPin(map[string]any{
		"responder_keys": []any{a.key},
		"key_validity":   map[string]any{a.key: map[string]any{"not_before": "2026-10-16T00:00:00Z"}},
	})
	require.NoError(t, err)
	r := verifyOne(t, verifierFor(t, trust, er.VerificationPolicy{}), a.request, a.reply)
	assert.Equal(t, er.StatusFail, r.Status("responder_trust"), "issued before the window opened")

	trust.KeyValidity = nil
	r = verifyOne(t, verifierFor(t, trust, er.VerificationPolicy{}), a.request, a.reply)
	assert.Equal(t, er.StatusPass, r.Status("responder_trust"))

	r = verifyOne(t, verifierFor(t, er.TrustPolicy{ResponderKeys: []string{strings.Repeat("0", 64)}}, er.VerificationPolicy{}), a.request, a.reply)
	assert.Equal(t, er.StatusFail, r.Status("responder_trust"), "a key the policy does not list")

	_, err = er.TrustPolicyFromPin(map[string]any{"key_validity": map[string]any{a.key: map[string]any{"not_after": "yesterday"}}})
	assert.ErrorIs(t, err, er.ErrInvalid)
}

func TestVerifierAsksTheResolverOnlyWhenOnline(t *testing.T) {
	a := answer(t, 1, er.MediaTypeJSON)
	asked := 0
	policy := er.VerificationPolicyFromPin(map[string]any{"online": true})
	policy.KeyStatus = func(key, at string) (string, string) {
		asked++
		assert.Equal(t, a.key, key)
		assert.Equal(t, "2026-10-16T00:00:00Z", at)
		return er.StatusFail, "revocation list"
	}
	v := verifierFor(t, er.TrustPolicy{ResponderKeys: []string{a.key}}, policy)
	r := verifyOne(t, v, a.request, a.reply)
	assert.Equal(t, er.StatusFail, r.Status("responder_key_current"))
	assert.Equal(t, 1, asked)
	assert.Equal(t, "envelope-4", r.Requirements["r"].Row, "responder_key_current is reported separately, never required")
}

func TestVerifierChecksTheAnchorUnderEitherCoverage(t *testing.T) {
	s, key := signer(t, 1)
	v := verifierFor(t, er.TrustPolicy{ResponderKeys: []string{key}}, er.VerificationPolicy{})
	five := uint64(5)
	for _, c := range []struct {
		name      string
		coverage  er.Coverage
		freshness any
		want      string
	}{
		{"size meets the floor", er.Coverage{MinFreshness: &er.Freshness{Size: &five}}, uint64(7), er.StatusPass},
		{"size below the floor", er.Coverage{MinFreshness: &er.Freshness{Size: &five}}, uint64(4), er.StatusFail},
		{"time meets the floor", er.Coverage{MinFreshness: &er.Freshness{Time: "2026-10-01T00:00:00Z"}}, "2026-10-02T00:00:00Z", er.StatusPass},
		{"time in the wrong type", er.Coverage{MinFreshness: &er.Freshness{Time: "2026-10-01T00:00:00Z"}}, uint64(9), er.StatusFail},
		{"no freshness", er.Coverage{MinFreshness: &er.Freshness{Size: &five}}, nil, er.StatusNotPresent},
	} {
		req := er.Request{Subject: er.Subject{Kind: er.SubjectCorrelation, Correlation: "deal-a"}, Coverage: c.coverage, Nonce: "n", Profile: er.ProfileID}
		octets, err := er.EncodeRequest(req, er.MediaTypeJSON)
		require.NoError(t, err, c.name)
		anchor := map[string]any{"digest": anchorPin}
		if c.freshness != nil {
			anchor["freshness"] = c.freshness
		}
		artifact := []byte("{}")
		value := map[string]any{"profile": er.ProfileID, "request_digest": er.Digest(octets), "subject": req.Subject.Value(), "anchor": anchor,
			"artifact_digest": er.Digest(artifact), "responder": key, "issued_at": "2026-10-15T00:00:00Z"}
		body, err := er.EncodeJCS(value)
		require.NoError(t, err)
		sig, _ := s.Sign(context.Background(), body)
		value["sig"] = hexOf(sig)
		value["artifact"] = artifact
		reply, err := er.EncodeJCS(value)
		require.NoError(t, err)
		r := verifyOne(t, v, er.Message{Octets: octets, MediaType: er.MediaTypeJSON}, er.Message{Octets: reply, MediaType: er.MediaTypeJSON})
		assert.Equal(t, c.want, r.Status("anchor_match"), c.name)
		assert.Equal(t, er.StatusPass, r.Status("envelope_signature"), c.name)
	}
}

func TestVerifierMapsARefusalByItsReason(t *testing.T) {
	a := answer(t, 1, er.MediaTypeJSON)
	s, key := signer(t, 1)
	v := verifierFor(t, er.TrustPolicy{ResponderKeys: []string{key}}, er.VerificationPolicy{})
	for reason, row := range map[string]string{
		er.ReasonNotAuthorized: "refusal-withheld", er.ReasonNoSuchSubject: "refusal-no_such_subject",
		er.ReasonDeadlineUnmet: "refusal-deadline_or_malformed", er.ReasonRetentionExpired: "refusal-retention_expired",
		"unregistered": "refusal-failed",
	} {
		refusal, err := er.Refusal{RequestDigest: er.Digest(a.request.Octets), Reason: reason, IssuedAt: "2026-10-15T00:00:00Z", KeyID: key}.Sign(context.Background(), s)
		require.NoError(t, err)
		octets, err := er.EncodeJCS(refusal.Value())
		require.NoError(t, err)
		r := verifyOne(t, v, a.request, er.Message{Octets: octets, MediaType: er.MediaTypeJSON})
		assert.Equal(t, "refusal", r.MessageType, reason)
		assert.Equal(t, row, r.Requirements["r"].Row, reason)
		assert.Equal(t, reason, r.Reason)
		if row == "refusal-withheld" {
			assert.Equal(t, []string{"analysis", "story"}, r.Requirements["r"].PresentationKindsAllowed())
		}
	}
}

func TestVerifierRefusesAContractItCannotEvaluate(t *testing.T) {
	_, err := er.NewVerifier(er.TrustPolicy{}, er.VerificationPolicy{}, "not a time", nil)
	assert.ErrorIs(t, err, er.ErrInvalid)
	twice := map[string]any{"id": "C", "version": "1", "requirements": []any{map[string]any{"id": "r"}, map[string]any{"id": "r"}}}
	_, err = er.NewVerifier(er.TrustPolicy{}, er.VerificationPolicy{}, "2026-10-16T00:00:00Z", twice)
	assert.ErrorIs(t, err, er.ErrInvalid)
	v := verifierFor(t, er.TrustPolicy{}, er.VerificationPolicy{})
	assert.Equal(t, "C@1", v.ContractRef())
	a := answer(t, 1, er.MediaTypeJSON)
	_, err = v.Verify([]er.Exchange{{Request: a.request}}, er.VerifyOptions{Requirements: []string{"missing"}})
	assert.ErrorIs(t, err, er.ErrInvalid)
}

// Row 7: with every required property PASS and no failed native check,
// the requirement is the content evaluator's, which may not claim met
// without SATISFIED (§8.2 invariant 1). The corpus's valid exchange is a
// record subject with CLL material, so it reaches row 7.
func TestVerifierRowSevenGoesToTheContentEvaluator(t *testing.T) {
	var corpus struct {
		Contract struct {
			Document map[string]any `json:"document"`
		} `json:"contract"`
		Cases []struct {
			ID     string     `json:"id"`
			Pins   vectorPins `json:"pins"`
			Inputs struct {
				Request vectorMessage   `json:"request"`
				Replies []vectorMessage `json:"replies"`
			} `json:"inputs"`
		} `json:"cases"`
	}
	readCorpus(t, "interop-profile-v0", &corpus)
	for _, c := range corpus.Cases {
		if c.ID != "valid-exchange" {
			continue
		}
		v := newVerifier(t, c.Pins, corpus.Contract.Document)
		ex := []er.Exchange{{Request: c.Inputs.Request.message(t), Replies: []er.Message{c.Inputs.Replies[0].message(t)}}}
		var seen []byte
		res, err := v.Verify(ex, er.VerifyOptions{Requirements: []string{"r-record"},
			Content: func(_ map[string]any, artifact []byte, native *er.PropertyReport) (string, string, bool) {
				seen = artifact
				assert.Nil(t, native)
				return "SATISFIED", "met", true
			}})
		require.NoError(t, err)
		r := res.Exchanges[0].Replies[0]
		assert.Equal(t, r.Artifact, seen)
		got := r.Requirements["r-record"]
		assert.Equal(t, []string{"envelope-7", "SATISFIED", "SATISFIED", "met"}, []string{got.Row, got.Status, got.Sufficiency, got.Verdict})
		assert.Len(t, r.Proofs, 1, "an inclusion proof backs the claim")

		_, err = v.Verify(ex, er.VerifyOptions{Requirements: []string{"r-record"},
			Content: func(map[string]any, []byte, *er.PropertyReport) (string, string, bool) {
				return "INSUFFICIENT", "met", true
			}})
		assert.Error(t, err, "met without SATISFIED breaks §8.2 invariant 1")
		_, err = v.Verify(ex, er.VerifyOptions{Requirements: []string{"r-record"},
			Content: func(map[string]any, []byte, *er.PropertyReport) (string, string, bool) { return "PROVEN", "met", true }})
		assert.Error(t, err, "not an Evidence Contract status")
		res, err = v.Verify(ex, er.VerifyOptions{Requirements: []string{"r-record"},
			Content: func(map[string]any, []byte, *er.PropertyReport) (string, string, bool) {
				return "NOT_APPLICABLE", "", true
			}})
		require.NoError(t, err)
		assert.Empty(t, res.Exchanges[0].Replies[0].Requirements, "NOT_APPLICABLE leaves the evaluated population")
		return
	}
	t.Fatal("no valid-exchange case")
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[2*i], out[2*i+1] = digits[c>>4], digits[c&15]
	}
	return string(out)
}

// A CBOR map with a key that is not text is outside the data model (§5.2)
// whatever its other members are named: a text member that names the
// marker the decoder might use cannot stand in for it, in any map order.
func TestVerifierFailsACBORMapWithANonTextKey(t *testing.T) {
	a := answer(t, 1, er.MediaTypeCBOR)
	v := verifierFor(t, er.TrustPolicy{ResponderKeys: []string{a.key}}, er.VerificationPolicy{})
	var reply map[any]any
	require.NoError(t, cbor.Unmarshal(a.reply.Octets, &reply))
	reply["extra"] = map[any]any{uint64(1): "x", "\x00non-text key": "y", "z": "w"}
	octets, err := cbor.Marshal(reply)
	require.NoError(t, err)
	for range 20 {
		r := verifyOne(t, v, a.request, er.Message{Octets: octets, MediaType: er.MediaTypeCBOR})
		require.Equal(t, "envelope", r.MessageType)
		assert.Equal(t, er.StatusFail, r.Status("envelope_signature"))
	}
}
