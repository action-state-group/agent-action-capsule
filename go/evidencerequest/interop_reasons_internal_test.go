package evidencerequest

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestProfileReasonsAreTheEightOfSection9_1 keeps evidence-interop/0 on the
// -01 registry while ER -02 registers two more.
func TestProfileReasonsAreTheEightOfSection9_1(t *testing.T) {
	assert.Equal(t, RefusalReasons[:8], profileRefusalReasons)
	assert.False(t, Refusal{Reason: ReasonCapacityExceeded, IssuedAt: "2026-09-28T00:00:00Z",
		RequestDigest: strings.Repeat("a", 64)}.Conforming())
	assert.NotContains(t, profileRefusalReasons, ReasonCapacityExceeded)
	assert.NotContains(t, profileRefusalReasons, ReasonRequestUnauthenticated)
}

// TestV1ReasonsAreTheTenOfER02 is evidence-interop/1 §9.1, and §6.3's
// reading of a refusal by the identifier its request asks for.
func TestV1ReasonsAreTheTenOfER02(t *testing.T) {
	assert.Equal(t, RefusalReasons, refusalReasonsByProfile[ProfileIDv1])
	assert.Len(t, RefusalReasons, 10)
	both := []string{ProfileID, ProfileIDv1}
	for _, c := range []struct {
		asked       any
		implemented []string
		registered  bool
	}{
		{ProfileIDv1, both, true},
		{ProfileIDv1, []string{ProfileIDv1}, true},
		{ProfileID, both, false},
		{ProfileID, []string{ProfileID}, false},
		{"evidence-interop/9", both, true}, // every token of the identifiers implemented
		{"evidence-interop/9", []string{ProfileID}, false},
		{nil, both, true}, // a profile member that is not text names no identifier
	} {
		assert.Equal(t, c.registered, slices.Contains(refusalReasonsFor(c.asked, c.implemented), ReasonCapacityExceeded), "%v under %v", c.asked, c.implemented)
	}
	r := Refusal{Reason: ReasonCapacityExceeded, IssuedAt: "2026-09-28T00:00:00Z", RequestDigest: strings.Repeat("a", 64)}
	assert.True(t, r.ConformingUnder(ProfileIDv1))
	assert.False(t, r.ConformingUnder(ProfileID))
	assert.True(t, r.ConformingUnder("evidence-interop/9"))
	r.Reason = ReasonPolicyDeclined
	assert.True(t, r.ConformingUnder(ProfileID))
}

// TestV2KeepsV1ReasonsAndSignsPolicyDigest is evidence-interop/2 §6.3: the
// ten tokens of v1, and a signing input chosen by the identifier the request
// asks for, or every one implemented when it asks for another.
func TestV2KeepsV1ReasonsAndSignsPolicyDigest(t *testing.T) {
	assert.Equal(t, RefusalReasons, refusalReasonsByProfile[ProfileIDv2])
	ref := map[string]any{"issued_at": "t", "reason": "r", "request_digest": "d", "policy_digest": "p", "detail": "x", "key_id": "k", "sig": "s"}
	a7 := map[string]any{"issued_at": "t", "reason": "r", "request_digest": "d"}
	v2 := map[string]any{"issued_at": "t", "reason": "r", "request_digest": "d", "policy_digest": "p"}
	for _, c := range []struct {
		asked       any
		implemented []string
		want        map[string]map[string]any
	}{
		{ProfileIDv2, Profiles, map[string]map[string]any{ProfileIDv2: v2}},
		{ProfileIDv1, Profiles, map[string]map[string]any{ProfileIDv1: a7}},
		{ProfileID, Profiles, map[string]map[string]any{ProfileID: a7}},
		{ProfileIDv2, []string{ProfileIDv1}, map[string]map[string]any{ProfileIDv1: a7}},
		{"evidence-interop/9", Profiles, map[string]map[string]any{ProfileID: a7, ProfileIDv1: a7, ProfileIDv2: v2}},
		{nil, nil, map[string]map[string]any{ProfileID: a7}},
	} {
		assert.Equal(t, c.want, refusalSigningInputs(ref, c.asked, c.implemented), "%v under %v", c.asked, c.implemented)
	}
	assert.True(t, refusalPolicyDigestMalformed(ref, ProfileIDv2, Profiles))
	assert.False(t, refusalPolicyDigestMalformed(ref, ProfileIDv1, Profiles), "outside the signature under /1")
	assert.False(t, refusalPolicyDigestMalformed(ref, ProfileIDv2, []string{ProfileIDv1}), "a verifier without /2 does not read it as signed")
	ref["policy_digest"] = strings.Repeat("a", 64)
	assert.False(t, refusalPolicyDigestMalformed(ref, ProfileIDv2, Profiles))
}
