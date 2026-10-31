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
