package evidencerequest

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestProfileReasonsAreTheEightOfSection9_1 keeps the profile on the -01
// registry while ER -02 registers two more (AAC#479 re-pins).
func TestProfileReasonsAreTheEightOfSection9_1(t *testing.T) {
	assert.Equal(t, RefusalReasons[:8], profileRefusalReasons)
	assert.False(t, Refusal{Reason: ReasonCapacityExceeded, IssuedAt: "2026-09-28T00:00:00Z",
		RequestDigest: strings.Repeat("a", 64)}.Conforming())
	assert.NotContains(t, profileRefusalReasons, ReasonCapacityExceeded)
	assert.NotContains(t, profileRefusalReasons, ReasonRequestUnauthenticated)
}
