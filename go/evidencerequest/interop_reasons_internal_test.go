package evidencerequest

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestProfileReasonsAreTheEightOfSection9_1 keeps the profile on the -01
// registry while ER -02 registers two more (AAC#479 re-pins).
func TestProfileReasonsAreTheEightOfSection9_1(t *testing.T) {
	assert.Equal(t, []string{
		"not_authorized", "no_such_subject", "coverage_unsatisfiable", "derivation_unsupported",
		"policy_declined", "deadline_unmet", "request_malformed", "retention_expired",
	}, profileRefusalReasons)
	assert.NotContains(t, profileRefusalReasons, ReasonCapacityExceeded)
	assert.NotContains(t, profileRefusalReasons, ReasonRequestUnauthenticated)
}
