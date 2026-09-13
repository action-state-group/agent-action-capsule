package verify_test

import (
	"strings"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/verify"
	"github.com/stretchr/testify/assert"
)

// References must not move check 6/8 diagnostics ahead of structural errors.
func TestReferenceFindingsFollowCheckOrder(t *testing.T) {
	capsule := loadCapsule(t, "pos-executed-confirmed")
	capsule["format_version"] = "4"
	delete(capsule, "operator")
	capsule["chain"] = map[string]interface{}{"parent_capsule_id": strings.Repeat("a", 64), "relation": "confirms"}
	capsule["references"] = []interface{}{
		map[string]interface{}{"type": "agent-action-capsule", "digest_alg": "SHA-256", "digest": strings.Repeat("a", 64), "citation_purpose": "future-purpose"},
	}
	result := verify.Verify(capsule, nil, nil)
	last := 0
	codes := []string{}
	for _, finding := range result.Findings {
		if finding.Check != nil {
			assert.GreaterOrEqual(t, *finding.Check, last)
			last = *finding.Check
		}
		codes = append(codes, finding.Code)
	}
	assert.Contains(t, codes, "missing_required_field")
	assert.Contains(t, codes, "reference_duplicates_chain_parent")
	assert.Contains(t, codes, "unknown_registry_value")
}
