package verify_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/registries"
	"github.com/action-state-group/agent-action-capsule/go/verify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCrossRecordReferenceVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/references.json")
	require.NoError(t, err)
	var vectors struct {
		Cases []struct {
			Name      string
			Capsule   map[string]interface{}
			Canonical string
			OK        bool
			Codes     []string
		}
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	require.NoError(t, decoder.Decode(&vectors))
	for _, vector := range vectors.Cases {
		t.Run(vector.Name, func(t *testing.T) {
			// The parent exists, but external references deliberately do not.
			result := verify.Verify(vector.Capsule, []interface{}{strings.Repeat("a", 64)}, nil)
			assert.Equal(t, vector.OK, result.OK, result.Findings)
			codes := make([]string, 0, len(result.Findings))
			for _, finding := range result.Findings {
				codes = append(codes, finding.Code)
			}
			assert.Equal(t, vector.Codes, codes)
			encoded, err := canonical.JCS(vector.Capsule)
			require.NoError(t, err)
			assert.Equal(t, vector.Canonical, string(encoded))
			if vector.Name == "future-purpose" {
				known, err := registries.Load("")
				require.NoError(t, err)
				known["citation_purpose"]["example-purpose"] = true
				custom := verify.Verify(vector.Capsule, []interface{}{strings.Repeat("a", 64)}, known)
				assert.True(t, custom.OK)
				assert.Empty(t, custom.Findings)
			}
		})
	}
}

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
