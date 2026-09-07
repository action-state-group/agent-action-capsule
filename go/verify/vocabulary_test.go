package verify_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/verify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPythonVocabularyOutcomes(t *testing.T) {
	data, err := os.ReadFile("testdata/vocabulary.json")
	require.NoError(t, err)
	type finding struct {
		Code     string
		Severity string
	}
	var vectors struct {
		Cases []struct {
			Name      string
			Capsule   map[string]interface{}
			OK        bool
			Assurance map[string]string
			Findings  []finding
		}
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	require.NoError(t, decoder.Decode(&vectors))
	for _, vector := range vectors.Cases {
		t.Run(vector.Name, func(t *testing.T) {
			result := verify.Verify(vector.Capsule, nil, nil)
			assert.Equal(t, vector.OK, result.OK)
			assert.Equal(t, vector.Assurance, result.Assurance)
			actual := make([]finding, 0, len(result.Findings))
			for _, f := range result.Findings {
				actual = append(actual, finding{f.Code, f.Severity})
			}
			assert.Equal(t, vector.Findings, actual)
		})
	}
}
