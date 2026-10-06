// SPDX-License-Identifier: BSD-3-Clause
package canonical_test

// Nostr-host profile vectors (vectors/profiles/) — Go parity with the Python reference generator
// python/scripts/generate_profile_vectors.py. For every committed fixture this test re-derives
// each labelled digest with canonical.JSONDigest and applies the same five rule codes the Python
// checker applies, asserting the committed `expect.violations` exactly. TypeScript asserts the
// same files in ts/test/profile-vectors.test.ts.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/stretchr/testify/require"
)

type profileDigestLabel struct {
	Path   string `json:"path"`
	Prefix string `json:"prefix"`
	Label  string `json:"label"`
}

type profileVector struct {
	Expect struct {
		Valid      bool     `json:"valid"`
		Violations []string `json:"violations"`
	} `json:"expect"`
	DigestLabels []profileDigestLabel   `json:"digest_labels"`
	Record       map[string]interface{} `json:"record"`
}

type profileManifest struct {
	Cases []struct {
		File       string   `json:"file"`
		Valid      bool     `json:"valid"`
		Violations []string `json:"violations"`
	} `json:"cases"`
}

var (
	profileHex64    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	profileTextKey  = regexp.MustCompile(`(^|_)(text|message|content|body)(_|$)`)
	profileScoreKey = regexp.MustCompile(`(^|_)(score|rating|rank)(_|$)`)
)

func profileVectorsDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	return filepath.Join(filepath.Dir(filename), "..", "..", "vectors", "profiles")
}

func profileAt(t *testing.T, record map[string]interface{}, path string) string {
	t.Helper()
	var value interface{} = record
	for _, part := range strings.Split(path, ".") {
		switch node := value.(type) {
		case map[string]interface{}:
			value = node[part]
		case []interface{}:
			i, err := strconv.Atoi(part)
			require.NoError(t, err)
			value = node[i]
		default:
			t.Fatalf("path %s: cannot descend into %T", path, value)
		}
	}
	s, ok := value.(string)
	require.True(t, ok, "path %s is not a string", path)
	return s
}

func profileKeys(value interface{}, out *[]string) {
	switch node := value.(type) {
	case map[string]interface{}:
		for k, v := range node {
			*out = append(*out, k)
			profileKeys(v, out)
		}
	case []interface{}:
		for _, v := range node {
			profileKeys(v, out)
		}
	}
}

// checkProfileRecord mirrors check_record in python/scripts/generate_profile_vectors.py.
func checkProfileRecord(record map[string]interface{}) []string {
	found := map[string]bool{}
	var eventID, semantic string
	subject, ok := record["subject"].(map[string]interface{})
	shapeOK := ok && len(subject) == 2
	if shapeOK {
		e, eok := subject["event_id"].(string)
		s, sok := subject["semantic_digest"].(string)
		shapeOK = eok && sok && profileHex64.MatchString(e) && profileHex64.MatchString(s)
		eventID, semantic = e, s
	}
	if !shapeOK {
		found["subject_shape"] = true
	}
	commitments, _ := record["payload_commitments"].([]interface{})
	if shapeOK {
		if semantic == eventID {
			found["event_id_as_digest"] = true
		}
		for _, c := range commitments {
			if m, ok := c.(map[string]interface{}); ok && m["digest"] == eventID {
				found["event_id_as_digest"] = true
			}
		}
	}
	for _, c := range commitments {
		m, ok := c.(map[string]interface{})
		role, rok := m["role"].(string)
		if !ok || !rok || role == "" || role == "semantic_digest" {
			found["body_digest_named"] = true
		}
	}
	var keys []string
	profileKeys(record, &keys)
	for _, k := range keys {
		if profileTextKey.MatchString(k) {
			found["message_text_present"] = true
		}
		if profileScoreKey.MatchString(k) {
			found["score_present"] = true
		}
	}
	out := []string{}
	for code := range found {
		out = append(out, code)
	}
	sort.Strings(out)
	return out
}

func TestProfileVectorsParity(t *testing.T) {
	dir := profileVectorsDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	require.NoError(t, err)
	var manifest profileManifest
	require.NoError(t, json.Unmarshal(raw, &manifest))
	require.Len(t, manifest.Cases, 10)

	for _, c := range manifest.Cases {
		t.Run(c.File, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(c.File)))
			require.NoError(t, err)
			var v profileVector
			require.NoError(t, json.Unmarshal(data, &v))

			require.NotEmpty(t, v.DigestLabels)
			for _, dl := range v.DigestLabels {
				d, err := canonical.JSONDigest(map[string]interface{}{"label": dl.Label})
				require.NoError(t, err)
				require.Equal(t, dl.Prefix+d, profileAt(t, v.Record, dl.Path), dl.Path)
			}

			require.Equal(t, c.Valid, v.Expect.Valid)
			require.Equal(t, c.Violations, v.Expect.Violations)
			require.Equal(t, v.Expect.Violations, checkProfileRecord(v.Record))
		})
	}
}
