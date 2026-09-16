// SPDX-License-Identifier: BSD-3-Clause
package emitter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/bundle"
	"github.com/stretchr/testify/require"
)

// bundleMarker matches the same window.__BUNDLE__ = ...;</script> slot the
// TypeScript tamper test (ts/test/report-tamper.test.ts) parses -- both
// languages tamper the same shared fixture and expect the same class of
// verifier disagreement, in each language's own bundle verifier.
var bundleMarker = regexp.MustCompile(`(?s)window\.__BUNDLE__ = (.*);</script>`)

func loadWeekBundle(t *testing.T) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "ts", "test", "testdata", "week-bundle.json"))
	require.NoError(t, err)
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	var value map[string]interface{}
	require.NoError(t, decoder.Decode(&value))
	return value
}

func extractBundle(t *testing.T, html string) map[string]interface{} {
	t.Helper()
	match := bundleMarker.FindStringSubmatch(html)
	require.Len(t, match, 2, "embedded bundle not found in report.html")
	decoder := json.NewDecoder(strings.NewReader(match[1]))
	decoder.UseNumber()
	var value map[string]interface{}
	require.NoError(t, decoder.Decode(&value))
	return value
}

func passes(result bundle.VerificationResult) bool {
	if result.GraphClosure.Status != "pass" || result.IntervalCoverage.Status != "pass" || result.PerRecordMembership.Status != "pass" {
		return false
	}
	for _, capsule := range result.CapsuleResults {
		if !capsule.OK {
			return false
		}
	}
	return true
}

func TestReportHTMLTamperUntampered(t *testing.T) {
	source := loadWeekBundle(t)
	html, err := EmitEvidenceGraphHTML(source, []byte("/*IIFE_MARKER*/"))
	require.NoError(t, err)
	require.True(t, passes(bundle.VerifyBundle(extractBundle(t, html))))
}

// TestReportHTMLTamperEditNumber: edit a number in the emitted report.html
// itself (the checkpoint's mmr_size) -- the recomputed row must disagree.
func TestReportHTMLTamperEditNumber(t *testing.T) {
	source := loadWeekBundle(t)
	html, err := EmitEvidenceGraphHTML(source, []byte("/*IIFE_MARKER*/"))
	require.NoError(t, err)

	checkpoint := source["checkpoint"].(map[string]interface{})
	size, err := checkpoint["mmr_size"].(json.Number).Int64()
	require.NoError(t, err)
	tampered := extractBundle(t, html)
	tamperedCheckpoint := tampered["checkpoint"].(map[string]interface{})
	tamperedCheckpoint["mmr_size"] = json.Number(strconv.FormatInt(size+1, 10))

	require.False(t, passes(bundle.VerifyBundle(tampered)))
}

// TestReportHTMLTamperEditRecord: edit a signed record -- its capsule_id no
// longer matches the recomputed identity.
func TestReportHTMLTamperEditRecord(t *testing.T) {
	source := loadWeekBundle(t)
	html, err := EmitEvidenceGraphHTML(source, []byte("/*IIFE_MARKER*/"))
	require.NoError(t, err)

	tampered := extractBundle(t, html)
	records := tampered["records"].([]interface{})
	record := records[0].(map[string]interface{})
	tamperedID := record["capsule_id"].(string)
	record["action_type"] = "decide"

	result := bundle.VerifyBundle(tampered)
	capsuleResult, ok := result.CapsuleResults[tamperedID]
	require.True(t, ok)
	require.False(t, capsuleResult.OK)
}

// TestReportHTMLTamperDropRecord: drop a record -- range/membership fails.
func TestReportHTMLTamperDropRecord(t *testing.T) {
	source := loadWeekBundle(t)
	html, err := EmitEvidenceGraphHTML(source, []byte("/*IIFE_MARKER*/"))
	require.NoError(t, err)

	tampered := extractBundle(t, html)
	records := tampered["records"].([]interface{})
	tampered["records"] = records[1:]

	require.False(t, passes(bundle.VerifyBundle(tampered)))
}

// TestReportHTMLTamperWholesaleBreaksDigest: editing the bundle wholesale
// changes the bundle digest. Go's neutral verifier does not implement
// countersignature cryptography (the spec requires every entry surface as
// "unverified" -- population and COSE verification are documented future
// scope; see spec/draft-mih-zhang-agent-action-capsule-evidence-bundle-00.md
// section "Bundle Digest and Countersignatures"). The viewer-side stamp that
// DOES verify a COSE_Sign1 countersignature (ts/src/countersignature-stamp.ts)
// signs over exactly this digest, so a digest change is the necessary and
// sufficient Go-provable precondition for that countersignature to fail --
// proven end-to-end (the signature itself failing to verify) by the
// TypeScript tamper test's "editing the bundle wholesale" case.
func TestReportHTMLTamperWholesaleBreaksDigest(t *testing.T) {
	source := loadWeekBundle(t)
	html, err := EmitEvidenceGraphHTML(source, []byte("/*IIFE_MARKER*/"))
	require.NoError(t, err)

	original := extractBundle(t, html)
	originalDigest, err := bundle.BundleDigest(original)
	require.NoError(t, err)

	tampered := extractBundle(t, html)
	root := tampered["root"].(string)
	tampered["root"] = root[:len(root)-1] + "0"
	tamperedDigest, err := bundle.BundleDigest(tampered)
	require.NoError(t, err)

	require.NotEqual(t, originalDigest, tamperedDigest)
}

func TestReportHTMLTamperKeepsXSSRegression(t *testing.T) {
	payload := "</script><script>window.pwned=1</script>"
	html, err := EmitEvidenceGraphHTML(map[string]interface{}{"payload": payload}, nil)
	require.NoError(t, err)
	require.NotContains(t, html, payload)
	require.Contains(t, html, `</script>`)
}
