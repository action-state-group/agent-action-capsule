// SPDX-License-Identifier: BSD-3-Clause
package emitter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/bundle"
	"github.com/stretchr/testify/require"
)

const marker = "/*IIFE_MARKER*/"

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return string(raw)
}

func loadJSON(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var value map[string]interface{}
	require.NoError(t, decoder.Decode(&value))
	return value
}

func wordingOf(text string) *Wording {
	sum := sha256.Sum256([]byte(text))
	return &Wording{Pack: text, SHA256: hex.EncodeToString(sum[:])}
}

// The token and the offline file come from ts/test/presentation-builder.test.ts
// ("the Go twin's goldens"): a sealed Result bundle scoped to its root for a
// counterparty, at depth L1, with a theme and a wording pack.
func TestOfflineHTMLFromFragmentMatchesTypeScript(t *testing.T) {
	token := strings.TrimSpace(readTestdata(t, "offline-fragment.txt"))
	got, err := OfflineHTMLFromFragment(token, []byte(marker), nil)
	require.NoError(t, err)
	require.True(t, got == readTestdata(t, "expected-offline.html"), "Go offline file differs from TypeScript's")
}

func TestBuildOfflineHTMLMatchesTypeScript(t *testing.T) {
	payload, err := DecodePresentationFragment(strings.TrimSpace(readTestdata(t, "offline-fragment.txt")), 0)
	require.NoError(t, err)
	require.Equal(t, "counterparty", payload.Audience)
	got, err := BuildOfflineHTML(payload.Bundle, []byte(marker), OfflineOptions{
		Audience: payload.Audience,
		Depth:    payload.Depth,
		ThemeCSS: payload.ThemeCSS,
		Wording:  payload.Wording,
	})
	require.NoError(t, err)
	require.True(t, got == readTestdata(t, "expected-offline.html"), "Go offline file differs from TypeScript's")
	require.Contains(t, got, "<title>Résumé &lt;/script&gt; &amp; co</title>")
	require.NotContains(t, got, "</script> & co")
}

func TestBuildOfflineHTMLDefaultIsTheEmitterPage(t *testing.T) {
	week := loadWeekBundle(t)
	got, err := BuildOfflineHTML(week, []byte(marker), OfflineOptions{Audience: "*"})
	require.NoError(t, err)
	want, err := EmitEvidenceGraphHTML(week, []byte(marker))
	require.NoError(t, err)
	require.True(t, got == want)
	require.True(t, got == readTestdata(t, "expected.html"))
}

func TestOfflineHTMLFromFragmentRefusesOtherCode(t *testing.T) {
	token := strings.TrimSpace(readTestdata(t, "offline-fragment.txt"))
	_, err := OfflineHTMLFromFragment(token, []byte("/*other*/"), nil)
	require.ErrorContains(t, err, "not the one the fragment was built with")
	module := []byte("/*m*/")
	_, err = OfflineHTMLFromFragment(token, []byte(marker), []Module{{Code: module, SHA256: hexPinOf(string(module))}})
	require.ErrorContains(t, err, "not the ones the fragment was built with")
}

func TestPresentationFragmentLimitsAndShape(t *testing.T) {
	_, err := DecodePresentationFragment(strings.Repeat("A", 9), 8)
	require.ErrorContains(t, err, "refused, never truncated")
	_, err = DecodePresentationFragment(strings.Repeat("A", FragmentTokenMaxLength+1), 0)
	require.ErrorContains(t, err, "over the 1046528-character maximum")

	encode := func(v map[string]interface{}) string {
		token, err := bundle.EncodeFragment(v)
		require.NoError(t, err)
		return token
	}
	base := func() map[string]interface{} {
		return map[string]interface{}{
			"fragment_version": PresentationFragmentVersion, "audience": "a", "presentation": "auto",
			"core_runtime_sha256": strings.Repeat("a", 64), "module_sha256": []interface{}{}, "bundle": map[string]interface{}{},
		}
	}
	_, err = DecodePresentationFragment("#"+encode(base()), 0)
	require.NoError(t, err)
	for member, value := range map[string]interface{}{
		"extra": json.Number("1"), "depth": "L3", "core_runtime_sha256": "A", "fragment_version": "v1",
	} {
		v := base()
		v[member] = value
		_, err = DecodePresentationFragment(encode(v), 0)
		require.Error(t, err, member)
	}
	v := base()
	delete(v, "bundle")
	_, err = DecodePresentationFragment(encode(v), 0)
	require.ErrorContains(t, err, "bundle is missing")
}

func TestCheckWordingPack(t *testing.T) {
	good := `{"entries":{"page.title":"T"},"id":"org.example.w/v0","locale":"en","wording_pack_version":"aac.wording-pack/v0"}`
	entries, err := CheckWordingPack(*wordingOf(good))
	require.NoError(t, err)
	require.Equal(t, "T", entries["page.title"])
	_, err = CheckWordingPack(Wording{Pack: good, SHA256: strings.Repeat("0", 64)})
	require.ErrorContains(t, err, "do not hash")
	for _, bad := range []string{
		`{"entries":{"Bad Key":"x"},"id":"org.example.w/v0","locale":"en","wording_pack_version":"aac.wording-pack/v0"}`,
		`{"entries":{},"id":"org.example.w/v0","locale":"en","wording_pack_version":"aac.wording-pack/v0"}`,
		good + ` {}`,
	} {
		_, err = CheckWordingPack(*wordingOf(bad))
		require.Error(t, err, bad)
	}
}

// The fragment codec agrees with capsule-viewer's fragment.py on the shared
// vectors: the same token for ASCII JSON, and each reads the other's.
func TestFragmentCodecMatchesFragmentPyVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "ts", "test", "testdata", "presentation-fragment-vectors.json"))
	require.NoError(t, err)
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var doc struct {
		Cases []struct {
			Name       string      `json:"name"`
			ASCIIJSON  bool        `json:"ascii_json"`
			FragmentPy string      `json:"fragment_py"`
			Payload    interface{} `json:"payload"`
		} `json:"cases"`
	}
	require.NoError(t, decoder.Decode(&doc))
	require.NotEmpty(t, doc.Cases)
	for _, c := range doc.Cases {
		token, err := bundle.EncodeFragment(c.Payload)
		require.NoError(t, err, c.Name)
		if c.ASCIIJSON {
			require.Equal(t, c.FragmentPy, token, c.Name)
		}
		decoded, err := bundle.DecodeFragment(c.FragmentPy)
		require.NoError(t, err, c.Name)
		require.Equal(t, c.Payload, decoded, c.Name)
	}
}

// The no-script slot: ts/test/emitter-csp.test.ts ("the no-script slot")
// writes the golden; the emitter, the offline builder and the fragment
// hand-back all write it byte for byte.
func TestEmitNoscriptTextMatchesTypeScript(t *testing.T) {
	text := `To check this file without JavaScript, run: example-verify --bundle "<this file>" & read its report.`
	week := loadWeekBundle(t)
	want := readTestdata(t, "expected-noscript.html")

	got, err := EmitEvidenceGraphHTMLWithOptions(week, []byte(marker), Options{NoscriptText: text})
	require.NoError(t, err)
	require.True(t, got == want, "Go HTML with noscript text differs from TypeScript HTML")
	require.Contains(t, got, "<noscript>To check this file without JavaScript, run: example-verify --bundle &#34;&lt;this file&gt;&#34; &amp; read its report.</noscript>\n    <div id=\"app\"></div>")

	offline, err := BuildOfflineHTML(week, []byte(marker), OfflineOptions{Audience: "*", NoscriptText: text})
	require.NoError(t, err)
	require.True(t, offline == want)

	small := map[string]interface{}{"note": "noscript"}
	token, err := bundle.EncodeFragment(map[string]interface{}{
		"fragment_version": PresentationFragmentVersion, "audience": "*", "presentation": "auto",
		"noscript_text": text, "core_runtime_sha256": hexPinOf(marker),
		"module_sha256": []interface{}{}, "bundle": small,
	})
	require.NoError(t, err)
	handBack, err := OfflineHTMLFromFragment(token, []byte(marker), nil)
	require.NoError(t, err)
	direct, err := EmitEvidenceGraphHTMLWithOptions(small, []byte(marker), Options{NoscriptText: text})
	require.NoError(t, err)
	require.True(t, handBack == direct, "the hand-back keeps the noscript text")

	defaultPage, err := EmitEvidenceGraphHTML(week, []byte(marker))
	require.NoError(t, err)
	require.Contains(t, defaultPage, "<noscript>"+DefaultNoscriptText+"</noscript>")
	require.Equal(t, policyOf(t, defaultPage), policyOf(t, got), "the noscript text adds nothing to the policy")

	_, err = EmitEvidenceGraphHTMLWithOptions(week, nil, Options{NoscriptText: "__CSP_SLOT__"})
	require.ErrorContains(t, err, "noscript text must not contain emitter placeholders")

	bad, err := bundle.EncodeFragment(map[string]interface{}{
		"fragment_version": PresentationFragmentVersion, "audience": "*", "presentation": "auto",
		"noscript_text": true, "core_runtime_sha256": hexPinOf(marker),
		"module_sha256": []interface{}{}, "bundle": small,
	})
	require.NoError(t, err)
	_, err = DecodePresentationFragment(bad, 0)
	require.ErrorContains(t, err, "noscript_text is not a string")
}
