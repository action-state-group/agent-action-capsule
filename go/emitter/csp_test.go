// SPDX-License-Identifier: BSD-3-Clause
package emitter

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	cspMeta      = regexp.MustCompile(`<meta http-equiv="Content-Security-Policy" content="([^"]*)" />`)
	inlineScript = regexp.MustCompile(`(?s)<script>(.*?)</script>`)
	inlineStyle  = regexp.MustCompile(`(?s)<style>(.*?)</style>`)
)

func hexPinOf(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func sourceOf(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

func policyOf(t *testing.T, html string) map[string][]string {
	t.Helper()
	match := cspMeta.FindStringSubmatch(html)
	require.Len(t, match, 2, "no CSP meta")
	policy := map[string][]string{}
	for _, directive := range strings.Split(match[1], "; ") {
		fields := strings.Fields(directive)
		policy[fields[0]] = fields[1:]
	}
	return policy
}

func TestEmitCSPListsEveryInlineElement(t *testing.T) {
	module := "window.moduleRan=true;"
	html, err := EmitEvidenceGraphHTMLWithOptions(loadWeekBundle(t), []byte("/*IIFE_MARKER*/"), Options{
		ThemeCSS: ":root{--aac-accent:#123456}",
		Modules:  []Module{{Code: []byte(module), SHA256: hexPinOf(module)}},
	})
	require.NoError(t, err)
	policy := policyOf(t, html)
	require.Equal(t, []string{"'none'"}, policy["default-src"])
	require.Equal(t, []string{"'none'"}, policy["connect-src"])
	require.Equal(t, []string{"data:"}, policy["img-src"])

	scripts := []string{}
	for _, match := range inlineScript.FindAllStringSubmatch(html, -1) {
		scripts = append(scripts, sourceOf(match[1]))
	}
	require.Len(t, scripts, 4)
	require.Equal(t, scripts, policy["script-src"])

	styles := []string{}
	for _, match := range inlineStyle.FindAllStringSubmatch(html, -1) {
		styles = append(styles, sourceOf(match[1]))
	}
	styles = append(styles, coreRuntimeStyleSources()...)
	require.Equal(t, styles, policy["style-src"])
	require.Len(t, coreRuntimeStyleSources(), 2)
}

func TestEmitCoreRuntimeHashIsItsHexPin(t *testing.T) {
	runtime := "/*IIFE_MARKER*/"
	pin := hexPinOf(runtime)
	html, err := EmitEvidenceGraphHTMLWithOptions(loadWeekBundle(t), []byte(runtime), Options{CoreRuntimeSHA256: pin})
	require.NoError(t, err)
	listed, err := CSPHashSourceFromHex(pin)
	require.NoError(t, err)
	require.Contains(t, policyOf(t, html)["script-src"], listed)
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(listed, "'sha256-"), "'"))
	require.NoError(t, err)
	require.Equal(t, pin, hex.EncodeToString(decoded))

	_, err = EmitEvidenceGraphHTMLWithOptions(loadWeekBundle(t), []byte(runtime), Options{CoreRuntimeSHA256: hexPinOf("other")})
	require.ErrorContains(t, err, "does not match its SHA-256 pin")
}

func TestEmitTitle(t *testing.T) {
	html, err := EmitEvidenceGraphHTML(loadWeekBundle(t), nil)
	require.NoError(t, err)
	require.Contains(t, html, "<title>Evidence Graph</title>")

	html, err = EmitEvidenceGraphHTMLWithOptions(loadWeekBundle(t), nil, Options{Title: `Receipt <b>"A" & 'B'</b>`})
	require.NoError(t, err)
	require.Contains(t, html, "<title>Receipt &lt;b&gt;&#34;A&#34; &amp; &#39;B&#39;&lt;/b&gt;</title>")
}

func TestEmitRefusals(t *testing.T) {
	bundle := loadWeekBundle(t)
	_, err := EmitEvidenceGraphHTMLWithOptions(bundle, nil, Options{Modules: []Module{{Code: []byte("window.x=1;"), SHA256: hexPinOf("window.x=2;")}}})
	require.ErrorContains(t, err, "module 0 does not match its SHA-256 pin")
	_, err = EmitEvidenceGraphHTML(bundle, []byte("a</SCRIPT>b"))
	require.ErrorContains(t, err, "browser IIFE must not contain")
	_, err = EmitEvidenceGraphHTML(bundle, []byte("a<!--b"))
	require.ErrorContains(t, err, "browser IIFE must not contain")
	_, err = EmitEvidenceGraphHTML(bundle, []byte("a\rb"))
	require.ErrorContains(t, err, "CR or NUL")
	_, err = EmitEvidenceGraphHTMLWithOptions(bundle, nil, Options{ThemeCSS: "a</style>"})
	require.ErrorContains(t, err, "theme CSS must not contain")
	_, err = EmitEvidenceGraphHTML(map[string]interface{}{"note": "__TITLE_SLOT__"}, nil)
	require.ErrorContains(t, err, "bundle JSON must not contain emitter placeholders")
	_, err = EmitEvidenceGraphHTMLWithOptions(bundle, nil, Options{Title: "__CSP_SLOT__"})
	require.ErrorContains(t, err, "title must not contain emitter placeholders")
}

func TestEmitReferencesNothingOutsideThePage(t *testing.T) {
	html, err := EmitEvidenceGraphHTML(loadWeekBundle(t), []byte("/*IIFE_MARKER*/"))
	require.NoError(t, err)
	frame := inlineScript.ReplaceAllString(html, "")
	require.NotRegexp(t, `(?i)\b(?:src|href)=|<link|url\(|https?:`, frame)
}
