// SPDX-License-Identifier: BSD-3-Clause
package emitter

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
)

const (
	cspSlot         = "__CSP_SLOT__"
	titleSlot       = "__TITLE_SLOT__"
	themeSlot       = "__THEME_SLOT__"
	bundleSlot      = "__BUNDLE_SLOT__"
	coreRuntimeSlot = "__CORE_RUNTIME_SLOT__"
	moduleSlot      = "__MODULE_SLOT__"
	bootstrapSlot   = "__BOOTSTRAP_SLOT__"

	// DefaultTitle is the page title used when Options.Title is empty.
	DefaultTitle = "Evidence Graph"
	// DefaultBootstrap is the bootstrap script used when Options.Bootstrap is empty.
	DefaultBootstrap = `renderEvidenceGraph(window.__BUNDLE__, document.getElementById("app"));`
)

var slots = []string{cspSlot, titleSlot, themeSlot, bundleSlot, coreRuntimeSlot, moduleSlot, bootstrapSlot}

//go:embed shell.html
var shell string

// runtimeStyleHashes lists the CSP hash sources of the stylesheets the
// reference core runtime inserts as <style> elements at render time. The
// TypeScript tests recompute them from the stylesheet constants.
//
//go:embed runtime-style-hashes.txt
var runtimeStyleHashes string

var hexPin = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Module is a digest-pinned script the builder knowingly incorporates.
type Module struct {
	// Code is the script source, inlined byte for byte.
	Code []byte
	// SHA256 is the lowercase hex SHA-256 of Code (a .sha256 pin).
	SHA256 string
	// StyleSHA256 lists the lowercase hex SHA-256 of each stylesheet the
	// module inserts at render time (the manifest's style_sha256). Each is
	// added to the page's style-src.
	StyleSHA256 []string
}

// Options fills the shell's optional slots. The zero value reproduces the
// default page: title "Evidence Graph", no theme CSS, no modules and the
// renderEvidenceGraph bootstrap.
type Options struct {
	// Title is HTML-escaped into <title>; empty uses DefaultTitle.
	Title string
	// ThemeCSS is placed in the theme <style> element (token overrides).
	ThemeCSS string
	// CoreRuntimeSHA256 is the lowercase hex pin of the core runtime; checked when set.
	CoreRuntimeSHA256 string
	// Modules run after the core runtime, in order.
	Modules []Module
	// Bootstrap is the final script; empty uses DefaultBootstrap.
	Bootstrap string
}

func replaceSingle(template, placeholder, value string) (string, error) {
	parts := strings.Split(template, placeholder)
	if len(parts) != 2 {
		return "", fmt.Errorf("emitter shell must contain exactly one %s slot", placeholder)
	}
	return parts[0] + value + parts[1], nil
}

func escapeJSONForHTMLScript(json string) string {
	return strings.NewReplacer(
		"<", `\u003c`,
		">", `\u003e`,
		"&", `\u0026`,
		"\u2028", `\u2028`,
		"\u2029", `\u2029`,
	).Replace(json)
}

func escapeHTMLText(value string) string {
	return strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&#34;",
		"'", "&#39;",
	).Replace(value)
}

func cspHashSource(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

// CSPHashSourceFromHex converts a lowercase hex SHA-256 pin (the form of a
// .sha256 file) to the CSP hash source for the same digest.
func CSPHashSourceFromHex(pin string) (string, error) {
	if !hexPin.MatchString(pin) {
		return "", fmt.Errorf("SHA-256 pin must be 64 lowercase hex characters")
	}
	sum, err := hex.DecodeString(pin)
	if err != nil {
		return "", err
	}
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum) + "'", nil
}

// checkInline keeps inline content byte-exact through the HTML parser: no end
// tag or comment opener that moves where the element ends, and no CR or NUL
// that the parser rewrites before the CSP check hashes the text.
func checkInline(name, value, endTag string) error {
	lower := strings.ToLower(value)
	if strings.Contains(lower, endTag) || strings.Contains(lower, "<!--") {
		return fmt.Errorf("%s must not contain %s or <!--", name, endTag)
	}
	if strings.ContainsAny(value, "\r\x00") {
		return fmt.Errorf("%s must not contain CR or NUL characters", name)
	}
	return nil
}

func checkPin(name, pin, value string) error {
	want, err := CSPHashSourceFromHex(pin)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if want != cspHashSource(value) {
		return fmt.Errorf("%s does not match its SHA-256 pin", name)
	}
	return nil
}

// inlineElements returns the text of every <script> and <style> element in
// document order. The shell writes both start tags bare, and checkInline
// guarantees each element's text runs to the first matching end tag.
func inlineElements(html string) (scripts, styles []string, err error) {
	offset := 0
	for {
		script := strings.Index(html[offset:], "<script>")
		style := strings.Index(html[offset:], "<style>")
		if script == -1 && style == -1 {
			return scripts, styles, nil
		}
		kind, at := "script", script
		if script == -1 || (style != -1 && style < script) {
			kind, at = "style", style
		}
		start := offset + at + len(kind) + 2
		end := strings.Index(html[start:], "</"+kind+">")
		if end == -1 {
			return nil, nil, fmt.Errorf("unterminated %s element", kind)
		}
		if kind == "script" {
			scripts = append(scripts, html[start:start+end])
		} else {
			styles = append(styles, html[start:start+end])
		}
		offset = start + end + len(kind) + 3
	}
}

func unique(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func coreRuntimeStyleSources() []string {
	sources := []string{}
	for _, line := range strings.Split(runtimeStyleHashes, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		sources = append(sources, "'"+fields[0]+"'")
	}
	return sources
}

// EmitEvidenceGraphHTML embeds an evidence bundle and browser runtime in the
// self-contained evidence graph HTML shell with the default options.
func EmitEvidenceGraphHTML(bundle map[string]interface{}, browserIIFE []byte) (string, error) {
	return EmitEvidenceGraphHTMLWithOptions(bundle, browserIIFE, Options{})
}

// EmitEvidenceGraphHTMLWithOptions embeds an evidence bundle, the browser
// runtime and any digest-pinned modules in the HTML shell, and writes a
// Content-Security-Policy whose script-src and style-src list the SHA-256 of
// every inline element actually emitted, then the stylesheets the core
// runtime and each module insert at render time.
func EmitEvidenceGraphHTMLWithOptions(bundle map[string]interface{}, browserIIFE []byte, options Options) (string, error) {
	bundleJSON, err := canonical.JCS(bundle)
	if err != nil {
		return "", err
	}
	bundleText := string(bundleJSON)
	browserText := string(browserIIFE)
	title := options.Title
	if title == "" {
		title = DefaultTitle
	}
	bootstrap := options.Bootstrap
	if bootstrap == "" {
		bootstrap = DefaultBootstrap
	}

	type input struct{ name, value string }
	inputs := []input{
		{"bundle JSON", bundleText},
		{"browser IIFE", browserText},
		{"title", title},
		{"theme CSS", options.ThemeCSS},
		{"bootstrap", bootstrap},
	}
	for index, module := range options.Modules {
		inputs = append(inputs, input{fmt.Sprintf("module %d", index), string(module.Code)})
	}
	for _, in := range inputs {
		for _, slot := range slots {
			if strings.Contains(in.value, slot) {
				return "", fmt.Errorf("%s must not contain emitter placeholders", in.name)
			}
		}
	}
	if err := checkInline("browser IIFE", browserText, "</script"); err != nil {
		return "", err
	}
	if err := checkInline("bootstrap", bootstrap, "</script"); err != nil {
		return "", err
	}
	if err := checkInline("theme CSS", options.ThemeCSS, "</style"); err != nil {
		return "", err
	}
	if options.CoreRuntimeSHA256 != "" {
		if err := checkPin("browser IIFE", options.CoreRuntimeSHA256, browserText); err != nil {
			return "", err
		}
	}
	moduleScripts := make([]string, 0, len(options.Modules))
	moduleStyleSources := []string{}
	for index, module := range options.Modules {
		name := fmt.Sprintf("module %d", index)
		if err := checkInline(name, string(module.Code), "</script"); err != nil {
			return "", err
		}
		if err := checkPin(name, module.SHA256, string(module.Code)); err != nil {
			return "", err
		}
		moduleScripts = append(moduleScripts, "<script>"+string(module.Code)+"</script>")
		for styleIndex, pin := range module.StyleSHA256 {
			source, err := CSPHashSourceFromHex(pin)
			if err != nil {
				return "", fmt.Errorf("%s style %d: %w", name, styleIndex, err)
			}
			moduleStyleSources = append(moduleStyleSources, source)
		}
	}

	embeddedBundleText := escapeJSONForHTMLScript(bundleText)
	html := shell
	for _, fill := range []struct{ slot, value string }{
		{titleSlot, escapeHTMLText(title)},
		{themeSlot, options.ThemeCSS},
		{bundleSlot, embeddedBundleText},
		{coreRuntimeSlot, browserText},
		{moduleSlot, strings.Join(moduleScripts, "\n    ")},
		{bootstrapSlot, bootstrap},
	} {
		if html, err = replaceSingle(html, fill.slot, fill.value); err != nil {
			return "", err
		}
	}

	scripts, styles, err := inlineElements(html)
	if err != nil {
		return "", err
	}
	scriptSources := []string{}
	for _, script := range scripts {
		scriptSources = append(scriptSources, cspHashSource(script))
	}
	styleSources := []string{}
	for _, style := range styles {
		styleSources = append(styleSources, cspHashSource(style))
	}
	styleSources = append(styleSources, coreRuntimeStyleSources()...)
	styleSources = append(styleSources, moduleStyleSources...)
	csp := strings.Join([]string{
		"default-src 'none'",
		"script-src " + strings.Join(unique(scriptSources), " "),
		"style-src " + strings.Join(unique(styleSources), " "),
		"img-src data:",
		"connect-src 'none'",
		"base-uri 'none'",
		"form-action 'none'",
	}, "; ")
	if html, err = replaceSingle(html, cspSlot, csp); err != nil {
		return "", err
	}

	bundleOffset := strings.Index(html, embeddedBundleText)
	for _, slot := range slots {
		if strings.Contains(html, slot) {
			return "", fmt.Errorf("emitter shell embed invariant failed")
		}
	}
	if bundleOffset == -1 || strings.Contains(html[bundleOffset+len(embeddedBundleText):], embeddedBundleText) {
		return "", fmt.Errorf("emitter shell embed invariant failed")
	}
	return html, nil
}
