// SPDX-License-Identifier: BSD-3-Clause
package emitter

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
)

const (
	bundlePlaceholder  = "__BUNDLE_JSON__"
	browserPlaceholder = "__BROWSER_IIFE__"
)

//go:embed shell.html
var shell string

func replaceSingle(template, placeholder, value string) (string, error) {
	parts := strings.Split(template, placeholder)
	if len(parts) != 2 {
		return "", fmt.Errorf("emitter shell must contain exactly one %s slot", placeholder)
	}
	return parts[0] + value + parts[1], nil
}

// EmitEvidenceGraphHTML embeds an evidence bundle and browser runtime in the
// self-contained evidence graph HTML shell. The browserIIFE is built in PR3.
func EmitEvidenceGraphHTML(bundle map[string]interface{}, browserIIFE []byte) (string, error) {
	bundleJSON, err := canonical.JCS(bundle)
	if err != nil {
		return "", err
	}
	bundleText := string(bundleJSON)
	browserText := string(browserIIFE)
	if strings.Contains(bundleText, bundlePlaceholder) || strings.Contains(bundleText, browserPlaceholder) {
		return "", fmt.Errorf("bundle JSON must not contain emitter placeholders")
	}
	if strings.Contains(browserText, bundlePlaceholder) || strings.Contains(browserText, browserPlaceholder) {
		return "", fmt.Errorf("browser IIFE must not contain emitter placeholders")
	}

	withBundle, err := replaceSingle(shell, bundlePlaceholder, bundleText)
	if err != nil {
		return "", err
	}
	html, err := replaceSingle(withBundle, browserPlaceholder, browserText)
	if err != nil {
		return "", err
	}
	bundleOffset := strings.Index(html, bundleText)
	if strings.Contains(html, bundlePlaceholder) || strings.Contains(html, browserPlaceholder) ||
		bundleOffset == -1 || strings.Index(html[bundleOffset+len(bundleText):], bundleText) != -1 {
		return "", fmt.Errorf("emitter shell embed invariant failed")
	}
	return html, nil
}
