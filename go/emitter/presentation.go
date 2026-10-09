// SPDX-License-Identifier: BSD-3-Clause
package emitter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/action-state-group/agent-action-capsule/go/bundle"
	"github.com/action-state-group/agent-action-capsule/go/canonical"
)

// The offline packaging of the presentation builder
// (spec/presentation-builder-v0.md), the Go twin of buildPresentation's
// "html" format and of offlineHtmlFromFragment in ts/src/presentation-builder.ts.
// For the same bundle, runtime and settings the two write the same bytes.
// Scoping, verification and module resolution happen in the TypeScript
// share builder before these inputs exist; this only packages.

const (
	// PresentationFragmentVersion is the fragment payload's version string.
	PresentationFragmentVersion = "aac.presentation-fragment/v0"
	// FragmentURLMaxLength is the longest permalink URL planned for (1 MiB).
	FragmentURLMaxLength = 1_048_576
	// FragmentTokenMaxLength is the URL limit less 2048 characters for the
	// viewer's address and the '#'.
	FragmentTokenMaxLength = FragmentURLMaxLength - 2_048
	// WordingTitleKey is the wording key the builder reads for the page title.
	WordingTitleKey = "page.title"

	wordingPackVersion = "aac.wording-pack/v0"
)

var (
	wordingKey = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	locale     = regexp.MustCompile(`^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$`)
)

// Wording is a wording pack as distributed: its exact text and the
// lowercase hex SHA-256 of its UTF-8 bytes (wording_sha256).
type Wording struct {
	Pack   string
	SHA256 string
}

// OfflineOptions are the offline file's settings.
type OfflineOptions struct {
	// Audience is required; "*" is no particular audience.
	Audience string
	// Depth is "", "L0", "L1" or "L2".
	Depth string
	// Title wins over the wording pack's page.title.
	Title    string
	ThemeCSS string
	Wording  *Wording
	// CoreRuntimeSHA256 is the runtime's pin; checked when set.
	CoreRuntimeSHA256 string
	Modules           []Module
}

// CheckWordingPack checks a wording pack against its digest and its shape
// and returns its entries. The bytes are hashed exactly as given.
func CheckWordingPack(w Wording) (map[string]string, error) {
	if !hexPin.MatchString(w.SHA256) {
		return nil, fmt.Errorf("wording sha256 is not a lowercase hex SHA-256")
	}
	sum := sha256.Sum256([]byte(w.Pack))
	if hex.EncodeToString(sum[:]) != w.SHA256 {
		return nil, fmt.Errorf("wording pack bytes do not hash to its wording_sha256")
	}
	var pack map[string]interface{}
	decoder := json.NewDecoder(strings.NewReader(w.Pack))
	decoder.UseNumber()
	if err := decoder.Decode(&pack); err != nil || decoder.More() {
		return nil, fmt.Errorf("wording pack is not JSON")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("wording pack is not JSON")
	}
	bad := fmt.Errorf("wording pack is not an %s object", wordingPackVersion)
	for key := range pack {
		switch key {
		case "wording_pack_version", "id", "locale", "entries":
		default:
			return nil, bad
		}
	}
	_, idOK := pack["id"].(string)
	tag, tagOK := pack["locale"].(string)
	raw, entriesOK := pack["entries"].(map[string]interface{})
	if pack["wording_pack_version"] != wordingPackVersion || !idOK ||
		!tagOK || !locale.MatchString(tag) || !entriesOK || len(raw) == 0 {
		return nil, bad
	}
	entries := map[string]string{}
	for key, value := range raw {
		text, ok := value.(string)
		if !ok || text == "" || !wordingKey.MatchString(key) {
			return nil, bad
		}
		entries[key] = text
	}
	return entries, nil
}

// BuildOfflineHTML packages a (scoped) bundle as one self-contained offline
// file with its per-page CSP. The default settings (audience "*", nothing
// else) write exactly EmitEvidenceGraphHTML's page.
func BuildOfflineHTML(value interface{}, runtime []byte, o OfflineOptions) (string, error) {
	bundleObject, ok := value.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("bundle is not a JSON object")
	}
	if o.Audience == "" {
		return "", fmt.Errorf("audience is required")
	}
	switch o.Depth {
	case "", "L0", "L1", "L2":
	default:
		return "", fmt.Errorf("depth is not L0, L1 or L2")
	}
	title := o.Title
	if o.Wording != nil {
		entries, err := CheckWordingPack(*o.Wording)
		if err != nil {
			return "", err
		}
		if title == "" {
			title = entries[WordingTitleKey]
		}
	}
	bootstrap := DefaultBootstrap
	if o.Audience != "*" || o.Depth != "" || o.Wording != nil {
		options := map[string]interface{}{"audience": o.Audience, "format": "html"}
		if o.Depth != "" {
			options["depth"] = o.Depth
		}
		if o.Wording != nil {
			options["wording"] = map[string]interface{}{"pack": o.Wording.Pack, "sha256": o.Wording.SHA256}
		}
		encoded, err := canonical.JCS(options)
		if err != nil {
			return "", err
		}
		bootstrap = `renderEvidenceGraph(window.__BUNDLE__, document.getElementById("app"), undefined, ` +
			escapeJSONForHTMLScript(string(encoded)) + `);`
	}
	return EmitEvidenceGraphHTMLWithOptions(bundleObject, runtime, Options{
		Title:             title,
		ThemeCSS:          o.ThemeCSS,
		CoreRuntimeSHA256: o.CoreRuntimeSHA256,
		Modules:           o.Modules,
		Bootstrap:         bootstrap,
	})
}

// PresentationFragment is the fragment permalink payload.
type PresentationFragment struct {
	Audience          string
	Presentation      string
	Depth             string
	Title             string
	ThemeCSS          string
	Wording           *Wording
	CoreRuntimeSHA256 string
	ModuleSHA256      []string
	Bundle            interface{}
}

// DecodePresentationFragment decodes and checks a fragment token (a leading
// '#' is allowed) with the Evidence Bundle permalink codec. A token over
// maxLength (FragmentTokenMaxLength when 0) is refused before decoding.
func DecodePresentationFragment(token string, maxLength int) (*PresentationFragment, error) {
	if maxLength <= 0 {
		maxLength = FragmentTokenMaxLength
	}
	body := strings.TrimLeft(token, "#")
	if len(body) > maxLength {
		return nil, fmt.Errorf("fragment token is %d characters, over the %d-character maximum; it is refused, never truncated", len(body), maxLength)
	}
	value, err := bundle.DecodeFragment(body)
	if err != nil {
		return nil, err
	}
	object, ok := value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("presentation fragment: not a JSON object")
	}
	fail := func(why string) (*PresentationFragment, error) {
		return nil, fmt.Errorf("presentation fragment: %s", why)
	}
	known := map[string]bool{"fragment_version": true, "audience": true, "presentation": true, "depth": true,
		"title": true, "theme_css": true, "wording": true, "core_runtime_sha256": true, "module_sha256": true, "bundle": true}
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !known[key] {
			return fail(fmt.Sprintf("unknown member %q", key))
		}
	}
	str := func(key string) (string, bool) {
		value, present := object[key]
		if !present {
			return "", true
		}
		text, ok := value.(string)
		return text, ok
	}
	out := &PresentationFragment{}
	if object["fragment_version"] != PresentationFragmentVersion {
		return fail("fragment_version is not " + PresentationFragmentVersion)
	}
	var okAll bool
	if out.Audience, okAll = str("audience"); !okAll || out.Audience == "" {
		return fail("audience is not a non-empty string")
	}
	if out.Presentation, okAll = str("presentation"); !okAll || out.Presentation == "" {
		return fail("presentation is not a non-empty string")
	}
	if out.Depth, okAll = str("depth"); !okAll {
		return fail("depth is not L0, L1 or L2")
	}
	if _, present := object["depth"]; present && out.Depth != "L0" && out.Depth != "L1" && out.Depth != "L2" {
		return fail("depth is not L0, L1 or L2")
	}
	if out.Title, okAll = str("title"); !okAll {
		return fail("title is not a string")
	}
	if out.ThemeCSS, okAll = str("theme_css"); !okAll {
		return fail("theme_css is not a string")
	}
	if raw, present := object["wording"]; present {
		w, ok := raw.(map[string]interface{})
		pack, packOK := w["pack"].(string)
		sum, sumOK := w["sha256"].(string)
		if !ok || len(w) != 2 || !packOK || !sumOK || !hexPin.MatchString(sum) {
			return fail("wording is not {pack, sha256}")
		}
		out.Wording = &Wording{Pack: pack, SHA256: sum}
	}
	if out.CoreRuntimeSHA256, okAll = str("core_runtime_sha256"); !okAll || !hexPin.MatchString(out.CoreRuntimeSHA256) {
		return fail("core_runtime_sha256 is not a lowercase hex SHA-256")
	}
	pins, ok := object["module_sha256"].([]interface{})
	if !ok {
		return fail("module_sha256 is not a list of lowercase hex SHA-256 pins")
	}
	for _, raw := range pins {
		pin, ok := raw.(string)
		if !ok || !hexPin.MatchString(pin) {
			return fail("module_sha256 is not a list of lowercase hex SHA-256 pins")
		}
		out.ModuleSHA256 = append(out.ModuleSHA256, pin)
	}
	bundleValue, present := object["bundle"]
	if !present {
		return fail("bundle is missing")
	}
	out.Bundle = bundleValue
	return out, nil
}

// OfflineHTMLFromFragment is the hand-back: it rebuilds the exact offline
// file a fragment was made from. The fragment carries pins, not code; the
// runtime and modules given here must match them, or it refuses.
func OfflineHTMLFromFragment(token string, runtime []byte, modules []Module) (string, error) {
	payload, err := DecodePresentationFragment(token, 0)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(runtime)
	runtimePin := hex.EncodeToString(sum[:])
	if runtimePin != payload.CoreRuntimeSHA256 {
		return "", fmt.Errorf("this runtime is not the one the fragment was built with")
	}
	if len(modules) != len(payload.ModuleSHA256) {
		return "", fmt.Errorf("these modules are not the ones the fragment was built with")
	}
	for i, module := range modules {
		if module.SHA256 != payload.ModuleSHA256[i] {
			return "", fmt.Errorf("these modules are not the ones the fragment was built with")
		}
	}
	return BuildOfflineHTML(payload.Bundle, runtime, OfflineOptions{
		Audience:          payload.Audience,
		Depth:             payload.Depth,
		Title:             payload.Title,
		ThemeCSS:          payload.ThemeCSS,
		Wording:           payload.Wording,
		CoreRuntimeSHA256: runtimePin,
		Modules:           modules,
	})
}
