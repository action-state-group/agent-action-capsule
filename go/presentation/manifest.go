// SPDX-License-Identifier: BSD-3-Clause

// Package presentation is the Go resolver of spec/presentation-contract-v0.md:
// presentation manifests (aac.presentation-manifest/v0), the descriptor a
// verified bundle yields (section 4.2), the presentation ABI refusal (section
// 3.2), the match (section 4.3), the two tiers (section 4.4) and the static
// ambiguity test applied at registration (section 4.5).
//
// It is the Go twin of ts/src/presentation-registry.ts. Both are held to the
// shared vectors under vectors/presentation-resolution/, which are normative
// for both: a resolution, refusal, ambiguity error or descriptor that differs
// from a vector is a bug in the implementation, not in the vector.
//
// Go has no module code to call, so there is no canRender here. Resolve picks
// the one manifest the declarative match selects, as if every module could
// render; ResolveWith takes the caller's answer for canRender when it has one.
// A builder or command-line tool uses this package to list the presentations a
// bundle can take and to refuse, before writing anything, a page the runtime
// would refuse or could not resolve.
package presentation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ManifestVersion is the manifest namespace (spec section 4.1).
const ManifestVersion = "aac.presentation-manifest/v0"

// APIV0 is the presentation ABI this package's reference runtime implements.
const APIV0 = "aac.presentation-api/v0"

// Format is where a page is shown: html, fragment or embedded.
type Format string

// The three formats of spec section 8, invariant I4.
const (
	FormatHTML     Format = "html"
	FormatFragment Format = "fragment"
	FormatEmbedded Format = "embedded"
)

// Formats lists every format, in the contract's order.
var Formats = []Format{FormatHTML, FormatFragment, FormatEmbedded}

// Manifest is one aac.presentation-manifest/v0 manifest. Build one with
// ParseManifest, which applies the registry's structural rules.
type Manifest struct {
	SpecVersion     string       `json:"spec_version"`
	ID              string       `json:"id"`
	PresentationAPI string       `json:"presentation_api"`
	RuntimeMin      string       `json:"runtime_min"`
	TrustClass      string       `json:"trust_class"`
	Requires        Requires     `json:"requires"`
	Forbids         *Forbids     `json:"forbids,omitempty"`
	Audiences       []string     `json:"audiences"`
	Formats         []Format     `json:"formats"`
	Fallback        bool         `json:"fallback"`
	Priority        *int64       `json:"priority,omitempty"`
	Executable      *Executable  `json:"executable,omitempty"`
	Declarative     *Declarative `json:"declarative,omitempty"`
}

// Requires is what a descriptor must carry for the manifest to match.
type Requires struct {
	BundleKind string              `json:"bundle_kind"`
	Profiles   []string            `json:"profiles,omitempty"`
	Extensions *RequiredExtensions `json:"extensions,omitempty"`
}

// RequiredExtensions lists the extension kinds that must be engaged.
type RequiredExtensions struct {
	Required []string `json:"required"`
}

// Forbids is what a descriptor must not carry for the manifest to match.
type Forbids struct {
	Profiles   []string `json:"profiles,omitempty"`
	Extensions []string `json:"extensions,omitempty"`
}

// Executable is a trusted-executable module's carrier (spec section 5.1).
type Executable struct {
	Carrier       string   `json:"carrier"`
	ScriptSHA256  string   `json:"script_sha256,omitempty"`
	StyleSHA256   []string `json:"style_sha256,omitempty"`
	WordingSHA256 string   `json:"wording_sha256,omitempty"`
}

// Declarative is a declarative module's block (spec section 5.2), kept as
// written: resolution never reads it.
type Declarative struct {
	Renderer      string            `json:"renderer"`
	WordingSHA256 string            `json:"wording_sha256"`
	Fields        []json.RawMessage `json:"fields"`
}

// RequiredProfiles is requires.profiles, or nothing.
func (m Manifest) RequiredProfiles() []string { return m.Requires.Profiles }

// RequiredExtensions is requires.extensions.required, or nothing.
func (m Manifest) RequiredExtensions() []string {
	if m.Requires.Extensions == nil {
		return nil
	}
	return m.Requires.Extensions.Required
}

// ForbiddenProfiles is forbids.profiles, or nothing.
func (m Manifest) ForbiddenProfiles() []string {
	if m.Forbids == nil {
		return nil
	}
	return m.Forbids.Profiles
}

// ForbiddenExtensions is forbids.extensions, or nothing.
func (m Manifest) ForbiddenExtensions() []string {
	if m.Forbids == nil {
		return nil
	}
	return m.Forbids.Extensions
}

// RegistrationError is a manifest a registry refuses to hold: malformed, dead
// (spec section 4.5) or a duplicate id. Its message is the TypeScript
// registry's, word for word.
type RegistrationError struct {
	// Problems lists each structural problem, in the order the TypeScript
	// registry reports them; empty for a duplicate id.
	Problems []string
	message  string
}

func (e *RegistrationError) Error() string { return e.message }

var (
	runtimeVersionRE  = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	presentationAPIRE = regexp.MustCompile(`^aac\.presentation-api/v(0|[1-9][0-9]*)$`)
	manifestIDRE      = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9_-]+)+/v[0-9]+$`)
	profileTokenRE    = regexp.MustCompile(`^(spec_version|result_version):[A-Za-z0-9][A-Za-z0-9._/@+-]*$`)
	audienceRE        = regexp.MustCompile(`^(\*|[a-z][a-z0-9_-]*)$`)
	arrayIndexRE      = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
)

var manifestMembers = map[string]bool{
	"spec_version": true, "id": true, "presentation_api": true, "runtime_min": true,
	"trust_class": true, "requires": true, "forbids": true, "audiences": true,
	"formats": true, "fallback": true, "priority": true, "executable": true,
	"declarative": true,
}

// ParseManifest reads one manifest from JSON and applies the structural rules
// a registry relies on (the TypeScript registry's manifestProblems: the
// closed member set, the id, presentation_api, runtime_min, trust class,
// bundle kind, profile tokens, audiences, formats, the fallback/priority rule,
// the trust-class block, and the dead-manifest rules of section 4.5). The JSON
// Schema stays the full definition. A well-formed manifest whose
// presentation_api a runtime does not implement is not an error here: the
// runtime refuses it at registration.
func ParseManifest(data []byte) (Manifest, error) {
	keys, raw, err := decodeObject(data)
	if err != nil {
		return Manifest{}, &RegistrationError{
			Problems: []string{"manifest is not an object"},
			message:  "manifest undefined refused: manifest is not an object",
		}
	}
	problems := manifestProblems(keys, raw)
	if len(problems) > 0 {
		return Manifest{}, malformed(raw["id"], raw, problems)
	}
	normalizePriority(raw)
	normalized, err := json.Marshal(raw)
	if err != nil {
		return Manifest{}, malformed(raw["id"], raw, []string{"manifest does not encode: " + err.Error()})
	}
	var manifest Manifest
	if err := json.Unmarshal(normalized, &manifest); err != nil {
		return Manifest{}, malformed(raw["id"], raw, []string{"a member has the wrong type: " + err.Error()})
	}
	return manifest, nil
}

// Problems applies ParseManifest's rules to a manifest value.
func (m Manifest) Problems() []string {
	data, err := json.Marshal(m)
	if err != nil {
		return []string{"manifest does not encode: " + err.Error()}
	}
	keys, raw, err := decodeObject(data)
	if err != nil {
		return []string{"manifest is not an object"}
	}
	return manifestProblems(keys, raw)
}

func malformed(id interface{}, raw map[string]interface{}, problems []string) *RegistrationError {
	name := "undefined"
	if _, present := raw["id"]; present {
		name = jsQuote(id)
	}
	return &RegistrationError{
		Problems: problems,
		message:  fmt.Sprintf("manifest %s refused: %s", name, strings.Join(problems, "; ")),
	}
}

// decodeObject decodes a JSON object with json.Number values, and returns its
// member names in the order a JavaScript object enumerates them (array-index
// names ascending, then the rest in source order).
func decodeObject(data []byte) ([]string, map[string]interface{}, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, nil, fmt.Errorf("not a JSON object")
	}
	raw := map[string]interface{}{}
	var order []string
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, nil, err
		}
		key, _ := token.(string)
		var value interface{}
		if err := decoder.Decode(&value); err != nil {
			return nil, nil, err
		}
		if _, seen := raw[key]; !seen {
			order = append(order, key)
		}
		raw[key] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, nil, fmt.Errorf("trailing data after the manifest")
	}
	var indices, names []string
	for _, key := range order {
		if arrayIndexRE.MatchString(key) && len(key) <= 10 {
			if n, err := strconv.ParseUint(key, 10, 64); err == nil && n < math.MaxUint32 {
				indices = append(indices, key)
				continue
			}
		}
		names = append(names, key)
	}
	sort.SliceStable(indices, func(i, j int) bool {
		a, _ := strconv.ParseUint(indices[i], 10, 64)
		b, _ := strconv.ParseUint(indices[j], 10, 64)
		return a < b
	})
	return append(indices, names...), raw, nil
}

// jsQuote renders a JSON value as JavaScript's JSON.stringify does.
func jsQuote(value interface{}) string {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return "undefined"
	}
	out := strings.TrimSuffix(buffer.String(), "\n")
	out = strings.ReplaceAll(out, ` `, " ")
	return strings.ReplaceAll(out, ` `, " ")
}

func object(value interface{}) (map[string]interface{}, bool) {
	m, ok := value.(map[string]interface{})
	return m, ok
}

// list reads an optional array member; present reports a non-array value.
func list(parent map[string]interface{}, key string) (items []interface{}, wrongType bool) {
	value, present := parent[key]
	if !present {
		return nil, false
	}
	items, ok := value.([]interface{})
	return items, !ok
}

func stringItems(items []interface{}) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func isInteger(value interface{}) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := strconv.ParseFloat(string(number), 64)
	if err != nil || math.IsInf(f, 0) || math.Trunc(f) != f || math.Abs(f) > 1<<53 {
		return 0, false
	}
	return int64(f), true
}

// normalizePriority turns an integral priority written as 1.0 or 1e0 (an
// integer to JavaScript) into an integer Go can decode.
func normalizePriority(raw map[string]interface{}) {
	if n, ok := isInteger(raw["priority"]); ok {
		raw["priority"] = n
	}
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func profileKey(token string) string {
	key, _, _ := strings.Cut(token, ":")
	return key
}

func onePerKey(tokens []string) bool {
	keys := map[string]bool{}
	for _, token := range tokens {
		key := profileKey(token)
		if keys[key] {
			return false
		}
		keys[key] = true
	}
	return true
}

func manifestProblems(keys []string, raw map[string]interface{}) []string {
	var problems []string
	for _, member := range keys {
		if !manifestMembers[member] {
			problems = append(problems, "unknown member "+jsQuote(member))
		}
	}
	if raw["spec_version"] != ManifestVersion {
		problems = append(problems, "spec_version is not "+ManifestVersion)
	}
	if id, ok := raw["id"].(string); !ok || !manifestIDRE.MatchString(id) {
		problems = append(problems, "id is not <dotted name>/v<major>")
	}
	if api, ok := raw["presentation_api"].(string); !ok || !presentationAPIRE.MatchString(api) {
		problems = append(problems, "presentation_api is not aac.presentation-api/v<major>")
	}
	if min, ok := raw["runtime_min"].(string); !ok || !runtimeVersionRE.MatchString(min) {
		problems = append(problems, "runtime_min is not MAJOR.MINOR.PATCH")
	}
	trust := raw["trust_class"]
	if trust != "trusted-executable" && trust != "declarative" {
		problems = append(problems, "trust_class is neither trusted-executable nor declarative")
	}
	requires, requiresOK := object(raw["requires"])
	if _, ok := requires["bundle_kind"].(string); !requiresOK || !ok {
		problems = append(problems, "requires.bundle_kind is missing")
	}
	forbids, _ := object(raw["forbids"])
	var goOnly []string
	requiredProfiles, bad := list(requires, "profiles")
	if bad {
		goOnly = append(goOnly, "requires.profiles is not a list")
	}
	forbiddenProfiles, bad := list(forbids, "profiles")
	if bad {
		goOnly = append(goOnly, "forbids.profiles is not a list")
	}
	var requiredExtensions []interface{}
	if extensions, present := requires["extensions"]; present {
		block, ok := object(extensions)
		if !ok {
			goOnly = append(goOnly, "requires.extensions is not an object")
		} else if requiredExtensions, bad = list(block, "required"); bad {
			goOnly = append(goOnly, "requires.extensions.required is not a list")
		}
	}
	forbiddenExtensions, bad := list(forbids, "extensions")
	if bad {
		goOnly = append(goOnly, "forbids.extensions is not a list")
	}
	for _, token := range append(append([]interface{}{}, requiredProfiles...), forbiddenProfiles...) {
		if s, ok := token.(string); !ok || !profileTokenRE.MatchString(s) {
			problems = append(problems, fmt.Sprintf("profile token %s is malformed", jsQuote(token)))
		}
	}
	audiences, audiencesOK := raw["audiences"].([]interface{})
	audiencesBad := !audiencesOK || len(audiences) == 0
	for _, audience := range audiences {
		if s, ok := audience.(string); !ok || !audienceRE.MatchString(s) {
			audiencesBad = true
		}
	}
	if audiencesBad {
		problems = append(problems, "audiences is not a non-empty list of audience tokens")
	}
	formats, formatsOK := raw["formats"].([]interface{})
	formatsBad := !formatsOK || len(formats) == 0
	for _, format := range formats {
		s, ok := format.(string)
		if !ok || !contains([]string{"html", "fragment", "embedded"}, s) {
			formatsBad = true
		}
	}
	if formatsBad {
		problems = append(problems, "formats is not a non-empty list of html/fragment/embedded")
	}
	priority, priorityPresent := raw["priority"]
	if fallback, ok := raw["fallback"].(bool); !ok {
		problems = append(problems, "fallback is not a boolean")
	} else if fallback && priorityPresent {
		problems = append(problems, "a fallback carries no priority")
	} else if n, integer := isInteger(priority); !fallback && !(integer && n >= 1) {
		problems = append(problems, "a specific module needs an integer priority >= 1")
	}
	_, hasExecutable := raw["executable"]
	_, hasDeclarative := raw["declarative"]
	if (trust == "trusted-executable") != (hasExecutable && !hasDeclarative) {
		problems = append(problems, "trusted-executable carries executable, declarative carries declarative")
	}
	reqP, forbP := stringItems(requiredProfiles), stringItems(forbiddenProfiles)
	reqE, forbE := stringItems(requiredExtensions), stringItems(forbiddenExtensions)
	for _, token := range forbP {
		if contains(reqP, token) {
			problems = append(problems, "requires and forbids share a profile")
			break
		}
	}
	for _, kind := range forbE {
		if contains(reqE, kind) {
			problems = append(problems, "requires and forbids share an extension")
			break
		}
	}
	if !onePerKey(reqP) {
		problems = append(problems, "requires two tokens of one profile key")
	}
	return append(problems, goOnly...)
}
