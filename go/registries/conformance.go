// SPDX-License-Identifier: BSD-3-Clause
package registries

// Registry conformance: is every registry-governed value a Capsule carries
// registered on the axis it is carried on? A producer-side check for a
// producer's own CI, never verification: a verifier MUST NOT reject a record
// solely because it carries an unregistered value (spec/REGISTRY.md, "The
// never-reject invariant").
// The Python reference is agent_action_capsule/registry_conformance.py; both
// read vectors/registry-conformance/.

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// CapsuleField is one registry-governed Capsule field. A path segment ending
// in "[]" means every element of that array.
type CapsuleField struct {
	Path string
	Axis string
}

// CapsuleFields lists the registry-governed Capsule fields, in report order.
var CapsuleFields = []CapsuleField{
	{"disposition.verdict_class", "verdict_class"},
	{"disposition.decision", "disposition.decision"},
	{"effect.type", "effect.type"},
	{"effect.irreversibility_class", "irreversibility_class"},
	{"effect.effect_attestation", "effect_attestation"},
	{"chain.relation", "chain.relation"},
	{"references[].citation_purpose", "citation_purpose"},
	{"domain", "domain"},
	{"provenance", "provenance"},
	{"provenance_mode.mode", "provenance_mode"},
}

// otherAxes are registries no checked Capsule field carries; they still count
// as "another axis" for the cross-axis case.
var otherAxes = []string{
	"Evidence Bundle kind",
	"Evidence Bundle extension kind",
	"Evidence Bundle countersignature type",
	"Evidence Request derivation",
	"Evidence Layer epistemic type",
	"Evidence Layer link type",
}

var (
	plainHeaderRE = regexp.MustCompile(`^##\s+\d+\.\s+(.+?)\s*$`)
	aliasRE       = regexp.MustCompile("^-\\s+`([^`]+)`\\s+→\\s+`([^`]+)`")
)

// §6 states the `sequence` alias in prose rather than as a mapping bullet.
const sequenceHeading = "**Deployed legacy alias — `sequence`.**"

// Conformance statuses. Registered and Private conform; the rest do not.
const (
	StatusRegistered   = "registered"
	StatusLegacyAlias  = "legacy_alias"
	StatusCrossAxis    = "cross_axis"
	StatusPrivate      = "private"
	StatusUnregistered = "unregistered"
)

// ConformanceFinding classifies one present registry-governed value.
type ConformanceFinding struct {
	Path         string   `json:"path"`
	Axis         string   `json:"axis"`
	Value        any      `json:"value"`
	Status       string   `json:"status"`
	RegisteredOn []string `json:"registered_on,omitempty"`
	EmitInstead  string   `json:"emit_instead,omitempty"`
}

// Conformant reports whether the value conforms.
func (f ConformanceFinding) Conformant() bool {
	return f.Status == StatusRegistered || f.Status == StatusPrivate
}

// Axes holds the registered sets and the chain.relation legacy aliases.
type Axes struct {
	Sets    map[string]map[string]bool
	Aliases map[string]string
}

func sectionsOf(md []byte) (map[string][]string, error) {
	sections := make(map[string][]string)
	current := ""
	scanner := bufio.NewScanner(bytes.NewReader(md))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "## "):
			current = ""
			if m := headerRE.FindStringSubmatch(line); m != nil {
				current = m[1]
			} else if m := plainHeaderRE.FindStringSubmatch(line); m != nil {
				current = m[1]
			}
			if current != "" {
				sections[current] = nil
			}
		case current != "" && strings.HasPrefix(line, "### "):
			// A provisional subsection is not the registered set.
			current = ""
		case current != "":
			sections[current] = append(sections[current], line)
		}
	}
	return sections, scanner.Err()
}

// LoadAxes parses every axis from the embedded authoritative REGISTRY.md.
func LoadAxes() (*Axes, error) {
	return ParseAxes(authoritativeRegistry)
}

// ParseAxes parses every Capsule-field axis, every other axis, and the §6
// legacy aliases from REGISTRY.md bytes. A missing or empty section is an
// error, so a renamed section fails loudly rather than emptying a set.
func ParseAxes(md []byte) (*Axes, error) {
	sections, err := sectionsOf(md)
	if err != nil {
		return nil, fmt.Errorf("reading REGISTRY.md: %w", err)
	}
	names := make([]string, 0, len(CapsuleFields)+len(otherAxes))
	for _, f := range CapsuleFields {
		names = append(names, f.Axis)
	}
	names = append(names, otherAxes...)
	axes := &Axes{Sets: make(map[string]map[string]bool), Aliases: make(map[string]string)}
	for _, name := range names {
		lines, ok := sections[name]
		if !ok {
			return nil, fmt.Errorf("registry section %q not found in REGISTRY.md", name)
		}
		values := seededValuesInSection(lines)
		if len(values) == 0 {
			return nil, fmt.Errorf("registry section %q parsed with no values", name)
		}
		set := make(map[string]bool, len(values))
		for _, v := range values {
			set[v] = true
		}
		axes.Sets[name] = set
	}
	for _, line := range sections["chain.relation"] {
		if m := aliasRE.FindStringSubmatch(line); m != nil {
			axes.Aliases[m[1]] = m[2]
		}
		if strings.HasPrefix(line, sequenceHeading) {
			axes.Aliases["sequence"] = "follows"
		}
	}
	return axes, nil
}

type located struct {
	path  string
	value any
}

func valuesAt(record map[string]any, path string) []located {
	nodes := []located{{"", record}}
	for _, seg := range strings.Split(path, ".") {
		key, isArray := strings.CutSuffix(seg, "[]")
		var next []located
		for _, n := range nodes {
			obj, ok := n.value.(map[string]any)
			if !ok {
				continue
			}
			child, ok := obj[key]
			if !ok {
				continue
			}
			here := key
			if n.path != "" {
				here = n.path + "." + key
			}
			if !isArray {
				next = append(next, located{here, child})
				continue
			}
			if items, ok := child.([]any); ok {
				for i, item := range items {
					next = append(next, located{fmt.Sprintf("%s[%d]", here, i), item})
				}
			}
		}
		nodes = next
	}
	return nodes
}

// CheckCapsule classifies every registry-governed value present in capsule
// (a decoded JSON object). An absent field produces no finding; a present
// value that is not a string is unregistered.
func (a *Axes) CheckCapsule(capsule map[string]any) []ConformanceFinding {
	var out []ConformanceFinding
	for _, field := range CapsuleFields {
		for _, loc := range valuesAt(capsule, field.Path) {
			out = append(out, a.classify(loc.path, field.Axis, loc.value))
		}
	}
	return out
}

func (a *Axes) classify(path, axis string, value any) ConformanceFinding {
	f := ConformanceFinding{Path: path, Axis: axis, Value: value}
	s, ok := value.(string)
	switch {
	case !ok:
		f.Status = StatusUnregistered
	case a.Sets[axis][s]:
		f.Status = StatusRegistered
	case axis == "chain.relation" && a.Aliases[s] != "":
		f.Status = StatusLegacyAlias
		f.EmitInstead = a.Aliases[s]
	case axis == "domain" && strings.HasPrefix(s, "x-"):
		f.Status = StatusPrivate
	default:
		for other, set := range a.Sets {
			if other != axis && set[s] {
				f.RegisteredOn = append(f.RegisteredOn, other)
			}
		}
		sort.Strings(f.RegisteredOn)
		f.Status = StatusUnregistered
		if len(f.RegisteredOn) > 0 {
			f.Status = StatusCrossAxis
		}
	}
	return f
}

// Conformant reports whether every finding conforms.
func Conformant(findings []ConformanceFinding) bool {
	for _, f := range findings {
		if !f.Conformant() {
			return false
		}
	}
	return true
}
