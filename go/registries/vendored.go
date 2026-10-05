// SPDX-License-Identifier: BSD-3-Clause

package registries

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime/debug"
	"sort"
	"strings"
)

// Problem codes of a vendored-copy check. They match the Python
// agent_action_capsule.registries.vendored codes; the shared vectors in
// vectors/vendored-registry/ pin both.
const (
	ProblemValuesDiffer     = "VALUES_DIFFER"
	ProblemStaleRef         = "STALE_REF"
	ProblemUnpinned         = "UNPINNED"
	ProblemRefUnresolvable  = "REF_UNRESOLVABLE"
	ProblemSectionNotFound  = "SECTION_NOT_FOUND"
	ProblemSectionAmbiguous = "SECTION_AMBIGUOUS"
	ProblemDocumentMismatch = "DOCUMENT_MISMATCH"
	ProblemMalformed        = "MALFORMED"
)

// ModulePath is this Go module's path, used to find the version of the
// embedded REGISTRY.md copy in the build info.
const ModulePath = "github.com/action-state-group/agent-action-capsule/go"

var (
	vendoredSectionRE = regexp.MustCompile(`(?i)\(section\s+(\d+)\)`)
	revisionRE        = regexp.MustCompile(`-\d\d$`)
	versionRefRE      = regexp.MustCompile(`^v\d+(\.\d+)*([-+].*)?$`)
)

// VendoredCheck is the outcome of CheckVendored. OK is true only when Problems
// is empty. Detail is human text and not part of the vector form.
type VendoredCheck struct {
	OK       bool     `json:"ok"`
	Registry *string  `json:"registry"`
	Section  *string  `json:"section"`
	Ref      *string  `json:"ref"`
	Added    []string `json:"added"`
	Missing  []string `json:"missing"`
	Problems []string `json:"problems"`
	Detail   []string `json:"-"`
}

func (c *VendoredCheck) fail(code, detail string) *VendoredCheck {
	for _, p := range c.Problems {
		if p == code {
			c.Detail = append(c.Detail, detail)
			return c
		}
	}
	c.Problems = append(c.Problems, code)
	c.Detail = append(c.Detail, detail)
	c.OK = false
	return c
}

// NormalizeRef makes "go/v0.6.0", "v0.6.0" and "0.6.0" compare equal.
func NormalizeRef(ref string) string {
	ref = strings.TrimSpace(ref)
	ref = strings.TrimPrefix(ref, "go/")
	if versionRefRE.MatchString(ref) {
		ref = ref[1:]
	}
	return ref
}

// vendoredFile is evidencebook's vendored value-set format. See the Python
// agent_action_capsule.registries.vendored docstring for each field.
type vendoredFile struct {
	Source *struct {
		Document        *string `json:"document"`
		InterimRegistry *string `json:"interim_registry"`
		Registry        *string `json:"registry"`
		RegistryRef     *string `json:"registry_ref"`
	} `json:"source"`
	Values []string `json:"values"`
}

// tablesFrom parses a REGISTRY.md, or a registries.json generated from one.
func tablesFrom(registry []byte) ([]Table, error) {
	if trimmed := bytes.TrimSpace(registry); len(trimmed) > 0 && trimmed[0] == '{' {
		var doc struct {
			Registries map[string]Table `json:"registries"`
		}
		if err := json.Unmarshal(registry, &doc); err != nil {
			return nil, err
		}
		out := make([]Table, 0, len(doc.Registries))
		for name, t := range doc.Registries {
			t.Name = name
			out = append(out, t)
		}
		return out, nil
	}
	return ParseTables(bytes.NewReader(registry))
}

func strPtr(s string) *string { return &s }

// CheckVendored compares a vendored value-set file with registry, the text of
// REGISTRY.md (or registries.json) as of registryRef. ref is the pin the caller
// checks against; empty means the file's own source.registry_ref. It fails on
// any difference in the value set, naming the added and missing values.
//
// A pass proves the copy equals the registry at the pinned ref, not that the
// pin is current.
func CheckVendored(vendored, registry []byte, registryRef, ref string) *VendoredCheck {
	out := &VendoredCheck{OK: true, Added: []string{}, Missing: []string{}, Problems: []string{}}
	var raw any
	if err := json.Unmarshal(vendored, &raw); err != nil {
		return out.fail(ProblemMalformed, "vendored file is not JSON: "+err.Error())
	}
	if _, ok := raw.(map[string]any); !ok {
		return out.fail(ProblemMalformed, "vendored file is not a JSON object")
	}
	var f vendoredFile
	if err := json.Unmarshal(vendored, &f); err != nil {
		return out.fail(ProblemMalformed, "vendored file: "+err.Error())
	}
	if f.Source == nil {
		return out.fail(ProblemMalformed, "vendored file has no source object")
	}
	if f.Values == nil {
		return out.fail(ProblemMalformed, "vendored values is not a list of strings")
	}

	pinned := ref
	if pinned == "" && f.Source.RegistryRef != nil {
		pinned = *f.Source.RegistryRef
	}
	if pinned == "" {
		return out.fail(ProblemUnpinned, "no pin: pass --ref or record source.registry_ref in the file")
	}
	out.Ref = strPtr(pinned)
	if f.Source.RegistryRef != nil && NormalizeRef(*f.Source.RegistryRef) != NormalizeRef(pinned) {
		out.fail(ProblemStaleRef, fmt.Sprintf("file was vendored at %q but the check pins %q: re-vendor at the pin, or move the pin deliberately", *f.Source.RegistryRef, pinned))
	}
	if NormalizeRef(registryRef) != NormalizeRef(pinned) {
		return out.fail(ProblemRefUnresolvable, fmt.Sprintf("the registry copy available is at %q, not the pin %q: pass --registry with REGISTRY.md at %q", registryRef, pinned, pinned))
	}

	tables, err := tablesFrom(registry)
	if err != nil {
		return out.fail(ProblemMalformed, "registry: "+err.Error())
	}
	section := ""
	if f.Source.InterimRegistry != nil {
		if m := vendoredSectionRE.FindStringSubmatch(*f.Source.InterimRegistry); m != nil {
			section = m[1]
		}
	}
	if section == "" && f.Source.Registry == nil {
		return out.fail(ProblemMalformed, "source.interim_registry names no '(section N)' and source.registry is absent")
	}
	var candidates []Table
	for _, t := range tables {
		if section != "" && t.Section != section {
			continue
		}
		if f.Source.Registry != nil && t.Name != *f.Source.Registry {
			continue
		}
		candidates = append(candidates, t)
	}
	if len(candidates) == 0 {
		where := "section " + section
		if section == "" {
			where = fmt.Sprintf("registry %q", *f.Source.Registry)
		} else if f.Source.Registry != nil {
			where += fmt.Sprintf(" holding %q", *f.Source.Registry)
		}
		return out.fail(ProblemSectionNotFound, fmt.Sprintf("REGISTRY.md at %q has no %s", pinned, where))
	}
	if len(candidates) > 1 {
		names := make([]string, len(candidates))
		for i, t := range candidates {
			names[i] = t.Name
		}
		return out.fail(ProblemSectionAmbiguous, fmt.Sprintf("section %s holds %s: add source.registry", section, strings.Join(names, ", ")))
	}
	table := candidates[0]
	out.Registry, out.Section = strPtr(table.Name), strPtr(table.Section)

	if f.Source.Document != nil && revisionRE.ReplaceAllString(*f.Source.Document, "") != table.DefinedIn {
		out.fail(ProblemDocumentMismatch, fmt.Sprintf("source.document %q does not own section %s (%s, defined in %s)", *f.Source.Document, table.Section, table.Name, table.DefinedIn))
	}

	have := make(map[string]string, len(f.Values))
	for _, v := range f.Values {
		have[strings.ToLower(v)] = v
	}
	registered := make(map[string]string, len(table.Values))
	for _, v := range table.Values {
		registered[strings.ToLower(v)] = v
	}
	for k, v := range have {
		if _, ok := registered[k]; !ok {
			out.Added = append(out.Added, v)
		}
	}
	for k, v := range registered {
		if _, ok := have[k]; !ok {
			out.Missing = append(out.Missing, v)
		}
	}
	sort.Strings(out.Added)
	sort.Strings(out.Missing)
	if len(out.Added) > 0 || len(out.Missing) > 0 {
		out.fail(ProblemValuesDiffer, fmt.Sprintf("%s at %q: added %v, missing %v", table.Name, pinned, out.Added, out.Missing))
	}
	return out
}

// EmbeddedRegistry returns a copy of the REGISTRY.md embedded in this package.
func EmbeddedRegistry() []byte { return append([]byte(nil), authoritativeRegistry...) }

// EmbeddedVersion is the module version the embedded REGISTRY.md belongs to,
// from the build info: the version of this module as a dependency, or as the
// main module under `go run <pkg>@<version>`. It is "" when unknown (a
// development build), so CheckVendored against the embedded copy then fails as
// REF_UNRESOLVABLE instead of checking against an unknown ref.
func EmbeddedVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	if info.Main.Path == ModulePath && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	for _, dep := range info.Deps {
		if dep.Path == ModulePath {
			if dep.Replace != nil {
				return ""
			}
			return dep.Version
		}
	}
	return ""
}
