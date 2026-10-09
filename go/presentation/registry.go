// SPDX-License-Identifier: BSD-3-Clause
package presentation

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Runtime is what a presentation runtime implements (spec section 3.2).
type Runtime struct {
	// PresentationAPIs lists every presentation_api value it implements.
	PresentationAPIs []string `json:"presentation_apis"`
	// RuntimeVersion is its own version, MAJOR.MINOR.PATCH.
	RuntimeVersion string `json:"runtime_version"`
}

// ReferenceRuntime is the reference runtime of this repository: exactly
// aac.presentation-api/v0, version 0.1.0.
func ReferenceRuntime() Runtime {
	return Runtime{PresentationAPIs: []string{APIV0}, RuntimeVersion: "0.1.0"}
}

// RefusalReason is why a runtime refused a module (spec section 3.2).
type RefusalReason string

// The refusal reasons, in their order of precedence.
const (
	RefusalAPIUnsupported RefusalReason = "presentation_api_unsupported"
	RefusalRuntimeTooOld  RefusalReason = "runtime_too_old"
)

// Refusal is a module a runtime refused, as the page reports it.
type Refusal struct {
	ID              string        `json:"id"`
	PresentationAPI string        `json:"presentation_api"`
	RuntimeMin      string        `json:"runtime_min"`
	Reason          RefusalReason `json:"reason"`
	// Extensions lists the extension kinds the module requires: the rows
	// that name it.
	Extensions []string `json:"extensions"`
	// RuntimeVersion is the refusing runtime's version.
	RuntimeVersion string `json:"runtime_version"`
}

func (r Refusal) need() string {
	if r.Reason == RefusalAPIUnsupported {
		return fmt.Sprintf("needs presentation API %s, which this viewer does not implement", r.PresentationAPI)
	}
	return fmt.Sprintf("needs runtime %s or later; this viewer is %s", r.RuntimeMin, r.RuntimeVersion)
}

// RefusalRow is the semantics cell of the row of an extension a refused
// module requires (spec section 3.2), exactly. covered is whether the bundle
// digest covers the block.
func RefusalRow(r Refusal, covered bool) string {
	integrity := "Integrity not verified"
	if covered {
		integrity = "Integrity verified"
	}
	return fmt.Sprintf("%s; meaning not interpreted: presentation module %s %s", integrity, r.ID, r.need())
}

// RefusalLine is the line for a refused module that requires no extension
// (spec section 3.2), exactly.
func RefusalLine(r Refusal) string {
	return fmt.Sprintf("Presentation module %s was not used: it %s", r.ID, r.need())
}

// compareVersions compares MAJOR.MINOR.PATCH numerically, component by
// component. A component that is not a number compares as neither lower nor
// higher, as the TypeScript runtime's comparison does.
func compareVersions(a, b string) int {
	left, right := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		if i >= len(left) || i >= len(right) {
			return 0
		}
		l, errL := strconv.ParseFloat(left[i], 64)
		r, errR := strconv.ParseFloat(right[i], 64)
		if errL != nil || errR != nil {
			return 0
		}
		if l != r {
			if l < r {
				return -1
			}
			return 1
		}
	}
	return 0
}

// RefuseReason says why runtime refuses manifest (spec section 3.2); ok is
// false when it does not.
func RefuseReason(m Manifest, runtime Runtime) (reason RefusalReason, refused bool) {
	if !contains(runtime.PresentationAPIs, m.PresentationAPI) {
		return RefusalAPIUnsupported, true
	}
	if compareVersions(runtime.RuntimeVersion, m.RuntimeMin) < 0 {
		return RefusalRuntimeTooOld, true
	}
	return "", false
}

// RefusalOf is the refusal runtime gives manifest; ok is false when it
// accepts it.
func RefusalOf(m Manifest, runtime Runtime) (Refusal, bool) {
	reason, refused := RefuseReason(m, runtime)
	if !refused {
		return Refusal{}, false
	}
	return Refusal{
		ID:              m.ID,
		PresentationAPI: m.PresentationAPI,
		RuntimeMin:      m.RuntimeMin,
		Reason:          reason,
		Extensions:      append([]string{}, m.RequiredExtensions()...),
		RuntimeVersion:  runtime.RuntimeVersion,
	}, true
}

// AmbiguityError is two or more manifests of one tier matching one
// descriptor: a hard error, never first-wins (spec sections 4.3 and 4.5).
type AmbiguityError struct {
	// IDs names every colliding module, sorted.
	IDs     []string
	message string
}

func (e *AmbiguityError) Error() string { return e.message }

func runtimeAmbiguity(ids []string) *AmbiguityError {
	sorted := append([]string{}, ids...)
	sort.Strings(sorted)
	return &AmbiguityError{
		IDs:     sorted,
		message: fmt.Sprintf("presentation is ambiguous: %s all match; a tie is an error, never first-wins", strings.Join(sorted, ", ")),
	}
}

// ResolutionKind is the outcome of a resolution.
type ResolutionKind string

// The three outcomes of spec section 4.3 (an ambiguity is an error).
const (
	// ResolutionRefusal: the bundle did not verify; nothing was matched.
	ResolutionRefusal ResolutionKind = "refusal"
	// ResolutionNone: no module; the page shows the "no presentation" notice.
	ResolutionNone ResolutionKind = "no-presentation"
	// ResolutionModule: one module is selected.
	ResolutionModule ResolutionKind = "module"
)

// Resolution is the result of resolving one descriptor, audience and format.
type Resolution struct {
	Kind ResolutionKind
	// Manifest is the selected module's manifest, for ResolutionModule only.
	Manifest *Manifest
	// Refused lists every module that matched but that the runtime refused,
	// in tier order. A page that shows anything else names each one.
	Refused []Refusal
}

// Matches is the declarative match of spec section 4.3, step 2.
func Matches(m Manifest, d Descriptor, audience string, format Format) bool {
	if d.BundleKind == nil || m.Requires.BundleKind != *d.BundleKind {
		return false
	}
	for _, token := range m.RequiredProfiles() {
		if !contains(d.Profiles, token) {
			return false
		}
	}
	for _, kind := range m.RequiredExtensions() {
		if !contains(d.Extensions, kind) {
			return false
		}
	}
	for _, token := range m.ForbiddenProfiles() {
		if contains(d.Profiles, token) {
			return false
		}
	}
	for _, kind := range m.ForbiddenExtensions() {
		if contains(d.Extensions, kind) {
			return false
		}
	}
	if !contains(m.Audiences, "*") && !contains(m.Audiences, audience) {
		return false
	}
	for _, f := range m.Formats {
		if f == format {
			return true
		}
	}
	return false
}

// CoMatchable is the static test of spec section 4.5: true exactly when some
// descriptor matches both manifests, whatever their tiers.
func CoMatchable(a, b Manifest) bool {
	if a.Requires.BundleKind != b.Requires.BundleKind {
		return false
	}
	if !contains(a.Audiences, "*") && !contains(b.Audiences, "*") {
		shared := false
		for _, audience := range a.Audiences {
			shared = shared || contains(b.Audiences, audience)
		}
		if !shared {
			return false
		}
	}
	sharedFormat := false
	for _, f := range a.Formats {
		for _, g := range b.Formats {
			sharedFormat = sharedFormat || f == g
		}
	}
	if !sharedFormat {
		return false
	}
	reqP := append(append([]string{}, a.RequiredProfiles()...), b.RequiredProfiles()...)
	reqE := append(append([]string{}, a.RequiredExtensions()...), b.RequiredExtensions()...)
	for _, token := range append(append([]string{}, a.ForbiddenProfiles()...), b.ForbiddenProfiles()...) {
		if contains(reqP, token) {
			return false
		}
	}
	for _, kind := range append(append([]string{}, a.ForbiddenExtensions()...), b.ForbiddenExtensions()...) {
		if contains(reqE, kind) {
			return false
		}
	}
	unique := map[string]bool{}
	var tokens []string
	for _, token := range reqP {
		if !unique[token] {
			unique[token] = true
			tokens = append(tokens, token)
		}
	}
	return onePerKey(tokens)
}

// ResolveManifests is spec section 4.3 over an explicit manifest list,
// exactly, without the registration test. canRender answers step 3 and 4's
// canRender for a matched, unrefused manifest (nil: every module renders);
// refuse says whether the runtime refused one (nil: none is refused).
// An *AmbiguityError is returned when a tier has two or more matches; it is
// decided before canRender is asked.
func ResolveManifests(
	manifests []Manifest,
	d Descriptor,
	audience string,
	format Format,
	canRender func(Manifest) bool,
	refuse func(Manifest) (Refusal, bool),
) (Resolution, error) {
	if !d.Verified {
		return Resolution{Kind: ResolutionRefusal}, nil
	}
	var matched []int
	for i, m := range manifests {
		if Matches(m, d, audience, format) {
			matched = append(matched, i)
		}
	}
	refused := []Refusal{}
	for _, fallback := range []bool{false, true} {
		var tier []int
		var ids []string
		for _, i := range matched {
			if manifests[i].Fallback == fallback {
				tier = append(tier, i)
				ids = append(ids, manifests[i].ID)
			}
		}
		if len(tier) > 1 {
			return Resolution{}, runtimeAmbiguity(ids)
		}
		if len(tier) == 0 {
			continue
		}
		only := manifests[tier[0]]
		if refuse != nil {
			if refusal, isRefused := refuse(only); isRefused {
				refused = append(refused, refusal)
				continue
			}
		}
		if canRender == nil || canRender(only) {
			selected := only
			return Resolution{Kind: ResolutionModule, Manifest: &selected, Refused: refused}, nil
		}
	}
	return Resolution{Kind: ResolutionNone, Refused: refused}, nil
}

// Registration is the outcome of Registry.Register.
type Registration struct {
	// Refused is true when the runtime refused the module (spec section 3.2):
	// it is held, counts for ambiguity, and is never selected.
	Refused bool
	// Refusal is the refusal, when Refused.
	Refusal Refusal
}

type entry struct {
	manifest Manifest
	refusal  *Refusal
}

// Registry is a set of manifests under one runtime: section 4.5 at
// registration, section 3.2 refusal, and section 4.3 at resolution.
// Registration order decides nothing.
type Registry struct {
	runtime Runtime
	entries []entry
}

// NewRegistry is an empty registry for runtime.
func NewRegistry(runtime Runtime) *Registry {
	return &Registry{runtime: runtime}
}

// Runtime is the runtime declaration the registry applies.
func (r *Registry) Runtime() Runtime { return r.runtime }

// Register adds a manifest. It returns a *RegistrationError for a malformed
// or dead manifest or a duplicate id, and an *AmbiguityError when some
// descriptor could match it together with a registered manifest of the same
// tier, refused or not (section 4.5). A well-formed manifest the runtime does
// not support is registered as refused (section 3.2).
func (r *Registry) Register(m Manifest) (Registration, error) {
	if problems := m.Problems(); len(problems) > 0 {
		return Registration{}, &RegistrationError{
			Problems: problems,
			message:  fmt.Sprintf("manifest %s refused: %s", jsQuote(m.ID), strings.Join(problems, "; ")),
		}
	}
	for _, other := range r.entries {
		if other.manifest.ID == m.ID {
			return Registration{}, &RegistrationError{message: fmt.Sprintf("manifest %s is already registered", m.ID)}
		}
		if other.manifest.Fallback == m.Fallback && CoMatchable(other.manifest, m) {
			ids := []string{other.manifest.ID, m.ID}
			sort.Strings(ids)
			tier := "specific"
			if m.Fallback {
				tier = "fallbacks"
			}
			return Registration{}, &AmbiguityError{
				IDs:     ids,
				message: fmt.Sprintf("manifests %s and %s are both %s and one descriptor can match both; state precedence with forbids", other.manifest.ID, m.ID, tier),
			}
		}
	}
	e := entry{manifest: m}
	if refusal, refused := RefusalOf(m, r.runtime); refused {
		e.refusal = &refusal
	}
	r.entries = append(r.entries, e)
	if e.refusal != nil {
		return Registration{Refused: true, Refusal: *e.refusal}, nil
	}
	return Registration{}, nil
}

// List is every manifest the registry can select, in registration order.
// Refused manifests are not listed; see Refused.
func (r *Registry) List() []Manifest {
	out := []Manifest{}
	for _, e := range r.entries {
		if e.refusal == nil {
			out = append(out, e.manifest)
		}
	}
	return out
}

// Refused is every manifest the runtime refused, with the reason.
func (r *Registry) Refused() []Refusal {
	out := []Refusal{}
	for _, e := range r.entries {
		if e.refusal != nil {
			out = append(out, *e.refusal)
		}
	}
	return out
}

// Resolve is spec section 4.3 with every module able to render: the one
// manifest the declarative match selects for d, audience and format. Go has
// no module code, so where the TypeScript runtime would also ask the
// module's canRender, this resolves to the selected manifest; use
// ResolveWith to supply that answer.
func (r *Registry) Resolve(d Descriptor, audience string, format Format) (Resolution, error) {
	return r.ResolveWith(d, audience, format, nil)
}

// ResolveWith is Resolve with canRender answering for each matched, unrefused
// manifest (nil: every module renders).
func (r *Registry) ResolveWith(d Descriptor, audience string, format Format, canRender func(Manifest) bool) (Resolution, error) {
	manifests := make([]Manifest, len(r.entries))
	refusals := make(map[string]Refusal)
	for i, e := range r.entries {
		manifests[i] = e.manifest
		if e.refusal != nil {
			refusals[e.manifest.ID] = *e.refusal
		}
	}
	return ResolveManifests(manifests, d, audience, format, canRender, func(m Manifest) (Refusal, bool) {
		refusal, ok := refusals[m.ID]
		return refusal, ok
	})
}
