# Presentation Contract — v0

**Status.** Design specification, pre-Internet-Draft, beside `spec/evidence-result-v0.md` and
`spec/evidence-plan-ir-v0.md`. This document defines how a verified Evidence Bundle becomes a
page: the module interface and the presentation ABI that versions it, the declarative
manifest a module is selected by, the two module trust classes, the chrome rule, the
text-binding rule, the presentation invariants and the three depth levels every module fills. It is normative for any viewer, builder or module that
claims to follow it. It defines no runtime code; the reference registry is a separate change.

**Companion schema.** `schemas/presentation-manifest-v0.json`, a JSON Schema (2020-12) for one
manifest (`$defs/PresentationManifest`) and for a wording pack (`$defs/WordingPack`). Its
checker, `schemas/check_presentation_manifest_examples.py`, also runs the resolution rule of
section 4 over the committed manifests, because ambiguity is a property of a set of manifests
that no schema of one manifest can see. Where the schema and this document disagree, this
document governs and the schema is corrected to match.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in
BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

## Dependency boundary

**Owns:** the `PresentationModule` interface and the presentation ABI that versions it
(`presentation_api`, `runtime_min`, the runtime's declaration and the refusal of section 3.2);
the immutability requirement on the context a module reads (section 3.1); the manifest namespace
`aac.presentation-manifest/v0` and its fields; the resolution algorithm and its ambiguity error;
the resolution descriptor; the trust classes; the chrome rule as it applies to modules; the
text-binding rule; the wording pack shape (`aac.wording-pack/v0`) and the meaning of
`wording_sha256`; the invariants of section 8; the depth levels L0, L1 and L2.

**Depends on, and does not redefine:**

- Bundle verification (`draft-mih-zhang-agent-disclosure-bundle`, and the reference
  `verifyBundle`): what "the bundle verified" means is decided there, once.
- `VerifiedBundleContext` (`ts/src/bundle.ts`): the one object built from one verification run.
  A module reads verified content only through it, and cannot change it (section 3.1).
- The bundle kind and extension kind registries (`spec/REGISTRY.md` sections 13 and 14).
- The emitter shell and its named slots (`go/emitter/shell.html`, `ts/src/emitter-shell.html`):
  `CSP_SLOT`, `TITLE_SLOT`, `THEME_SLOT`, `BUNDLE_SLOT`, `CORE_RUNTIME_SLOT`, `MODULE_SLOT`,
  `BOOTSTRAP_SLOT`, and the per-page Content-Security-Policy the emitter computes.
- The `presentation/v1` bundle extension and the Result `view` block
  (`spec/evidence-result-v0.md` section 8): header chrome, which section 6 generalizes.
- RFC 8785 (JCS) and SHA-256 (FIPS 180-4).

**Out of scope:** any particular module's layout; hosting, caching or delivery of pages; a
module catalogue. A module that is not shipped by this repository plugs in through this
contract and is not described here beyond its manifest.

## 1. Terms

- **Verified bundle context** (the context): a `VerifiedBundleContext`. It carries a frozen copy
  of the bundle as supplied, the one verification result, the disclosures as the verifier resolved them
  (`disclosed`, `withheld` or `disclosure_mismatch`), the records whose identity verified, the
  countersignature results, the caller's countersigner source and the extension results.
- **Verified**: the bundle passed the viewer's verification gate (graph closure, interval
  coverage, per-record membership proven or unbound, every record's identity, every disclosure
  a match or withheld). Today this is `bundleVerified` in `ts/src/evidence-graph-view.ts`.
- **Descriptor**: the resolution inputs derived from a context (section 4.2).
- **Module**: a presentation, from a single panel to a whole report application, selected by
  its manifest.
- **Specific module / fallback**: a module whose manifest has `fallback: false` / `true`.
- **Host**: the core runtime's object that owns the page frame and gives a module the regions
  it fills (section 9).
- **Refusal**: the fixed statement a viewer shows instead of any module's content, with the
  verification checks beneath it (section 8, I1).
- **Audience**: who the page is built for (for example the record holder, a counterparty, an
  adjudicator). An audience is an input to resolution and to disclosure, never an output of a
  module.
- **Format** (packaging target): how the page is packaged: `html` (one offline file),
  `fragment` (a page whose bundle travels in the URL fragment), `embedded` (a region inside a
  host page). A format is **supported** for a bundle when a page in that packaging can be
  produced for it (section 8, I4).
- **Presentation runtime** (the runtime): the core runtime that builds the context, holds the
  registry and calls modules. It declares the presentation API versions it implements and its
  own runtime version (section 3.2).
- **Refused module**: a module whose manifest the runtime cannot honour, because it does not
  implement the manifest's `presentation_api` or is older than its `runtime_min` (section 3.2).

## 2. The pipeline

```
bundle ──▶ verify core ──▶ VerifiedBundleContext ──▶ registry.resolve(context, audience, format)
                                                         │
                                         one module (or the refusal, or an error)
                                                         │
                     canRender(context) ──▶ buildModel(context) ──▶ render(model, host, services)
                                                         │
                                       shell (L0, L1, L2 regions) ──▶ html | fragment | embedded
```

Verification happens once, before resolution, in the core. Nothing a module does can change
its outcome. A host or builder MUST select a module by asking the registry (`list` or
`resolve`); it MUST NOT select one by inspecting the bundle's extensions or root itself. The
manifests are where precedence lives.

## 3. The module interface

A module is the following object. The types are written in TypeScript for precision; an
implementation in another language MUST provide the same members with the same meaning.

```ts
interface PresentationModule<Model> {
  /** The module's manifest (section 4). For a module-slot script it MUST be
   *  JCS-equal to the manifest the builder was given for that script. */
  readonly manifest: PresentationManifest;

  /** Pure and side-effect free. True exactly when buildModel(context) would
   *  produce a model. Called only on a verified context, and only after the
   *  manifest matched (section 4.3). */
  canRender(context: VerifiedBundleContext): boolean;

  /** Builds the module's model from verified content. Pure: no DOM, no
   *  network, no clock, no randomness. */
  buildModel(context: VerifiedBundleContext): Model | Promise<Model>;

  /** Writes the model into the host's depth regions using the services. */
  render(model: Model, host: PresentationHost, services: PresentationServices):
    void | Promise<void>;
}

interface PresentationHost {
  readonly L0: HTMLElement;     // what matters
  readonly L1: HTMLElement;     // why
  readonly L2: HTMLElement;     // verify: module detail, after the core's checks
  readonly depth: "L0" | "L1" | "L2";   // the requested opening level (section 9)
  /** Restyle the banner and the verification section by class only. Their
   *  words, order and data attributes are the core's and do not change. */
  setChromeClass(name: string): void;
}
```

`PresentationServices` are DOM primitives. Each returns an element (or a string) and nothing
else:

| Service | What it does |
|---|---|
| `section(labelKey)` | A titled section whose heading comes from the module's wording pack. |
| `details(summaryKey, open?)` | A native `<details>`/`<summary>` disclosure: the depth primitive. Script-free, prints, survives a narrow screen. |
| `badge(state)` | A state badge from a closed vocabulary the core owns (for example verified / failed / withheld / mismatch / producer-asserted). A module cannot invent a badge state. |
| `citation(capsuleId)` | An in-page link to that record's entry in the L2 verification section. It names the record by its digest; it never fetches. |
| `format.count / format.percent / format.date / format.digest` | Number, date and digest formatting for the active locale. |
| `disclosure(capsuleId, member)` | The member's disclosure state as the verifier resolved it, rendered as the core renders it. |
| `countersigner(entry)` | The display name of a verified, independent countersignature from the caller's countersigner source, or the core's "unlisted" form. Never a name read from the bundle. |
| `wording(key)` | The string for `key` in the module's wording pack (section 7.4). |

Services are not a router. There are no routes, no history manipulation, no navigation between
pages, no fetch and no timers among them; the only links are in-page anchors. A module MAY be a
whole report application with its own internal structure, built from these primitives.

**A module never verifies.** A module MUST NOT call `verifyBundle` or any verifier, MUST NOT
recompute a digest, signature or proof to decide whether something is valid, MUST NOT read a
payload except through the context (in particular never from `window.__BUNDLE__` or the raw
bundle's `disclosures`), and MUST NOT write, alter or restyle the words of the verification
banner, the refusal or the core's verification checks. A module MAY recompute a derived
figure from verified content (a coverage count, a per-bucket total) and MUST then show a
disagreement with the producer's stated figure as a disagreement, never silently prefer either.

### 3.1 The context is effectively immutable

**A `VerifiedBundleContext` MUST be effectively immutable.** No module can change the
verification result or the resolved-disclosure map that anything downstream of it sees.

- A runtime MUST build the context over its own copy of the bundle, verify that copy, and make
  the context's whole object graph unchangeable before any module receives it: the bundle
  copy; the verification result, including every claim, capsule result, disclosure result,
  extension result and countersignature result; the resolved-disclosure map, each of its
  entries and each disclosed payload; the record list, the record index and each record; the
  countersigner source; and the completeness members.
- A map in the context MUST be handed out as a read-only view that has no mutating method, not
  as a mutable map object made read-only by type alone.
- An attempt to change any part of the context MUST fail. In an ES module, which is strict
  code, the attempt throws a `TypeError`. The attempt MUST NOT change what any later reader
  sees: the next module, the core's verification section, the banner and the refusal all read
  the original.
- A module MUST NOT attempt such a change. A module that needs a derived structure (a sorted
  list, an index of its own) builds a new one from the context.
- The caller's own bundle object is not the context: the runtime copies it and does not freeze
  it, and a later change to it does not reach the context.

### 3.2 The presentation ABI

The interfaces of this section (`PresentationModule`, `PresentationHost`,
`PresentationServices`), the closed badge vocabulary, and the members and immutability of the
context together are the **presentation ABI**. It is versioned by its own identifier,
`presentation_api`, which is independent of the manifest namespace (`spec_version`), of the
bundle and capsule format versions, of any package or release version, and of any
command-line tool's plugin interface. A module written against the presentation ABI is loaded
by a presentation runtime, never through a plugin mechanism of some other tool, and a change to
either one never implies a change to the other.

- **`presentation_api`** is `aac.presentation-api/v<major>`. This document defines
  `aac.presentation-api/v0`. The identifier bumps, to a new major, exactly when a change would
  break a conforming module: a member of the interfaces above is removed or its meaning
  changes, a context member is removed or changes meaning, a service is removed or its output
  changes, or a badge state is removed. Adding a service, a context member or a badge state does
  not bump it.
- **The runtime's declaration.** A runtime declares the set of `presentation_api` values it
  implements and its own **runtime version**, `MAJOR.MINOR.PATCH`. An addition within one
  presentation API raises the runtime's minor version. The reference runtime in this
  repository implements exactly `{aac.presentation-api/v0}` and declares runtime version
  `0.1.0`.
- **`runtime_min`** is the lowest runtime version that provides everything the module uses
  within its `presentation_api`, in the same `MAJOR.MINOR.PATCH` form. Versions are compared
  numerically, component by component.

**Refusal.** A runtime refuses a module, in this order of reasons:

1. `presentation_api_unsupported`: the manifest's `presentation_api` is not in the set the
   runtime implements;
2. `runtime_too_old`: the runtime's version is lower than the manifest's `runtime_min`.

A refused module is registered as refused, not rejected as malformed. It MUST NOT be selected,
and none of its methods is called. It still takes part in the static ambiguity test (section
4.5) and in the match of section 4.3, step 2, so that a runtime which refuses it can never put
another specific module in its place. When its manifest matches the descriptor, audience and
format being resolved, the refusal is part of the resolution result and MUST be shown on the
page. **There is no silent fallback**: a page that renders another module (or the "no
presentation" notice) where a refused module matched says so, in these words.

- **In the extension row.** For each extension kind in the refused module's
  `requires.extensions.required` that the bundle carries, that kind's row on the verification
  section has the semantics cell, exactly:

  `Integrity verified; meaning not interpreted: presentation module <id> needs presentation API <presentation_api>, which this viewer does not implement`

  for `presentation_api_unsupported`, and

  `Integrity verified; meaning not interpreted: presentation module <id> needs runtime <runtime_min> or later; this viewer is <runtime version>`

  for `runtime_too_old`. When the bundle digest could not be computed, the cell begins
  `Integrity not verified;` instead of `Integrity verified;` and is otherwise the same. The row
  carries `data-semantics="refused"`, `data-refused-module="<id>"` and
  `data-refusal="<reason>"`. A refusal takes precedence over "interpreted by": the refused
  module did not run, so nothing interpreted the block on its behalf.
- **When it requires no extension.** A refused module whose manifest requires no extension has
  no row of its own, so the verification section shows, after the extension rows, one line per
  such module, exactly:

  `Presentation module <id> was not used: it needs presentation API <presentation_api>, which this viewer does not implement`

  or

  `Presentation module <id> was not used: it needs runtime <runtime_min> or later; this viewer is <runtime version>`

  carrying `data-presentation-refused="<id>"` and `data-refusal="<reason>"`.
- `<id>`, `<presentation_api>`, `<runtime_min>` and `<runtime version>` are inserted as text,
  never as markup.

A manifest with **no** `presentation_api` (or no `runtime_min`) is malformed, not refused: the
schema rejects it and a registry rejects it at registration like any other malformed manifest.
A builder asked to put into a page a module the page's runtime would refuse MUST NOT write the
page, and MUST name the module, its `presentation_api` and `runtime_min`, and the runtime's
declaration: the builder knows both sides, so it fails at build time instead.

## 4. The manifest

### 4.1 Fields

A manifest is a JSON object in the namespace `aac.presentation-manifest/v0`. The namespace is
not `presentation/v1`: that name is a bundle extension kind carrying header chrome, and a
manifest that names it is rejected.

| Field | Required | Meaning |
|---|---|---|
| `spec_version` | yes | The constant `"aac.presentation-manifest/v0"`. |
| `id` | yes | The **module id**: `<dotted name>/v<major>`, for example `org.example.view/v0`. Unique in a registry. The `aac.` prefix is reserved for modules this repository ships. An id is never inferred: a new major version is a new manifest. |
| `presentation_api` | yes | The presentation ABI the module is written against (section 3.2), for example `aac.presentation-api/v0`. |
| `runtime_min` | yes | The lowest runtime version the module needs, `MAJOR.MINOR.PATCH` (section 3.2). |
| `trust_class` | yes | `"trusted-executable"` or `"declarative"` (section 5). |
| `requires.bundle_kind` | yes | The bundle kind the module renders, compared by string equality. |
| `requires.profiles` | no | Profile tokens (section 4.2) the root MUST carry. At most one token per profile key. |
| `requires.extensions.required` | no | Extension kinds that MUST be engaged (section 4.2). |
| `forbids.profiles` | no | Profile tokens the root MUST NOT carry. |
| `forbids.extensions` | no | Extension kinds that MUST NOT be engaged. |
| `audiences` | yes | Audience tokens the module serves; `"*"` serves every audience. |
| `formats` | yes | Any of `"html"`, `"fragment"`, `"embedded"`. |
| `fallback` | yes | `true` for a fallback, `false` for a specific module. |
| `priority` | specific only | An integer ≥ 1. REQUIRED when `fallback` is `false`; MUST be absent when `fallback` is `true` (section 4.4). |
| `executable` | trusted-executable only | `carrier` (`"core-runtime"` or `"module-slot"`); for `module-slot`, `script_sha256` and optional `style_sha256[]`; optional `wording_sha256`. |
| `declarative` | declarative only | `renderer` (`"aac.declarative-renderer/v0"`), `wording_sha256`, `fields[]` (section 5.2). |

A manifest carries no presentation words: no title, label or description. Words live in the
wording pack (section 7.4). Unknown members are an error.

**`id` is the module id.** A module and its manifest have one identity, and `id` is it: the
registry keys modules by it, the ambiguity error and the refusal name it, and
`data-refused-module` carries it. There is no separate `module_id` member, because two members
for one identity could disagree. The id's `/v<major>` is the module's own major version;
`presentation_api` is the ABI's version; `runtime_min` is the runtime's version. The three move
independently.

### 4.2 The descriptor

Resolution reads a **descriptor** derived from the context and nothing else:

- `verified`: whether the bundle passed the verification gate.
- `bundle_kind`: the bundle's `bundle_kind` string.
- `profiles`: the root's profile tokens. A token is `<profile key>:<value>`. The profile keys
  in v0 are:

  | Key | Value taken from |
  |---|---|
  | `spec_version` | the `spec_version` string of the root record's `agent_input`, when that member is `disclosed` in the context and is an object carrying a string `spec_version`. |
  | `result_version` | `evidence-result-v0` when the root record carries an Evidence Result v0 in a `disclosed` member: a payload whose `result_version` is `evidence-result-v0` in `agent_output` or `agent_input`, or an `agent_input` whose `record_type` is `evidence_result` (the book form). |

  A root carries at most one token per key, since each key is one string. Different keys are
  independent: a root can in principle carry both a `spec_version` and a `result_version`
  token, which is why the built-in manifests state their precedence with `forbids` (appendix
  A). A root whose `agent_input` is withheld or mismatched carries no `spec_version` token.
  A new profile key is added only by a revision of this document.
- `extensions`: the set of **engaged** extension kinds. A kind is engaged when it is a member
  of the verified bundle's `extensions` object and the core's reader for that kind accepts the
  block. A kind for which the core has no reader is engaged when present. The v0 readers that
  decline a present block are:
  - `outcome-report/v1`: engaged only when `enabled` is `true`;
  - `eu-ai-act-compliance/v1`: engaged only when `enabled` is `true` and at least one
    obligation is recognizable.

  A present block that its reader declines counts as absent for resolution, in `requires` and
  in `forbids` alike. Every extension, engaged or not, is still reported on the verification
  section with its integrity and interpretation status.

The descriptor never contains the audience, the format, the theme, the locale or the depth;
those are separate inputs.

### 4.3 Resolution

`resolve(context, audience, format)` over a registry `M`, exactly:

1. **Verification gate.** If the context is not verified, return the refusal. No manifest is
   matched and no module method is called.
2. **Match.** Let `C` be every `m` in `M`, refused modules included (section 3.2), such that:
   `m.requires.bundle_kind = D.bundle_kind`;
   `m.requires.profiles ⊆ D.profiles`;
   `m.requires.extensions.required ⊆ D.extensions`;
   `m.forbids.profiles ∩ D.profiles = ∅`;
   `m.forbids.extensions ∩ D.extensions = ∅`;
   `audience ∈ m.audiences` or `"*" ∈ m.audiences`;
   `format ∈ m.formats`.
   (An absent list is empty.)
3. **Specific tier.** Let `S = { m ∈ C : m.fallback = false }`. If `|S| ≥ 2`, raise the
   **ambiguity error** naming every id in `S`. If `|S| = 1` and its module is refused, record
   the refusal and continue, calling no method of it. If `|S| = 1` and its module's
   `canRender(context)` is true, select it. If `|S| = 1` and `canRender` is false, continue.
4. **Fallback tier.** Let `F = { m ∈ C : m.fallback = true }`. If `|F| ≥ 2`, raise the
   ambiguity error naming every id in `F`. If `|F| = 1` and its module is refused, record the
   refusal and continue. If `|F| = 1` and its `canRender(context)` is true, select it.
5. **Nothing.** Otherwise return **no presentation**.

The result of steps 3 to 5 carries every refusal recorded on the way, each with the module id,
its `presentation_api`, its `runtime_min` and the reason, and the page shows each as section
3.2 words it.

**An ambiguous match is a hard error, never first-wins.** Registration order, file order,
priority, id order and `canRender` MUST NOT break a tie between two matching manifests of one
tier. Ambiguity is decided on the declarative match of step 2, before any `canRender` is
called, so a module cannot hide an ambiguity by declining.

On an ambiguity error a builder MUST NOT write a page and MUST name the colliding ids; a
runtime that meets one MUST show the refusal with the statement that the presentation could not
be resolved, and MUST NOT show any module's content. On "no presentation", the host shows the
banner, a fixed notice that no presentation is available for this bundle, audience and format,
and the core's verification section; no module content.

If a selected module's `buildModel` or `render` throws, the host MUST discard everything that
module wrote and show the refusal with the statement that the presentation failed. It MUST NOT
fall through to another module: that would be first-wins by exception.

### 4.4 Priority

`priority` ranks a specific module above every fallback and does nothing else. It is how a
manifest states, in data, that it is not a fallback. Two specific modules that both match are
an ambiguity error whatever their priorities; two fallbacks that both match are an ambiguity
error, and a fallback carries no priority. A module author who needs one module to win over
another specific module MUST express that with `forbids` on the other, not with a number.

### 4.5 The static ambiguity test

A registry MUST reject, at registration, any two manifests of the same tier that some
descriptor matches both of. Two manifests `A` and `B` can match one descriptor exactly when
all of the following hold:

1. `A.requires.bundle_kind = B.requires.bundle_kind`;
2. their audiences intersect, or either lists `"*"`;
3. their formats intersect;
4. `R_p = A.requires.profiles ∪ B.requires.profiles` and
   `R_e = A.requires.extensions.required ∪ B.requires.extensions.required` are disjoint from
   `A.forbids.profiles ∪ B.forbids.profiles` and `A.forbids.extensions ∪ B.forbids.extensions`
   respectively;
5. `R_p` carries at most one token per profile key.

*Why this is exact.* If all five hold, the descriptor with `profiles = R_p` and
`extensions = R_e` (verified, of that bundle kind) matches both manifests for the common
audience and format. If either fails, no descriptor can contain a token both required and
forbidden, nor two values of one key. The test therefore never misses an ambiguity that step 3
or 4 could meet at runtime, and step 3 or 4 is reached only by a registry that skipped it.

A manifest whose own `requires` and `forbids` intersect, or that requires two tokens of one
profile key, can never match; a registry SHOULD reject it as dead.

Refused manifests are part of `M` for this test: whether a runtime implements a module's
presentation API never changes which modules are ambiguous with it.

Registering a manifest whose `id` is already registered is an error. Manifests that differ
only in `audiences` or `formats` are not ambiguous when those sets are disjoint.

## 5. Trust classes

There are exactly two. Both are bound by sections 6 to 9.

### 5.1 Trusted-executable

A trusted-executable module is code the builder knowingly incorporates into the page.

- `carrier: "core-runtime"`: the module ships inside the core runtime, in `CORE_RUNTIME_SLOT`,
  and is covered by the core runtime's own SHA-256 pin. The built-in modules are this kind.
- `carrier: "module-slot"`: the module is a separate script the builder inlines in
  `MODULE_SLOT`. `script_sha256` is the lowercase hex SHA-256 of the script's UTF-8 bytes, the
  same value as its `.sha256` pin and as the emitter's module pin. The builder MUST refuse a
  script whose bytes do not hash to it. The page's CSP `script-src` lists that digest (base64
  of the same 32 bytes), so a script the builder did not pin does not run.
- `style_sha256` lists the SHA-256 of each stylesheet the module inserts. The page's CSP
  `style-src` MUST list each, exactly as it lists the core runtime's own inserted stylesheets.
- A module-slot script registers its module with the core at load; the module's in-code
  manifest MUST be JCS-equal to the manifest the builder was given, or the core rejects the
  registration.

Incorporating a trusted-executable module is a decision by whoever builds the page. The pin
makes that decision enforceable and attributable; it does not make the code correct.

### 5.2 Declarative

A declarative module is a manifest and a wording pack. It contains no code. The donated
declarative renderer (`aac.declarative-renderer/v0`, part of the core runtime) interprets it.

`declarative.fields[]` lists what to show. Each field names a `level` (`L0` or `L1`), a
`source` (an RFC 6901 JSON Pointer into the root record's verified `agent_input`), a `kind`
and a `label_key` (the wording key of its label):

| `kind` | What the renderer shows |
|---|---|
| `enum` | The wording entry `<value_key_prefix><value>`. A value with no entry is shown as an unrecognized value with the raw token beside it: never dropped, never guessed. |
| `count` | A non-negative integer, formatted. |
| `digest` | A citation (section 3) when the digest names a record in the context; otherwise the digest, marked as not in this bundle. |
| `identifier` | A short token (no whitespace, at most 128 characters), shown verbatim in a monospace face. |
| `rows` | An array of objects, one row each; `columns[]` uses the four kinds above, with sources relative to the row. |

There is no free-text kind: a declarative module never displays prose taken from a payload.
`canRender` for a declarative module is true exactly when every field's source resolves to a
value of its kind in the verified root payload. L2 for a declarative module is the core's
verification section alone.

## 6. The chrome rule

Generalized from `spec/evidence-result-v0.md` section 8, for both trust classes:

**A module reads presentation hints only for its own chrome.** Presentation hints are the
bundle-carried presentation settings (the `presentation/v1` block, a Result's `view`, a display
setting inside a presentation extension such as `outcome-report/v1`'s `percentages`, and any
other producer-supplied block about how to present) and the viewer's inputs (the theme, the
locale, the wording pack and the depth setting). Chrome is the module's header, layout, number
formatting and styling.

- **Wording and depth never come from the bundle.** A module MUST NOT read a bundle-carried
  presentation setting to choose, supply, select or alter **wording** (any presentation word of
  section 7.3: a label, heading, column name, explanation, notice or button text) or **depth**
  (which level opens, which disclosures start open, which level a region is placed in). The
  module's wording pack, bound by `wording_sha256` (section 7.4), and the core's own fixed text
  are the only sources of wording; the shell's depth setting (`host.depth`, section 9) is the
  only source of depth. A module that reads a bundle-carried setting for wording or depth is
  non-conformant, whatever the setting says. The header fields the core's `presentation/v1`
  reader extracts (title, producer name, logo) are shown as the producer's own header content
  and are not module wording.

- A hint MUST NOT supply data: no claim, verdict, status, count, digest, sufficiency, grade or
  record reference is ever read from a hint. A renderer that reads a hint for anything beyond
  its own chrome has misused it.
- A hint MUST NOT reach the verification banner, the refusal or the core's verification
  checks, except through `setChromeClass`, which changes a class and nothing else.
- Only the fields a reader knows are ever extracted from a hint block; any other member is
  never read, so markup or a "verified" claim inside a hint cannot reach any renderer.
- A presentation extension MAY take part in selection through the manifest's engaged
  extensions (section 4.2). Selecting which module renders verified content is not reading data
  from the hint.
- **Producer annotations.** Producer-written text inside a presentation extension (for
  example a producer's note) is neither evidentiary nor presentation wording. A module MAY show
  it only as text (never markup), only under a fixed label from its wording pack that says it is
  the producer's note and not evidence, and never in L0.

**Detecting a module that takes wording or depth from the bundle.** The manifest has no member
through which a module could name a bundle-carried setting as a source of wording or depth: a
manifest is closed, and the only wording source it can name is `wording_sha256`. The schema
therefore rejects a manifest that declares one (`neg-hint-wording-source.json`, appendix B).
Code inside a trusted-executable module is not visible to a schema, so for it the test is
behavioural and a reviewer or conformance harness applies it: render one verified bundle with
the same wording pack, locale, theme and depth three times, with its bundle-carried
presentation settings as supplied, removed, and with every string in them altered and every
display flag flipped. Outside the header fields the core's header reader extracts and the
formatting a display flag is defined to control (such as `percentages`), the module's regions
MUST be byte-identical across the three, and which levels and disclosures are open MUST be the
same. A reviewer also checks that the module's source reads a bundle-carried setting only in
its chrome code path, never where a label, heading, notice or depth is chosen.

## 7. The text-binding rule

Words on a page are of two kinds, and each has one place to live.

### 7.1 Evidentiary words

Evidentiary words are words a relying party may rely on as what someone said, saw, approved,
was shown or was told: a user's request, the wording of an authority or mandate, a proposal, an
approval sentence, terms displayed to a party, a representation made by a counterparty.
**Evidentiary words MUST be bound by one of three registered mechanisms**, and a module MUST
display them only after the core has checked the binding:

1. **Digest with an out-of-band opening.** A record commits the digest of the exact text (or
   of the JCS form of the object carrying it); the text, the opening, travels separately, for
   example as a disclosure. The text is shown only when its recomputed digest equals the
   committed one, exactly as a disclosed `agent_input` is shown only on a disclosure match.
2. **Nonce-salted commitment, `commit_alg: "sha256-jcs-nonce256"`** (section 7.2). The record
   carries the commitment and declares the construction; the opening `{nonce, text}` travels
   separately. The text is shown only when the commitment recomputes. Without an opening, the
   page says the text is committed and not opened; it never shows a placeholder as the text.
3. **A separately sealed text record.** The text is the disclosed payload of its own record in
   the bundle, cited by `capsule_id`, and is shown only when that record verified and the
   member is `disclosed`.

**Forbidden: clear text in a digest-committed UI field.** Placing words meant for display
inside a sealed payload, as a label, status or reason field, binds the wrong thing. It seals
presentation words, so changing a heading changes the evidence's identifier (against I3), and it
gives producer-asserted prose the look of a checked result. The cited counter-example is the
`report/v1` row model (`ts/src/report-rows.ts`): each row's `label`, `status` and `reason` are
clear text inside the root's digest-committed `agent_input`, nothing recomputes `status`, and a
change of wording is a change of record. A new row model MUST NOT repeat this; it carries
enumerated states and references, and takes its words from a wording pack. Equally forbidden is
the opposite failure: evidentiary words displayed from a bundle extension no record seals.

### 7.2 `sha256-jcs-nonce256`

This construction was not defined in this repository before this document; this section
defines it. It is the construction already declared under the same identifier by an existing
public producer profile (capsule-cli's `record-common-v0` schema), and this definition is
intended to be identical to it.

```
commitment = lowercase_hex( SHA-256( JCS( { "nonce": N, "text": T } ) ) )
```

- `N` is 64 lowercase hexadecimal characters encoding 32 bytes from a cryptographically secure
  random source, drawn fresh for each committed text. Uppercase hex is not a valid `N`.
- `T` is the exact text as a JSON string: no Unicode normalization, trimming or case folding
  is applied before committing. JCS serializes it as UTF-8.
- The object has exactly the two members `nonce` and `text`; JCS (RFC 8785) orders them.
- There is no key. The commitment is recomputable only by a holder of the opening `{N, T}`, and
  a guess at `T` cannot be tested without `N`.
- A record declares the construction as `commit_alg: "sha256-jcs-nonce256"` and names its
  commitment members `<name>_commitment`. A verifier recomputes from an opening and compares
  the lowercase hex strings for equality.
- Reusing one nonce for two texts is permitted only where a profile deliberately states that
  equal commitments mean equal text; otherwise it is a producer defect.

### 7.3 Presentation words

Presentation words are labels, headings, column names, explanations, notices and button text.
**Presentation words MUST NOT be sealed.** They live in a wording pack. A record or a manifest
refers to the pack it was rendered with by `wording_sha256`, the existing field name; no other
name (such as a "wording pack digest") is minted for it.

A `wording_sha256` in a record is presentation provenance: it says which words rendered a page.
It is never part of the semantic digest of the evidence being presented, so a new wording pack
never changes that evidence's identifier.

### 7.4 Wording packs and `wording_sha256`

A wording pack is a JSON object (`$defs/WordingPack`):

```json
{ "wording_pack_version": "aac.wording-pack/v0",
  "id": "org.example.view.wording/v0",
  "locale": "en",
  "entries": { "heading.l0": "What the comparison found", "...": "..." } }
```

`entries` maps wording keys to non-empty strings. One pack is one locale; a translation is a
different pack with a different `wording_sha256`.

`wording_sha256` is the lowercase hex SHA-256 of the pack's **exact bytes as distributed**. The
bytes are hashed as they are; a consumer MUST NOT re-serialize a pack before hashing it. A
producer SHOULD distribute the JCS form of the pack, so that independent producers of the same
pack arrive at the same digest. A renderer MUST refuse a pack whose bytes do not hash to the
`wording_sha256` it was given, and then shows the core's own fallback labels, never a guess.

## 8. Invariants

- **I1. Failure collapses to the refusal, never to Level 0.** A bundle that did not verify gets
  the banner, the refusal and the core's verification checks, and nothing else from any module:
  no headline, no summary, no "what matters", no softened L0. The refusal's text is the core's:
  "This bundle did not verify. Its records, rows and payloads are not shown; the verification
  page below lists which checks failed." An ambiguity error or a module failure (section 4.3)
  collapses the same way.
- **I2. Depth selects among verified content.** Every level shows only content from the
  verified context. Changing the depth opens or closes levels; it never adds content the
  context does not hold, never removes the banner or the refusal, and never hides a finding.
- **I3. Theme, wording, locale and depth never change evidence identifiers.** The bundle
  digest, every `capsule_id`, every disclosure digest, `composed_digest` and every identifier
  inside a payload are the same whatever theme, wording pack, locale or depth renders them.
  None of those four is ever inside a digest-committed payload of the evidence.
- **I4. Acceptance is over (bundle, audience) pairs, for every supported packaging target.**
  For one bundle and one audience, every packaging target (`html`, `fragment`, `embedded`)
  that is **supported** for that bundle MUST show identical semantic content and identical
  verification state: the same module (or the same refusal or notice), the same verified items
  at each level, the same verification state, findings, refusals and extension rows. Supported
  targets differ only in packaging.

  Whether a target is supported for a bundle MAY depend on the artifact's size (a bundle too
  large to travel in a URL fragment) or on a capability of the target (a host page that cannot
  run the core runtime for `embedded`). **Availability MUST be reported explicitly.** A builder
  asked for a target that is not supported for a bundle produces no artifact for it and reports
  the target with its reason (`artifact_too_large`, `capability_missing`); it never produces a
  truncated, partial or differently resolved artifact in its place. A tool or page that offers
  targets lists an unsupported one as unavailable, with the reason. A target that the module
  resolved for the pair in `html` does not list in its `formats` is not supported for that pair
  (reason `module_format_unsupported`): a builder reports it so and MUST NOT produce it by
  resolving a different module.

  Conformance goldens are keyed by (bundle digest, audience) and hold for every supported
  target. A variant that shows different semantic content or verification state for the same
  pair on two supported targets is non-conforming unless it is declared as an exemption by a
  revision of this document.
- **I5. Modules never verify** (section 3).
- **I6. Ambiguity is an error** (section 4.3).
- **I7. The context cannot be changed by a module** (section 3.1): every module and the core
  read the verification result and the resolved disclosures the verifier produced.
- **I8. A refused module is refused out loud** (section 3.2): never selected, never silently
  replaced, always named on the page it would have rendered.

## 9. Depth levels and the shell

### 9.1 The three levels

Every module fills three levels. They are regions the host creates inside the page root, in
this order, after the header chrome and the verification banner:

| Level | Name | What it holds | Who fills it |
|---|---|---|---|
| L0 | what matters | The module's headline over verified content: one screen, no scrolling at a phone's width, every figure on it traceable to L1. | The module. |
| L1 | why | The reasons: rows, claims, joins and their cited evidence, each item a `details` disclosure. | The module. |
| L2 | verify | The core's verification section (the three bundle claims, every record's identity and membership, disclosure states, countersignatures, every extension with its integrity and interpretation status, every refused module as section 3.2 words it), then any module-specific detail. | The core, then the module. |

The core's part of L2 is always present and always comes before any module detail in L2. A
module MUST NOT replace, reorder or reword it; it MAY append detail (for example a
recomputation it showed in L1) after it.

`depth` is the requested opening level: at `L0` only L0 is open; at `L1`, L1's disclosures
are open; at `L2`, everything is open. The shell's depth setting, given to the module as
`host.depth`, is the only source of depth. A module MUST NOT take a depth, a default open
level or the open state of a disclosure from a bundle-carried presentation setting (section 6),
and a module that does is non-conformant. Every level is present in the document at every depth
and in every format, so printing and I4 hold. On a failed bundle, L0 and L1 are not created
(I1).

### 9.2 Mapping to the shell slots

| Shell slot | Role in this contract |
|---|---|
| `CSP_SLOT` | The page policy. `script-src` lists the core runtime's pin and each module-slot module's `script_sha256`; `style-src` lists the inline theme, the core runtime's inserted stylesheets and each module's `style_sha256`. Pinning is enforcement. |
| `TITLE_SLOT` | The page title: chrome. Filled by the builder from the selected module's wording pack or the `presentation/v1` title, HTML-escaped; never from a payload. |
| `THEME_SLOT` | Theme tokens (`--aac-*` CSS custom properties). Presentation only (I3). |
| `BUNDLE_SLOT` | The bundle, the page's only data. |
| `CORE_RUNTIME_SLOT` | The verify core, the context, the registry, the built-in modules, the declarative renderer and the services. |
| `MODULE_SLOT` | Zero or more trusted-executable module-slot scripts, each registering one module. |
| `BOOTSTRAP_SLOT` | Builds the context, calls `resolve(context, audience, format)` and renders. |

L0, L1 and L2 are not text placeholders in the shell file: they are elements the core runtime
creates inside `#app` at render time, after the header and the banner. The shell's base
stylesheet owns the frame, the banner area and the `details` disclosure style; a module's own
stylesheet owns the module's layout.

## 10. Conformance

- A manifest conforms when it validates against `$defs/PresentationManifest`.
- A registry conforms when it applies section 4.5 at registration and section 4.3 at
  resolution, including the ambiguity error, and refuses modules as section 3.2 requires.
- A runtime conforms when the context it hands a module is effectively immutable (section 3.1)
  and it declares the presentation API versions it implements and its runtime version
  (section 3.2).
- A module conforms when it satisfies sections 3, 6, 7 and 9 and its manifest conforms. A
  module that reads a bundle-carried presentation setting for wording or depth does not
  conform; section 6 says how that is detected.
- A viewer conforms when it satisfies section 8.
- `schemas/check_presentation_manifest_examples.py` checks the committed manifests: each
  schema negative is proven load-bearing by a mutant, the static and runtime ambiguity tests
  are run over the built-ins, the examples and an ambiguous pair, the built-in manifests are
  resolved over every descriptor the current viewer distinguishes and compared with today's
  dispatch, and a module with an unsupported `presentation_api` is shown to be refused, reported
  in the words of section 3.2 and never selected.

## Appendix A. The built-in manifests

Today `renderEvidenceGraph` (`ts/src/evidence-graph-view.ts`) dispatches in control flow:
`report/v1` rows, then a Result root with `outcome-report/v1`, then a Result root with
`eu-ai-act-compliance/v1` (read only when `outcome-report/v1` is absent), then the generic
Result page, then the `evaluation-summary/v1` graph, then the no-aggregate note. That gives
five page shapes and one floor. They are expressed here as six manifests, five specific and one
fallback; the files are in `schemas/examples/presentation-manifest-v0/`. All six have
`trust_class: "trusted-executable"`, `executable.carrier: "core-runtime"`,
`presentation_api: "aac.presentation-api/v0"`, `runtime_min: "0.1.0"`,
`requires.bundle_kind: "evidence-bundle/v2"`, `audiences: ["*"]` and all three formats.

### A.1 The manifests

| Id | `fallback` / `priority` | `requires` | `forbids` |
|---|---|---|---|
| `aac.builtin.report-rows/v0` | false / 1 | profile `spec_version:report/v1` | — |
| `aac.builtin.result-outcome-report/v0` | false / 1 | profile `result_version:evidence-result-v0`; extension `outcome-report/v1` | profile `spec_version:report/v1` |
| `aac.builtin.result-compliance/v0` | false / 1 | profile `result_version:evidence-result-v0`; extension `eu-ai-act-compliance/v1` | profile `spec_version:report/v1`; extension `outcome-report/v1` |
| `aac.builtin.result/v0` | false / 1 | profile `result_version:evidence-result-v0` | profile `spec_version:report/v1`; extensions `outcome-report/v1`, `eu-ai-act-compliance/v1` |
| `aac.builtin.evaluation-summary-graph/v0` | false / 1 | profile `spec_version:evaluation-summary/v1` | profile `result_version:evidence-result-v0` |
| `aac.builtin.no-aggregate/v0` | true / — | — | — |

"Compliance only when outcome is absent" is the compliance manifest's `forbids` of
`outcome-report/v1`. "Rows first" is every Result manifest's `forbids` of
`spec_version:report/v1`. "Result before graph" is the graph's `forbids` of the Result profile.
The graph's `canRender` is false exactly when today's `buildEvidenceGraph` throws an
`EvidenceGraphError`, which sends resolution to the fallback, as today.

### A.2 No pair is ambiguous

The fallback tier has one member, so it has no pair. The ten pairs of the specific tier, each
with the token that one requires and the other forbids (or the two values of one key):

| Pair | Why they cannot both match |
|---|---|
| rows / outcome-report | outcome-report forbids `spec_version:report/v1`, which rows requires. |
| rows / compliance | compliance forbids `spec_version:report/v1`. |
| rows / result | result forbids `spec_version:report/v1`. |
| rows / graph | both require a `spec_version` token, with different values. |
| outcome-report / compliance | compliance forbids `outcome-report/v1`, which outcome-report requires. |
| outcome-report / result | result forbids `outcome-report/v1`. |
| outcome-report / graph | graph forbids `result_version:evidence-result-v0`, which outcome-report requires. |
| compliance / result | result forbids `eu-ai-act-compliance/v1`, which compliance requires. |
| compliance / graph | graph forbids `result_version:evidence-result-v0`. |
| result / graph | graph forbids `result_version:evidence-result-v0`. |

### A.3 Behaviour is preserved

For a verified bundle, with `D` its descriptor:

| Today's branch | Condition today | The one module resolution selects |
|---|---|---|
| rows table | root `agent_input.spec_version = report/v1` | rows: every other specific forbids or excludes that token. |
| outcome-report card | Result root, `outcome-report/v1` enabled | outcome-report: compliance and result forbid the extension; rows is not matched; graph forbids the Result profile. |
| compliance card | Result root, `outcome-report/v1` not enabled, compliance enabled with an obligation | compliance. |
| Result page | Result root, neither card engaged | result. |
| graph | `spec_version = evaluation-summary/v1`, no Result carrier, the model builds | graph. |
| no-aggregate note | anything else, including a graph model that fails to build | no specific matches or the graph declines, so the fallback. |
| refusal | not verified | step 1: the refusal; no module is called. |

The checker enumerates 1,536 (descriptor, audience, format) cases (verified or not; four
`spec_version` states; Result carrier or not; every subset of `outcome-report/v1`,
`eu-ai-act-compliance/v1` and `composed/v1`; graph model builds or not; two audiences; three
formats) and requires the resolved module to equal today's branch in every case. Removing any
one of the forbids above makes it report an ambiguity.

### A.4 Depth for the built-ins

The built-ins move into the depth regions without changing a word: the depth regions are
wrapper elements with no text. The goldens of the five shapes and the floor, captured before
the registry change, govern what "unchanged" means.

## Appendix B. Example manifests

In `schemas/examples/presentation-manifest-v0/`, as one registry. Each declares
`presentation_api: "aac.presentation-api/v0"` and `runtime_min: "0.1.0"`:

- `example-unilateral.json` (`org.example.unilateral/v0`): a module-slot module for a root
  profile `spec_version:org.example.exchange/v0` that **forbids** `composed/v1`.
- `example-composition-aware.json` (`org.example.composition-aware/v0`): a module that declares
  it understands a composition: same profile, **requires** `composed/v1`. `composed/v1` is a
  composition primitive, not a presentation type; the generic surfacing of it (members, joins
  and their states, same-custody agreement shown as redundant, not corroborating) belongs to a
  donated view, and a module like this one adds to it by declaring the requirement.
- `example-generic-fallback.json` (`org.example.generic-view/v0`): a fallback with no profile.
- `example-declarative-rules.json` (`org.example.rules-table/v0`): a declarative module that
  renders a count in L0 and a table of rules in L1, with words from
  `example-wording-pack.json`, whose exact bytes hash to its `wording_sha256`.

Negatives, each rejected:

| Fixture | Rejected by |
|---|---|
| `neg-unknown-field.json` | schema: a `title` member (the manifest is closed; words live in a pack). |
| `neg-fallback-with-priority.json` | schema: a fallback carrying `priority`. |
| `neg-missing-id.json` | schema: no `id`. |
| `neg-presentation-v1-namespace.json` | schema: `spec_version: "presentation/v1"`. |
| `neg-hint-wording-source.json` | schema: a declarative module naming the `presentation/v1` block as a wording source. The manifest has no such member: wording comes only from the pack `wording_sha256` binds (section 6). |
| `neg-missing-presentation-api.json` | schema: no `presentation_api` (a malformed manifest, not a refused one). |
| `neg-unsupported-presentation-api.json` | the checker's resolution test: a schema-valid specific module declaring `aac.presentation-api/v99`, registered beside the examples into a runtime that implements only `aac.presentation-api/v0`. It is refused (`presentation_api_unsupported`); a descriptor it matches resolves to the generic fallback with the refusal in the result, and its extension's row reads exactly as section 3.2 words it. A resolver that ignores `presentation_api` would select it instead. |
| `neg-ambiguous-pair/a.json`, `b.json` | the checker's resolution test: both are schema-valid specific modules (priorities 1 and 9) that one descriptor matches; the static test reports the pair and resolving it raises the ambiguity error. |

## Appendix C. Divergences recorded while writing this

These are facts in the current code that this contract does not silently paper over:

1. `spec/evidence-result-v0.md` section 8 names the header field `producer_name`;
   `ts/src/presentation.ts` reads `producer_display_name` from the `presentation/v1` block.
2. `presentation/v1` is used as a bundle extension kind in code but is not a row of
   `spec/REGISTRY.md` section 14.
3. The `report/v1` row model is carried as the root's `agent_input` in the viewer, while the
   registry text says such a row model is an extension only when registered. Section 7.1 cites
   it as the counter-example for text binding.
4. The viewer renders `presentation/v1` header chrome before the banner even when the bundle
   did not verify. Section 6 permits header chrome; I1 forbids any module content. Whether
   producer-supplied chrome should appear above a refusal is left to a revision.
5. The emitter accepts module scripts with pins but has no input for a module's stylesheet
   pins; section 5.1's `style_sha256` needs that input before a module-slot module may insert a
   stylesheet.
6. The extension result type marks every extension uninterpreted; section 9.1's L2 requires the
   interpretation status to be reported truthfully per extension.
7. Resolved. The per-extension rows of the verification section and the registry were
   separate changes; they are now joined. The reference runtime reports a refusal in the
   resolution result, as `data-presentation-refused` on the page root, and in the section 3.2
   wording: in the row of each extension the refused module requires, or, for a refused module
   that requires no extension, in a line after the rows.
