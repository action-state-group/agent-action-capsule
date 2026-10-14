# Presentation Builder — v0

**Status.** Design specification beside `spec/presentation-contract-v0.md`. This document defines
the one builder that turns a verified Evidence Bundle into a page for one audience, and the four
ways it packages that page: one offline `.html` file, a fragment permalink, an element in a host
page, and a static page that runs no script. It also defines how the builder reports that a
packaging is unavailable for a bundle. The reference is `ts/src/presentation-builder.ts` (with
`ts/src/presentation-fragment.ts` and `ts/src/presentation-mount.ts`); the Go twin of the offline
packaging is `go/emitter/presentation.go`. The static packaging is TypeScript only (section 2.4).

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as described in BCP 14
(RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

## Dependency boundary

**Owns:** `buildPresentation`; the four packagings; `availablePackagings` and its reasons; the
fragment payload `aac.presentation-fragment/v0`; the fragment size limits and the default link
budget; the static page and its statement; the share-side scoping step; the hand-back from a
fragment to the offline file; the one wording key the builder reads (`page.title`).

**Depends on, and does not redefine:** bundle verification and `VerifiedBundleContext`
(`ts/src/bundle.ts`); the registry, the manifest, the formats `html` / `fragment` / `embedded`,
the invariants I1 to I6 and the wording pack (`spec/presentation-contract-v0.md`); the emitter
shell, its slots and its per-page Content-Security-Policy (`ts/src/emitter.ts`,
`go/emitter/emitter.go`); the Evidence Bundle permalink codec (the "Fragment Codec" section of
`draft-mih-zhang-agent-disclosure-bundle`).

**Out of scope:** hosting a viewer, caching, delivery, and any server. Nothing here needs a host
to verify a bundle, and nothing here creates one.

## 1. The call

```ts
buildPresentation(context, { presentation, audience, format, ...settings })
```

- `context` is a `VerifiedBundleContext`, or a bundle (verified once by the call).
- `presentation` is `"auto"` or the id of the module the caller expects. The builder asks the
  registry (`resolve(context, audience, format)`); it never selects a module itself. An explicit
  id that the registry does not select is an error, and so is an ambiguous match.
- `audience` is an audience token; `"*"` is no particular audience.
- `format` is a packaging target: `html` (offline file), `fragment` (permalink), `embedded`
  (host element) or `static` (no-script page). The first three are the contract's formats; the
  static page is the `html` page rendered at build time, so the registry resolves it, and the
  module renders it, as `html`.
- Settings: `runtime` (the core runtime and, optionally, its pin; required for `html` and
  `fragment`), `modules` (digest-pinned module-slot scripts), `registry` (the resolver; the
  built-ins when omitted), `disclose` (section 3), `depth`, `title`, `themeCss`, `wording` (a
  wording pack's exact text and its `wording_sha256`), `maxFragmentLength`, `viewerUrl`.

The steps run in this order: scope (section 3), verify the scoped bundle, resolve, package. Every
packaging carries the same scoped bundle and the same settings.

**A module the page's runtime would refuse.** A module-slot script may be given with its manifest,
which must pin it (`executable.carrier` `module-slot`, `script_sha256` equal to the script's pin).
When the page's runtime would refuse that module (presentation contract section 3.2:
`presentation_api_unsupported` or `runtime_too_old`), or when `presentation` names a module the
registry holds as refused, the builder writes no page in any packaging and fails with
`PresentationModuleRefusedError`, naming the module's id, `presentation_api` and `runtime_min`
and the runtime's declaration (the `presentation_api` values it implements and its version). The
page's runtime is the registry's when the builder resolves with a `PresentationRegistry`, and the
reference runtime otherwise. `availablePackagings` throws the same error: it is an error of the
request, not of one target.

**Module stylesheet pins.** A module-slot script carries the SHA-256 pins of the stylesheets it
inserts at render time (`styleSha256`; Go: `Module.StyleSHA256`), and the builder passes them to
the emitter, which lists each in the page's `style-src` (presentation contract section 5.1). When
the script is given with its manifest, the manifest's `executable.style_sha256` (absent: empty)
MUST equal the script's pins as a set: order and repetition decide nothing. Otherwise the builder
writes no page in any packaging and fails with `PresentationStylePinsError` (Go:
`*StylePinsError`), naming the module's id and both lists as given. The Go offline packaging
(`BuildOfflineHTML`, and so `OfflineHTMLFromFragment`) applies the same check to a `Module` given
with its `Manifest`, after the same check that the manifest pins the script. A page with no
module stylesheets is unchanged byte for byte.

**Supported targets.** The builder supports four packaging targets: `html`, `fragment`,
`embedded` and `static`. A target is *supported* for one (bundle, audience) and one set of
settings when the builder can package it; otherwise it is *unavailable*, and the builder says so
(section 1.1). It never hands out a packaging that cannot be used, such as a link too long to
share.

### 1.1 Availability

```ts
availablePackagings(context, { presentation, audience, ...settings })
  // => [{ target, available: true } | { target, available: false, reason }, ...]
```

`availablePackagings` takes the same arguments as `buildPresentation` without `format` and
returns one entry per target, in the order `html`, `fragment`, `embedded`, `static`. It returns
no packaging. An entry is `available: true` exactly when `buildPresentation` succeeds for that
target with the same settings. Otherwise it is `available: false` with a `reason`:

| `reason.code` | Target | Meaning | Other members |
|---|---|---|---|
| `fragment-too-large` | `fragment` | The token, or the whole URL with `viewerUrl`, is over the budget. | `subject` (`"fragment token"` or `"permalink URL"`), `length`, `limit` |
| `runtime-missing` | `html`, `fragment` | No core runtime was given. | |
| `no-document` | `static` | No DOM `document` to render with at build time. | |
| `static-carries-script` | `static` | The rendered page holds a script element or an event-handler attribute. | |

Every reason also carries a `message` in words. An error of the request itself (no audience, a
bad depth or wording pack, an ambiguous registry, a requested presentation the registry does not
select, scoping a bundle that did not verify) is not a packaging question: it is thrown, by both
calls, as it is for every target alike.

A direct `buildPresentation` call for an unavailable target throws. A fragment over its budget
throws `FragmentTooLargeError` (with `length`, `maxLength` and `subject`), as it always has; the
other reasons throw `PackagingUnavailableError`, a `PresentationBuildError` carrying the same
`reason`.

## 2. The four packagings

### 2.1 Offline `.html` (`html`)

One self-contained file: the shell, the scoped bundle in `BUNDLE_SLOT`, the core runtime in
`CORE_RUNTIME_SLOT`, any modules in `MODULE_SLOT`, the theme in `THEME_SLOT`, the title in
`TITLE_SLOT`, and a bootstrap that calls `renderEvidenceGraph` with the audience, the format, the
depth and the wording pack. The page carries the emitter's per-page Content-Security-Policy
(`default-src 'none'`, `connect-src 'none'`, and every inline script and style by hash), so it
makes no request and runs no script it was not built with.

The title is the `title` setting, else the wording pack's `page.title` entry, else the shell's
default. The wording pack's bytes MUST hash to its `wording_sha256`, and the pack MUST be an
`aac.wording-pack/v0` object, or the build is refused. Theme, wording, locale and depth are
presentation only (contract I3): changing any of them changes the file's bytes and never an
evidence identifier.

With the default settings (audience `"*"`, no depth, no wording) the builder writes exactly the
page `emitEvidenceGraphHtml(bundle, runtime)` writes, byte for byte.

### 2.2 Fragment permalink (`fragment`)

The payload travels in the URL fragment, which a browser never sends over the wire, so the link
needs no host to hold the data: `viewer.html#<token>`.

**Codec.** The token is the Evidence Bundle permalink codec applied to the payload: RFC 8785 JCS
text, UTF-8, base64url (RFC 4648 section 5) without padding. This is the model of
capsule-viewer's fragment codec (`src/capsule_viewer/fragment.py`: base64url of the compact JSON,
no padding). For a payload whose JSON text is ASCII, read in JCS member order, the two write the
same token. For non-ASCII text, `fragment.py` writes `\uXXXX` escapes (Python's
`ensure_ascii`) where the bundle codec writes UTF-8; each decoder reads the other's token. The
shared vectors are `ts/test/testdata/presentation-fragment-vectors.json`. The decoder here is
stricter than `fragment.py` in one way: a character outside the base64url alphabet is an error,
where Python drops it.

**This is not a security mechanism.** The payload is encoded, not encrypted. Anyone who holds
the link can read all of it. What an audience may see is decided before encoding (section 3).

**Payload** (`aac.presentation-fragment/v0`; unknown members are an error):

| Member | Meaning |
|---|---|
| `fragment_version` | The constant `"aac.presentation-fragment/v0"`. |
| `audience` | The audience token. |
| `presentation` | The module id the builder resolved, or `"auto"`. Informational. |
| `depth`, `title`, `theme_css` | Optional settings, as in section 1. |
| `wording` | Optional: `{pack, sha256}`, the pack's exact text and its digest. |
| `core_runtime_sha256` | Lowercase hex SHA-256 of the core runtime the page was built with. |
| `module_sha256` | The pins of the module-slot scripts, in order. |
| `bundle` | The scoped bundle. |

Code travels by pin, never inline: the token stays small and a viewer runs only code it already
holds.

**Size limits.** The longest URL planned for is 1,048,576 characters (1 MiB), the smallest of the
major browsers' documented limits. 2,048 characters are kept for the viewer's address and the
`#`, so the longest token is 1,046,528 characters (`FRAGMENT_TOKEN_MAX_LENGTH`). That is a ceiling,
not a link anyone can share: chat and email cut links far shorter. The builder therefore packages a
fragment within a **budget**, by default 65,536 characters (`FRAGMENT_TOKEN_DEFAULT_BUDGET`), and
a caller MAY lower it or raise it up to the ceiling (`maxFragmentLength`); a budget above the
ceiling is an error. A monthly report of a few hundred kilobytes is over the default budget, and
its fragment is reported unavailable (section 1.1), not packaged as an unusable link. A token over
the budget, or a whole URL over 1 MiB when `viewerUrl` is given, is refused with
`FragmentTooLargeError`, which names the length and the limit. Nothing is ever truncated. The
codec's own encoder and every decoder keep the ceiling as their limit, so any link a caller chose
to make opens; a decoder refuses an over-long token before decoding it. A bundle too large for a
permalink is shared as the offline file or the static page.

**The viewer.** `buildFragmentViewerHtml(runtime)` writes a serverless viewer: an offline page
with the same shell and CSP whose data is its own `location.hash`. It renders the payload as the
`fragment` format. It applies no theme CSS from the fragment, since its CSP admits only the styles
hashed into it; the theme is restored in the offline file. A fragment that cannot be read shows a
fixed statement and nothing else.

**The hand-back.** A hosted permalink is optional transport over the same artifact. Any viewer
holding the runtime and modules the payload pins MUST be able to hand back the exact offline file:
`offlineHtmlFromFragment(token, runtime, modules)` (Go: `OfflineHTMLFromFragment`) rebuilds it,
and its bytes equal what `buildPresentation(..., {format: "html"})` writes for the same bundle,
audience and settings. A runtime or module set that does not match the pins is refused rather
than used to build a different file.

### 2.3 Embedded (`embedded`)

`mount(element)` renders the scoped bundle into a host element with the same audience, depth
and wording, as the `embedded` format, through the caller's registry. The host page owns its own
CSP.

### 2.4 Static page (`static`)

The same presentation model, rendered at build time into HTML that runs no script at all. The
builder renders the scoped bundle exactly as the offline file renders it in the reader's browser
(the same bundle, audience, `html` format, depth, wording pack and registry), and writes the
result into the emitter's shell, with its base stylesheet, title and theme, and nothing else: no
bundle element, no core runtime, no module, no bootstrap.

**Statement.** The page states, before the rendered content, the constant
`STATIC_NOT_SELF_VERIFYING`:

> Not self-verifying; verify the bundle separately.

then the constant `STATIC_BUILD_TIME_STATEMENT`:

> This page runs no code. It shows the verification result computed when it was built and cannot
> re-verify anything in your browser.

then the verification result the builder computed at build time ("verified" or "did not
verify"), which is also on the notice as `data-built-verification` and returned as
`verification`. That result is the one the rendered content shows; the builder refuses to write a
page where the two differ.

**CSP.** `default-src 'none'; script-src 'none'; style-src <hashes>; img-src data:;
connect-src 'none'; base-uri 'none'; form-action 'none'`. Every `<style>` element the page carries
is listed by hash. A rendered element's `style` attribute (a bar's width, for one) is listed by
hash under `'unsafe-hashes'`; no other inline style applies. The page makes no request and runs
nothing. The builder refuses (`static-carries-script`) a rendering that holds a script element or
an event-handler attribute, which the CSP would block anyway.

**What it does not do.** It does not carry the bundle: the reader verifies the bundle, shared
separately, with a verifier they trust. Controls that the scripted page answers on click (a row's
detail, a claim's detail, a cited record) are written but do nothing; native `<details>`
disclosure still opens. It needs a DOM `document` at build time; in Node that is a jsdom
document set as `globalThis.document`, and without one the target is unavailable
(`no-document`). There is no Go twin: the presentation model is rendered by the TypeScript
modules only.

**Use.** A copy for a reader who should not run code from the sender, and a copy whose every byte
is data that a share-side check can read whole, with no vendored script to exempt.

## 3. Scoping

Scoping decides what one audience may see. It happens in the share builder, before anything is
encoded or packaged, and never in a viewer: a viewer shows the bundle it was given.

`disclose` is an allow-list from `capsule_id` to the members (`agent_input`, `agent_output`) the
audience may see. Every other disclosure is removed from the bundle, so the recipient's verifier
reads it as withheld; the records, certificates, checkpoints and proofs are untouched, so the
scoped bundle verifies wherever the input did. Without `disclose`, the disclosures are packaged as
they are. Scoping only removes; it never adds, rewrites or reorders.

The builder refuses to scope a bundle that did not verify: removing a disclosure could turn a
mismatch into a withheld member and hide the failure.

Like the codec, scoping is not a security mechanism. It decides what is put in the artifact;
whoever holds the artifact can read everything in it.

## 4. Acceptance

Acceptance is over (bundle, audience) pairs (contract I4). **Identical semantics across SUPPORTED
packagings:** for one bundle and one audience, every packaging that is available (section 1.1)
MUST select the same module and show the same verified content, the same verification state and
the same evidence identifiers. A packaging that is unavailable is reported, never approximated.
The rendered markup is compared as HTML parsing reads it: a static page is parsed, and parsing
adds the elements HTML implies (a table row's `tbody`), which a page drawn by script may omit.

`ts/test/presentation-builder.test.ts` checks this over the fixtures for each built-in page shape
and a bundle that does not verify, for three audiences, in all four targets, by rendering each
packaging and comparing what it shows, and checks that `availablePackagings` reports exactly the
targets that built; the only unavailability the fixtures meet is a fragment over its budget. Two
monthly-scale compliance bundles, derived deterministically from the committed two-session
fixture (`ts/test/helpers/monthly-fixtures.ts`: 40 sessions, about 490 KB, and 80 sessions, about
1 MB), assert that the fragment is reported unavailable with its length and limit, at the default
budget and, for the larger, at the ceiling, while the other three targets show the same thing.
Every static page in the table is checked for no script, its CSP and its statement. The same file
checks that theme, wording, locale and depth leave every evidence identifier unchanged, and
`ts/test/presentation-builder-browser.test.ts` opens the offline file, the fragment URL and the
static page in a CSP-enforcing browser and finds no request beyond the document itself, no CSP
violation, and the static page showing what the offline file shows.

The Go and TypeScript offline outputs match byte for byte for the same inputs
(`go/emitter/testdata/expected-offline.html` and `offline-fragment.txt`).

## 5. Known gaps

1. The built-in modules do not read wording packs yet. The pack is checked, carried in the page
   and used for the title; the modules keep the core's own labels.
2. The viewer does not check its own runtime against `core_runtime_sha256`: it renders with the
   runtime it holds. The hand-back does check.
3. The countersigner list of the caller's context does not travel in any packaging; a page names
   no independent countersigner unless its host supplies a list.
4. The offline file's `<html lang>` stays `en` whatever the wording pack's locale. So does the
   static page's.
5. The static page's click-driven controls are inert (section 2.4); what they would reveal is
   not on the page.
6. The fragment's `module_sha256` pins module scripts only. A module's stylesheet pins are not
   in the fragment: the hand-back takes them from the modules it is given, and checks them
   against a manifest given with a module.
