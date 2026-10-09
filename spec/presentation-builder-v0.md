# Presentation Builder — v0

**Status.** Design specification beside `spec/presentation-contract-v0.md`. This document defines
the one builder that turns a verified Evidence Bundle into a page for one audience, and the three
ways it packages that page: one offline `.html` file, a fragment permalink, and an element in a
host page. The reference is `ts/src/presentation-builder.ts` (with
`ts/src/presentation-fragment.ts` and `ts/src/presentation-mount.ts`); the Go twin of the offline
packaging is `go/emitter/presentation.go`.

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as described in BCP 14
(RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

## Dependency boundary

**Owns:** `buildPresentation`; the three packagings; the fragment payload
`aac.presentation-fragment/v0`; the fragment size limits; the share-side scoping step; the
hand-back from a fragment to the offline file; the one wording key the builder reads
(`page.title`).

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
- `format` is `html` (offline file), `fragment` (permalink) or `embedded` (host element).
- Settings: `runtime` (the core runtime and, optionally, its pin; required for `html` and
  `fragment`), `modules` (digest-pinned module-slot scripts), `registry` (the resolver; the
  built-ins when omitted), `disclose` (section 3), `depth`, `title`, `themeCss`, `wording` (a
  wording pack's exact text and its `wording_sha256`), `maxFragmentLength`, `viewerUrl`.

The steps run in this order: scope (section 3), verify the scoped bundle, resolve, package. Every
packaging carries the same scoped bundle and the same settings.

## 2. The three packagings

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
`#`, so the longest token is 1,046,528 characters. A token over the limit, or a whole URL over
1 MiB when `viewerUrl` is given, is refused with `FragmentTooLargeError`, which names the length
and the limit. Nothing is ever truncated. A caller MAY set a lower limit (`maxFragmentLength`),
for example for a link that will be pasted into a chat or an email, which commonly cut links far
shorter; a limit above the maximum is an error. A decoder refuses an over-long token before
decoding it. A bundle too large for a permalink is shared as the offline file.

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

Acceptance is over (bundle, audience) pairs (contract I4). For one bundle and one audience, the
offline file, the fragment permalink and the embedded element MUST select the same module and
show the same verified content, the same verification state and the same evidence identifiers.
`ts/test/presentation-builder.test.ts` checks this over the fixtures for each built-in page shape
and a bundle that does not verify, for three audiences, in all three formats, by rendering each
packaging and comparing what it shows; the only refusal it accepts is a fragment over the size
limit. The same file checks that theme, wording, locale and depth leave every evidence
identifier unchanged, and `ts/test/presentation-builder-browser.test.ts` opens the offline file
and the fragment URL in a CSP-enforcing browser and finds no request beyond the document itself.

The Go and TypeScript offline outputs match byte for byte for the same inputs
(`go/emitter/testdata/expected-offline.html` and `offline-fragment.txt`).

## 5. Known gaps

1. The built-in modules do not read wording packs yet. The pack is checked, carried in the page
   and used for the title; the modules keep the core's own labels.
2. The viewer does not check its own runtime against `core_runtime_sha256`: it renders with the
   runtime it holds. The hand-back does check.
3. The countersigner list of the caller's context does not travel in any packaging; a page names
   no independent countersigner unless its host supplies a list.
4. The offline file's `<html lang>` stays `en` whatever the wording pack's locale.
