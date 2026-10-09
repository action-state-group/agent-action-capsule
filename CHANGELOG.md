# Changelog

## Unreleased

- TypeScript: `VerifiedBundleContext` (`buildVerifiedBundleContext`) verifies a bundle once and is
  what every builder reads. `buildReportRows`, `buildResultRoot`, `isResultRoot`,
  `buildEvidenceGraph` and `renderEvidenceGraph` take a context (new overload; the `(bundle)`
  form still works and builds one); the 24 per-builder disclosure re-resolution sites are gone and
  a payload reaches a builder only when `verifyBundle` classified it `disclosure_match`.
  `renderEvidenceGraph` reads the countersigner list from the context when no third argument is
  passed. Rendered output is byte-identical for every fixture. Called directly, a builder no
  longer reads a record whose capsule_id does not recompute (it previously could).
- TypeScript: a `VerifiedBundleContext` is effectively immutable. It is built over the library's
  own copy of the bundle and its whole object graph (verification result, `resolvedDisclosures`,
  records and `recordIndex`, countersignatures and the countersigner list, extensions,
  completeness) is frozen; the two maps are read-only views. Code that tries to change any of it
  throws, and every later reader sees what the verifier produced. The caller's bundle and
  countersigner list are copied, not frozen. Payload objects a builder returns from the context
  are the frozen ones.
- `spec/presentation-contract-v0.md` + `schemas/presentation-manifest-v0.json`: the presentation
  contract (module interface, `aac.presentation-manifest/v0` manifests, resolution where an
  ambiguous match is a hard error, two trust classes, the chrome and text-binding rules,
  `sha256-jcs-nonce256`, `wording_sha256`, invariants, depth levels L0/L1/L2 mapped to the shell
  slots). The six built-in manifests express today's dispatch; `schemas/check_presentation_manifest_examples.py`
  proves no pair is ambiguous and that they resolve as today over 1,536 cases. Documents and
  schema only; no runtime change.
- Presentation contract amendments: a presentation ABI versioned on its own. Every manifest
  declares `presentation_api` (`aac.presentation-api/v0`) and `runtime_min`; `id` is the module
  id. A runtime refuses a module whose `presentation_api` it does not implement, or whose
  `runtime_min` it does not meet, and says so on the page in fixed words, never by a silent
  fallback. The verified bundle context MUST be effectively immutable. Invariant I4 now holds
  for every packaging target supported for a bundle, and an unsupported target MUST be reported.
  A module MUST NOT take wording or depth from a bundle-carried presentation setting. New
  negatives: a manifest with no `presentation_api`, a module with an unsupported one (refused at
  resolution), and a declarative module naming a hint as its wording source.

### Emitter (Go and TypeScript)
- The HTML shell has named slots: `TITLE_SLOT`, `THEME_SLOT`, `BUNDLE_SLOT`, `CORE_RUNTIME_SLOT`,
  `MODULE_SLOT` (zero or more digest-pinned scripts) and `BOOTSTRAP_SLOT`, plus `CSP_SLOT` for the
  policy. Each slot must occur exactly once in the shell. New entry points take the optional
  fills: `EmitEvidenceGraphHTMLWithOptions` (Go) and the third `options` argument of
  `emitEvidenceGraphHtml` (TypeScript). A supplied title is HTML-escaped; with none, the title
  stays "Evidence Graph". A module's bytes must match its lowercase hex SHA-256 pin, and a
  core-runtime pin is checked when given.
- A module carries a list of stylesheet pins (`Module.StyleSHA256` in Go, `styleSha256` in
  TypeScript): the lowercase hex SHA-256 of each stylesheet it inserts at render time, as in the
  presentation contract's `style_sha256`. The emitter lists each, in base64 form, in `style-src`
  after the core runtime's, and refuses a malformed pin. Pages with no module stylesheets are
  unchanged.
- Every emitted page carries a Content-Security-Policy meta element: `default-src 'none'`,
  `script-src` and `style-src` as SHA-256 hashes of the inline elements actually written (plus the
  two stylesheets the reference runtime inserts at render time, listed in
  `go/emitter/runtime-style-hashes.txt`), `img-src data:`, `connect-src 'none'`,
  `base-uri 'none'`, `form-action 'none'`. A script whose hash is not listed does not run. The core
  runtime's entry is the base64 form of the same digest as its hex `.sha256` pin.
- The shell carries a base stylesheet: theme tokens as CSS variables, a typography baseline,
  page width, overflow containment (wide tables scroll inside their own box below 760px), focus
  and reduced-motion defaults, details/summary disclosure, a verification-banner class and print
  defaults. Every rule has zero specificity, so a presentation's own stylesheet wins. No report
  layout is in the shell. Rendered page content is unchanged.
- Inline content that would change where its element ends (`</script`, `</style`, `<!--`) or
  that the HTML parser rewrites before hashing (CR, NUL) is refused.
- Pages emitted by this version run only the scripts the emitter wrote. A consumer that edits
  the emitted HTML afterwards to add a script or style element must pass it through the new
  slots instead, or the browser will refuse it.

## 0.7.0 — 2026-10-07

**Headline: string-typed fields are type-checked in every verifier.** A list, an object or a
null where the profile requires a string now fails check 1 (`field_not_string`) in Python, Go,
TypeScript and Rust, and a malformed `references[].retention` declaration (§5.5.5) is rejected
(#147, #148, #149, #150). Records that 0.6.0 accepted with an informational finding, or silently,
are now refused. Capsule vector case files shipped in 0.6.0 / `go/v0.6.0` are byte-identical; the
new cases are added beside them. The Evidence Result and judge-record fixture vectors were
regenerated with the `EXAMPLE-ORG` placeholder and their positive files renamed (#158); a consumer
pinning those files by name or hash re-pins.

### Verifier (all four implementations)
- A non-string in a string-typed field fails check 1 (#147). The string-typed block members
  (`disposition.decision`, `verdict_class`; `effect.status`, `type`, `irreversibility_class`,
  `effect_attestation`; `chain.relation`; `assurance.effect_mode`, `attestation_mode`,
  `ledger_mode`, `cross_party_rung`) holding any other JSON type, null included, give
  `field_not_string` (error), in that order. A non-string `disposition.approver` gives
  `field_not_string`. Python's closed-set lookups take strings only, so a list or an object no
  longer raises and yields a single `verifier_internal_error`; a registry field holding a
  non-string is treated as any unseeded value (informational, never a rejection). Fixes #146.
- `provenance_mode.source_asserted_at`, `import_batch`, `imported_at` and
  `references[].retention.declarant`, `retained_until`, `not_retained_after` are type-checked
  the same way (#148).
- A malformed `references[].retention` (§5.5.5) is rejected in check 1 (#149): a retention that
  is not a JSON object (null included) is `field_not_object` and nothing else in it is checked; an
  absent or null `declarant` is `missing_required_field`; an empty retention is
  `retention_empty`.
- Vectors `neg-retention-null` and `neg-retention-declarant-missing-and-empty` pin the finding
  order; the generator now lets a case expect several findings (#150).

### Added
- Evidence Request vectors (`vectors/evidence-request/`) for
  `draft-mih-agent-evidence-request-00`, derived from the -00 text: the request map and its
  refusal reasons, the six subject forms, coverage, exact-match resolution, the request digest
  over the bytes as received (JSON and deterministic CBOR), signed refusals, the three outcomes
  and pending, caller invariance, and retention commitments. Open readings are listed as
  ambiguities in the README (#142). DIFFS items 1 and 2 are marked resolved (#170).
- Evidence Request vectors: three request cases for coverage that carries both members where a
  value does not conform (`neg-coverage-both-pin-malformed`, `neg-coverage-both-freshness-malformed`,
  `neg-coverage-both-both-malformed`), all refused `request_malformed`. Ambiguity note A4 is
  amended with the 2026-10-06 ruling: a responder checks each present member's value first, and
  only then refuses both-or-neither `coverage_unsatisfiable`. The normative sentence goes into
  `-01` §3.2; the posted `-00` files are unchanged. Existing vector bytes are unchanged (#189).
- Evidence Bundle `-01` working revision (`spec/draft-mih-zhang-agent-disclosure-bundle-01`;
  the posted `-00` files are unchanged). It defines the `countersign/v1` entry (signing input
  `UTF8(JCS({over, signer, statement, type}))`, five per-check results, self-countersignature
  rendered as not independent), the `producer-key/v1` extension kind, `composed/v1`, and
  provisional SD-JWT kinds (#167).
- `producer-key/v1` registered in `REGISTRY.md` §14 (with the Python and Go mirrors), and
  `countersign/v1` in §15. The block is `{"public_key": "<64 lowercase hex>"}`, digest-covered;
  a verifier uses it only to classify a countersignature by that key as not independent. A
  malformed block is ignored.
- TypeScript: `declaredProducerKeys(bundle)` and `PRODUCER_KEY_V1`, exported from the
  countersignature stamp; the evidence graph view now reads the declared key through it
  (unchanged behaviour).
- Vectors `vectors/bundle/producer-key/` (generator
  `python/scripts/generate_bundle_producer_key_vectors.py`): a declared self-countersignature
  is not independent; the same Bundle without the declaration, a different signer, and five
  malformed blocks are not. Consumed by Python and TypeScript tests. Existing vector files are
  unchanged; only the top-level `SHA256SUMS` and `manifest.json` gained entries.
- Go: `bundle.VerifyBundle` now interprets the `composed/v1` extension (bundle `-01` §7.2)
  instead of reporting it uninterpreted. `ExtensionResult.Composed` reports the recomputed
  composed digest, each member (outcome, body carried or declared missing, digest reproduced,
  and a carried member Bundle's own verification), composition closure
  (`pass`/`withheld`/`fail`), each join's declared and re-derived state
  (`pre_agreed_identifier`, `shared_artifact_digest`; the reserved bases are `not_derivable`),
  and per-join redundancy. `bundle.ComposedDigest` recomputes the digest from the block alone.
  Refusal signatures use a caller-supplied profile (`Options.RefusalSignature`) and are
  `signature_unverified` without one. Tested byte for byte against `vectors/bundle/composed/`.
  Python and TypeScript still report the block uninterpreted (#168).
- Evidence Result v0: optional claim `type` (`requirement` | `reconcile` | `close`; absent means
  `requirement`), with the `reconcile` and `close` bodies, fixtures and mutant checks. Existing
  fixtures validate unchanged (#140).
- TypeScript emitter: a sealed Result v0 as the bundle root (`buildResultRoot`). Headlines come
  from the root and drill-downs from the records it cites; a claim whose cited ids do not resolve
  renders `unsupported`, and a root that is not a Result v0 is an error (#141).
- TypeScript emitter: two Result v0 presentation profiles, the outcome-report card
  (`extensions["outcome-report/v1"]`, #160) and the EU AI Act obligations card (#164), each
  selected only after the verify-first gate. A claim citing a published capsule now resolves to
  the book record carrying it.
- `spec/draft-mih-agent-settlement-records-00` with `vectors/settlement/` (14 spec-derived cases;
  payer and payee legs, gross, fee and net per side, exact integer amount comparison), for
  review (#159).
- TypeScript package: isolated `./core` entry points and a manual npm trusted-publishing workflow
  (`publish-ts.yml`, `ts/v*` tags). The npm package is versioned on its own train; the PyPI
  release workflow ignores `ts/v*` releases (#184).

### Changed
- A null `references[].retention.declarant` is now reported as `missing_required_field` (check 1),
  as a null `disposition.approver` is: `declarant` is REQUIRED (§5.5.5). #148 had reported it as
  `field_not_string`; #149 changed the code in every verifier (Python, Go, TypeScript, Rust).
- `close/v1`: the peer-Close link moves off `citation_purpose` (`reconciles_with` was never
  registered) into an Evidence Layer `cites` link carried in `x-evidence-links`. A Close with
  `reconcile` carries exactly one `cites` link to the peer's Close for the same period. The old
  positive `pos-example-org-close.json` is frozen and now rejected; the new positive is
  `pos-example-org-close-linked.json` (#176).
- `REGISTRY.md` §6: the `chain.relation` tokens `resolves`, `escalates`, `adjudicates`, `assesses`
  are noted as read-only legacy aliases (never emitted; mapped to `supersedes` / `confirms`). The
  parsed table is unchanged (#178).
- Fixture placeholder org renamed to `EXAMPLE-ORG` across spec, schema descriptions, generators,
  checkers and vectors (#158); the fixture placeholder is called the counterparty placeholder
  (#154).

### Fixed
- Go `canonical.JCS` writes negative zero as `0`, as RFC 8785 and the Python and TypeScript
  serializers do; `-0` previously gave a different digest in Go (#188).
- TypeScript: a verified bundle whose root is not `report/v1`, a Result v0, or an
  `evaluation-summary/v1` renders with a plain-text note instead of throwing (#191).
- `vectors/disclosure-envelope/README.md` checksum refreshed in both `SHA256SUMS` files (#156).

### Spec
- Bilateral `-02`: retention decay of the bilateral property stated as a named mechanism property,
  with the three verifier states kept apart (#119). Bilateral `-03`: RFC 9943 terms, no
  "witnesses" role, "countersign" pinned (#151); the "anchor" verb replaced by SCITT registration
  terms (#174).
- Evidence Bundle `-01`: "anchored" becomes "bound" in Interval coverage (#173).
- Evidence Layer `-00`: freshness pass before first upload (references pinned to posted
  revisions, RFC 9942/9943 terms, Reconcile and Close states) (#175).
- Result v0: names the right enum for `NOT_APPLICABLE` and `UNKNOWN` (wording only, #181); Close
  rules stated without review-round attributions (#161).
- AAC `-05` draft artifacts regenerated for the October build date (#153); guide and Bundle author
  email refreshed (#183); rulings cited by date (#155); value sets and rules described directly
  (#145).

### CI
- Neutrality scanner: reads only regular files and does not follow symlinks; redacts terms on
  untrusted runs (#143); scans every tracked file (`git ls-files -z`) with pinned actions (#144);
  catches adoption claims about reference projects (#169); refuses a double-encoded
  `NEUTRALITY_TERMS` (#186).
- Leak lint reads its term list from the `LEAK_LINT_TERMS` secret and fails closed (#171).

## 0.6.0 — 2026-09-27

**Headline: the -05 wire.** Producers now emit `spec_version`
`draft-mih-scitt-agent-action-capsule-05`; verifiers accept both `-04` and `-05`. The -05
registrations are seeded (below). Released vectors are unchanged: every vector case file
shipped in 0.5.0 / `go/v0.5.x` is byte-identical, and the -05 cases are added beside them
(only the corpus indexes, `SHA256SUMS` manifests and READMEs gained entries).

### Changed
- TypeScript countersignature stamp (`ts/src/countersignature-stamp.ts`) now verifies
  `countersign/v1` entries: `over` must equal the recomputed bundle digest, and the Ed25519
  signature (128 hex, under the 64-hex `signer.key_id`) must cover
  `UTF8(JCS({over, signer, statement, type}))`, with `signer` and `statement` signed as they
  appear on the wire. A result or `signer.id` edited after signing makes the entry `invalid`, and
  its checks are not shown. An absent or empty `type` is verified as `countersign/v1`: the input
  binds `"countersign/v1"`, so a signature over `""` fails. `cose-sign1` and any other type the
  viewer does not implement render as `unverified`. Previously the stamp accepted only
  `cose-sign1` and classed a `countersign/v1` entry as `invalid`.
- Countersigners are named from a list the caller passes in (`CountersignerSource`: `{name,
  key_ids[]}` listings), or one loaded by `pinnedCountersignerSource` against a pinned SHA-256.
  They are never read from the witness directory: a `witnesses.json` document resolves no signer.
  A key listed under two names resolves to neither. The checks and results come from the signed
  statement and are listed per check as the signer's statement, never totalled. The old flat
  directory (`publicKey`/`name`/`logoDataUrl`/`checksRecomputed`) and the stamp logo are removed.
  A present receipt is shown as unverified; the viewer does not verify receipts.
- Stamp states: `hollow`, `unverified`, `invalid`, `not-independent`, `unresolved-signer`,
  `resolved`. **Breaking (TypeScript API):** `classifyCountersignatures(entries, digest,
  producerKeys[], countersigners)`. `renderEvidenceGraph`'s third argument is a
  `CountersignerSource`, and the emitted report shell passes none. `CountersignerDirectoryEntry`
  and `BUNDLE_DIGEST_CONTENT_TYPE` are removed.
- Tests consume capsule-anchor's shared `countersign/v1` golden vector, vendored byte for byte as
  `ts/test/testdata/countersign-v1-anchor-golden.json` with its SHA-256 pinned (`d057691c…155fb`).
  Its negatives fail as the vector says: flipped result, digest-only signature, spoofed
  `signer.id`, and signature without `signer` are invalid, and a receipt for a different
  statement leaves the entry valid with the receipt unverified.

### Fix: bundle completeness without the CLL reference is not an invalid certificate
- `verify_bundle` (Python) reported every well-formed `completeness_certificate` as
  `completeness_certificate_invalid` on interval coverage and per-record membership when
  the CLL reference (`cll`) was not installed. `pip install agent-action-capsule` never
  installs it, so the clean report bundles were rejected there while the TS and in-report
  verifiers passed them. A certificate that is structurally valid but cannot be checked
  now fails closed as `completeness_verifier_unavailable`: it never passes, and it is never
  called invalid. A certificate that is wrong on its face is still
  `completeness_certificate_invalid` with or without CLL. A missing COSE checkpoint
  authenticator now leaves the checkpoint `checkpoint_unverified` (as in TS), not
  `checkpoint_authentication_invalid`.
- New `bundle` extra: `pip install 'agent-action-capsule[bundle]'` adds
  `checkpointed-local-log>=0.4.0`. It is an extra, not a core dependency, because
  `checkpointed-local-log` depends on this package.
- Vectors: `vectors/bundle/report-single-record.json` holds literal single-record report
  bundles (the rendered-report shape): the positive, `neg-checkpoint-root-mismatch` and
  `neg-leaf-index-equals-seq`, with `expected_without_cll` for the Python reference
  without the extra. Python and TS test it. `vectors/bundle/SHA256SUMS` now covers it, and
  its stale `README.md` line is corrected.

### Wire: `spec_version` -05
- **A producer conforming to -05 emits `draft-mih-scitt-agent-action-capsule-05`; a
  verifier accepts `-04` and `-05`** (the revisions that define format 4).
  `spec_version` never selects an algorithm, and an unrecognized value is informational,
  never by itself a rejection. Python `DEFAULT_SPEC_VERSION` (and `SPEC_VERSION`) moves to
  -05; Python, Go and TypeScript export the current and accepted values
  (`ACCEPTED_SPEC_VERSIONS`, `verify.CurrentSpecVersion` / `verify.AcceptedSpecVersions`,
  `CURRENT_SPEC_VERSION` / `ACCEPTED_SPEC_VERSIONS`). No verifier branches on
  `spec_version`, so a format-4 Capsule carrying -04 verifies unchanged; each
  implementation tests a committed -04 vector and its -05 twin, and an unrecognized value.
- Registrations in -05: `chain.relation` `follows` (and `duplicates`, with
  `provenance_mode`); `citation_purpose` `ran_under` (#95), `corroborates_source_time`,
  `counterparty_half` and `counterparty_inclusion`; `effect.type` `inference_completion`;
  `effect_attestation` `host_served_observed`. Python check 8 (and Go, which reads the same
  `REGISTRY.md`) now reports `inference_completion` and `host_served_observed` as seeded
  values rather than unknown ones.
- Vectors: released vectors are unchanged. The capsule corpus keeps its -04 cases and adds
  five `pos-v05-*` cases (`python/scripts/generate_v05_vectors.py`); the provenance-mode
  corpus and the cross-language interlock fixture each gain `-v05` twins beside the
  released -04 files.
  The top-level `vectors/SHA256SUMS` also now lists the correct digests for three
  `interop/composition/` files whose bytes did not change; the 0.5.0 manifest had stale
  entries. Go's registry-vocabulary test fixture (`go/verify/testdata/vocabulary.json`) is
  regenerated for the new registrations; it is test data, not a conformance vector.
- TypeScript `registries.ts` now matches `spec/REGISTRY.md` (it was on the draft-04 seed
  sets) and is checked against it by a test.

### Spec
- `spec/draft-mih-agent-evidence-request-00.md` — new Internet-Draft, "An
  Interaction Model for Requesting Verifiable Evidence" (sole author Steven
  Mih), defining a transport-agnostic request/response interaction for
  verifiable evidence: a request naming a subject and a coverage anchor,
  resolving to exactly one of three outcomes — the evidence artifact, a
  signed refusal carrying a machine-readable reason (registry includes
  `derivation_unsupported`), or a recorded absence — with a distinct
  pending state for a request still inside its waiting window. Defines no
  evidence format, identity scheme, trust policy, or availability
  guarantee; requester identity, purpose, authorization, and disclosure
  policy are explicit non-goals.
- `spec/judge-record-family-v1.md` — added the Judge Record Family: eight companion JSON
  Schemas (`schemas/judge/*.json`) unifying two previously-divergent record families for the
  same two capsules (`evaluation-compiler` fixtures vs. `capsule-judge`'s
  `judge_judgment`/`judge_adjudication`) into one — `contract-compile/v1` (`producer_claim`),
  `evaluation-report/v1` (`semantic_judgment`; per-case `met`/`not_met`/`not_evaluable`),
  `close/v1` (`producer_claim`; period + counts + head + optional reconcile), `sample-manifest/v1`
  (`producer_claim`), `human-rating/v1` (`human_report`; `blind: true` fixed, rater as
  `principal_ref`, never a name), `calibration-summary/v1` (`derived_metric`; k-of-n per clause,
  never a rate), plus the mesh family (`adjudication/v1`, `adjudication-response/v1`) schema-ing
  capsule-emit-mesh's twin `adjudication`/`adjudication_delivery_receipt`/`ack`/`rebuttal` so
  `evaluation-report/v1` is the single-party case of the same adjudication shape rather than a
  parallel one. `epistemic_type` is fixed per schema and vendored from the Evidence Layer's closed
  set (`schemas/vendor/epistemic-types.json`), held in sync by a three-way parity check (schema
  `const`, python-side table, vendored set) with its own mutant check. §9 maps every old capsule-judge/capsule-emit-mesh
  field onto this family so the pin/drift port is mechanical.
- `spec/draft-mih-scitt-agent-action-capsule-05.md` — retention-undertaking declaration and
  cross-algorithm re-anchoring format (#118); corrected the selective-disclosure I-D reference
  and stale pins (#120); cites RFC 9942 in place of the superseded merkle-tree-proofs draft
  (#128). The evidence-bundle and disclosure-envelope drafts pin AAC -05 (#127).
- `spec/evidence-result-v0.md` + `schemas/evidence-result-v0.json` — Evidence Result schema
  v0, with examples and a checker (#114).

### Added
- Go: check 9 (`provenance_mode`) in `go/verify`, with seven more provenance-mode vectors
  (#113; first tagged as `go/v0.5.1`).
- Interop: TRACE digest-agreement fixture and test (#115; `rfc8785==0.1.4` added to the
  `dev` extra for the cross-check only), and `docs/interop/aac-trace-references.md` (#97).
- Emitter (Go `go/emitter`, TypeScript `ts/src/emitter.ts`): renders an Evidence Bundle as a
  self-contained HTML report — evidence-graph drill-down, verification page,
  `presentation/v1` header, countersignature stamp — byte-equal between Go and TypeScript.
- CI: fail-closed internal-leak lint (#121, #129).

### Fixed
- Python tests read capsule vectors as UTF-8 (#109).

## 0.5.0 — 2026-09-22

### Spec
- `spec/draft-mih-scitt-agent-action-capsule-05.md` — added `provenance_mode`,
  a MODE on the ordinary Capsule (never a distinct record type; ruled
  2026-09-22) disambiguating a contemporaneous action record from a
  backfilled import of a historical one: `mode` (`contemporaneous` default |
  `backfilled`), and — REQUIRED when backfilled — `source_ref` (typed digest
  reference), `source_asserted_at`, `import_batch`, `imported_at`. Normative
  time semantics: `timestamp`/`source_asserted_at` are always producer
  self-attestations, never log-witnessed by virtue of being carried in the
  Capsule; a backfilled record's occurrence-time claim (`time_rung`:
  `self_attested` | `witnessed`) is capped at self-attested unless a
  `references[]` entry cites a signed/witnessed source timestamp under the
  new `corroborates_source_time` citation_purpose — and even then never
  upgrades `attestation_mode`/`ledger_mode`, which stay independently
  derived. Class 1 verification gains check 9: the required-field structural
  check, the `time_rung` overclaim (gating — unlike the informational
  overclaim treatment check 7 gives `attestation_mode`/`ledger_mode`/
  `cross_party_rung`), and the `imported_at == source_asserted_at`
  laundering-shape failure (a backfilled record must not be made to look
  contemporaneous by construction). Deliberately named `provenance_mode`,
  not `provenance` — REGISTRY.md §9's pre-existing `provenance` field (the
  `-02` gate/runtime/collector dedup-rank signal) is an unrelated
  vocabulary; the two names never collide. New `chain.relation: "duplicates"`
  (REGISTRY.md §6) lets a backfilled Capsule cite the contemporaneous
  Capsule of the same logical event in this producer's own stream; a
  `duplicates`-linked pair is counted once, the contemporaneous record
  governing — never fold history retroactively (an imported record is
  appended at import position, never spliced into the chain at the position
  its `source_asserted_at` implies).
  Authored by Steven Mih (draft author of record,
  `draft-mih-scitt-agent-action-capsule`).

### Added
- **`provenance_mode` (§5.3(bis) Provenance mode, draft -05).**
  `python/agent_action_capsule/contracts.py`: `ProvenanceMode` producer-side
  carrier (`mode`, `source_ref`, `source_asserted_at`, `import_batch`,
  `imported_at`, `time_rung`), enforcing the four-companion-fields-REQUIRED-
  when-backfilled invariant and the orphaned-fields-forbidden-when-
  contemporaneous invariant at construction; `PROVENANCE_MODES`,
  `TIME_RUNGS`, `TIME_RUNG_RANK`. `python/agent_action_capsule/parse.py`:
  `Capsule.provenance_mode` / `parse_capsule` round-trip the new block.
  `python/agent_action_capsule/emit.py`: `emit(provenance_mode=...)`.
  `python/agent_action_capsule/verify.py`: new check 9 — the
  required-field structural check, `provenance_mode_source_ref_malformed`,
  the `time_rung` overclaim (`provenance_time_rung_overclaim`, rederived
  from a well-formed `references[]` entry citing
  `citation_purpose: "corroborates_source_time"`, never from the claim),
  and `provenance_time_laundering_shape` (`imported_at == source_asserted_at`
  on a backfilled record) — all gating, unlike check 7's informational
  overclaim treatment of `attestation_mode`/`ledger_mode`/`cross_party_rung`.
  `derived.provenance_mode`/`derived.provenance_time_rung` are always
  reported in `VerificationResult.assurance` when the block is present.
  `verify_store()`: `chain.relation: "duplicates"` store-level handling —
  `duplicate_collapsed` (info) records the collapse, and
  `duplicate_parent_not_contemporaneous` (info) flags a `duplicates` parent
  that is itself backfilled. `spec/REGISTRY.md`: `duplicates` added to the
  `chain.relation` registry (§6), `corroborates_source_time` added to the
  `citation_purpose` registry (§11), new §12 `provenance_mode` documenting
  the closed two-value `mode` enum and `time_rung`'s scope
  (`python/agent_action_capsule/data/REGISTRY.md` resynced to match — it had
  also drifted on an unrelated section number, §5.4.4 vs §5.5.4, fixed as a
  side effect of the resync).
  `provenance-mode-vectors/`: a new frozen-vector corpus (one positive, three
  negative, one store-level) in the same discipline as
  `disclosure-envelope-vectors/` — kept OUT of `test-vectors/` because that
  corpus is cross-language-shared with the Go reference implementation,
  which has never implemented the `-02` `domain`/`provenance` addendum
  either; `provenance_mode` joins that same Python-only surface rather than
  breaking Go conformance on a feature it does not implement.
  `evaluation-compiler`'s `demo/backfill/backfill.py` (a downstream backfill
  tool that seals historical tau2-bench transcripts — exactly the
  `mode: "backfilled"` case) now threads `mode`/`source_asserted_at`/
  `import_batch`/`imported_at` into its existing opaque, already-digest-
  committed `payload.provenance` dict, using field names that match this
  profile's `provenance_mode` block 1:1 — not yet a first-class, wire-level
  Capsule field, since `capsule-emit-go`'s `emit.Input` has no
  `ProvenanceMode` member and `capsulectl`'s request decoder rejects unknown
  fields outright; promoting these to a real `capsule.ProvenanceMode` block
  (with a genuine `source_ref` digest) is a follow-up once that Go-side
  support lands.

## 0.4.0 — 2026-09-17

### Reference (breaking)
- **Format-4-only canonical reference.** The Python and Go reference verifiers and
  `capsule_id` computation now accept `format_version: "4"` only; any other value is
  rejected with `unsupported_format_version`, and the legacy absent-field ("vintage")
  construction has been removed rather than left unreachable. Records in the retired
  format-2 (vintage absent-field) construction remain verifiable with the frozen reference release
  **`legacy-verify/v0.1.0`** (commit `43b349dd6e8ee5f30dac3add9261b8f84e13ba7e`, the
  pre-format-4-only `main` tip), which the `pinned-legacy-format-2-verification`
  conformance job checks out to re-verify the cited July interop record. That tag is
  the single pinned legacy artifact; do not re-tag.

## 0.3.0 — 2026-09-08 (Python library)

### Python
- **draft-04 `references[]` — parity with the Go reference implementation.** The
  builder, `Capsule` model, parser, and serialization now carry `references[]`,
  preserving the tri-state **absent ≠ empty ≠ populated**. Reference validation
  mirrors `go/verify/references.go` 1:1 (entry structure; AAC/SHA-256 digest
  format; no duplicate chain-parent target; optional citation-purpose /
  log-coordinate checks). Foreign reference types / digest contexts remain open;
  unknown citation purposes are informational; coordinate checks do not verify
  inclusion proofs. Adds the `citation_purpose` registry (7th §12 registry) and
  validates against the 25 shared Go test vectors + producer-path unit tests.
  This is the version emit/CLL should pin as their AAC floor for `references[]`.

### Added
- **Python `references[]` parity with Go (draft-04 §5.5.5, {{xref}}).**
  `python/agent_action_capsule/contracts.py`: `ReferenceEntry` and
  `LogCoordinates` producer-side carriers. `python/agent_action_capsule/parse.py`:
  `Capsule.references` — a genuine tri-state (`None` omits the key; `()` emits
  `"references": []`; a populated tuple emits the entries), since absent and
  empty are the same claim but distinct bytes and therefore distinct
  `capsule_id` digests; the "MUST NOT duplicate `chain.parent_capsule_id`"
  boundary rule is enforced at `Capsule.__post_init__`.
  `python/agent_action_capsule/verify.py`: `references[]` findings (entry
  structure, the AAC/SHA-256 self-identity digest-format gate, the duplicate-
  chain-parent check, `citation_purpose` and `log_coordinates` checks) spliced
  into checks 1/6/8, mirroring `go/verify/references.go` finding-for-finding —
  foreign reference types/digest contexts stay open, unknown `citation_purpose`
  values are informational (never rejected), and `log_coordinates.inclusion_proof`
  is recorded as structural only, never independently verified.
  `python/agent_action_capsule/registries.py`: `citation_purpose` added as the
  seventh registry (§12), with the same missing-section fallback as the Go
  loader for an older `REGISTRY.md` snapshot. `python/agent_action_capsule/emit.py`:
  `emit(references=...)`. Validated against the 25 shared vectors in
  `go/verify/testdata/references.json` (`python/tests/test_references.py`),
  replaying the same store and check-order assertions as
  `go/verify/references_test.go`.

## 0.2.0 — 2026-08-28

### Spec
- `spec/draft-mih-scitt-agent-action-capsule-03.md` §5.3 Assurance — added the
  cross-party assurance rung, a FOURTH, orthogonal `assurance` claim
  (`cross_party_rung`: `unilateral_fallback` < `acknowledged_receipt` <
  `full_bilateral`) plus its supporting `cross_party` evidence block
  (`initiator_ref`, `counterparty_ref`, `correlator`, `substantive`). Kept
  orthogonal to `attestation_mode` rather than folded into it (log custody and
  counterparty exchange evidence are independent facts a producer can hold in
  any combination); the draft states this reasoning inline. Same
  never-grades-up overclaim discipline as `attestation_mode` / `ledger_mode`.
- `spec/draft-mih-scitt-agent-action-capsule-03.md` §5.4 Disposition —
  extended the CLOSED `disposition.approver` enum from `{human, policy}` to
  `{human, policy, counterparty}`. Stays closed (not registry-governed); the
  pre-existing honesty invariant (`human_disposed: true` REQUIRES
  `approver: "human"`) is unaffected.

### Compat
- **Migration path (never-grades-up):** an old verifier that does not
  recognize `cross_party_rung` or the `cross_party` block simply does not see
  them — it verifies the record on the three axes it already knows and never
  errors on the unrecognized field/block, matching how it already tolerates
  any other unrecognized value. A verifier that DOES recognize the field but
  is handed a `cross_party_rung` value outside what it can independently
  derive ranks the claim below what it knows: a `full_bilateral` or
  `acknowledged_receipt` claim it cannot corroborate is treated no stronger
  than `unilateral_fallback` (the same floor an unrecognized `attestation_mode`
  value is already held to, §5.3) — nothing breaks, and no record is silently
  over-trusted.
- An old verifier encountering `disposition.approver: "counterparty"` before
  this revision would reject the Capsule outright (closed two-member enum);
  this revision is additive, not a relaxation — the enum grows from two
  members to three, still closed, so no third-party value is newly admitted.

### Docs
- `docs/telemetry-binding-profile.md`: new informational profile (AARM R8,
  `capsule-ledger`'s `ldg-otel-exporter-aarm-r8`) specifying the
  reference-never-copy rule for telemetry export, the minimum attribute set,
  and the mapping to OTLP/`gen_ai` (primary) and OCSF (secondary,
  best-effort — documents the mismatch rather than presenting a native fit).
  Not core spec: telemetry is a projection of the capsule, and this profile
  moves at OTel/OCSF's release speed so core doesn't have to.

### Added
- `python/agent_action_capsule/contracts.py`: `CrossParty` producer-side
  carrier (§5.3 Cross-party assurance evidence), `CROSS_PARTY_RUNGS`,
  `CROSS_PARTY_RUNG_RANK`; `AssuranceBlock.cross_party_rung` (OPTIONAL);
  `VALID_APPROVERS` extended to include `"counterparty"`.
- `python/agent_action_capsule/verify.py`: check 7 (`assurance_overclaim`)
  extended to `cross_party_rung` — a claimed rung above what the verifier
  independently rederives from the `cross_party` block is flagged and the
  reported `derived.cross_party_rung` is downgraded to the value the evidence
  supports.
- `python/agent_action_capsule/parse.py`: `Capsule.cross_party` /
  `parse_capsule` round-trip the new block and `assurance.cross_party_rung`.
- `vectors/capsule/`: four new conformance vectors — one per cross-party rung
  (`pos-cross-party-full-bilateral`, `pos-cross-party-acknowledged-receipt`,
  `pos-cross-party-unilateral-fallback`), and the named overclaim case
  (`neg-cross-party-overclaim`: `full_bilateral` claimed with only the
  initiator's half present) plus `pos-disposition-approver-counterparty`
  confirming the honesty invariant holds against the new approver value.

### Fixed
- Packaging: `python/pyproject.toml` now declares `license-files = ["LICENSE"]` (PEP 639) so the
  BSD-3-Clause `LICENSE` text ships inside both the wheel (`*.dist-info/licenses/LICENSE`) and the
  sdist, not just the `License-Expression` METADATA field. `python/LICENSE` is a symlink to the
  repo-root `LICENSE` (single source of truth; root `LICENSE` text unchanged). Bumped the
  `setuptools` build requirement to `>=77.0.3` (the floor with stable PEP 639 `license-files`
  support) and dropped the now-superseded `License :: OSI Approved :: BSD License` classifier.
- API: the top-level convenience function `anchor()` shadowed the `agent_action_capsule.anchor`
  submodule on attribute access (`import agent_action_capsule.anchor as x` bound the function, not
  the module, under Python's attribute-wins semantics). Renamed the canonical export to
  `anchor_capsule()`; `anchor()` remains available as a deprecated alias (emits
  `DeprecationWarning`, delegates to `anchor_capsule()`) for this release and will be removed in a
  future one, at which point the submodule shadow is fully resolved.

## 0.1.0 — 2026-07-06

### Added
- `history` module: `list_capsules`, `verify_chain_completeness`, `export_verifiable_bundle`, `ChainReport` — ledger-grade capsule history API
- `selective_disclosure` module: salted per-field SHA-256 commitments, `commit_fields`, `disclose_subset`, `verify_disclosure`
- `bilateral` module: four-move bilateral attestation handshake (`BilateralHandshake`), `seal_request/action/bilateral`, `BilateralState`
- `verify_pair` module: bilateral capsule pair verification

### Changed
- Registry: seeded `"confirms"` in `chain.relation` allowed values

### Spec
- `spec/draft-mih-scitt-agent-action-capsule-02.*` — compiled -02 spec artifact
