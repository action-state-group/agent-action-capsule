# Changelog

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

## Unreleased

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
  set (`schemas/vendor/epistemic-types.json`), extending capsule-engine's Batch 1 parity pattern
  (commit `ba7b7a0`) with its own three-way check. §9 maps every old capsule-judge/capsule-emit-mesh
  field onto this family so the pin/drift port is mechanical.
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
