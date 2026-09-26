# Judge Record Family — v1

**Status.** Design specification, pre-Internet-Draft, alongside `spec/evidence-result-v0.md`. This
document defines the **judge record family**: the record shapes a compile-time contract check, a
semantic evaluation, a period close, a sampling manifest, a human rating, a twin adjudication and
its responses, and a calibration summary all use to report what was judged and on what basis. It
exists because two families currently encode the same two capsules for the same purpose —
`evaluation-compiler` fixtures and `capsule-judge`'s `judge_judgment`/`judge_adjudication` — and
the planned book-verb and skills tooling that consumes these records
needs exactly one.

**Companion schemas.** `schemas/judge/*.json` — eight JSON Schemas (2020-12), one per record shape
below. Each is descriptive of the semantics fixed here; where they conflict, this document governs
and the schema is corrected to match.

## Dependency boundary

**Owns:** the eight record shapes below, the shared `Citation` and `Basis` building blocks, and the
old-field → new-field mapping in §9.

**Depends on, and mirrors by reference rather than redefines:**

- The Evidence Layer's (`draft-mih-agent-evidence-layer-00.md`) closed eight-value `epistemic_type`
  set (section "Epistemic Type") and its `principal_ref` convention. Vendored machine-readably at
  `schemas/vendor/epistemic-types.json` for this family's own parity check (§0).
- The Evidence Layer's six-state reconcile vocabulary and Close model (section "Reconcile and
  Close") — `close/v1` (§3) is a direct schema encoding of that prose, not a second model.
- The Evidence Contract's (`evidence-contract-internal-spec-v3.md`) three-value `Verdict` (§8),
  mirrored by `evaluation-report/v1`'s `cases[].verdict`, identical to `evidence-result-v0.json`'s
  `Claim.verdict`.
- `evidence-result-v0.json`'s and `evidence-plan-ir-v0.json`'s `<contract_id>@<version>`
  `contract_ref` convention.

**Explicitly out of scope (never defined here):** a judging engine, a sampler, or a calibration
computation. This document names what a conforming judge record looks like on the wire — the same
boundary `evidence-result-v0.md`'s Dependency boundary draws. It also never names `Authority`,
`Relay`, `score`/`scoring`, or `reputation`; every synthetic fixture's placeholder is `OO`, never a
company name.

## 0. The family-wide citation convention

Every record in this family cites what it read by digest, with a `citation_purpose` stating why —
never a bare digest and never inline bytes:

```
citation:
  type: string               # the cited artifact/record type, open token
  digest_alg: "SHA-256"
  digest: <64-hex>
  citation_purpose: string    # open token stating why this record cites the target
```

Each schema below fixes `citation_purpose` to a specific constant per field (`compiles_contract`,
`grounds`, `method`, `approves`, `reconciles_with`, ...) rather than leaving it free at each call
site — a reader can tell what a citation is for from the field's own schema, not from trusting the
string a producer happened to write.

Every schema also fixes `epistemic_type` to exactly one value (a `const`, never an `enum`) — the
epistemic type is a property of the *record shape*, not a per-instance choice. §0's own check,
`schemas/check_judge_record_examples.py`, extends capsule-engine's Batch 1 parity pattern (commit
`ba7b7a0`) to this family: every schema's `epistemic_type` const, a python-side table
(`SCHEMA_EPISTEMIC_TYPES`), and `schemas/vendor/epistemic-types.json`'s vendored copy of the
Evidence Layer's set must agree, with its own mutant check.

## 1. Contract Compile — `contract-compile/v1`

`epistemic_type: producer_claim` — the compiler's own claim that it compiled a given contract into
a given skill, with a human approval record on file. Unverified by any store until something else
cites it.

```
contract-compile:
  record_version: "contract-compile/v1"
  record_id: string
  epistemic_type: "producer_claim"
  compiled_at: date-time
  contract_ref: <contract_id>@<version>
  contract: citation                # citation_purpose: compiles_contract
  compiled_skill: [citation, ...]   # citation_purpose: compiled_skill, >=1
  human_approval: citation          # citation_purpose: approves — REQUIRED, not optional
```

A Contract Compile with no `human_approval` citation is not a legal record in this family — the
compile step never self-certifies; a human approval is always a separately committed fact this
record cites, never a boolean this record sets on itself.

## 2. Evaluation Report — `evaluation-report/v1`

`epistemic_type: semantic_judgment` — a judgment reached by interpretation, not direct observation.
Unifies capsule-judge's `judge_judgment`/`judge_adjudication` and capsule-compiler's
`judge_judgment_adapter` row convention into one schema: per-case `met`/`not_met`/`not_evaluable`,
each case citing the acts it grounds on and the method it was judged against, all cases sharing one
judge pin.

```
evaluation-report:
  record_version: "evaluation-report/v1"
  record_id: string
  epistemic_type: "semantic_judgment"
  generated_at: date-time
  contract_ref: <contract_id>@<version>
  judge_pin: basis                  # §6 — model_id, prompt_digest, axes_digest, sampling
  cases:
    - case_id: string
      verdict: met | not_met | not_evaluable   # owned by evidence-contract-internal-spec-v3.md §8
      acts: [citation, ...]         # citation_purpose: grounds, >=1
      method: citation              # citation_purpose: method — REQUIRED
```

**This is the single-party case of `adjudication/v1`'s shape, not a parallel family.** A `Case`'s
`verdict`/`basis` fields are named identically to `adjudication/v1`'s — see §6 — because a
single-party evaluation is an adjudication where the rubric stands in for a second party, not a
structurally different act of judgment. The two schemas differ only in verdict vocabulary
(`met`/`not_met`/`not_evaluable`, owned by the Evidence Contract, vs.
`corroborated`/`inconclusive`/`contradicted`, mesh's twin-comparison vocabulary) and in how many
parties `basis` judges (a rubric citation via `method`, vs. one or two `parties` citations).

## 3. Close — `close/v1`

`epistemic_type: producer_claim` — a store's own statement about its own history. Direct schema
encoding of the Evidence Layer's reconcile model (`draft-mih-agent-evidence-layer-00.md`, section
"Reconcile and Close"): period, counts by kind, and the head digest at close time, with an optional
reconcile block.

```
close:
  record_version: "close/v1"
  record_id: string
  epistemic_type: "producer_claim"
  closed_at: date-time
  period: { start: date-time, end: date-time }
  counts_by_kind: { <record_type>: integer, ... }
  head: digest-ref
  reconcile?:
    tallies: { matched, a_only, b_only, conflicting, insufficient, unresolved: integer }
    peer_close: citation           # citation_purpose: reconciles_with — REQUIRED if reconcile present
    status: AGREED | UNILATERAL | CONTESTED
```

**One schema serves both the single-store period Close and capsule-emit-mesh's two-party Close** —
no mesh-specific record kind exists for the latter; mesh's own repo has no formal schema for it
today (searched: no `peer_reconciliation`/`seal_close` match). `reconcile.peer_close` cites the
other side's own Close record, which is exactly the two-party mechanism. `reconcile.status` is a
**reporting convenience, not the authoritative source**: per the owning document, AGREED /
UNILATERAL / CONTESTED is read fresh from `acknowledges`/`rebuts` links pointing *at* a Close, never
trusted from a field the Close itself sets. A verifier that wants the authoritative status resolves
those links; `reconcile.status` is this record's own belief at generation time.

## 4. Sample Manifest — `sample-manifest/v1`

`epistemic_type: producer_claim` — the sampler's own statement of what it selected.

```
sample-manifest:
  record_version: "sample-manifest/v1"
  record_id: string
  epistemic_type: "producer_claim"
  generated_at: date-time
  policy: citation                  # citation_purpose: sampling_policy
  stratification: { <stratum>: integer, ... }
  cases: [string, ...]              # case ids, >=1
```

## 5. Human Rating — `human-rating/v1`

`epistemic_type: human_report` — asserted by a human, not machine-observed.

```
human-rating:
  record_version: "human-rating/v1"
  record_id: string
  epistemic_type: "human_report"
  rated_at: date-time
  blind: true                       # fixed const — a non-blind rating is not this schema
  rater_ref: principal_ref          # opaque; never a name in this schema
  case: citation                    # citation_purpose: rated_case
  label: string
```

`blind` is a `const true`, not a boolean a producer can set `false` — a rating that is not blind
uses a different record shape; it never sets this field to `false` to say so. `rater_ref` follows
the Evidence Layer's own `principal_ref` convention: an opaque identifier whose scheme is
host-defined. A rater's real-world identity binding is out of scope here, exactly as the owning
document states for `principal_ref` generally — this record never carries a display name, email, or
other directly identifying string.

## 6. Adjudication — `adjudication/v1`

`epistemic_type: adjudication` — a ruling on a matter that was disputed or required judgment.
Schemas capsule-emit-mesh's twin adjudication (`twin_adjudicator.py`: cites two halves,
`chain.relation: adjudicates`) and supplies the `Basis` shape `evaluation-report/v1`'s `Case` reuses
verbatim (§2).

```
adjudication:
  record_version: "adjudication/v1"
  record_id: string
  epistemic_type: "adjudication"
  adjudicated_at: date-time
  verdict: corroborated | inconclusive | contradicted
  contradicted_party?: string       # REQUIRED iff verdict == contradicted
  margin?: string                   # exact decimal string, never a float
  margin_tau?: string
  divergence_index?: string
  basis:
    model_id: string
    prompt_digest: digest-ref
    axes_digest?: digest-ref
    weights_digest?: digest-ref
    sampling: { <param>: int | string | bool, ... }   # never a float
  parties: [citation, ...]          # citation_purpose: adjudicated_party, 1-2 items
  referee?: citation                # citation_purpose: referee
```

`verdict: contradicted` is a fixed token; the *which party* half of mesh's own
`"contradicted:<owner_id>"` string is split out into `contradicted_party` rather than colon-encoded
inside what would otherwise need to be an open string this schema cannot close. `basis.sampling`
carries only `int`/`string`/`bool` values, mirroring capsule-judge's own `JudgePin.sampling_params`
discipline: a judge pin's reproducible call shape must not drift from float serialization.

## 7. Adjudication Response — `adjudication-response/v1`

`epistemic_type: producer_claim` — each is the responder's own claim about an adjudication it read,
never itself a ruling. Unifies capsule-emit-mesh's `adjudication_delivery_receipt`, `ack`, and
`rebuttal` (`adjudication_delivery.py`, `twin_adjudicator.py`) as one schema with a `kind`
discriminator, rather than three parallel record shapes.

```
adjudication-response:
  record_version: "adjudication-response/v1"
  record_id: string
  epistemic_type: "producer_claim"
  responded_at: date-time
  kind: delivery_receipt | ack | rebuttal
  adjudication: citation            # citation_purpose: responds_to
  verdict?: corroborated | inconclusive | contradicted   # REQUIRED for ack/rebuttal, PROHIBITED for delivery_receipt
  basis?: string                    # REQUIRED non-empty for rebuttal, PROHIBITED otherwise
```

`kind: delivery_receipt` carries neither `verdict` nor `basis` — it is sealed unconditionally at
delivery time, before any ack or rebuttal decision exists. This is mesh's own distinction between
"delivered" and "authored" provenance, made structural rather than left to call-site discipline.
`kind: rebuttal`'s `basis` is prose, never a numeric or ordinal field — mesh's own rule (a rebuttal
must never carry an empty `basis`) is enforced by this schema's `minLength: 1` plus the
kind-conditional `required`, not only at the python call site that built it before.

## 8. Calibration Summary — `calibration-summary/v1`

`epistemic_type: derived_metric` — a value computed or aggregated from other records. Never a rate:
no field in this schema is a computed ratio or percentage. Mirrors capsule-judge's own
`JudgeCalibrationStats` discipline (rates are `None`, not `0.0`, when unmeasured) by not storing a
rate at all — a reader who wants one divides `k` by `n` at read time.

```
calibration-summary:
  record_version: "calibration-summary/v1"
  record_id: string
  epistemic_type: "derived_metric"
  computed_at: date-time
  judge_pin: citation                # citation_purpose: calibrates
  clauses:
    - clause_ref: string
      agreement: { k: integer, n: integer }
      drift: { k: integer, n: integer }
```

**Normative, not schema-enforced in v1:** `agreement.k <= agreement.n` and `drift.k <= drift.n` are
cross-field constraints plain JSON Schema cannot express — the same class of gap
`evidence-result-v0.md` §4 documents for claim id uniqueness. A conforming verifier MUST check both
in addition to schema validation.

## 9. Field mapping — old families → this family

This table maps every field capsule-judge and capsule-emit-mesh's existing judge/adjudication
record builders carry today onto this family, so capsule-judge's pin/drift port is mechanical.
Where two systems already agreed on a name (capsule-judge's `EVENT_JUDGMENT = "judge_judgment"` and
capsule-compiler's `judge_agent/satellite.py` sealing under the same event name and
`judge_pin_digest` computation — the runtime convergence already happened before this task), this
table is the schema-level unification that convergence did not itself produce.

| Old field (source) | New field (this family) | Note |
|---|---|---|
| capsule-judge `judge_judgment.detail.prompt_digest`, `.model_id` | `evaluation-report/v1 judge_pin.prompt_digest`, `.model_id` | same names; `prompt_digest` becomes a `digest-ref` object, was a bare digest string |
| capsule-judge `judge_judgment.detail.label` | `evaluation-report/v1 cases[].verdict` | renamed and revocabularied: `label` was an open string; `verdict` is the closed `met`/`not_met`/`not_evaluable` set owned by `evidence-contract-internal-spec-v3.md` §8 |
| capsule-judge `judge_judgment.detail.confidence_micros` | *(no counterpart)* | a confidence figure has no field in this family — the same "never a score above the fold" discipline `evidence-result-v0.md` §3 rules; `calibration-summary/v1` reports k-of-n counts, never a confidence value |
| capsule-judge `judge_judgment.detail.evidence.turn_capsule_ids[]` | `evaluation-report/v1 cases[].acts[]` | renamed and typed: bare ids become `citation` objects (`citation_purpose: grounds`), by digest only — the identical `evidenceIds` → digest-ref rename `evidence-result-v0.md` §9 already made for its own family |
| capsule-judge `judge_judgment.detail.judge_pin.judge_pin_digest` | *(no counterpart — recomputed, not carried)* | this family cites the judge pin's own fields directly; a reader who wants the digest computes it over the same canonicalization, same discipline as every other digest here |
| capsule-judge `judge_judgment.detail.judge_pin.sampling_params` | `evaluation-report/v1 judge_pin.sampling` / `adjudication/v1 basis.sampling` | same name, same int/string/bool-only discipline |
| capsule-judge `judge_judgment.detail.judge_pin.adjudication_sampling_rate_micros` | `sample-manifest/v1` (policy-level) | a sampling rate is a manifest-level policy fact, not a per-judgment field — moved out of the judgment record entirely |
| capsule-judge `judge_judgment.detail.judge_pin.measured_agreement_rate_micros` | `calibration-summary/v1 clauses[].agreement {k, n}` | a stored micros-scaled rate becomes a k-of-n count pair — never a rate; computed at read time |
| capsule-judge `judge_adjudication.detail.judgment_capsule_id` + `chain.relation: confirms` | folded into `evaluation-report/v1`'s single-party `Case` | capsule-judge's two-capsule pattern (judgment, then a separate confirming capsule) collapses to one record for the single-party case; the two-party case is `adjudication/v1` |
| capsule-judge `judge_adjudication.detail.agrees_with_judge` (bool) | `evaluation-report/v1 cases[].verdict` (direct) | no separate agree/disagree field — a case's `verdict` IS the adjudicated outcome |
| capsule-judge `calibration.py` `JudgeCalibrationStats.{judgment,adjudicated,agreement,drift_check,drift}_count` | `calibration-summary/v1 clauses[].agreement{k,n}` / `.drift{k,n}` | same never-store-a-rate discipline, now per-clause rather than judge-pin-global, cited to a `judge_pin` by digest rather than an embedded `judge_pin_digest` string |
| mesh `adjudication.detail.half_a_capsule_id` / `half_b_capsule_id` | `adjudication/v1 parties[]` (`citation_purpose: adjudicated_party`) | unified into one order-independent array of `citation` |
| mesh `adjudication.detail.referee_capsule_id` / `referee_id` | `adjudication/v1 referee` | unified into one citation; a referee's model identity belongs in `basis.model_id`, not a second bare id |
| mesh `adjudication.detail.verdict` (`"corroborated"`\|`"inconclusive"`\|`"contradicted:<owner_id>"`) | `adjudication/v1 verdict` + `contradicted_party` | split: a fixed three-value enum plus a separate field for the dynamic owner id |
| mesh `adjudication.detail.margin` / `margin_tau` / `divergence_index` / `weights_digest` | `adjudication/v1` top-level `margin`/`margin_tau`/`divergence_index` (exact decimal strings) / `basis.weights_digest` | same values, relocated and typed |
| mesh `adjudication.detail.prefix_digest` / `twin_owner_distinct` / `schema` / `source` / `capture_method` / `status` / `references` / `tau` / `referee_logprobs_absent` | *(no counterpart)* | mesh-internal pipeline bookkeeping, out of scope for the wire shape this family defines; capsule-emit-mesh MAY continue to carry these in its own capsule detail alongside a `citation` into `adjudication/v1` — the same "profile MAY add further header fields" allowance the Evidence Layer itself states |
| mesh `adjudication_delivery_receipt.detail.adjudication_capsule_id` | `adjudication-response/v1 adjudication` (`kind: delivery_receipt`) | renamed, typed as `citation` |
| mesh `ack.detail.adjudication_capsule_id` / `verdict` | `adjudication-response/v1 adjudication` / `verdict` (`kind: ack`) | same fields, unified schema |
| mesh `rebuttal.detail.adjudication_capsule_id` / `verdict` / `basis` | `adjudication-response/v1 adjudication` / `verdict` / `basis` (`kind: rebuttal`) | same fields, unified schema; `basis`'s non-empty requirement is now structural (schema `minLength: 1` + kind-conditional `required`), not only a python call-site check |

**On "tau2 fixtures" (this task's DONE line).** No judge-shaped tau2 fixture exists anywhere today
to validate against directly — capsule-compiler's `examples/data/tau2_airline/` holds raw
conversation transcripts and a separate `hand_labels.json` (`{sim_id, hand_label, predicted}`), not
`judge_judgment`-shaped records, and that repo is outside this lane's scope. `evaluation-report/v1`'s
positive fixture (`vectors/judge/evaluation-report/pos-oo-evaluation-report.json`) is instead built
from content shaped like that conversation family, with `hand_label: true` rewritten onto
`verdict: "met"` — the one-line rewrite this family's schema requires — documented in
`vectors/judge/README.md`. Wiring capsule-compiler's actual tau2 fixtures through this schema is
follow-up work for whichever task ports capsule-judge/capsule-compiler onto this family; it is not
schema-blocking.

## 10. Capsule record kinds this family reads

Some records this family's shapes read are ordinary Agent Action Capsules rather than judge record
shapes. They are defined by the Agent Action Capsule profile (`draft-mih-scitt-agent-action-capsule`,
`spec/REGISTRY.md`), not here: this section names them so a reader of a two-party Close (§3) or an
evidence bundle knows which Capsule to look for. Each kind is identified by its `references[]`
entry's `citation_purpose`, **never** by the `chain.relation` string, and none is a ninth record
shape of this family (no schema, no `record_version`).

| Kind | Identified by | Record | Read by |
|---|---|---|---|
| Counterparty-half custody record | a `references[]` entry with `citation_purpose: counterparty_half` (AAC `citation_purpose` registry, `REGISTRY.md` §11) | The producer's own Capsule, chained to its own head via `chain.relation: follows`, whose `references[]` entry cites the counterparty's already-sealed half by digest; the received half's bytes stay a held artifact, never an entry in this producer's chain | a two-sided (closed) exchange state, which reads this record as the committed fact that the counterparty's half is held; an evidence bundle carries it alongside the producer's own half |

A counterparty-half custody record produced by migrating previously received halves (rather than at
receipt time) is a backfilled Capsule: it carries `provenance_mode.mode = "backfilled"` as the AAC
profile already defines it (Provenance mode section; `REGISTRY.md` §12). This family does not
redefine that mode.

## 11. Open follow-ups (not this task's DONE)

- **`capsule-registry` Home-2 registration.** The item header notes profile ids for this family are
  registered in `capsule-registry` Home-2. No registry PR is part of this task's DONE line (schemas
  + parity test only) — filing it is follow-up work once these eight `record_version` strings are
  reviewed.
- **capsule-judge / capsule-compiler port.** §9's table is the mechanical map; the port itself
  (capsule-judge emitting `evaluation-report/v1`/`adjudication/v1` instead of its own
  `judge_judgment`/`judge_adjudication` shapes) is a separate implementation task in a private repo
  outside this lane.
