# Evidence Result — v0

**Status.** Design specification, pre-Internet-Draft, beside `spec/evidence-plan-ir-v0.md` (the
Evidence Plan IR). This document defines the **Evidence Result**: the artifact that reports, per
requirement, what was judged and with what assurance, over an Evidence Contract. Sections 1–3
(result semantics, disclosure policy, aggregate/coverage) carry **Steven's ruling, quoted verbatim
below (2026-09-22)** — the gate Batch 4 required before this schema could freeze. The gate is
satisfied; the schema, validator, and fixtures below are encoded to the ruled text and are no
longer DRAFT.

**Companion schema.** `schemas/evidence-result-v0.json` — a JSON Schema (2020-12) encoding of
every object model defined below. The schema is descriptive of the semantics fixed here; where
they conflict, this document governs and the schema is corrected to match.

## Dependency boundary

**Owns:** the Evidence Result document shape (claims + aggregate + optional view), the claim
object model, the disclosure-policy carrier vocabulary (`disclosure` / `analysis` / `story`), and
the aggregate coverage statement and bucket grouping.

**Depends on, and mirrors by reference rather than redefines:**

- The Evidence Contract's (`evidence-contract-internal-spec-v3.md`) two closed result
  vocabularies — the four-value Sufficiency (§5.2) and the three-value Verdict (§8) — and its
  eight-value per-requirement bundle assertion status (§5.1).
- The Evidence Plan IR's (`evidence-plan-ir-v0.md`) two-value `tier` vocabulary (§4.2) and its
  `<contract_id>@<version>` compact contract-reference convention (§2, carried on every IR node
  as `contract_ref`; this document uses the identical field name and shape on every claim).
- The Witness/Countersign definitions' three-value assurance `grade` vocabulary, owned
  elsewhere and never redefined here.

A drift between any of the above and this document's mirrored copy is a defect in this document,
never a second legitimate spelling.

**Explicitly out of scope (never defined here):** a planner, a judging engine, or a viewer. This
document names what a conforming Result looks like on the wire — the same "wire shape, not the
decision layer that produces it" boundary `evidence-plan-ir-v0.md`'s Dependency boundary draws for
plans. It also never names `Authority`, `Relay`, `score`/`scoring`, or `reputation` (§9).

## 1. Result semantics — what a claim is

**Status: RULED (Steven, 2026-09-22) — gate item (a). Quoted verbatim, normative:**

> A claim is one requirement of one contract version, evaluated once. Every claim carries two
> answers that are never merged: whether enough of the required evidence existed to judge it
> (`SATISFIED / GAP / INSUFFICIENT / UNKNOWN`), and, only when sufficiency is `SATISFIED`, the
> resulting judgment (`met / not met / not evaluable`). `not evaluable` is a judgment outcome
> defined by the contract; it is never used to represent missing or insufficient evidence.
>
> A result never states a number that cannot be traced to claims, and never states a claim that
> cannot be traced to evidence by digest.

The remainder of this section encodes the ruling above into this document's vocabulary and cites
where the companion schema enforces it.

A **claim** is the atomic unit of an Evidence Result: one requirement, of one Evidence Contract
version, judged exactly once, together with the evidence and proofs that judgment rests on. A
claim is not a capsule, not a bundle, and not itself evidence — it is the record of a single
adjudication: "requirement `req-X` of contract `ec:...@N`, evaluated against evidence
`{digest, ...}`, resolved to sufficiency `S` and verdict `V`."

A claim MUST cite exactly one requirement (`requirement_ref`) of exactly one contract version
(`contract_ref`, the compact `<contract_id>@<version>` reference — the identical convention
`evidence-plan-ir-v0.md` §2 uses for its own `contract_ref`; a claim never carries a bare,
unversioned contract id as two separate fields). Re-judging the same requirement — a re-run, an
appeal, a later evaluation period — produces a **new** claim, never an edited one: a claim is
immutable once emitted, the same non-negotiable this repository applies to a capsule or a
checkpoint.

Two independent, closed vocabularies compose on every claim, and neither may be inferred from the
other:

- **Sufficiency** (`sufficiency` — `SATISFIED | GAP | INSUFFICIENT | UNKNOWN`) — the Evidence
  Contract's §5.2 contract result: was enough of the right evidence found, committed, and
  disclosed to make a determination on this requirement at all. Owned by
  `evidence-contract-internal-spec-v3.md` §5.2; mirrored here, never redefined.
- **Verdict** (`verdict` — `met | not_met | not_evaluable`) — the Evidence Contract's §8 judged
  outcome, once sufficiency allows a determination at all. Owned by the same document, §8.

**The rule that binds them (v3 §8, restated normatively here because a Result is exactly the
artifact this rule constrains):** `verdict` MUST be `not_evaluable` whenever `sufficiency` is
anything other than `SATISFIED`; `verdict` MUST be `met` or `not_met` only when `sufficiency` is
`SATISFIED`. A claim asserting `met` or `not_met` against `GAP`, `INSUFFICIENT`, or `UNKNOWN`
sufficiency is malformed. The companion schema enforces this structurally (§4, `Claim`'s
`if`/`then`).

Every claim also carries:

- `tier` (`recomputed | judged`) — how the claim's evidence was resolved and its verdict
  projected, mirroring `evidence-plan-ir-v0.md` §4.2's vocabulary and its ruled mapping
  (`recomputed` ⇔ *Verifiable*, `judged` ⇔ *Attested* on the assurance ladder, 2026-09-22 ruling).
- `grade` (`self-attested | witnessed | countersigned`) — the assurance grade the claim's own
  bundle carries on the Witness/Countersign ladder, owned elsewhere,
  mirrored here, never redefined.
- `evidence[]` — the evidence this claim rests on, by digest only (§5). A claim never inlines
  evidence bytes; a reader who wants the bytes resolves the digest against the evidence's own
  disclosure record.
- `proofs[]` — the inclusion-proof/receipt refs that make the claim's evidence and grade
  checkable, by digest only, never inline bytes (§5).

A claim never re-derives, and never self-declares, its own sufficiency — **"the evidence record
never self-declares that it satisfies a requirement; the Evidence Contract defines sufficiency"**
(fabric v3 §9.1). A claim's `sufficiency`/`verdict` pair is the Evidence Contract's projection
over that claim's cited evidence, never a property the evidence asserts about itself.

**Traceability (the ruling's second paragraph, encoded).** "A claim that cannot be traced to
evidence by digest" is structurally impossible here: `evidence[]` is REQUIRED on every claim
(§4), by digest only. "A number that cannot be traced to claims" is §3's concern — every count in
`aggregate.coverage` and every entry in `aggregate.buckets` resolves to real claim objects in this
same Result, never a number computed and reported without the claims that back it.

## 2. Disclosure policy — `disclosure` · `analysis` · `story`

**Status: RULED (Steven, 2026-09-22) — gate item (b). Quoted verbatim, normative:**

> Disclosure: a result carries evidence digests and the disclosure record's own status, never
> evidence payload bytes. Withheld, not committed, unavailable, or otherwise missing evidence
> remains explicit in the result; story and analysis may explain the gap but may not repair it.

The remainder of this section encodes the ruling above into this document's vocabulary and cites
where the companion schema enforces it.

A Result is sponsor-facing: it is read by a party who is not the counterparty holding the
underlying evidence, and it MUST NOT become a side channel for evidence the disclosure layer has
decided not to share. Every claim therefore carries exactly one **presentation carrier** —
`disclosure`, `analysis`, or `story` — naming what the claim shows a reader, and the carrier's own
`status` field (the eight-value per-requirement bundle assertion status owned by v3 §5.1,
mirrored here by reference) states why that carrier, and not a stronger one, was used.

**The gate (encodes "withheld... evidence remains explicit... story and analysis may explain the
gap but may not repair it").** A claim's presentation carrier is `disclosure` only if its `status`
is anything other than `WITHHELD` or `NOT_COMMITTED`. When `status` IS `WITHHELD` or
`NOT_COMMITTED`, the carrier MUST be `analysis` or `story` — `disclosure` is not a legal choice,
structurally (§6, `DisclosureCarrier`'s restricted `status` enum): the ruling's "may explain the
gap but may not repair it" is exactly the difference between `analysis`/`story` (characterization
or narrative) and `disclosure` (the evidence itself, by digest) — `analysis`/`story` can never
substitute for `disclosure` once the gap is closed. `WITHHELD` and `NOT_COMMITTED` are singled out
(rather than every non-`SATISFIED` status) because both mean the underlying evidence *exists* — a
counterparty holds it, or declined to commit it — as distinct from e.g. `NOT_FOUND`, where there
is nothing to withhold in the first place; §5.2 collapses both into `GAP` sufficiency, but the
disclosure policy needs exactly the distinction that projection discards. Every carrier's required
`status` field is what makes "remains explicit in the result" checkable — a claim can never omit
naming why the stronger carrier was not used.

The three carriers, in descending order of what they show:

- **`disclosure`** — the claim's evidence, by digest, plus the status that licensed showing it.
  This is the strongest carrier and it still never inlines payload bytes: `disclosure.evidence[]`
  is a list of `{digest_alg, digest}` refs, identical in shape to the claim's own `evidence[]`
  field. A reader who wants the bytes resolves the digest against the evidence's disclosure
  record directly — the Result is never that record.
- **`analysis`** — a derived characterization of evidence that is withheld or not committed: what
  the adjudicator can say about the evidence without repeating it. `analysis.summary` is free
  text, but it MUST NOT quote or closely paraphrase the underlying payload — it characterizes
  ("the counterparty's response addressed three of the four cited items"), it does not disclose.
- **`story`** — a narrative-only account, the weakest carrier, for claims where not even a
  derived characterization exists to share (e.g. a `recorded_absence` — nothing was ever produced
  to analyze). `story.narrative` describes what happened at the process level (a request was
  made, on this date, and no artifact resulted), never a claim about the withheld content itself.

**A Result never re-discloses payload bytes.** This holds for all three carriers, not only
`analysis`/`story` — `disclosure` carries digests, never the bytes those digests address. The
distinction between the three carriers is never about how much of the payload is shown (none of
them show payload); it is about how much can be said about evidence a reader cannot see.

## 3. What the sponsor sees first

**Status: RULED (Steven, 2026-09-22) — gate item (c). Quoted verbatim, normative:**

> What the sponsor sees first is coverage: requirements evaluated, excluded as not applicable, and
> unresolved. Then the claim buckets. Never put a single score, grade, or percentage above the
> fold. Assurance stays attached to each claim: evaluation tier (`recomputed / judged`) and
> evidence grade (`self-attested / witnessed / countersigned`), because the sponsor's question is
> always: who says so, and could I independently check it?

The remainder of this section encodes the ruling above into this document's vocabulary and cites
where the companion schema enforces it.

A Result's top-level `aggregate` is what a sponsor-facing reader sees before any individual claim:
a **coverage statement**, then **three buckets** — never a single number, score, grade, or
percentage above the fold.

**Coverage (mandatory) — "requirements evaluated, excluded as not applicable, and unresolved."**
`aggregate.coverage` states the evaluated population precisely: `evaluated_population` (requirements
evaluated), `excluded_not_applicable` (excluded as `NOT_APPLICABLE` — §5.2, outside the evaluated
population by construction, not a gap), and `unknown_count` (the "unresolved" count — evaluated
requirements that resolved `UNKNOWN`). An aggregate without a coverage statement is not a summary,
it is a claim with the denominator hidden, and the companion schema refuses to validate one (§7).

**Three buckets, never a single number.** Beneath coverage, `aggregate.buckets` groups every
evaluated claim by its `verdict` — `met`, `not_met`, `not_evaluable` — never rolled up into one
pass/fail figure or a percentage. A single number hides which requirements were actually judged
versus which were skipped for lack of evidence; the three buckets keep that distinction visible at
the point a sponsor first looks at the Result. `not_evaluable` is not a failure and not a success
— it is its own bucket, exactly as large as `sufficiency != SATISFIED` makes it (§1), and a Result
that folds it into either of the other two has silently converted "we could not tell" into an
answer.

**Assurance stays attached to each claim.** The ruling's closing sentence — "who says so, and could
I independently check it?" — is why `tier` and `grade` are per-claim fields (§1, §4), never
aggregate-level. Nothing above the fold summarizes assurance; a sponsor who wants to know how a
particular `met`/`not_met`/`not_evaluable` bucket entry was produced reads that claim's own `tier`
and `grade`, not a rollup.

## 4. Claim

```
claim:
  id: string                          # unique within the Result
  contract_ref: string                # <contract_id>@<version> — §1
  requirement_ref: string             # a requirement id within that contract
  tier: recomputed | judged           # §1, mirrors evidence-plan-ir-v0.md §4.2
  grade: self-attested | witnessed | countersigned   # §1, owned elsewhere
  sufficiency: SATISFIED | GAP | INSUFFICIENT | UNKNOWN   # §1, owned by contract v3 §5.2
  verdict: met | not_met | not_evaluable                  # §1, owned by contract v3 §8
  evidence: [digest-ref, ...]         # §5 — by digest only
  proofs: [proof-ref, ...]            # §5 — by digest only
  presentation: disclosure-carrier | analysis-carrier | story-carrier   # §2, §6
```

**Normative, not schema-enforced in v0:** claim `id` uniqueness within a Result, and every
`aggregate.buckets` entry actually naming a claim `id` that exists with the matching `verdict`,
are cross-element constraints over the `claims` array plain JSON Schema cannot express — the same
class of gap `evidence-plan-ir-v0.md` §3.1 documents for node `id` uniqueness and DAG order. A
conforming verifier MUST check both in addition to schema validation.

## 5. Evidence and proofs

`evidence[]` and `proofs[]` are both by-digest-only arrays; neither ever inlines bytes.

```
digest-ref:
  digest_alg: "SHA-256"
  digest: <64-hex>

proof-ref:
  kind: inclusion_proof | receipt
  digest_alg: "SHA-256"
  digest: <64-hex>
```

`proof-ref.kind` is closed to the two proof shapes v0 needs: an inclusion proof (the claim's
evidence is a member of some committed structure) and a receipt (a witness's confirmation over
that structure). Both are named, never defined, here — their own shapes are owned by the
checkpoint/witness definitions this document depends on but does not redefine.

## 6. Presentation carriers

The schema encoding of §2's disclosure policy. Every claim's `presentation` is exactly one of:

```
disclosure-carrier:
  kind: "disclosure"
  status: SATISFIED | INSUFFICIENT | NOT_FOUND | CONTRADICTED | NOT_APPLICABLE | UNKNOWN
        # the eight-value EvidenceStatus (§1) MINUS WITHHELD and NOT_COMMITTED — §2's gate
  evidence: [digest-ref, ...]

analysis-carrier:
  kind: "analysis"
  status: <any of the eight EvidenceStatus values>
  summary: string                     # a derived characterization — never quotes the payload

story-carrier:
  kind: "story"
  status: <any of the eight EvidenceStatus values>
  narrative: string                   # process-level account — never a claim about withheld content
```

`disclosure-carrier.status` is the ONLY place this document restricts the eight-value
`EvidenceStatus` to a subset — `analysis-carrier` and `story-carrier` accept any status, since a
producer MAY choose either for evidence it is structurally allowed to disclose but chooses to
characterize or narrate instead; §2's gate is one-directional and this is deliberate.

## 7. Aggregate

```
aggregate:
  coverage:
    evaluated_population: integer     # requirements actually evaluated
    excluded_not_applicable: integer  # requirements excluded, NOT_APPLICABLE — §1's Sufficiency
    unknown_count: integer            # evaluated requirements resolved UNKNOWN
  buckets:
    met: [claim-id, ...]
    not_met: [claim-id, ...]
    not_evaluable: [claim-id, ...]
```

`buckets` always carries all three keys, each an array (possibly empty) — never an absent key,
and never collapsed into a single figure (§3).

## 8. View

Presentation hints only — **never data**. The `presentation/v1` header fields: producer
name, logo data URL, title. `view` MUST NOT carry any claim, verdict, sufficiency, digest,
or other data field — a renderer that reads
`view` for anything beyond how to label its own header chrome has misused it.

```
view:
  spec_version: "presentation/v1"
  producer_name: string               # optional
  logo_data_url: string               # optional, a data: URL
  title: string                       # optional
```

## 9. Field mapping — #102 evidence-graph model → Result v0

Batch 4's EM brief named PR #102's evidence-graph emitter model (`ts/src/evidence-graph.ts`,
`agent-action-capsule` PR #102) and `capsule-engine/report/model.py`'s dry-run report rows as the
closest existing artefacts — "close in spirit, not field-compatible." This table is the
reconciliation: every #102 field, renamed or explicitly noted as having no counterpart on either
side. `capsule-engine/report/model.py`'s `DryRunReport`/`ReportRow` shape is a **dry-run guard
report**, not a Result — its `ReportRow.capsule`/`cited_capsule` fields inline full capsule
objects, which §4–§6 above forbid outright (evidence and proofs are by digest only); it has no
counterpart field at all in Result v0 and is not tabulated below.

| #102 `evidence-graph.ts` field | Result v0 field | Note |
|---|---|---|
| `ReportNode.capsuleId` | *(no counterpart)* | Result v0 claims are not keyed to a capsule id; a claim's identity is `id` within the Result, not a capsule reference. |
| `CaseNode.caseId` / `taskId` / `trial` | *(no counterpart)* | Case/trial structure is planner/executor bookkeeping (evidence-plan-ir-v0.md's explicit out-of-scope list); a Result reports per-requirement claims, not per-case trials. |
| `AxisJudgment.axisId` / `outcomeId` | `claim.requirement_ref` | Renamed and flattened: #102's per-axis judgment within a case becomes one claim per requirement; there is no case/axis nesting in v0. |
| `AxisJudgment.status` (`pass \| fail \| not_applicable \| unjudgeable`) | `claim.verdict` (`met \| not_met \| not_evaluable`) + `claim.sufficiency` | **Rename pass, not a 1:1 map.** `pass`→`met`, `fail`→`not_met`, `unjudgeable`→`not_evaluable` (mirrors verdict); `not_applicable` has no `verdict` counterpart at all — it is excluded from the evaluated population entirely and only appears as `aggregate.coverage.excluded_not_applicable`, never as a claim. #102's single four-value `status` conflates the sufficiency and verdict axes §1 requires kept separate; a Result claim always carries both. |
| `AxisJudgment.rationale` | `presentation.summary` (`analysis` carrier) or `presentation.narrative` (`story` carrier) | Renamed and gated: #102's rationale is unconditional free text; Result v0 only allows the equivalent carriers when the disclosure policy (§2) permits, and `disclosure`-carried claims have neither field. |
| `AxisJudgment.evidenceIds` | `claim.evidence[]` | Renamed; #102 carries bare ids (implicitly capsule ids), Result v0 carries `{digest_alg, digest}` refs — by digest only, never a bare id resolved against an unspecified namespace. |
| `RatingNode.verdict` (`pass \| fail \| unsure`) | `claim.verdict` | A THIRD independent three-value spelling of the same pass/fail/unclear concept #102 already spells two ways (`AxisJudgment.status` and `RatingNode.verdict` disagree with each other). Result v0 has exactly one verdict vocabulary; both #102 fields rename onto it. |
| `ReportNode.outcomes[].aggregate` (`pass \| fail \| null`) | *(no direct counterpart)* | Closest analogue is a claim's own `verdict`, but #102's `Outcome.aggregate` is a rollup across cases, and §3 forbids rolling verdicts up into anything narrower than the three named buckets. `aggregate.buckets` is the v0 replacement shape, not a per-outcome pass/fail/null field. |
| `ReportNode.withheldActs` | `presentation` = `analysis` or `story` carrier, `status` gated by §2 | #102 marks an act "withheld" structurally (missing `agentInput`/`agentOutput`) with no further typed distinction. Result v0 requires naming *why* via the eight-value `EvidenceStatus`, and gates which carrier may be used (§2) — a strictly more specific replacement. |
| `SummaryNode.crossCaseAggregation` / `perAxis` / `counts` / `cohort` | *(no counterpart)* | Free-form cross-case aggregation and cohort fields; out of scope for v0's per-requirement claim model. A future revision MAY add a comparable rollup once a concrete need exists (the same deferral `evidence-plan-ir-v0.md` §3.1 uses for typed-ref alignment). |
| `CalibrationNode.*` | *(no counterpart)* | Calibration (confusion matrix, agreement, corrected rate) is a derived-metric concept outside the per-requirement claim model; not part of v0. |
| *(no #102 counterpart)* | `claim.tier` | New in Result v0 — #102 has no recomputed/judged distinction; every judgment there is implicitly the semantic-adjudication kind. |
| *(no #102 counterpart)* | `claim.grade` | New in Result v0 — #102 has no assurance-ladder concept at all. |
| *(no #102 counterpart)* | `claim.proofs[]` | New in Result v0 — #102 has no inclusion-proof/receipt concept; its evidence is cited by bare id with no checkability claim. |
| *(no #102 counterpart)* | `view` | New in Result v0 — #102 has no presentation-hints concept; `presentation/v1` header fields are defined separately for the viewer, not by the evidence-graph model. |

## 10. Vocabulary discipline

This document and its companion schema/examples MUST NOT use, in any form: `Authority`, `Relay`,
`score`/`scoring` (as a feature or product term), or `reputation`. Every synthetic fixture's
anchor/prospect placeholder is `OO`, never a company name and never `NN`.

## 11. Examples

`vectors/evidence-result/` — one synthetic OO claims Result (`pos-oo-claims-result.json`, all
three buckets populated, exercising both the sufficiency/verdict rule (§1) and the disclosure gate
(§2) in one fixture) and five negative fixtures, each mutated from the positive by exactly one
field, each failing at exactly one documented rule. See that directory's `README.md` for the exact
cases and `schemas/check_evidence_result_examples.py` for the validation run, including the
mutant/load-bearing proof for each negative.
