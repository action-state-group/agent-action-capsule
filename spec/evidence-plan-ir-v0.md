# Evidence Plan IR — v0

**Status.** Design specification, pre-Internet-Draft. This document is the OPEN half of the
Evidence Plan IR work: it defines the wire-visible intermediate representation (IR) that a plan
is serialized as, the classification tags that gate where a node may execute, and the minimal v0
operator catalogue. It does not define, and never will define in this repository, a planner: the
logic that decides which operators to invoke, in what order, with what evidence-gathering
strategy, or under what prompts. That decision layer is an implementation concern outside this
document's scope — this document specifies only what a conforming plan and its replay results
look like on the wire, so that any implementation of the decision layer produces and consumes the
same shape.

**Companion schema.** `schemas/evidence-plan-ir-v0.json` — a JSON Schema (2020-12) encoding of
every object model defined below. The schema is descriptive of the semantics fixed here; where
they conflict, this document governs and the schema is corrected to match.

## Dependency boundary

**Owns:** the Evidence Plan document shape (header + ordered node list), the node object model,
input references, the `classification` locality-tag vocabulary, the v0 operator catalogue, the
per-node result envelope shape, the family-agnostic attestation record shape, and the
replay-determinism rule.

**Depends on:** an Evidence Contract (referenced, not redefined, by `contract_ref`/
`requirement_ref` — see below) and its two closed vocabularies: the seven-value `profile`
discriminator and the eight-value per-requirement bundle assertion status. This document mirrors
the status vocabulary by reference and does not maintain an independent copy; a drift between the
two is a defect.

**Explicitly out of scope (never defined here):**

- A planner or planning algorithm — how an implementation decides which nodes to add to a plan,
  what evidence to request next, or how to re-plan after inspecting a result.
- Prompts, judgment rubrics, or model-selection policy for any `semantic`-family operator.
- Any executor implementation — how an operator call actually runs.
- Company-, product-, or partner-identifying content of any kind.

## 1. Core rule

A plan is an ordered DAG of operator nodes over exactly one Evidence Contract. The order of the
`nodes` array is normative: a node's inputs may reference, by id, only a node that appears earlier
in the array. This makes the array order a topological order and acyclicity a structural property
of a conforming plan, not a property a verifier has to separately discover.

The IR names what ran, over what, and under what classification and assurance tier. It does not
say why those particular nodes were chosen — that answer lives in the (private) implementation
that built the plan, never in the plan itself.

## 2. Plan header

Every plan carries exactly these five header fields:

| Field | Type | Meaning |
|---|---|---|
| `contract_version` | string | The single immutable Evidence Contract this plan is evaluated against, as a compact versioned reference `<contract_id>@<version>` (e.g. `ec:oo-outcome-eval:2026-09-22@1`). A plan is over exactly one contract in v0; there is no multi-contract plan. |
| `ir_version` | string | MUST be the literal string `evidence-plan-ir-v0` for a plan conforming to this document. |
| `planner_id` | string | Identifies the planner that produced this plan, namespaced `local:<name>` or `remote:<name>` (§4.1). The namespace is normative and gates `LOCAL_ONLY` nodes (§4). |
| `created_at` | string | RFC 3339 timestamp. |
| `replay_seed` | string | An opaque seed value carried with the plan so that any planning step whose own internals are not fully deterministic (out of scope here) can still be asked to reproduce the same plan shape from the same seed. The IR does not interpret this value; it only carries it for the private planner's own use. |

`contract_version` is repeated, unabbreviated, on every node as `contract_ref` (§3) so that a
single node is independently checkable without the header. **Normative, not schema-enforced in
v0:** every node's `contract_ref` MUST equal the plan header's `contract_version`. This is a
cross-field constraint outside plain JSON Schema's expressiveness; a conforming verifier MUST
check it in addition to schema validation.

## 3. Node

```
node:
  id: string                          # unique within the plan
  family: traditional | semantic | evidence | assurance | decision
  operator: <catalogue entry — §5>
  inputs: [input-ref, ...]            # §3.1
  classification: LOCAL_ONLY | ABSTRACTABLE | CLOUD_SAFE | PUBLIC   # §4
  tier: recomputed | judged           # §4.2
  contract_ref: string                # MUST equal header.contract_version — §2
  requirement_ref: string             # a requirement id within that contract
```

`family` and `tier` are constrained by which `operator` is named (§5's catalogue table is
closed for v0): a node whose `operator` belongs to the `semantic` family MUST carry `tier:
judged`; every other v0 family MUST carry `tier: recomputed`. This constraint IS schema-enforced
(§5, and see the companion schema's node `if`/`then` blocks) because, unlike the header/node
cross-check above, both fields live on the same node object.

### 3.1 Input references

A node's `inputs` array is a list of references, each one of exactly two shapes:

```
input-ref:
  by-digest: { by: "digest", digest_alg: "SHA-256", digest: <64-hex> }
  by-node:   { by: "node", node_id: <id of an earlier node in this plan> }
```

A `by-digest` reference cites evidence content or a prior artifact directly by its content
address — the digest of `UTF8(JCS(value))` over the cited value, the same digest convention used
throughout this repository (RFC 8785 canonicalization, lowercase-hex SHA-256; see
`draft-mih-zhang-agent-action-capsule-evidence-bundle-00.md` §"Digest"). A `by-node` reference
cites the (not-yet-known-at-authoring-time) result of a prior node in the same plan by that node's
`id`; a verifier resolves it against that node's result envelope (§6) once the plan has been
executed. `by-node` MUST NOT reference a node at or after its own position in the `nodes` array
(§1's DAG-order rule). **Normative, not schema-enforced in v0:** node `id` uniqueness within a
plan and the DAG-order rule are both cross-element constraints over the `nodes` array that plain
JSON Schema cannot express (there is no standard keyword for "this array's items must have
distinct `id`s" or "this field may only cite an earlier array index"); a conforming verifier MUST
check both in addition to schema validation, the same way it must check the header/node
`contract_ref` cross-check above.

A future revision of this document MAY align `by-digest` to the full CPB typed digest reference
model (`type`/`purpose`/`digest_alg`/`digest`, `draft-mih-sokolov-scitt-payload-binding`) once a
concrete need for multiple accepted artifact types per reference exists. v0 deliberately carries
only the two fields it needs today.

## 4. Classification

`classification` is a data-locality axis — where a node's inputs, execution, and outputs are
permitted to travel — and is a distinct axis from evidence provenance (the epistemic-type
vocabulary owned by the Evidence Contract's evidence side) and from the assurance ladder (§4.2).
Conflating the three is a category error a reviewer of this document should flag.

| Value | Meaning |
|---|---|
| `LOCAL_ONLY` | This node's inputs, execution, and outputs MUST NOT leave the boundary of a local (on-premises / keeper-controlled) planner. It MUST NOT be serialized into, or executed by, a plan destined for a non-local planner. |
| `ABSTRACTABLE` | This node's raw inputs/outputs are local-sensitive, but an abstraction of them (redacted, summarized, or otherwise transformed so the sensitive content does not travel) MAY be sent to a non-local planner. This document does not define the abstraction transform itself — that is an executor concern. |
| `CLOUD_SAFE` | This node's inputs, execution, and outputs may run in a hosted/non-local planner without redaction; nothing about them is locality-sensitive. |
| `PUBLIC` | This node's inputs, execution, and outputs may be published verbatim (e.g. into a public report or anchored disclosure). Strictly stronger than `CLOUD_SAFE`: every `PUBLIC` node is also safe to run non-locally, but not every `CLOUD_SAFE` node is safe to publish. |

### 4.1 The `planner_id` locality convention and the `LOCAL_ONLY` rule

A plan header's `planner_id` (§2) MUST be namespaced with one of exactly two prefixes, each
followed by a colon and an opaque planner name: `local:<name>` or `remote:<name>`. This is the
only mechanism this document defines for stating where a plan is destined to execute.

**Normative rule (schema-enforced — §4's `if`/`then` in the companion schema):** if a plan's
`header.planner_id` does not begin with `local:`, then no node in that plan's `nodes` array may
carry `classification: LOCAL_ONLY`. A plan whose `planner_id` begins with `remote:` and that
contains a `LOCAL_ONLY` node is **not conforming** and MUST fail schema validation. §7's worked
examples include both a conforming case (a `LOCAL_ONLY` node under a `local:` planner) and the
non-conforming case this rule exists to reject.

This rule says nothing about `ABSTRACTABLE`, `CLOUD_SAFE`, or `PUBLIC` nodes under a `remote:`
planner — all three are conforming there by construction; only `LOCAL_ONLY` is restricted.

### 4.2 Tier and the assurance-ladder mapping

`tier` states how a node's result was produced, not where. Exactly two values in v0:

| Value | Meaning |
|---|---|
| `recomputed` | The result is mechanically reproducible: a deterministic function of the node's cited inputs, with no model inference or human judgment in the loop. |
| `judged` | The result was produced by a semantic adjudicator (model or human) applying judgment to the cited inputs, pinned by the attestation record's `adjudicator`/`policy_digest` fields (§6). |

**Ruled mapping (2026-09-22, Steven) — stated here as a mapping only, never redefined:** on the
assurance ladder owned by the Witness/Countersign definitions (self-attested → witnessed/
continuity-witnessed → self-countersigned → countersigned), `recomputed` corresponds to
*Verifiable* and `judged` corresponds to *Attested*. This document does not own, and does not
restate the semantics of, that ladder — it states only which of the ladder's two coarse buckets
each `tier` value falls into.

## 5. Operator catalogue v0

The minimal, closed set of operators the OO synthetic fixtures (§9) exercise — nothing more. A
node's `operator` MUST be one of these six values; `family` and `tier` are fixed by the choice of
`operator` (§3).

| `operator` | `family` | `tier` | What it names |
|---|---|---|---|
| `traditional.fold_replay` | `traditional` | `recomputed` | Deterministic, ledger-order replay over already-committed ledger data. Names the existing fold-family executor; this document does not define fold semantics. |
| `semantic.judge_adjudicate` | `semantic` | `judged` | Semantic adjudication of evidence against a digest-pinned policy, by a model or BYOM scorer. Names the existing judge-harness executor; this document does not define or pin any prompt. |
| `evidence.request_answer` | `evidence` | `recomputed` | A request to a counterparty answered with exactly one of an artifact, a signed policy refusal, or a signed recorded absence — never a bare unsigned absence. Names the existing three-state responder. |
| `assurance.verify` | `assurance` | `recomputed` | Verification of an evidence artifact's signature, binding, inclusion proof, or witness stamp. Names the existing verifier. |
| `assurance.bundle` | `assurance` | `recomputed` | Assembly of a proof bundle (receipt, inclusion proof, covering checkpoint and witness stamp, prior checkpoint, consistency proof) over an already-verified artifact. Names the existing bundle assembler. |
| `decision.resolve_verdict` | `decision` | `recomputed` | Mechanical projection of the `evidence`/`assurance` results gathered for one requirement into the closed three-value verdict vocabulary `met \| not_met \| not_evaluable`. Deterministic given its inputs — no judgment of its own; the judgment, if any, already happened in an upstream `semantic` node. |

No operator in this catalogue names, cites, or depends on a specific model, prompt, or planning
heuristic. `semantic.judge_adjudicate` names the *existence* of a semantic-adjudication step; the
policy it runs under is cited only by digest (`policy_digest`, §6), never inlined.

## 6. Attestation record (family-agnostic)

Every result envelope's `attestation_ref` (§6.1 below) resolves to an attestation record — one
shape, used identically whether the operator that produced it was `recomputed` or `judged`. This
is deliberate: the "who ran this, over what inputs, under what policy" question is askable of
every operator family, not only the judged ones.

```
attestation-record:
  adjudicator:
    id: string                  # REQUIRED — identifies the executor: a deterministic engine
                                 # build id for a `recomputed` operator, or a model/reviewer id
                                 # for a `judged` operator
    model: string                # REQUIRED when the owning node's tier is `judged`; MUST be
                                 # absent otherwise
    model_version: string        # REQUIRED exactly when `model` is present
  operator: <catalogue entry — §5>
  inputs: [ { digest_alg: "SHA-256", digest: <64-hex> }, ... ]   # by digest ONLY — an
                                 # attestation record must be independently checkable without
                                 # the rest of the plan
  policy_digest: { digest_alg: "SHA-256", digest: <64-hex> }
                                 # the digest of the policy/prompt/manifest the operator ran
                                 # under; the policy content itself is never inlined here
  contract_version: string      # MUST equal the owning plan's header.contract_version
```

`adjudicator.model`/`model_version` are the "model+version" pair this document's brief names
explicitly; they are conditionally required on `tier: judged` and conditionally forbidden
otherwise, so a reader can tell from the record alone whether judgment was involved without also
needing the owning node.

## 6.1 Result envelope

A plan's *result* — what came back from executing it — is a second document, distinct from the
plan itself, keyed by node id:

```
plan-result:
  plan_ref: { digest_alg: "SHA-256", digest: <64-hex> }   # digest of the plan document itself
                                                            # (UTF8(JCS(plan)))
  results:
    <node-id>:
      status: SATISFIED | INSUFFICIENT | NOT_FOUND | NOT_COMMITTED | WITHHELD | CONTRADICTED
            | NOT_APPLICABLE | UNKNOWN
      outputs: [ { digest_alg: "SHA-256", digest: <64-hex> }, ... ]   # by digest only
      attestation_ref: { digest_alg: "SHA-256", digest: <64-hex> }    # digest of an
                                                            # attestation-record (§6)
```

`status` is the eight-value per-requirement bundle assertion status owned by the Evidence
Contract (mirrored here by reference, per the Dependency boundary above) — never redefined or
extended in this document. `attestation_ref` is REQUIRED on every result envelope, including
`recomputed`-tier ones: the executor loop stamps an attestation record on every operator call, not
only the judged ones (§6).

This document does not define how a `status` value is derived from `outputs`; that derivation is
the (private) executor's concern. It defines only the closed vocabulary the field is drawn from
and the fact that a conforming result envelope always names one.

## 7. Replay determinism

**Normative statement.** For a given plan `P` (identified by `plan_ref`, the digest of `P`'s own
canonical bytes) and a given set of evidence digests cited by `P`'s nodes (directly, by
`by-digest` references, or transitively through prior nodes' outputs), every conforming execution
of `P` MUST produce the same `status` for every node in the resulting `plan-result.results`.

This guarantee is unconditional for every `recomputed`-tier node: by definition (§4.2) a
`recomputed` result is a deterministic function of its cited inputs, so replay under the same
inputs is replay under the same function.

For a `judged`-tier node, the guarantee is **conditional on replaying under the identically pinned
adjudicator**: the same `adjudicator.model`/`model_version` and the same `policy_digest` (§6). A
replay that substitutes a different model version or a different policy is executing a *different*
attestation, not re-running the same one, and this document makes no determinism claim across that
substitution — that is precisely the drift a conforming implementation's own drift-check step
exists to catch, and is out of scope here. The claim this document makes is narrower and does hold
unconditionally: **the closed `status` vocabulary, not the adjudicator's free-text reasoning, is
what must reproduce** — two runs of the same pinned adjudicator over the same inputs are not
required to produce byte-identical prose, only the same eight-value status.

### 7.1 Worked example

Take a two-node plan fragment (full plans in `schemas/examples/evidence-plan-ir-v0/`):

1. `node-1` (`evidence.request_answer`, `recomputed`) cites one `by-digest` input — the digest of
   a counterparty's evidence artifact — and produces one output digest plus an attestation record
   whose `inputs` cites that same input digest.
2. `node-2` (`decision.resolve_verdict`, `recomputed`) cites `node-1`'s output by `by-node`
   reference and produces a `status`.

Run 1 executes `P` against the evidence corpus at digest `D`. `node-1` resolves the counterparty's
answer, producing `status: SATISFIED` and `outputs: [{digest: E}]`. `node-2` consumes `E`,
mechanically projects it to `status: SATISFIED`. The `plan-result` for this run has `plan_ref:
{digest: R(P)}` and `results: {node-1: {status: SATISFIED, ...}, node-2: {status: SATISFIED,
...}}`.

Run 2 executes the same plan `P` (same `plan_ref`, i.e. `R(P)` is unchanged — nothing about the
plan's own bytes differs) against the same evidence corpus (the same digest `D` resolves the same
counterparty artifact — nothing about the cited evidence differs). Because `node-1` and `node-2`
are both `recomputed`, both are deterministic functions of inputs that have not changed between
the two runs; Run 2's `results` MUST be byte-identical to Run 1's for `status` on both nodes. A
verifier that observes a divergent `status` between two runs sharing the same `plan_ref` and the
same cited evidence digests has detected a nonconformance — either the executor is not actually
deterministic, or one run's evidence resolution silently used different bytes behind the same
digest (which would itself be a digest collision or a resolution bug, either way a defect outside
this document's own guarantee).

The outcome-profile fixture under `schemas/examples/evidence-plan-ir-v0/` extends this same
pattern by one node (`evidence.request_answer` → `assurance.verify` → `decision.resolve_verdict`,
rather than the two-node `evidence` → `decision` fragment above) and uses real digests computed
via this repository's own canonicalization (`agent_action_capsule.canonical.json_digest`), not
placeholder hex — see that directory's `README.md` for the exact values and how they were
produced.

## 8. Vocabulary discipline

This document and its companion schema/examples MUST NOT use, in any form: `Authority`, `Relay`,
`score`/`scoring` (as a feature or product term — "semantic adjudication" or "judged assessment"
is used instead throughout), or `reputation`. Every synthetic fixture's anchor/prospect
placeholder is `OO`, never a company name and never `NN`.

## 9. Examples

`schemas/examples/evidence-plan-ir-v0/` — three synthetic OO plans, one per profile the Evidence
Contract defines (`outcome`, `obligation`, `process`), each schema-valid; one deliberately
nonconforming plan (a `LOCAL_ONLY` node under a `remote:` planner, §4.1) that MUST fail schema
validation; a matching `plan-result` document for each of the three plans; and one
`attestation-record` document (the one `judged`-tier node across the three plans). See that
directory's `README.md` for how each was generated and validated, and
`schemas/check_evidence_plan_ir_examples.py` for the validation run itself.
