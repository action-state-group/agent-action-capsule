# Outcome-claim-limit vectors

Two negative cases a reader must refuse, each with a positive twin it must
accept, and a condition-removed mutant per case that must flip the result.

- A controller's report that an effect succeeded is not proof that the effect
  occurred.
- An outcome signed by the producer's own key is not independent proof.

A negative with no passing twin shows only that a reader says no, not that it
discriminates. A case whose mutant does not flip is not exercised.

The cases carry two proposed negative vectors, written with proposed field
names, in this repository's existing spelling. The mapping is recorded below
rather than applied silently.

## Name mapping

| Proposed | This repository | Defined in |
|---|---|---|
| `controller_reported_outcome` (string or null) | `effect.status` with `response_digest`, from which the verifier derives `assurance.effect_mode` | `draft-mih-scitt-agent-action-capsule-05` §5.2, §5.3 |
| `physical_completion: "none"` | `effect.effect_attestation` `runtime_claimed` or `host_served_observed`, or any unregistered value (graded no stronger than `runtime_claimed`) | -05 §5.3; `spec/REGISTRY.md` §5 |
| `physical_completion: "observed"` | `effect.effect_attestation` `gate_executed`: the engine observed the effect boundary directly. The observer is the gate, and the payload names no other party | -05 §5.3; `spec/REGISTRY.md` §5 |
| `physical_completion: "attested_by:<witness-id>"` | none. `spec/REGISTRY.md` §5 lists independent sensor confirmation as a plausible registration that is deliberately not seeded | `spec/REGISTRY.md` §5 |
| `outcome_signer.key_id` | `countersign/v1` `signer.key_id` | `draft-mih-zhang-agent-disclosure-bundle-01`, "The countersign/v1 Entry" |
| `outcome_signer.relationship: "same_party"` | stamp `not independent`: the signer key equals the key the Bundle declares in `producer-key/v1` | Bundle -01, "Self-Countersignature", "The producer-key/v1 Extension" |
| `outcome_signer.relationship: "independent"` | stamp `resolved`: not a declared producer key, and named by the caller's countersigner source | Bundle -01, "Self-Countersignature" |
| `consumer_intent` | no field. The two intents below are reading rules for these vectors | this file |
| reasons `physical_completion_absent`, `outcome_signer_not_independent` | kept as proposed | this file |
| reason `outcome_signer_unresolved` | added here for a valid independent entry the caller's source does not name | this file |

The mapping differs from the proposal in two ways:

- **Independence is computed, never declared.** Here the verifier computes
  it from the signer key. No member of the entry can make it independent, and
  a `producer-key/v1` declaration can only downgrade an entry. A same-party
  signature under a key the producer does not declare cannot be told apart
  from an independent one using the Bundle alone. The mutant of
  `outcome-signer-not-independent` shows this.
- **The observer is not a named party.** `gate_executed` names the gate's role
  and no identity in the payload. The gate's identity is the key that signs
  the Producer Envelope.

## Reading rules

- `physical_proof`: accept only if the Class-1 result (-05 §6) is `ok`, the
  derived `effect_mode` is `confirmed`, and `effect.effect_attestation` is
  `gate_executed`. Otherwise refuse with `physical_completion_absent`. An
  accepted case names its observer as `gate`.
- `independent_outcome_proof`: accept only if the `countersign/v1` stamp is
  `resolved`. Refuse `not independent` with `outcome_signer_not_independent`
  and `unresolved signer` with `outcome_signer_unresolved`. An accepted case
  names its countersigner from the caller's source, never from the Bundle.

## Cases (`vectors.json`)

| id | kind | input | expected |
|---|---|---|---|
| `physical-completion-absent-presented-as-proof` | negative | `effect.status` `confirmed`, `effect_attestation` `runtime_claimed` | Class-1 `ok`, `effect_mode` `confirmed`; refused, `physical_completion_absent` |
| `physical-completion-observed` | positive | the same Capsule with `effect_attestation` `gate_executed` | Class-1 `ok`, `effect_mode` `confirmed`; accepted, observed by `gate` |
| `outcome-signer-not-independent` | negative | signed by the declared producer key, which the caller's source also lists | stamp `not independent`; refused, `outcome_signer_not_independent` |
| `outcome-signer-independent` | positive | signed by another key, which the caller's source names | stamp `resolved`; accepted, countersigner `countersign.example` |

Mutants (`mutants` in each case):

| case | condition removed | result |
|---|---|---|
| `physical-completion-absent-presented-as-proof` | grade raised to `gate_executed` | accepted |
| `physical-completion-observed` | grade lowered to `runtime_claimed` | refused |
| `physical-completion-observed` | grade set to the unregistered value `observed` | refused: unknown never grades up |
| `outcome-signer-not-independent` | `producer-key/v1` declaration removed (the same key, re-signed) | stamp `resolved`, accepted |
| `outcome-signer-independent` | caller's listing of the signer removed | stamp `unresolved signer`, refused |
| `outcome-signer-independent` | caller also holds the signer key as a producer key | stamp `not independent`, refused |

The two Capsules differ only in `effect_attestation` and `capsule_id`. Their
Class-1 results are identical: derived assurance carries `effect_mode`, not
the grade. -05 §5.3 places the grade in the payload, "available to any
payload-bearing verifier", so a reader that consults only the Class-1 result
cannot tell the twins apart. The vectors pin this, and the tests assert it.

The Bundles are copied unchanged from `../bundle/producer-key/vectors.json`
(`declared-self-countersignature`, `declared-other-signer`, and, for the
mutant, `undeclared-self-countersignature`). Their keys are test-only. Each
case names its source.

## Runners

- Python (`python/tests/test_outcome_claim_limits_vectors.py`): the Class-1
  verifier and the `physical_proof` rule over the Capsule pair and its
  mutants. For the Bundle pair it checks that each Bundle is its source
  vector verbatim and recomputes each digest.
- TypeScript (`ts/test/outcome-claim-limits.test.ts`): the Class-1 verifier
  over the Capsule pair, and `classifyCountersignatures` over the Bundle pair
  and its mutants.
- Go and Rust run the Class-1 verifier over `../capsule/` only. Neither
  implements the countersignature stamp, so the Bundle pair is not run there.

## Regenerating

From the repository root:

```sh
python3 python/scripts/generate_outcome_claim_limits_vectors.py
```

The output is a pure function of the generator and the producer-key vectors.
`SHA256SUMS` pins every file in this directory, including this hand-written
README.
