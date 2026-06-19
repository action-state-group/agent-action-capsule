---
title: "An Agent Action Capsule Profile for SCITT"
abbrev: "Agent Action Capsules"
docname: draft-mih-scitt-agent-action-capsule-01
category: std
submissiontype: IETF
ipr: trust200902
area: "Security"
workgroup: "SCITT"
keyword:
 - SCITT
 - AI agent
 - transparency
 - audit
 - verdict
stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 - ins: S. Mih
   name: Steven Mih
   organization: Action State Group, Inc.
   email: spec@actionstate.ai

normative:
  RFC2119:
  RFC8174:
  RFC9052:
  RFC8392:
  RFC8785:
  RFC3339:
  RFC8126:
  RFC6838:
  RFC8259:
  I-D.ietf-scitt-architecture:

informative:
  I-D.ietf-cose-merkle-tree-proofs:
  I-D.ietf-scitt-scrapi:
  I-D.ietf-scitt-receipts-ccf-profile:
  I-D.ietf-spice-sd-cwt:
  RFC8949:
  RFC9053:
  I-D.munoz-scitt-permit-profile:
  I-D.emirdag-scitt-ai-agent-execution:
  I-D.kamimura-scitt-refusal-events:
  I-D.kamimura-scitt-vcp:
  I-D.dawkins-scitt-ai-article50:
  I-D.sato-soos-gar:
  I-D.nivalto-agentroa-route-authorization:
  RFC8141:
  RFC6839:

--- abstract

This document defines a SCITT statement profile for recording what an AI
agent did: the Agent Action Capsule. A Capsule is a digest-committed record
of one agent action carrying its verdict-level disposition (executed,
blocked, denied, errored, timed out), the deterministic constraints that
were evaluated, the effect that was committed together with a
confirmed-effect binding that distinguishes a dispatched attempt from an
observed result, and an honest human-in-the-loop flag. Capsules are
expressed as SCITT Signed Statements (COSE_Sign1) and made transparent by
registration in a SCITT Transparency Service. A Capsule is recorded on
every verdict, including refusals: a blocked or denied Capsule is the
auditor-grade evidence that a gate worked.

--- note_Note_to_Readers

This document is an individual submission. The intended venue for
discussion is the SCITT Working Group (scitt@ietf.org). The source of
truth for the profile's prose is the specification repository from which
this document is derived; see the repository's `docs/ietf-draft/README.md`
for the section mapping.

--- middle

# Introduction

AI agents increasingly take actions with external consequences: writing
records, sending payments, filing documents. Two distinct evidentiary
questions follow. The question "was this action permitted?" is answered by
authorization records produced before execution. The question this profile
answers is different: "what did the agent actually do?" — including the
cases where the answer is "it was stopped."

This document profiles SCITT {{I-D.ietf-scitt-architecture}} Signed
Statements to carry an Agent Action Capsule: a digest-committed record of
one agent action and its verdict-level disposition. The profile's central
design commitments are:

1. The may/did distinction. A Capsule records what occurred, with an
   effect-state binding ({{effect}}) that structurally distinguishes "the
   effect was dispatched" from "the effect's result was observed and
   bound." A producer cannot present an attempt as a completion.

2. A Capsule on every verdict ({{everyverdict}}). Capsules are recorded
   for refusals, blocks, errors, and timeouts — not only for executed
   effects. An evidence trail that records only successes is
   survivorship-biased and cannot prove its gates ever fired.

3. Independent verifiability. The substrate guarantees (envelope
   signature, registration, receipt) are SCITT's and are verified by
   reference; the agent-domain checks defined here ({{verification}},
   {{class2}}) are deterministic and reproducible by any verifier from
   the record's own bytes, in two conformance classes ({{conformance}}).

The terms "statement profile" and "profile" in this document always mean a
SCITT statement profile in the sense of {{I-D.ietf-scitt-architecture}}: a
constraint on the protected header and payload of a Signed Statement. The
word is never used in any other sense in this document.

# Conventions and Definitions {#conventions}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals,
as shown here.

Capsule:
: The Agent Action Capsule — the JSON payload of a profiled Signed
  Statement, recording one agent action.

Verdict:
: The terminal outcome of one agent action — what the decision gate
  concluded and what is consequently known about the effect.

Disposition:
: The digest-committed block within a Capsule recording how the decision
  was disposed: the gate outcome, who disposed it, an honest
  human-in-the-loop flag, and optionally a verdict reason-class.

Producer:
: The party that constructs, signs, and (for the transparent tier)
  registers Capsules.

Verifier:
: Any party that validates a Capsule from its bytes, without trusting the
  Producer. Verifier conformance is split into two classes
  ({{conformance}}).

JSON-DIGEST:
: HEX(SHA-256(JCS(normalize(v)))) — the lowercase-hex SHA-256 of the
  {{RFC8785}} JSON Canonicalization Scheme serialization of a value after
  absent-field normalization (members whose value is null, an empty array,
  or an empty object are removed, bottom-up). All JSON digests in this
  profile use this single construction.

# The SCITT Signed Statement envelope {#projection}

## Protected header and payload media type {#envelope}

A Capsule is carried as the payload of a SCITT Signed Statement — a
COSE_Sign1 {{RFC9052}} (a CBOR structure, {{RFC8949}}). The protected
header MUST carry the CWT Claims parameter (label 15) {{RFC8392}} with:

| Claim | Req | Meaning |
|---|---|---|
| iss (CWT 1) | REQUIRED | The signing agent identity (the Capsule's developer). |
| sub (CWT 2) | REQUIRED | urn:agent-action-capsule:OPERATOR:ACTION_ID — the tenant-scoped action subject (provisional URN namespace; see below). |
| capsule_statement_type | REQUIRED | "agent_action" or "outcome". Additional values are reserved ({{future}}). |
| capsule_action_type | RECOMMENDED | "fyi" or "decide" — lets a registration policy gate by action class without parsing the payload. |
| capsule_decision_id | RECOMMENDED | Correlates the statements of one decision (and its outcomes) at the SCITT layer. |

plus `alg`, `kid`, and `content_type` per COSE. The `content_type` MUST
be `application/agent-action-capsule+json` (or the outcome media type,
{{outcomes}}). The `capsule_*` protected-header claim set is CLOSED:
extensions are payload-only ({{extensibility}}). The `capsule_*` claim
labels are provisional string-keyed names pending registration in the
existing IANA "CWT Claims" registry; a future revision pins integer
labels. The `urn:agent-action-capsule:` namespace of the `sub` claim is
likewise provisional and used here by example; a future revision either
registers a formal URN namespace ({{RFC8141}}) or replaces it with a
profile-defined subject scheme. A plain structured-string subject (no URN
form) is under consideration for that revision, since the CWT `sub` claim
does not require URN syntax; the choice is deferred to avoid churning the
protected-header subject format in this revision.

A field is a protected-header claim only if a SCITT-generic party (a
Transparency Service registration policy, or a profile-unaware verifier)
must act on it without understanding this profile; everything
semantically rich stays in the payload.

## Registration and Receipts {#registration}

A producer makes a Capsule transparent by registering its Signed
Statement with a SCITT Transparency Service per
{{I-D.ietf-scitt-architecture}} and attaching the returned Receipt
(COSE Receipts, {{I-D.ietf-cose-merkle-tree-proofs}}) to the unprotected
header, forming a Transparent Statement. This profile does not define
receipt formats or proof verification; both are the substrate's, by
reference. A verifier MUST NOT report `attestation_mode: "anchored"`
without having verified a Receipt from a Transparency Service whose key
it trusts. A conforming anchor is any SCITT Transparency Service; this
profile requires no specific operator. The transport of registration
requests is likewise out of scope: {{I-D.ietf-scitt-scrapi}} defines a
reference registration API, and a Transparency Service may employ a
receipt profile such as {{I-D.ietf-scitt-receipts-ccf-profile}}; this
profile is indifferent to both choices.

## Outcomes {#outcomes}

An asynchronously observed consequence — a reversal, dispute, correction,
or confirmation — is recorded as its own Signed Statement
(`capsule_statement_type: "outcome"`, content type
`application/agent-action-capsule-outcome+json`) whose `sub` equals the
original action's `sub`. Correlation is by subject and decision id, never
by mutating the original statement: the log is append-only and the
original is immutable.

# Registries of this profile (summary) {#registries}

Six vocabularies of this profile are registry-governed under a
Specification Required policy ({{RFC8126}}, Section 4.6):
`verdict_class`, `disposition.decision`, `effect.type`,
`irreversibility_class`, `effect_attestation`, and `chain.relation`. The
registries and their initial contents are defined in {{iana}}, kept at
the back of this document per convention.

The binding invariant, stated once here and again in {{iana}}: verifiers
MUST treat unregistered values as informational and MUST NOT reject a
Capsule for carrying one. Registration governs shared meaning, never
acceptance. Every registry check in this profile is performable from the
Capsule's own bytes and the registry contents alone.

# The Agent Action Capsule {#capsule}

A Capsule is a JSON object: the envelope that is disclosed and
digest-committed. Sensitive content (model reasoning, evaluated evidence,
raw tool payloads) is not carried in the envelope; it is committed to by
digest only. A Capsule also carries Constraint Records — the public
verdicts of the deterministic checks that ran against the action; their
detail is specified in {{constraints}}.

## Identity and parties {#identity}

| Field | Type | Req | Meaning |
|---|---|---|---|
| spec_version | string | REQUIRED | The profile prose version the Capsule conforms to. The value defined by this profile version is "draft-mih-scitt-agent-action-capsule-01"; it tracks the document name and advances with each revision. |
| format_version | string | REQUIRED | The serialization-suite version of the envelope. The value defined by this profile version is "2"; the value reflects the pre-IETF reference-implementation serialization lineage this profile inherits, which is why a -00 document begins at "2" rather than "1". |
| capsule_id | string (64 hex) | REQUIRED | JSON-DIGEST of the canonical capsule form: the envelope minus capsule_id and chain-linkage fields, after absent-field normalization. Content-addresses the envelope. |
| action_id | string | REQUIRED | Stable identifier of the action; unique within one producer ledger. |
| action_type | string | REQUIRED | "fyi" (informational) or "decide" (a disposition was required). |
| operator | string | REQUIRED | The accountable tenant the action was performed for. |
| developer | string | REQUIRED | The agent identity and version that performed the action. |
| timestamp | string | REQUIRED | {{RFC3339}} UTC with "Z" suffix. |

Monetary and quantity values anywhere in a Capsule MUST be exact decimal
strings, never JSON floating-point numbers; digests are not reproducible
across implementations otherwise.

Chain-linkage fields are intentionally excluded from `capsule_id` so that
a Capsule's content-address remains stable regardless of what later chains
to it — including the chain block itself, which references a parent's
`capsule_id` and so could not be inside the address it helps compute. This
exclusion does not weaken integrity: the entire Capsule payload, the chain
block included, is signed within the COSE_Sign1 envelope ({{envelope}}),
so the chain linkage is tamper-evident even though it is not part of the
content-address.

## Effect Record and the confirmed-effect binding {#effect}

The Effect Record describes the side effect the action committed. Its
`status` member takes one of five values:

| status | Meaning | Binding requirement |
|---|---|---|
| planned | Intended, not dispatched. | request_digest and response_digest MUST be absent. |
| dispatched | Sent; result not observed. | request_digest SHOULD be present; response_digest MUST be absent. |
| confirmed | Result observed and bound. | response_digest MUST be present and MUST be the JSON-DIGEST of the actual response. |
| failed | Attempted; runtime reported failure (state known). | response_digest, when present, digests the failure response. |
| reverted | A committed effect was undone. | Correlated via external_ref / decision_id. |

The confirmed-effect invariant: a producer MUST NOT emit
`status: "confirmed"` without a `response_digest` over the actually
observed response. A verifier MUST treat `confirmed` with a missing
response_digest as a verification failure. This is the byte-level
mechanism behind the may/did distinction: "confirmed" is an observed
result, never a promise.

The Effect Record also carries the logical `type` (registry-governed,
{{iana}}), an optional `external_ref` join key for later outcomes, and an
`irreversibility_class` — an ordered consequence enumeration (`two_way`,
`one_way_recoverable`, `one_way_consequential`, `one_way_terminal`;
registry-governed, {{iana}}).

The Effect Record additionally carries `effect_attestation`: WHO vouches
for the effect's execution — the evidence grade of the effect claim. The
vocabulary is registry-governed ({{iana}}; Specification Required), seeded
with two values:

| effect_attestation | Meaning |
|---|---|
| gate_executed | The commit transited the gate; the engine observed the effect boundary directly. |
| runtime_claimed | The gate issued a verdict only; the executing runtime asserted completion; the capsule records that claim, not an observation. |

Validity is checked against the assurance `effect_mode` ({{assurance}}):

| effect_mode | effect_attestation |
|---|---|
| confirmed | REQUIRED (states WHO confirmed) |
| dispatched_unconfirmed | REQUIRED |
| not_applicable | MUST be absent — nothing executed, there is no claim to grade |

The planned carve: `effect.status: "planned"` asserts no execution, so
`effect_attestation` MUST be absent — there is nothing to grade, and a
phantom grade would poison grade-based queries. It becomes REQUIRED the
moment dispatch occurs.

The matrix is total over the `effect.status` values of {{effect}}. An
`effect.status` of `failed` (the effect was dispatched and the runtime
reported a failure; state known) derives `effect_mode:
"dispatched_unconfirmed"` — the effect was dispatched and its result, though
a failure, was not gate-confirmed; therefore `effect_attestation` is REQUIRED.
`reverted` (a previously-committed effect was undone) likewise derives
`effect_mode: "dispatched_unconfirmed"` and REQUIRES `effect_attestation`; the
underlying committed effect it reverses is correlated separately via
`external_ref` / `decision_id` (the Effect Record fields, {{effect}}), not
by a distinct `effect_mode`. So
every `effect.status` other than `planned` (carved above) and the
no-effect case (`not_applicable`) requires `effect_attestation`.

Consumers MUST treat an unregistered or unrecognized `effect_attestation`
value as no stronger than `runtime_claimed`; unknown values are
informational, never a verification failure, and unknown never grades up.
The grade is digest-committed in the Capsule payload and is available to
any payload-bearing verifier, which can thereby distinguish gate-observed
execution from runtime-claimed execution; promotion of the grade to a
protected-header (CWT claim) position is an explicit candidate for a -02
revision, to be decided once real transparency-log consumers exist. This
version deliberately claims no header-level visibility for the grade.

## Assurance {#assurance}

Every Capsule carries an `assurance` object stating, as
independently-rederivable claims: `attestation_mode` ("self_attested" or
"anchored"), `effect_mode` ("not_applicable", "dispatched_unconfirmed", or
"confirmed"), and `ledger_mode` ("standalone", "chained", or "anchored").
`ledger_mode` records the custody tier of the record: "standalone" is a
lone Capsule (no chain linkage); "chained" is a Capsule whose hash-chain
linkage to a predecessor is present and intact; "anchored" is a chained
Capsule whose chain root has additionally been committed to an independent
transparency log. A verifier rederives `ledger_mode` from the bytes it can
check — "standalone" versus "chained" from the presence and integrity of
the hash-chain linkage, and "anchored" only after it verifies an inclusion
proof against a trusted log key — and the three tiers are ordered
standalone < chained < anchored for overclaim detection. A producer MUST
NOT record an assurance mode it did not achieve; a verifier rederives each
mode from the evidence present and reports any overclaim.

## Disposition and the verdict reason-class {#disposition}

A Capsule's `disposition` block records how the decision was disposed:

- `decision` (REQUIRED): "accept", "reject", "needs_input", or "deferred"
  (registry-governed, {{iana}}).
- `approver` (REQUIRED): a closed enum, exactly "human" or "policy".
  The value domain is fixed by this specification (not registry-governed);
  an unknown approver value is not a conforming Capsule.
- `human_disposed` (REQUIRED, boolean): the honest in-the-loop flag —
  true ONLY when a human actually acted. A policy auto-approval is false.
  `human_disposed: true` REQUIRES `approver: "human"`; a producer MUST
  NOT claim a human disposed what a policy did.
- `authority` (OPTIONAL): an opaque reference to the authority under
  which a non-human disposition acted. A conforming Capsule carries at
  most the reference, never the authority's internal structure.
- `verdict_class` (OPTIONAL): the terminal-verdict reason-class
  ({{verdictclass}}). It is RECOMMENDED for any non-executed verdict,
  where it carries the terminal reason; it is legitimately absent for a
  clean `executed` verdict (which has no reason-class, mirroring an absent
  `reason_digest`).
- `reason_digest` (OPTIONAL): JSON-DIGEST of a structured, private reason
  object — machine-readable members such as the constraint identifier,
  the threshold, and the observed value; never free prose — so two
  engines attesting the same refusal produce the same digest. The member
  is absent (not a digest of an empty object) when a verdict has no
  reason, such as a clean "executed".
- `expiry_policy` (OPTIONAL; deferral dispositions only): a digested
  `{ttl_seconds, on_expiry}` object — `ttl_seconds` is an integer count
  of seconds, never a duration string, and `on_expiry` is "expired" or
  "escalated". `ttl_seconds` is evaluated against the deferral Capsule's
  registration time — the `timestamp` field inside the digest commitment
  — not the Transparency Service receipt time, and not a consumer's
  local wall clock; a named clock basis is what makes the expiry
  computation deterministically reproducible, so any verifier derives the
  same elapsed-time result from the record's own bytes. The deferral's
  frozen summary is a
  digest-committed, content-side layer written once at deferral time; it
  MUST NOT be regenerated.


### The verdict_class vocabulary {#verdictclass}

`verdict_class` records WHY the action terminated as it did. The seeded
vocabulary (registry-governed, {{iana}}; unregistered values are
informational to a verifier, never a rejection):

| verdict_class | Meaning |
|---|---|
| executed | The action ran. |
| blocked | A blocking constraint stopped it before dispatch. |
| hitl_dispatched | Routed to a human operator; awaiting resolution. |
| denied | An operator or policy refused it before dispatch. |
| timeout | The decision timed out (see the orthogonality rule). |
| errored | The action ran and threw; final state unknown. |
| engine_failure | The engine could not evaluate the action. |
| deferred | A human elected to postpone the decision; open item. |
| needs_decision | Evaluation complete; decision required, not yet routed to a decider; open item. |
| expired | TTL policy on the deferral elapsed; terminal unless superseded by escalation. |
| escalated | Expiry or policy routed the item to a higher authority; open item at the new authority. |
| resolved | A terminal decision Capsule closed the chain without executing — the non-executing closure only (see the pairing rule, {{orthogonality}}). |

`hitl_dispatched` and `deferred` are sequential states, not synonyms:
`hitl_dispatched` means sent to a decider and awaiting response;
`deferred` means a decider responded "later".

### Orthogonality with effect_mode {#orthogonality}

`verdict_class` (why the verdict) and `assurance.effect_mode` (what is
known about the effect) are independent axes and MUST NOT be folded into
one another:

- The pre/post-dispatch distinction lives in `effect_mode`, not in the
  class. A timeout before dispatch is `verdict_class: "timeout"` with
  `effect_mode: "not_applicable"`; a timeout after dispatch is
  `verdict_class: "timeout"` with `effect_mode: "dispatched_unconfirmed"`.
  One `timeout` value covers both.
- `errored` pairs with `effect_mode: "dispatched_unconfirmed"` — the
  effect was dispatched and may have left a partial side effect.
  `not_applicable` would falsely assert nothing happened, which is the
  inverse of attesting an execution that did not occur and equally
  non-conforming.
- A class that by its kind never dispatches (`blocked`,
  `hitl_dispatched`, `denied`, `engine_failure`, `deferred`,
  `needs_decision`, `expired`, `escalated`, `resolved`) REQUIRES the
  derived `effect_mode` to be `"not_applicable"`. A verifier reports any
  other derived mode as an error: an effect attempt contradicts a
  verdict that claims it never executed.
- The pairing rule: `resolved` is exclusively the NON-executing closure
  (decline, waive, recorded-elsewhere) — it pairs with `effect_mode:
  "not_applicable"` and an absent `effect_attestation`. An EXECUTING
  closure is encoded as `verdict_class: "executed"` chained
  `supersedes` to the deferral ({{hitl}}) — one valid encoding of
  "closed with effect", never two.
- The effect status `"failed"` (ran and returned a clean failure, state
  known) is distinct from `verdict_class: "errored"` (ran and threw,
  state unknown). "failed" is an effect status, never a reason-class.

### A Capsule on every verdict {#everyverdict}

A conforming producer MUST record a Capsule for every verdict, whatever
its disposition. This requirement is universal over the `verdict_class`
vocabulary — the IANA registry of this document ({{iana}}) — and
applies to every value later admitted by registration; it is
deliberately not stated as an enumerated list, which would go stale the
moment Specification Required admits a new value. A refusal or block with
no Capsule is invisible to an auditor; a blocked or denied Capsule is
auditor-grade evidence that the gate worked: the affirmative,
digest-committed record that the constraint or policy fired and the
action did not proceed. Recording only successes makes the evidence trail
survivorship-biased and the refusal path unverifiable.

### Chained Capsules and human-in-the-loop resolution {#hitl}

Every Capsule that references a prior Capsule carries a digested `chain`
block: `{parent_capsule_id, relation}`. The `relation` vocabulary is
registry-governed ({{iana}}; Specification Required), seeded with one
value:

| relation | Meaning |
|---|---|
| supersedes | Terminal transition over the parent — resolution, expiry, escalation close or replace the parent's open state. |

Single-parent is intentional: a Capsule chains to exactly one parent.

Human-in-the-loop resolution is the `supersedes` relation: a
`hitl_dispatched` Capsule is sealed at dispatch time and is never
mutated. When the decision is later resolved, that resolution is a
second, linked Capsule carrying its own disposition and chaining to the
dispatch Capsule with `relation: "supersedes"`. The dispatch Capsule
stays `hitl_dispatched` forever; resolution state lives only on the
resolution Capsule, preserving the append-only model.

Concurrent-supersedes rule: the ledger is append-only and totally
ordered; the earliest capsule in ledger order with `relation=supersedes`
over a given parent is authoritative; any later supersedes over the same
parent is structurally valid but MUST surface as a verification finding.

Open-items predicate: an item is open when its Capsule's
`verdict_class` is one of `deferred`, `needs_decision`,
`hitl_dispatched`, `escalated`, or `blocked`, and no Capsule in the
store carries `chain.parent_capsule_id` equal to its `capsule_id` with
`relation: "supersedes"`.

# Class 1 verification {#verification}

Verification has two tiers. Substrate verification — the issuer's
COSE_Sign1 signature, and for the transparent tier the Receipt's
inclusion proof and Transparency Service signature — is performed by
reference to {{RFC9052}}, {{I-D.ietf-scitt-architecture}}, and
{{I-D.ietf-cose-merkle-tree-proofs}}; this profile does not respecify it.

The agent-profile checks below are normative here and constitute Class 1
verification ({{conformance}}): every check is performable from the
Signed Statement, the Capsule payload, the registry contents
({{registries}}), and — for the chain checks — the producer's store of
Capsules; no other input is needed. A verifier MUST return a structured
result, never throw; a single `ok` boolean gates trust in every other
reported field; findings are reported in a fixed order.

1. Structural: REQUIRED fields present and typed; no floating-point
   values in digest-bearing fields.
2. Identity: recompute `capsule_id` over the canonical capsule form and
   compare.
3. Confirmed-effect binding: `effect.status: "confirmed"` without a
   well-formed `response_digest` is a failure ({{effect}}).
4. Verdict/effect orthogonality: a never-dispatching `verdict_class`
   with a derived `effect_mode` other than `"not_applicable"` is a
   failure ({{orthogonality}}); `resolved` is in the never-dispatch set
   per the pairing rule.
5. Effect-attestation matrix: `effect_attestation` missing where the
   matrix REQUIRES it, or present where it MUST be absent — including
   the planned carve — is a failure ({{effect}}).
6. Chain semantics (store-level): a missing chain parent is a failure;
   concurrent supersedes surface as findings per {{hitl}}.
7. Assurance reconciliation: rederive the assurance modes from evidence
   actually verified; report overclaims.
8. Unknown registry values (`verdict_class`, `decision`,
   `effect.type`, `irreversibility_class`, `effect_attestation`,
   `chain.relation`): report as informational findings; MUST NOT reject
   ({{iana}}). An unknown `effect_attestation` is additionally graded no
   stronger than `runtime_claimed` ({{effect}}).

Disposition honesty is structurally guaranteed, not a live check above.
The honesty invariant — `human_disposed: true` REQUIRES `approver:
"human"` ({{disposition}}) — is enforced when the disposition is
constructed: the typed disposition carrier rejects `human_disposed:
true` paired with any non-`human` approver, so a violating Capsule
cannot be formed or signed at all. A Class 1 verifier
therefore does not re-assert it in the enumeration above; like
parse- and type-level malformations that a typed record cannot
represent, a dishonest disposition is an unrepresentable state rather
than a runtime failure mode. A verifier consuming arbitrary bytes not
produced by a conforming constructor SHOULD nonetheless assert the
invariant defensively against hand-crafted input. The
closed `approver` enum ({{disposition}}) is likewise structural: an
approver value outside `{human, policy}` is non-conforming by
construction and so is absent from the unknown-registry-value reporting
of check 8.

NOTE (Class 1 test vector, effect-attestation matrix, check 5): a Capsule
carrying `effect.status: "failed"` derives `effect_mode:
"dispatched_unconfirmed"` ({{effect}}); the matrix therefore REQUIRES
`effect_attestation`. A conforming verifier MUST report a check-5 failure
for such a Capsule when `effect_attestation` is absent, and MUST NOT treat
the `failed` status as exempt (only `planned` is carved, and only
`not_applicable` is the no-effect case). The same expectation holds for
`effect.status: "reverted"`, which likewise derives
`dispatched_unconfirmed`. This vector exists to demonstrate the matrix is
total over `effect.status`: the runtime reporting a failure is still a
dispatch, and a dispatch that escapes attestation is the precise condition
check 5 exists to catch.

A verifier MUST NOT consult a model, a clock-dependent heuristic, or
network state to decide `ok` for the checks above. Manifest-dependent
verification is Class 2 ({{class2}}).

# Conformance: two verifier classes {#conformance}

This profile defines two verifier conformance classes. Producer
conformance is a single class and is unchanged by this split: a
conforming producer emits the same Capsules regardless of which verifier
class consumes them.

Class 1 verifier:
: Verifies the Signed Statement envelope and the Capsule payload WITHOUT
  any constraint manifest: substrate verification by reference, the
  structural and identity checks, the registry vocabularies, the digest
  recomputations, and the validity matrices (confirmed-effect binding,
  verdict/effect orthogonality, effect-attestation, chain semantics).
  The complete Class 1 check set is {{verification}}.

Class 2 verifier:
: A Class 1 verifier that additionally performs manifest-aware
  verification ({{class2}}): constraint evidence-schema checks and
  manifest-sourced thresholds. Class 2 conformance presupposes access to
  the producer's constraint manifest and the private evidence its
  Constraint Records bind; absent those inputs, a Class 2 verifier
  reports Class 1 results unchanged.

# Manifest-dependent material {#manifestdep}

The producer's constraint manifest — the private definition of each
constraint's predicate, evidence schema, and thresholds — is not carried
in the Capsule. The material in this section depends on it: the detail
of Constraint Records and the Class 2 checks. Manifest discovery and
authentication are out of scope for this profile; they are expected to be
handled via out-of-band tenant configuration or a future discovery
mechanism.

## Constraint Records {#constraints}

A Constraint Record is the public verdict of one deterministic check that
ran against the action. It carries only sanitized categories — an `id`,
optional `check_type` and `method` labels, a `result` of "pass" / "fail" /
"n/a", `severity`, a `blocking` flag recording whether the check actually
gated this decision, and an optional `evidence_digest` (JSON-DIGEST)
binding the verdict to the private evidence the check evaluated. The
content a check evaluated MUST NOT appear in the public record; it is
bound by digest only. The check's predicate, evidence schema, and
thresholds live in the producer's manifest.

Every recorded `result` MUST be the output of a deterministic predicate
over disclosed or digest-committed evidence. The live decision path MUST
NOT re-prompt a model to make a check pass, and a verifier MUST NOT
re-prompt a model to "re-check" one: re-running a non-deterministic check
is not verification.

Constraint `id`, `check_type`, and `method` values are lowercase
snake_case categories. New values follow the namespacing convention of
{{namespacing}}.

## Class 2 verification {#class2}

The checks below are manifest-aware: they require the producer's
constraint manifest and the private evidence a Constraint Record binds
by digest. A Class 2 verifier performs them in addition to the complete
Class 1 set ({{verification}}); their results never weaken a Class 1
result — they extend it.

1. Constraint evidence-schema check: for each Constraint Record
   ({{constraints}}) carrying an `evidence_digest`, confirm the bound
   evidence conforms to the manifest's evidence schema for that
   constraint `id` and that the recomputed digest matches; a mismatch is
   a failure.
2. Threshold checks: confirm that manifest-sourced thresholds were
   applied as the manifest states.

# Extensibility {#extensibility}

All extension points are payload-only. The protected-header `capsule_*`
claim set is closed by this profile version: a strict Transparency
Service registration policy may reject statements bearing header claims
it does not recognize, while payload bytes are opaque to it — so a
payload-only extension can never make a Capsule unregistrable. A verifier
encountering an unrecognized `capsule_*` header claim MUST still verify
and report it as informational; rejection of unknown header claims is a
registration-policy prerogative, not a verifier behavior.

## Namespacing convention {#namespacing}

Three vocabularies are deliberately not registry-governed — constraint
`id`/`check_type`, `compliance.framework_tags`, and
`assurance.sources[].kind` — because their value space is producer-local
by nature. Bare names (no namespace separator) are reserved for the
values seeded in this document; any party introducing a new value MUST
namespace it with a URI or reverse-DNS prefix (for example,
`com.example.margin_floor`). A bare, unseeded name is non-conforming for
a producer; a verifier still treats it as informational.

## Selective Disclosure {#selectivedisclosure}

The base confidentiality posture of this profile is whole-envelope: a
producer discloses a Capsule by sharing its full payload, or withholds it
entirely. Sensitive content not carried in the envelope leaves no on-wire
indicator of its existence. This whole-envelope posture is sufficient for
the common case where the unit of disclosure is the Capsule as a whole.

For cases in which a producer must reveal a subset of payload fields to a
counterparty while concealing both the values and the existence of
unrevealed fields, a per-field selective-disclosure mechanism is needed.
This profile reserves an extension point in the Capsule payload for such
a mechanism. The intended field-level technique is informatively
anticipated to follow {{I-D.ietf-spice-sd-cwt}}, the SPICE WG selective-
disclosure draft, whose salted-hash commitment structure is COSE-native
and consistent with Capsules expressed as COSE_Sign1 Signed Statements.

The complete normative profile of this extension — including the
commitment encoding, disclosure syntax, and verifier checks — is deferred
to a companion Internet-Draft; see {{future}}.

Implementations of this profile version MUST NOT generate or interpret
selective-disclosure payload structures: the extension point is reserved,
and no conformance claim or verification behavior is defined for it here.

# Related Work {#related}

Several active individual drafts address adjacent evidence problems for
AI agent actions; this profile is complementary to each.
{{I-D.munoz-scitt-permit-profile}} defines pre-execution authorization
records (Permits) that bind an allow/deny/challenge decision to the
request bytes subsequently dispatched.
{{I-D.nivalto-agentroa-route-authorization}} defines Agent Route Origin
Authorization (AgentROA), a cryptographic policy-enforcement framework
that authorizes agent capability invocations before dispatch through
signed policy envelopes and per-hop attestations; like Permits it governs
whether an action may proceed (may), complementary to this profile's
record of what occurred (did).
{{I-D.emirdag-scitt-ai-agent-execution}} defines AgentInteractionRecords
signed by an agent operator and registered with an independent evidence
custodian, with redaction receipts and regulatory mappings.
{{I-D.kamimura-scitt-refusal-events}} defines a serialization-independent
claim set for AI content-refusal audit trails carried in SCITT Signed
Statements; the same author's {{I-D.kamimura-scitt-vcp}} (VeritasChain
Protocol) is a SCITT profile for verifiable audit trails in algorithmic
trading — a vertical-specific application of the same transparency
substrate. {{I-D.dawkins-scitt-ai-article50}} profiles SCITT receipts
for the transparency obligations of EU AI Act Article 50.
{{I-D.sato-soos-gar}} defines session-level Governance Audit Records
produced by a governing enforcement component; this profile differs in
recording per-action verdicts with effect-state binding rather than
session-close summaries.

The distinction this profile contributes is verdict-level disposition
with effect-state binding: authorization records prove permission was
granted (may); Capsules prove what occurred (did) — executed, blocked,
denied, errored, or timed out — with a structural binding that prevents
an attempt from being presented as a completion, and with refusals
recorded as affirmative evidence.

# Future Work {#future}

A counterparty attestation extension is in preparation; it will define
additional statement-type and verdict values, which are reserved for that
purpose.

A companion Internet-Draft is planned to normatively profile the
selective-disclosure extension point reserved in {{selectivedisclosure}},
specifying the per-field commitment structure, disclosure syntax, and
verifier checks, aligned with {{I-D.ietf-spice-sd-cwt}}.

# IANA Considerations {#iana}

## New registries

Every registry requested below governs a vocabulary that lives entirely
in the Capsule *payload* — values a SCITT-generic Transparency Service
never parses, since registration, inclusion, and Receipt issuance operate
on the COSE_Sign1 envelope and its protected header, not on payload
content. The registrations this profile requests against *existing* IANA
registries are the `capsule_*` CWT claims ({{no-new-registry}}) and the
two media types of {{media-types}}; both are addressed separately from the
payload-vocabulary registries here. This profile requests no new COSE
header parameter registry and no new CWT claim registry; the new
registries here are payload-vocabulary registries only.

IANA is requested to create a new registry group, "Agent Action Capsule
Parameters", containing the six registries below. The registration
policy for each is Specification Required ({{RFC8126}}, Section 4.6).

Specification Required is chosen deliberately. The threat it answers is a
vocabulary value whose meaning is defined only inside a closed product —
two verifiers would then disagree on what the value means, and the
interoperable, falsifiable-from-the-record property this profile depends
on would erode. The mitigation is the policy's publicly-available-spec
requirement: a value enters the shared vocabulary only once its semantics
are pinned in a specification any implementer can read. Accordingly, for
each registry the designated expert approves a registration when (1) the
citing specification defines the value's semantics precisely enough that
two independent implementations would apply it identically — for
verdict_class, including its dispatch consequence and its effect_mode
pairing under {{orthogonality}}; (2) the value's meaning is not already
expressible by an existing registered value; and (3) the citing
specification is publicly available.

Binding invariant for all six registries: verifiers MUST treat
unregistered values as informational and MUST NOT reject a Capsule for
carrying one. Registration governs shared meaning, never acceptance.

Initial contents are the seeded values of this document, verbatim:

1. "verdict_class" registry ({{verdictclass}}): executed, blocked,
   hitl_dispatched, denied, timeout, errored, engine_failure, deferred,
   needs_decision, expired, escalated, resolved.
   The `deferred` token's semantics are OWNED by this registry; the
   entry of the same spelling in the "disposition.decision" registry is
   a cross-reference to it.
2. "disposition.decision" registry ({{disposition}}): accept, reject,
   needs_input, deferred. The `deferred` entry is a cross-reference to
   the "verdict_class" registry, which owns the token's semantics.
3. "effect.type" registry ({{effect}}): write_order, send_payment.
4. "irreversibility_class" registry ({{effect}}; ordered by ascending
   consequence — a registration states its position): two_way,
   one_way_recoverable, one_way_consequential, one_way_terminal.
5. "effect_attestation" registry ({{effect}}): gate_executed,
   runtime_claimed. The registry definition carries the grade-floor
   invariant of {{effect}} — an unregistered or unrecognized value is
   graded no stronger than runtime_claimed; unknown never grades up —
   and the planned carve of {{effect}}: with `effect.status: "planned"`
   the member MUST be absent, and it becomes REQUIRED the moment
   dispatch occurs. Designated-expert guidance: plausible future
   registrations exist and are deliberately not seeded — for example,
   independent sensor confirmation of a claimed effect, or hardware- or
   TEE-anchored execution; a registration states where its grade sits
   relative to the seeded values.
6. "chain.relation" registry ({{hitl}}): supersedes. Designated-expert
   guidance: this registry is seeded with the single terminal relation;
   additional non-terminal relations (for example, deposit-toward-open
   and effort-toward-open relations, or amends / contradicts) are
   expected future registrations, each admitted once its semantics and
   any verifier consequence are pinned in a publicly available
   specification.

Interim registry of record: until this document is published as an RFC,
the registry of record is the `REGISTRY.md` file of the source
specification repository, seeded with the same initial contents and the
same policy; on publication the IANA registries become the registry of
record. Change controller: Action State Group, Inc. (interim); the IETF
on publication.

## No new registry {#no-new-registry}

- Attestation/signature algorithms: this profile defines no algorithm
  registry; algorithm identifiers are those of the existing IANA "COSE
  Algorithms" registry ({{RFC9053}}).
- Constraint `id`/`check_type`, `compliance.framework_tags`, and
  `assurance.sources[].kind`: no registry; governed by the namespacing
  convention of {{namespacing}}.
- The `capsule_*` CWT claim labels: registration is requested in the
  existing IANA "CWT Claims" registry ({{RFC8392}}), not in a new
  registry; the claim set is closed by this profile version.

## Media Type Registrations {#media-types}

This profile mandates two media types ({{envelope}}, {{outcomes}}); IANA is
requested to register both in the "Media Types" registry per the templates
below ({{RFC6838}}, with the `+json` structured-syntax suffix of
{{RFC8259}}).

Agent Action Capsule media type:

- Type name: application
- Subtype name: agent-action-capsule+json
- Required parameters: N/A
- Optional parameters: N/A
- Encoding considerations: binary; the payload is JSON ({{RFC8259}}) as
  defined in this document, carried as the payload of a COSE_Sign1
  ({{RFC9052}}) Signed Statement.
- Security considerations: see {{security}} of this document.
- Interoperability considerations: see this document.
- Published specification: this document (and its successors).
- Applications that use this media type: SCITT
  ({{I-D.ietf-scitt-architecture}}) producers and verifiers recording and
  verifying AI agent actions.
- Fragment identifier considerations: as for application/json
  ({{RFC8259}}) per the `+json` suffix ({{RFC6839}}).
- Additional information: Deprecated alias names: N/A. Magic number(s):
  N/A. File extension(s): N/A. Macintosh file type code(s): N/A.
- Person & email address to contact for further information: the author of
  this document.
- Intended usage: COMMON
- Restrictions on usage: N/A
- Author: see the Authors' Addresses section of this document.
- Change controller: Action State Group, Inc. (interim); the IETF on
  publication.
- Provisional registration: yes (pending publication of this document).

Agent Action Capsule outcome media type:

- Type name: application
- Subtype name: agent-action-capsule-outcome+json
- Required parameters: N/A
- Optional parameters: N/A
- Encoding considerations: binary; the payload is JSON ({{RFC8259}}) as
  defined in {{outcomes}} of this document, carried as the payload of a
  COSE_Sign1 ({{RFC9052}}) Signed Statement.
- Security considerations: see {{security}} of this document.
- Interoperability considerations: see this document.
- Published specification: this document (and its successors).
- Applications that use this media type: SCITT
  ({{I-D.ietf-scitt-architecture}}) producers and verifiers recording
  asynchronous outcomes correlated to an agent action.
- Fragment identifier considerations: as for application/json
  ({{RFC8259}}) per the `+json` suffix ({{RFC6839}}).
- Additional information: Deprecated alias names: N/A. Magic number(s):
  N/A. File extension(s): N/A. Macintosh file type code(s): N/A.
- Person & email address to contact for further information: the author of
  this document.
- Intended usage: COMMON
- Restrictions on usage: N/A
- Author: see the Authors' Addresses section of this document.
- Change controller: Action State Group, Inc. (interim); the IETF on
  publication.
- Provisional registration: yes (pending publication of this document).

# Security Considerations {#security}

Tamper-evidence is for record bytes, not recorder honesty. This profile
attests what was recorded; it cannot prove the recording runtime was
honest at the moment of recording. A dishonest runtime with no external
witness can produce an internally valid record of a fiction. Registration
in a Transparency Service bounds the timing of such a record and makes
its omission or later substitution detectable; it does not make its
content true.

Confirmed means observed-and-bound, not world-state. A `confirmed`
effect proves the producer bound the bytes of an observed response, not
that the external world reached the claimed state. The same boundary
extends one hop upstream: binding an observed response proves the producer
observed those bytes, not that the responding system was authentic or that
the channel was on-path-intact. An attacker who substitutes or forges the
response — a false success delivered on-path — induces an honest
`confirmed` Capsule for an effect that did not land; this profile does not
mitigate upstream spoofing of the response itself, which is bounded by the
same trust assumption as runtime honesty above. Later, independently
sourced outcome statements ({{outcomes}}) are the mechanism by which such
a spoofed confirmation is contradicted over time.

Self-attested versus anchored tiers differ in evidentiary weight. A
self-attested Capsule is verifiable against its own bytes and signer; an
anchored (registered) Capsule additionally resists omission and
back-dating through the Transparency Service's append-only log and
receipts. A verifier reports the tier it actually verified and never
upgrades a claim it could not check.

The honest human-in-the-loop flag ({{disposition}}) is itself
security-relevant: it prevents a policy auto-approval from being
presented as human oversight. The invariant — `human_disposed: true`
requires `approver: "human"` — is structurally guaranteed: a conforming
producer cannot construct or sign a Capsule that violates it, so the
combination simply does not arise in well-formed records, and the claim
is falsifiable from the record alone. A verifier consuming
non-constructor-produced bytes SHOULD assert the invariant defensively
against hand-crafted input ({{verification}}).

Digests can leak the values they commit. A digest is hiding only to the
extent its committed value space is large and unguessable; when the
committed value is low-entropy — a small enumeration, a short identifier,
a bounded amount — an adversary can recover it by digesting candidate
values and matching (a dictionary attack), so a `reason_digest`,
`evidence_digest`, or any other digest over a low-entropy value is not
confidential merely by being a digest. Producers SHOULD commit such values
under a per-tenant salt or via a tenant-private manifest rather than
digesting the bare value, so that recovering the input requires the secret
and not merely a guess of the value space.

--- back

# Acknowledgments
{:numbered="false"}

The author thanks the reviewers and contributors who shaped the design
recorded here, and the SCITT and COSE working groups whose substrate this
profile builds on.
