---
title: "An Agent Action Capsule Profile for SCITT"
abbrev: "Agent Action Capsules"
docname: draft-mih-scitt-agent-action-capsule-03
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
  RFC9943:
  I-D.mih-sokolov-scitt-payload-binding:
    title: "Canonical Payload Binding: A Signed Statement Construction Profile"
    seriesinfo:
      Internet-Draft: draft-mih-sokolov-scitt-payload-binding-02
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.
      - ins: A. Sokolov
        name: Anton Sokolov
        organization: Tyche Institute

informative:
  RFC6973:
  I-D.mih-sato-agent-accountability-composition:
    title: "Agent Accountability: Composition and Conformance"
    seriesinfo:
      Internet-Draft: draft-mih-sato-agent-accountability-composition-01
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.
      - ins: T. Sato
        name: Tom Sato
  I-D.birkholz-verifiable-agent-conversations:
    title: "Verifiable Agent Conversations"
    seriesinfo:
      Internet-Draft: draft-birkholz-verifiable-agent-conversations-00
    author:
      - ins: H. Birkholz
        name: Henk Birkholz
        organization: Fraunhofer Institute for Secure Information Technology
  I-D.ietf-cose-merkle-tree-proofs:
  I-D.ietf-scitt-scrapi:
  I-D.ietf-scitt-receipts-ccf-profile:
  I-D.ietf-spice-sd-cwt:
  RFC8949:
  RFC9053:
  RFC9901:
  I-D.munoz-scitt-permit-profile:
  I-D.emirdag-scitt-ai-agent-execution:
  I-D.kamimura-scitt-refusal-events:
  I-D.kamimura-scitt-vcp:
  I-D.kamimura-vap-framework:
  I-D.dawkins-scitt-ai-article50:
  I-D.sato-soos-gar:
  I-D.nivalto-agentroa-route-authorization:
  RFC8141:
  RFC6839:
  I-D.mih-scitt-agent-action-capsule-selective-disclosure:
    title: "Selective Disclosure Profile for Agent Action Capsules"
    seriesinfo:
      Internet-Draft: draft-mih-scitt-agent-action-capsule-selective-disclosure-00
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.
  I-D.mih-scitt-agent-action-capsule-disclosure-envelope:
    title: "Disclosure Envelope Profile for Agent Action Capsules"
    seriesinfo:
      Internet-Draft: draft-mih-scitt-agent-action-capsule-disclosure-envelope-00
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.
  I-D.mih-agent-bilateral-attestation:
    title: "Bilateral Agent Action Attestation"
    seriesinfo:
      Internet-Draft: draft-mih-agent-bilateral-attestation-00
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.
  NotarizedAgents:
    title: "Notarized Agents: Decentralized, Verifiable AI Agent Receipts"
    target: https://arxiv.org/abs/2606.04193
    date: 2026
  ERC8004:
    title: "ERC-8004: Agent Identity Registry"
    target: https://eips.ethereum.org/EIPS/eip-8004
  VerifiableIntent:
    title: "Verifiable Intent"
    author:
      - organization: Mastercard
  I-D.rampalli-scitt-capsule-provenance-binding:
    title: "SCITT Capsule Provenance Binding"
    author:
      - ins: K. Rampalli
        name: Karthik Rampalli
        organization: Glyphzero
    seriesinfo:
      Internet-Draft: draft-rampalli-scitt-capsule-provenance-binding

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
auditor-grade evidence that a gate worked. This document expresses the
Capsule as a payload class of the companion Canonical Payload Binding
(CPB) construction profile: CPB supplies the canonicalization,
derived-identifier, and typed-reference mechanisms; this document defines
what a Capsule's fields mean, including the artifact types, wire grammar,
and cross-record binding semantics specific to agent-action evidence.

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

This document profiles SCITT {{RFC9943}} Signed
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
SCITT statement profile in the sense of {{RFC9943}}: a
constraint on the protected header and payload of a Signed Statement. The
word is never used in any other sense in this document.

The design principle that unifies this profile's fields: **the Capsule
is honest about its own limits, and never overstates.** It states how
close its producer stood to the action ({{observationmode}}), what
order among actions it actually observed ({{order}}), what it admitted
into the record and what it kept out ({{privacy}}), and which assurance
tier it genuinely achieved ({{assurance}}). A record that overclaims
proximity, sequence, scope, or assurance is worse than no record,
because it converts a verifier's trust into error with a signature on
it; every field in this profile that could overclaim therefore
carries a mode that makes the limit legible.

## Relationship to the Canonical Payload Binding {#cpb-relationship}

This document is a payload class of the Canonical Payload Binding (CPB)
{{I-D.mih-sokolov-scitt-payload-binding}}. The division of labor is fixed:
CPB defines the mechanism — how a canonical octet string is produced from
a structured value, how a derived identifier is computed from it, how a
Signed Statement binds to a Receipt, and how one record cites another by
digest — and never defines what a payload class's fields mean. This
document defines the meaning: the Capsule's own fields, their vocabularies,
and the semantic rules a producer and verifier apply to them. Where this
document states a wire-level rule (canonicalization algorithm selection,
presence and representation rules, typed references), it does so as a
CPB payload class declaration, not as a restatement of CPB's own mechanism;
{{canonpayload}} and {{artifacttypes}} state this profile's declarations
without repeating CPB's mechanics.

## This profile within a governance runtime {#governanceruntime}

A Capsule is one leg of a larger accountability composition. Using the
terms of {{I-D.mih-sato-agent-accountability-composition}}: whether an
action was permitted at all is a **CAN** question, answered by a
pre-action authorization record; which accountable human or policy
authorized this exact action is a **WHO** question; the transparency
substrate anchoring and cross-party assertion of any of the above is an
**AUDIT** question. This document answers the remaining, complementary
question — **WHAT** the agent actually did — and is the reference
WHAT-record of that composition. A governance runtime that gates,
routes, and disposes agent actions produces its record of doing so as a
Capsule: `disposition` ({{disposition}}) is the runtime's decision
surface, `verdict_class` ({{verdictclass}}) is the runtime's own
vocabulary for why it decided as it did, and the chain and epoch
mechanisms ({{hitl}}, {{epochs}}) are how the runtime's decisions
compose into a queryable history. This profile does not define a
governance runtime's policy engine, decision logic, or manifest format
— those remain implementation-specific and are referenced only by digest
({{constraints}}) — it defines the evidentiary record such a runtime
leaves behind, so that a party who trusts neither the runtime nor its
operator can verify what it decided and what happened as a result.

# Changes from -02 {#changes}

This revision:

- Absorbs the payload-semantic content that the sibling Canonical
  Payload Binding document sheds under its own charter-scoping revision
  ({{I-D.mih-sokolov-scitt-payload-binding}}): the Artifact Type
  Registry ({{artifacttypes}}), and this profile's own presence,
  representation, and number-handling rules ({{canonpayload}}) — the
  wire grammar previously stated as part of CPB's `jcs-n` algorithm
  definition and CPB's Artifact Type Registry section. CPB retains only
  the canonicalization-algorithm registry and the binding mechanism
  ({{cpb-relationship}}).
- Moves the capsule profile's `identifier` digest context from `jcs-n`
  to `jcs` ({{art-agent-action-capsule}}) via a new, immutable digest
  context entry: `jcs` performs no normalization of its own; the
  equivalent null/empty removal is now this profile's own Presence Rule
  ({{presence}}), applied before `jcs` rather than inside the withdrawn
  `jcs-n` algorithm. The byte audit accompanying the `jcs-n` withdrawal
  found the production capsule corpus (191 of 191 records examined)
  byte-identical under both constructions, with 12 mesh proof-of-concept
  demonstration artefacts documented as historical exceptions;
  `capsule_id` values already sealed are unaffected by this change. The
  full per-corpus accounting is filed with the `jcs-n` withdrawal record
  in the CPB registry; this document states only the aggregate result
  and does not reproduce it.
- Declares `canonicalization_id` as a new OPTIONAL payload field
  ({{canonid}}) and `conversation_ref` as a new OPTIONAL
  (conditionally-REQUIRED) payload field ({{conversationbinding}}).
- Declares `references` as a new OPTIONAL payload field ({{xref}}) for
  citing a record outside this producer's own chain and order —
  a different stream, a different order, or any other registered
  artifact — with a seeded `citation_purpose` registry
  (`acted_on`, `responds_to`) distinct from CPB's own `purpose` field.
  Resolves, without minting a new `chain.relation` value, a citation
  some deployed `capsule-emit` implementations previously expressed as
  a same-stream `chain` relation ({{hitl}}) even when the cited record
  was not the same-stream parent.
- Narrows the prior blanket float prohibition to the per-field
  Representation Rule ({{representation-rule}}): monetary and exact
  quantities remain decimal strings; the rule for other digest-bearing
  numeric fields (the HYBRID number discipline) is now stated
  explicitly rather than left to the withdrawn algorithm's implicit
  prohibition.
- Changes conformance behavior for one input class: a null, empty-array,
  or empty-object member in a digest-bearing field, which the prior
  `jcs-n`-based construction silently normalized away, is now a
  verification failure that a verifier reports naming the offending
  member ({{presence}}) — consistent with `jcs` performing no
  normalization and this profile's own Presence Rule instead being a
  producer-side MUST.
- Adds the governance-runtime framing of {{governanceruntime}}, the
  explicit relationship statement to CPB of {{cpb-relationship}}, and
  cites {{I-D.mih-sato-agent-accountability-composition}} at its posted
  -01 revision for the first time; none of these three changes any
  normative Capsule field or verifier behavior.
- Restores and updates Issuer Binding ({{issuer-binding}}: did:web,
  x5chain, and SPIFFE SVID binding patterns for the `iss` claim) and the
  cross-party assurance rung ({{crossparty}}: `assurance.cross_party_rung`
  and the `approver: "counterparty"` disposition value), both carried
  forward from the prior `-03` candidate (PR #64) and reconciled against
  every feature this revision adds — Observation mode, Observed order and
  concurrency, the Disclosure Envelope companion, and the RFC 6973-grounded
  Privacy Considerations — none of which existed when that candidate was
  first written.
- Adds normative verifier-behavior text for `canonicalization_id` across
  -02/-03 record vintages ({{canonid-transition}}), so a -03 verifier's
  treatment of a Capsule sealed before the field existed is specified
  rather than left to accident.
- Points to producer-local log checkpointing as planned scope for a
  subsequent CPB revision ({{future}}); this document defines no
  checkpointing behavior of its own.

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
: CANONICAL-DIGEST(jcs, P(v)), in the terms of
  {{I-D.mih-sokolov-scitt-payload-binding}} — the CPB `jcs` canonicalization
  algorithm (plain {{RFC8785}} JCS, SHA-256, lowercase hex) applied to a
  value after this profile's own Presence Rule P has been applied
  ({{presence}}). All JSON digests in this profile use this single
  construction. This construction is byte-identical to the prior
  revision's `HEX(SHA-256(JCS(normalize(v))))` for every value this
  profile's Presence Rule accepts, because P performs the same bottom-up
  null/empty-array/empty-object removal `normalize()` did; only the name
  and the document of record for the canonicalization step change
  ({{changes}}).

# Canonical Payload Construction {#canonpayload}

CPB requires every payload class to declare a canonicalization algorithm
and its own presence and representation rules; this section is that
declaration for the Capsule payload class. It states this profile's own
rules and does not restate CPB's mechanics ({{cpb-relationship}}).

## The Presence Rule (P) {#presence}

Before a Capsule value is canonicalized, a producer and a verifier each
apply the Presence Rule: recursively and bottom-up, remove every object
member whose value is JSON null, an empty array (zero elements), or an
empty object (zero members). Array elements are exempt — an element of
an array is never removed by this rule, regardless of its value. Apply
the Presence Rule after any exclusion set required by the computation
(for example, `capsule_id` and chain-linkage fields when computing
`capsule_id` itself, {{identity}}) and before the `jcs` canonicalization
algorithm.

A producer MUST emit values already in Presence-Rule normal form: a
digest-bearing field MUST NOT carry a null, an empty array, or an empty
object member that the rule would remove. A verifier that encounters
such a member in a digest-bearing field MUST treat the Capsule as a
verification failure and SHOULD name the offending member; a producer's
non-conforming output is not silently repaired by re-normalizing it,
because doing so would make two different byte sequences verify
identically. This is a change from the prior revision, where `normalize()`
was a step inside the digest construction that any input passed through
regardless of its own shape ({{changes}}).

## The Representation Rule (R) and number handling {#representation-rule}

Every value entering a Capsule digest MUST already be in a single,
producer-chosen token form: object members carry no duplicate keys;
array element order is the order the producer observed or constructed,
never reordered by a verifier; strings carry no representation choice
this profile leaves open beyond RFC 8785's own string-escaping rules.

Numbers are HYBRID. A producer MUST emit every digest-bearing numeric
quantity as a token in canonical integer form (no exponent notation, no
leading zeros, no `-0`) when the quantity is a count or an identifier,
and as an exact decimal string, never a JSON floating-point literal,
when the quantity is monetary or otherwise requires exact-value
reproducibility ({{identity}}). A verifier applies the value rule — it
compares numeric quantities by value, not by lexical token — because a
standard JSON parser cannot see a digest-bearing field's original
lexical form once parsed, and this profile does not require a
non-standard parser of a Class 1 verifier. This is a declared gap: a
producer that violates the token-form MUST above and a verifier that
applies only the value rule can, in principle, both regard a
non-canonical numeric literal as valid, even though two producers could
have serialized the same value differently and produced different
digests. A verifier operating in an environment where byte-exact input
is available MAY additionally implement a strict tier that inspects the
raw pre-parse bytes and rejects a non-canonical numeric token; this
strict tier is OPTIONAL and its absence does not make a Class 1
verifier non-conforming.

## canonicalization_id {#canonid}

A Capsule MAY carry a `canonicalization_id` field: the name of the
Artifact Type Registry digest context ({{artifacttypes}}) that produced
`capsule_id`. The field is a declaration, not a source of truth: it
confirms the registry entry the producer used and never overrides it. A
verifier that reads a `canonicalization_id` value MUST cross-check it
against the digest context the Capsule's own registered artifact type
and profile version resolve to; a mismatch, an unknown identifier, or an
identifier naming an algorithm withdrawn in the Canonicalization Algorithm
Registry of {{I-D.mih-sokolov-scitt-payload-binding}} is a verification
failure — the verifier MUST fail closed on all three rather than fall
back to resolving the digest context some other way. A Capsule omitting
`canonicalization_id` is not thereby non-conforming: the digest context
is otherwise resolved from the registered artifact type and profile
version alone ({{artifacttypes}}), exactly as before this field existed;
`canonicalization_id` is a redundant, self-describing confirmation, not
a required index. `canonicalization_id` MUST NOT be confused with the
discovery-mirror mechanism of {{I-D.mih-sokolov-scitt-payload-binding}} (an
unprotected-header, advisory field carrying no binding authority);
`canonicalization_id` is a signed payload member and is part of the
record's own claim about itself.

## Verifier behavior across -02/-03 record vintages {#canonid-transition}

This section states, for a Capsule produced under either revision and a
verifier implementing either revision, what a verifier does. The terms
used are:

Pre-id record:
: A Capsule produced before `canonicalization_id` was available to it:
  the record carries no such field.

Post-id record:
: A Capsule produced by a producer that populates `canonicalization_id`,
  declaring by reference the digest context that produced its
  `capsule_id`.

-02-era verifier:
: A verifier implementing only the prior revision of this document. It
  has no knowledge of `canonicalization_id` or the `jcs` digest context
  ({{art-agent-action-capsule}}); it resolves `jcs-n` directly.

-03 verifier:
: A verifier implementing this revision.

| Record vintage | -02-era verifier | -03 verifier |
|---|---|---|
| pre-id | Verifies exactly as under -02: resolves `jcs-n` from the registered artifact type alone. Unaffected by this revision. | Resolves the identifier digest context to `jcs` ({{art-agent-action-capsule}}) — the sole current context, since `jcs-n` is withdrawn — and recomputes `capsule_id` under it. The byte audit accompanying the withdrawal ({{changes}}) established that a pre-id record already in Presence-Rule normal form reproduces, under `jcs`, the identical `capsule_id` `jcs-n` produced at seal time, so verification succeeds without special-casing. A pre-id record among the 12 documented-historical exceptions to that audit is not byte-identical and is treated per the withdrawal record as historical, not as a live conformance case. |
| post-id | Does not recognize `canonicalization_id`. Ignores it under this profile's payload-extensibility posture ({{extensibility}}) and verifies every other check normally. | Cross-checks the declared value against the resolved digest context per {{canonid}}, failing closed on a mismatch, an unknown identifier, or an identifier naming a withdrawn algorithm. |

The invariant governing both cells of the pre-id row, already stated in
{{canonid}} and repeated here because it is what makes the table above
safe: a -03 verifier MUST NOT reject a pre-id record solely for
predating `canonicalization_id`. This document registers only one
artifact type ({{art-agent-action-capsule}}); an artifact type whose
registered history contains exactly one digest context has no
pre-id/post-id ambiguity to begin with, since there is only one
candidate context to resolve to — the ambiguity this section resolves is
specific to `agent-action-capsule` having registered two contexts
(`jcs-n`, now withdrawn, and `jcs`) over its history.

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

## Issuer Binding {#issuer-binding}

A Capsule's `iss` claim (CWT protected header) identifies the producer. Registration
policies SHOULD authenticate that the signing key belongs to the claimed issuer;
three supported binding patterns exist:

1. **did:web** — `iss` is a DID URI; the verifier resolves it at verification time
   to obtain the current signing key. Handles rotation without pinning a certificate.

2. **x5chain** — an X.509 certificate chain in the COSE `x5chain` protected header;
   the leaf's public key MUST match the signing key; the chain is anchored to a
   configured CA trust root.

3. **SPIFFE SVID** — a variant of x5chain in which the leaf MUST carry a SPIFFE ID
   URI in its Subject Alternative Name; `iss` MUST equal that SPIFFE ID URI.
   Trust anchor is a SPIFFE trust bundle. Rotation is SPIRE-managed; the SPIFFE ID
   persists across certificate renewals.

A Capsule whose signing key is a bare, unresolvable `kid` with no `x5chain` and no
resolvable DID maps to a degraded assurance grade in the producing registration policy;
this state MUST be reported, not silenced. The reference anchor
(anchor.agentactioncapsule.org) runs an open registration policy and does not enforce
issuer binding; production deployments SHOULD enforce at least one of the patterns above.
No cross-pattern substitution is valid: a did:web resolution result does not satisfy
x5chain trust-chain verification, and neither satisfies SPIFFE trust-bundle verification.

## Registration and Receipts {#registration}

A producer makes a Capsule transparent by registering its Signed
Statement with a SCITT Transparency Service per
{{RFC9943}} and attaching the returned Receipt
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

This profile is VDS-agnostic at the statement layer. Receipt format and
proof verification are governed by the Verifiable Data Structure (VDS)
of the chosen Transparency Service; this profile imposes no VDS
requirement. RFC9162_SHA256 ({{I-D.ietf-cose-merkle-tree-proofs}}) is
the default neutral VDS used by reference implementations; the CCF
receipt profile ({{I-D.ietf-scitt-receipts-ccf-profile}}) is a
conforming optional alternative. A Capsule submitted to any conforming
SCITT Transparency Service produces a valid Transparent Statement
regardless of which VDS that service employs.

## Outcomes {#outcomes}

An asynchronously observed consequence — a reversal, dispute, correction,
or confirmation — is recorded as its own Signed Statement
(`capsule_statement_type: "outcome"`, content type
`application/agent-action-capsule-outcome+json`) whose `sub` equals the
original action's `sub`. Correlation is by subject and decision id, never
by mutating the original statement: the log is append-only and the
original is immutable.

# Registries of this profile (summary) {#registries}

Eight vocabularies of this profile are registry-governed under a
Specification Required policy ({{RFC8126}}, Section 4.6):
`verdict_class`, `disposition.decision`, `effect.type`,
`irreversibility_class`, `effect_attestation`, `chain.relation`,
`observation_mode`, and `citation_purpose`. The
registries and their initial contents are defined in {{iana}}, kept at
the back of this document per convention.

A separate registry, the Artifact Type Registry ({{artifacttypes}}), is
also hosted by this document as of this revision: it governs the
payload-content vocabulary that a CPB typed digest reference's `type`
field may name ({{I-D.mih-sokolov-scitt-payload-binding}}). It differs
from the eight vocabularies above in shape (a digest-context template,
not a flat token list) and in scope — it is not limited to values this
profile itself defines — and so is addressed on its own in
{{artifacttypes}} rather than folded into the list above.

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
| spec_version | string | REQUIRED | The profile prose version the Capsule conforms to. The value defined by this profile version is "draft-mih-scitt-agent-action-capsule-03"; it tracks the document name and advances with each revision. |
| format_version | string | REQUIRED | The serialization-suite version of the envelope. The value defined by this profile version is "2"; the value reflects the pre-IETF reference-implementation serialization lineage this profile inherits, which is why a -00 document begins at "2" rather than "1". |
| capsule_id | string (64 hex) | REQUIRED | JSON-DIGEST of the canonical capsule form: the envelope minus capsule_id and chain-linkage fields, after the Presence Rule ({{presence}}). Content-addresses the envelope. |
| action_id | string | REQUIRED | Stable identifier of the action; unique within one producer ledger. |
| action_type | string | REQUIRED | "fyi" (informational) or "decide" (a disposition was required). |
| operator | string | REQUIRED | The accountable tenant the action was performed for. |
| developer | string | REQUIRED | The agent identity and version that performed the action. |
| timestamp | string | REQUIRED | {{RFC3339}} UTC with "Z" suffix. |
| epoch_id | string | OPTIONAL | An operator-assigned epoch identifier, stable within one operational configuration of the agent system. Producers SHOULD populate this field and rotate its value — together with an epoch-boundary Capsule ({{epochs}}) — when a configuration change that materially alters agent behavior occurs (for example, a model-version swap, a policy-manifest revision, or a significant constraint-schema change). A verifier or ledger consumer scopes a history window to a specific operational configuration by filtering on operator and epoch_id. Absent epoch_id implies a single, unnamed epoch; a producer MUST NOT back-fill epoch_id on Capsules already sealed. |
| canonicalization_id | string | OPTIONAL | The Artifact Type Registry digest-context name that produced capsule_id ({{canonid}}). A self-describing confirmation, not a required index. |
| conversation_ref | typed digest reference | OPTIONAL (REQUIRED when applicable) | A CPB typed digest reference citing the enclosing conversation-grain record when the action was sealed inside one ({{conversationbinding}}). |

Monetary and quantity values anywhere in a Capsule MUST be exact decimal
strings, never JSON floating-point numbers; digests are not reproducible
across implementations otherwise. This is the Capsule-specific instance
of the Representation Rule ({{representation-rule}}).

## Configuration epochs {#epochs}

A configuration epoch is the contiguous sequence of Capsules produced by
one agent configuration — one model version, one policy-manifest version,
one runtime variant — before any of those configuration dimensions changes.
Epochs exist because a model swap or policy revision is a behavioral
discontinuity; without a recorded epoch boundary, pre- and post-change
history blend silently and a verifier cannot scope a query to "the current
configuration."

### The epoch_id field

The `epoch_id` payload field ({{identity}}) carries the current epoch
identifier. It is committed to `capsule_id` and is therefore tamper-evident.
Producers that operate across multiple epochs SHOULD populate `epoch_id` and
rotate its value on every configuration change. Producers that do not
anticipate epoch changes MAY omit it; absent `epoch_id` implies a single,
unnamed epoch.

A producer MUST NOT assign the same `epoch_id` value across a configuration
boundary. The invariant "all Capsules sharing an operator and epoch_id were
produced under the same configuration" is what makes epoch-scoped history
queries meaningful; violating it makes pre- and post-change records
indistinguishable by `epoch_id` alone.

### Epoch-boundary Capsules {#epochboundary}

When an epoch opens, a producer SHOULD emit a single epoch-boundary Capsule
before resuming normal action recording. An epoch-boundary Capsule is a
regular Capsule (no new statement type) with:

- `action_type: "fyi"` (it is an administrative record, not a decided
  action);
- the **new** `epoch_id` value — the epoch it opens;
- `chain.relation: "epoch_opens"` linking to the last Capsule produced
  under the prior epoch (registry-governed, {{iana}}); and
- a RECOMMENDED `model_attestation` block ({{identity}}) recording the
  new model and provider, so the transition is commit-addressed and verifiable
  from the Capsule's own bytes.

An epoch-boundary Capsule MAY additionally carry `disposition.verdict_class:
"epoch_boundary"` (registry-governed, {{iana}}) and a `reason_digest`
committing to a machine-readable record of what changed — at minimum the
prior `epoch_id`, the new model identity, and the new policy-manifest
version — so that a verifier can distinguish a configuration-change record
from an ordinary `fyi` action.

### Epoch-scoped verification {#epochverify}

A verifier scoping a query to a specific epoch filters by `operator` and
`epoch_id`. An epoch-boundary Capsule carrying `chain.relation: "epoch_opens"`
marks the temporal left edge of that epoch; the next epoch-boundary Capsule
whose chain parent lies within this epoch marks its right edge. A verifier
SHOULD report, as an informational finding, any action Capsule whose
`epoch_id` differs from the prevailing epoch established by the most recent
epoch-boundary Capsule for that operator; such a discrepancy is not a
verification failure (an epoch change mid-stream is not structurally
non-conforming), but it is evidence that a configuration boundary occurred
without a corresponding epoch-boundary Capsule.

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
protected-header (CWT claim) position is an explicit candidate for a
future revision, to be decided once real transparency-log consumers
exist. This version deliberately claims no header-level visibility for
the grade.

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

### Cross-party assurance {#crossparty}

A Capsule's evidentiary weight along the *counterparty* dimension — how
much of a counterparty's own attestation is structurally present in this
record — is a fourth, orthogonal claim: `assurance.cross_party_rung`. It
is a new axis, not a new value folded into `attestation_mode`, for the
same reason {{orthogonality}} already gives for keeping `verdict_class`
and `effect_mode` separate: `attestation_mode` answers "has this record
been committed to an independent transparency log" (log custody);
`cross_party_rung` answers "how much of the counterparty's own signed
evidence is bound into this record" (exchange evidence). These are
independent facts a producer can hold in any combination — a
`self_attested` record can still be `full_bilateral` (both parties signed,
neither side anchored yet), and an `anchored` record can still stand on
`unilateral_fallback` evidence alone (a solo attestation that was
independently anchored). Folding a `countersigned` value into
`attestation_mode` would collapse these two facts into one claim and make
that combination inexpressible, so this profile keeps them orthogonal.

`cross_party_rung` takes one of three values, ordered
`unilateral_fallback` < `acknowledged_receipt` < `full_bilateral` for
overclaim detection — the same never-grades-up discipline
{{assurance}} already applies to `attestation_mode`, `effect_mode`, and
`ledger_mode`:

| cross_party_rung | Meaning |
|---|---|
| unilateral_fallback | Only the initiator's own signed half is present; no counterparty evidence, or the counterparty was unreachable or its half did not verify. |
| acknowledged_receipt | A counterparty reference and correlator are present and well-formed: the counterparty cryptographically acknowledged receipt, but the referenced half carries no substantive co-signed result. |
| full_bilateral | A counterparty reference and correlator are present and well-formed, and the referenced half is marked as carrying a substantive co-signed result — both parties' evidence is bound to the same exchange. |

`cross_party_rung` is REQUIRED when a `cross_party` evidence block (below)
is present, and both are OPTIONAL on a Capsule with no cross-party
exchange. A producer MUST NOT claim a `cross_party_rung` its evidence does
not support. A Class-1 verifier independently rederives the highest rung
the `cross_party` block supports and reports any claim above the derived
rung as an `assurance_overclaim` ({{verification}}), downgrading the
reported derived rung to the value the evidence actually supports — the
same treatment {{verification}} already gives an overclaimed
`attestation_mode` or `ledger_mode`.

A Capsule that participates in a cross-party exchange carries an OPTIONAL
top-level `cross_party` block:

- `initiator_ref` (REQUIRED when the block is present): a JSON-DIGEST
  ({{conventions}}) of the initiator's own signed half. A bare
  intra-profile digest, not a CPB typed digest reference ({{effect}}).
- `counterparty_ref` (OPTIONAL): a JSON-DIGEST of the counterparty's
  signed half. Its absence means no usable counterparty evidence was
  obtained — the counterparty was unreachable, or its half did not verify
  at the layer that checked it.
- `correlator` (REQUIRED when `counterparty_ref` is present): an opaque
  profile-native correlation string joining `initiator_ref` and
  `counterparty_ref` to the same exchange — the same kind of "opaque
  correlation string" primitive `external_ref` already uses ({{effect}}),
  not a CPB reference.
- `substantive` (OPTIONAL boolean, meaningful only when `counterparty_ref`
  is present): true only when the counterparty's referenced half carries a
  substantively co-signed result rather than a bare receipt of the
  initiator's half.

A verifier derives `cross_party_rung` from this block's own bytes alone,
never by dereferencing the digests it cites: `unilateral_fallback` when
`counterparty_ref` is absent or malformed; `acknowledged_receipt` when
`counterparty_ref` and `correlator` are both present and well-formed but
`substantive` is absent or false; `full_bilateral` when
`counterparty_ref` and `correlator` are both present and well-formed and
`substantive` is true. This is a structural check, the same kind
{{assurance}} already uses to derive "chained" from the mere presence of a
well-formed `chain` block — it does not verify the counterparty's
underlying signature itself, which is a substrate concern by reference
({{verification}}), mirroring how this layer never derives `anchored`.
The two-party wire encoding this rung summarizes — the initiator and
counterparty attestation halves, their signatures, and the handshake that
produces them — is the companion
{{I-D.mih-agent-bilateral-attestation}}'s concern, not this profile's;
this profile carries only the rung claim and the minimal correlation
evidence needed to rederive it honestly.

## Observation mode {#observationmode}

A Capsule MAY carry a `compute_attestation` map: producer-environment
claims, digested with the rest of the payload — every member
participates in the `capsule_id` digest and sits under the Signed
Statement's signature, so the claims are tamper-evident even though
they are testimony. The reference implementation already carries this
map; this document defines its first registered member.
`observation_mode` states how the producer observed the action it
sealed. Two values are defined: `in_path` — the producer executed in
the action's own path and bound input and output from its own
position: a callback, a decorated tool, or a wire-level intermediary
the action traverses (a gateway sealing at the boundary) — and
`event_stream` — the producer observed the runtime's event narration
after the fact and paired input to output from that narration. The
distinction is provenance, not a quality score: under identifier-less
concurrency an event-stream producer's input-to-output pairing is
best-effort, and this field makes that proximity legible to the
consumer, who decides what weight the pairing guarantee deserves.

Like the assurance modes, `observation_mode` is producer testimony —
but unlike them it is not independently rederivable from the record,
which is precisely why it is recorded rather than inferred. The
adversarial consequence is stated plainly: a producer can claim a
proximity it did not have, and the signature proves the claim was
made, not that it is true. The field therefore shifts evidentiary
weight only downward — a verifier MAY discount event-stream pairing,
but MUST NOT grant `in_path` any additional cryptographic assurance
on the field's word alone. Proximity claims become verifiable only by
composition with platform attestation, which is the registry's growth
path: the value set is deliberately open, governed under the same
Specification Required policy as the other vocabularies of this
profile ({{registries}}), so stronger proximities — an in-path
producer whose position is itself platform-attested — register as
they mature. An absent `observation_mode` means unstated; a verifier
treats an unrecognized value the same way — informational, unstated —
and MUST NOT reject a Capsule for stating, omitting, or carrying an
unrecognized value.

`compute_attestation` MAY additionally carry `agent_input_digest` and
`agent_output_digest`, each a JSON-DIGEST ({{conventions}}) of the raw agent
input or output content associated with this action. Like other
`compute_attestation` members these digests are digested with the rest of
the payload and are therefore tamper-evident, but the content they commit
to is not itself carried in the Capsule. A producer that later wishes to
reveal that content to a specific verifier, without altering `capsule_id`
or the signed bytes, does so with the companion Disclosure Envelope
mechanism of {{I-D.mih-scitt-agent-action-capsule-disclosure-envelope}},
which wraps the unmodified Capsule alongside an out-of-band `disclosures`
object and defines the verifier's digest-recomputation checks.

## Disposition and the verdict reason-class {#disposition}

A Capsule's `disposition` block records how the decision was disposed:

- `decision` (REQUIRED): "accept", "reject", "needs_input", or "deferred"
  (registry-governed, {{iana}}).
- `approver` (REQUIRED): a closed enum, exactly "human", "policy", or
  "counterparty". The value domain is fixed by this specification (not
  registry-governed); an unknown approver value is not a conforming
  Capsule. Unlike the registry-governed vocabularies of this document
  ({{iana}}), `approver` stays a closed three-member enum after this
  addition — never a registry an implementation is expected to extend by
  registration.
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

- `approver: "counterparty"` (see {{crossparty}}) records that a
  counterparty to a cross-party exchange, rather than this operator's own
  human or policy, disposed the decision. The honesty invariant above is
  unaffected: `human_disposed: true` still REQUIRES `approver: "human"`,
  so a counterparty disposition is never claimed as human-in-the-loop.

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
| epoch_opens | Non-terminal: this Capsule opens a new operational epoch. The chain parent is the last Capsule produced under the prior epoch. The opening Capsule carries the new epoch_id ({{epochboundary}}); the prior epoch's last Capsule is the parent. |

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

### Observed order and concurrency {#order}

The chain block's single parent is intentional and remains so:
`chain` records state transitions — supersession, epoch openings —
and its authority rules ({{hitl}}) assume exactly one parent.
Observed order is a different claim, and it gets a different, optional
structure. A Capsule MAY carry a digested `order` block with two
members, separately optional:

`follows` — a list of `capsule_id` values naming the Capsules whose
completion the producer actually observed before this action began.
This expresses fan-in ("this followed several") without general graph
semantics: no edge typing, no transitive claims, only direct observed
precedence.

`concurrency_group` — an opaque value shared by a set of Capsules
whose mutual order the producer does not assert. Sealing is
sequential per producer even when actions are not; a runtime that
seals concurrent actions in completion order would otherwise write a
linear sequence that never existed. The group marker tells a consumer
exactly what not to infer. The group value MUST be opaque and freshly
generated — a random value scoped to the group, never a reused
internal identifier — since it is baked irreversibly into the record;
the admission rules of {{privacy}} apply to it as to any clear field.

The invariant: a producer MUST NOT assert order it did not observe.
Seal order and ledger order are storage facts, not causal claims, and
a consumer MUST NOT infer sequence among Capsules sharing a
`concurrency_group`. Completion order is not causal order. The
converse discipline also holds: a producer that observed an order
SHOULD record it rather than mark the set unordered — concealing
observed sequence is the same honesty failure in the other
direction.

One structure spans the scales this problem appears at. A runtime
sealing parallel tool calls marks the set with one
`concurrency_group`. A join step `follows` the several Capsules it
actually waited for. And across organizations, a bilateral
completion attestation is fan-in by design — both parties'
attestations precede it — and the `order` block gives that shape a
native expression: the bilateral companion
(cf. {{?I-D.mih-agent-bilateral-attestation}}) is the intended first
user, its reference implementation today chaining to a single parent
until its wire encodings are fixed. Intra-agent parallelism and
cross-organization exchange are the same partial-order question at
different radii, and they share this one primitive. Full DAG
semantics — typed after/concurrent-with edges, transitive closure —
remain future work; `follows` plus `concurrency_group` eliminate the
false-sequence inference without general graph verification.

### Cross-record references {#xref}

`chain` and `order` both presuppose the cited Capsule is this
producer's own: `chain` is scoped to same-custody-stream, single-parent
state transitions ({{hitl}}), and `order` records what this producer
itself observed among its own Capsules ({{order}}). Neither has a shape
for citing a record outside that stream — a different producer's
Capsule, a different order's dispatch, or any other artifact this
Capsule's action was performed on or in response to. A Capsule MAY
carry a digested `references` array for exactly that case; absent, or
(per the Presence Rule, {{presence}}) empty, means the Capsule makes no
such citation. Unlike `chain`, `references` participates in the
`capsule_id` digest like any other payload content ({{art-agent-action-capsule}}):
citing a record is itself a claim this Capsule's signature covers.

**Boundary rule.** `chain` is exclusively the producer's own same-stream
parent and is the only field {{assurance}}'s `ledger_mode` derivation
reads. `references` is exclusively for everything else. A `references`
entry MUST NOT name the same target as `chain.parent_capsule_id` — a
producer citing its own same-stream parent states that once, in
`chain`, never redundantly in `references`.

**Shape.** Each `references` entry's identity is a CPB typed digest
reference {{I-D.mih-sokolov-scitt-payload-binding}}: `{type, digest_alg,
digest}`. `type` names an Artifact Type Registry entry; a Capsule citing
another Capsule sets `type: "agent-action-capsule"`, resolving to this
document's own entry ({{art-agent-action-capsule}}) with zero additional
CPB-layer registration — the same mechanism already used for
`conversation_ref` ({{conversationbinding}}). A reference MAY instead
cite a record of any other registered artifact type; this document
defines the shape, not an exhaustive list of what may be cited.

A reference MAY additionally carry `log_coordinates`, an object
`{log_id, leaf_index, inclusion_proof}`, present as a unit when the
cited record has been registered to an append-only log a verifier can
consult. `log_coordinates` is an upgrade, not a second identity: it
proves the exact referenced bytes were found at the stated log
position, and its presence or absence never changes what `type` +
`digest_alg` + `digest` already identify. Producer-local log
checkpointing is future scope at the CPB binding layer, not this
document ({{future}}); until that mechanism is specified, a Class 1
verifier treats a present `log_coordinates` member as structurally
recorded and MUST NOT report it as independently verified, the same
present-but-unverified treatment {{conversationbinding}} already applies
to a `conversation_ref` with no resolvable registry entry.

**Citation purpose.** A `references` entry MAY carry `citation_purpose`,
a registry-governed (Specification Required, {{iana}}) string stating
why this Capsule cites the target. `citation_purpose` is a distinct
vocabulary from CPB's own `purpose` field on a typed digest reference:
CPB's `purpose` selects among an artifact type's registered digest
contexts and is orthogonal to any role a companion profile assigns a
digest within a cross-document citation
{{I-D.mih-sokolov-scitt-payload-binding}} — `agent-action-capsule`
registers exactly one digest context, so CPB's `purpose` is always
absent on a Capsule-to-Capsule reference, and `citation_purpose` is
this profile's own, separately-named field for the citing relationship,
never a repurposing of CPB's field. The seeded vocabulary:

| citation_purpose | Meaning |
|---|---|
| acted_on | This Capsule's action targeted, consumed, or was performed against the cited record's declared content — a stream boundary, not a custody claim: the cited record may belong to a different producer or stream entirely, and citing it asserts only that this action is about that content, never that the citing producer holds or continues its custody. |
| responds_to | This Capsule addresses or answers the cited record without a same-stream chain relationship to it — the cited record is not this Capsule's `chain.parent_capsule_id` and MAY be a different order, a different producer's dispatch, or otherwise outside this producer's own stream. |

Designated-expert guidance: both seeded values name a cross-stream or
cross-order citation intent that `chain.relation` cannot express because
`chain.relation` is scoped to same-stream transitions ({{hitl}}). A
producer whose citation is a same-stream state transition over its own
parent uses `chain` instead and never mints a `references` entry for it
(the boundary rule above). Additional `citation_purpose` values are
expected future registrations, each admitted once its semantics are
pinned in a publicly available specification, per this document's
Specification Required policy ({{iana}}).

**Relation to `chain.relation`'s `confirms` value in deployed
implementations.** A cross-stream or cross-order citation — for example,
a denial Capsule addressing a prior dispatch that is not its own chain
parent — is not a same-stream state transition and so is not a
`chain.relation` value under this profile; `chain.relation` registers no
value for it, and none is added by this revision. Such a citation is a
`references` entry with `citation_purpose: "responds_to"` (or
`"acted_on"`, if it is the affirmative case). An implementation using
`chain` with a `confirms`-shaped relation for a citation that is not the
same-stream parent is not using `chain` as this document defines it;
the compatible migration is a `references` entry with the appropriate
`citation_purpose`, not a fourth `chain.relation` value.

# Class 1 verification {#verification}

Verification has two tiers. Substrate verification — the issuer's
COSE_Sign1 signature, and for the transparent tier the Receipt's
inclusion proof and Transparency Service signature — is performed by
reference to {{RFC9052}}, {{RFC9943}}, and
{{I-D.ietf-cose-merkle-tree-proofs}}; this profile does not respecify it.

The agent-profile checks below are normative here and constitute Class 1
verification ({{conformance}}): every check is performable from the
Signed Statement, the Capsule payload, the registry contents
({{registries}}), and — for the chain checks — the producer's store of
Capsules; no other input is needed. A verifier MUST return a structured
result, never throw; a single `ok` boolean gates trust in every other
reported field; findings are reported in a fixed order.

1. Structural: REQUIRED fields present and typed; no floating-point
   values in digest-bearing fields; no null, empty-array, or
   empty-object member present in a digest-bearing field — the Presence
   Rule ({{presence}}) is a producer-side MUST, and a verifier finds a
   violation by inspection, not by digest mismatch, since recomputation
   would otherwise silently absorb it.
2. Identity: recompute `capsule_id` over the canonical capsule form and
   compare; when `canonicalization_id` ({{canonid}}) is present, cross-
   check it against the resolved digest context and fail closed on a
   mismatch, an unknown identifier, or an identifier naming a withdrawn
   algorithm.
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
   concurrent supersedes surface as findings per {{hitl}}. A
   `references` entry ({{xref}}) is a different claim: it is informational
   cross-stream or cross-order correlation, never a chain-integrity input,
   and a verifier MUST NOT treat a `references` entry naming an
   unresolvable or absent target as a chain-semantics failure — only a
   `references` entry that duplicates `chain.parent_capsule_id` is a
   failure, per the boundary rule of {{xref}}.
7. Assurance reconciliation: rederive the assurance modes from evidence
   actually verified; report overclaims.
8. Unknown registry values (`verdict_class`, `decision`,
   `effect.type`, `irreversibility_class`, `effect_attestation`,
   `chain.relation`, `citation_purpose`): report as informational
   findings; MUST NOT reject ({{iana}}). An unknown `effect_attestation`
   is additionally graded no stronger than `runtime_claimed` ({{effect}}).

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
approver value outside `{human, policy, counterparty}` is non-conforming
by construction and so is absent from the unknown-registry-value
reporting of check 8.

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
verifier while concealing both the values and the existence of
unrevealed fields, a per-field selective-disclosure mechanism is needed.
This profile reserves an extension point in the Capsule payload for such
a mechanism. The intended field-level technique follows the SD-JWT
selective-disclosure model {{RFC9901}} — salted-hash commitments over
JCS-canonicalized arrays — because the Capsule payload is JSON; it is
written to stay aligned with SPICE's SD-CWT {{I-D.ietf-spice-sd-cwt}}
(the CBOR sibling) for SCITT-ecosystem consistency.

The complete normative profile of this extension — including the
commitment encoding, disclosure syntax, and verifier checks — is defined
in the companion Internet-Draft {{I-D.mih-scitt-agent-action-capsule-selective-disclosure}}.
That document profiles the `_sd_alg` / `_sd` payload vocabulary, the
salted-hash commitment construction over JCS-serialized disclosure arrays,
the decoy-digest mechanism, the set of eligible fields, and the ordered
verifier check set (SD-1 through SD-6 plus integration with the base
Class 1 and Class 2 checks).

Implementations of this profile version MUST NOT generate or interpret
selective-disclosure payload structures unless they additionally implement
{{I-D.mih-scitt-agent-action-capsule-selective-disclosure}}: the extension point is
defined only in that companion, and no conformance claim or verification
behavior is defined for it in this document.

## Binding to conversation-grain records {#conversationbinding}

An agent action frequently occurs inside a multi-turn conversation
between an agent and a counterparty, a user, or another agent.
{{I-D.birkholz-verifiable-agent-conversations}} (Verifiable Agent
Conversations, VAC) defines a conversation-grain Signed Statement for
exactly this container. A Capsule and a VAC record are complementary,
not competing: a Capsule records what one action did; a VAC record
records the conversation that action occurred within. This document
states the Capsule-side binding normatively; it does not, and cannot on
its own, make the binding independently verifiable, because that
additionally requires an Artifact Type Registry entry for the VAC
record ({{artifacttypes}}), which is a separate registration act by that
document's own editors.

A producer whose runtime sealed an action inside a VAC-conveyed
conversation MUST populate `conversation_ref` ({{identity}}) with a CPB
typed digest reference {{I-D.mih-sokolov-scitt-payload-binding}} citing
the conversation's Signed Statement; a producer MUST NOT omit
`conversation_ref` when the runtime observed such an enclosing
conversation. `conversation_ref` is otherwise absent — an action with no
observed enclosing conversation carries no reference to fabricate one
against.

Until an Artifact Type Registry entry for the VAC conversation record
exists, a verifier resolving a populated `conversation_ref` follows
{{I-D.mih-sokolov-scitt-payload-binding}}'s rule for an unregistered
`type`: the citation is structurally present and recorded, but not
verified — it is not evidence, and its presence is not a defect in the
Capsule. The requirement to populate `conversation_ref` above binds a
producer regardless of registry state; only the verifier's ability to
independently confirm the citation depends on the registry entry's
completion, which this document does not control.

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
substrate. {{I-D.kamimura-vap-framework}}, by the same author, is a
conformance-tiered Verifiable AI Provenance framework (hash-chaining,
signatures, SCITT anchoring, and a completeness invariant) under which the
trading profile sits; it shares this profile's SCITT-anchored,
third-party-verifiable substrate, framed as a provenance architecture
rather than a per-action verdict record. {{I-D.dawkins-scitt-ai-article50}}
profiles SCITT receipts
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

{{NotarizedAgents}} defines receiver-attested confidential agent-action
receipts registered on a witness-cosigned Merkle log. This profile
differs in providing self-and-counterparty bilateral attestation — each
party holds proof of the other's commitment — over a SCITT-neutral
anchor, with an explicit disposition vocabulary (executed, blocked,
denied, timeout, errored, deferred, expired, escalated) that
distinguishes outcome categories rather than receiver attestation alone.
The companion Internet-Draft {{I-D.mih-agent-bilateral-attestation}}
profiles the two-party extension.

{{ERC8004}} defines on-chain identity, reputation, and validation
registries for AI agents on a public blockchain. This profile differs in
that payload content is content-private — only digests and timestamps are
anchored, never payloads or PII — and the transparency log is off-chain-anchorable
to any conforming SCITT service, separating conduct evidence from the
on-chain content-public constraint of registry entries.

Mastercard Verifiable Intent ({{VerifiableIntent}}) records a signed
intent-to-act over a checkout-authorization chain. This profile
complements it by recording general-purpose conduct, obligation, and
refusal verdicts in an agent-to-agent lane, anchored to a neutral
transparency log, without being coupled to a specific payment or
checkout context.

{{I-D.rampalli-scitt-capsule-provenance-binding}} binds a per-action
delegation-authorization decision and provenance references into an Agent
Action Capsule via namespaced payload extensions that leave the core fields
untouched, recording that an action was taken under a stated authorization
without asserting the authority. This specification is complementary; the
profile is deliberately agnostic to the delegation mechanism, and such
bindings compose by shared action digest.

# Future Work {#future}

The companion Internet-Draft {{I-D.mih-agent-bilateral-attestation}}
defines a bilateral attestation extension in which two parties
independently seal Capsules over a shared action digest, each holding
proof of the other's commitment. The extension reuses this profile's
disposition vocabulary (executed, blocked, denied, timeout, errored,
deferred, expired, escalated) and anchors both seals to a conforming
SCITT Transparency Service, so a third party trusting neither signatory
can verify the record end-to-end. Statement-type and verdict-class
values reserved in this document for that extension are governed by
the registries in {{iana}}.

The companion Internet-Draft {{I-D.mih-scitt-agent-action-capsule-selective-disclosure}}
normatively profiles the selective-disclosure extension point reserved in
{{selectivedisclosure}}, specifying the per-field commitment structure,
disclosure syntax, eligible fields, and verifier checks, aligned with
{{I-D.ietf-spice-sd-cwt}}.

Producer-local log checkpointing — a producer that maintains a local
append-only log of Capsules periodically emitting signed, TS-registered
checkpoints (log size, a Merkle Mountain Range peaks digest, monotonic
consistency with the prior checkpoint, a declared cadence and lag policy,
and independent witness countersignatures) so that a rollback of
already-witnessed records is detectable by any party holding a prior
checkpoint — is planned scope for a subsequent revision of
{{I-D.mih-sokolov-scitt-payload-binding}}, which is where this capability
belongs as a payload-neutral binding-layer facility rather than a
Capsule-specific one ({{cpb-relationship}}); this document does not
define it and takes no dependency on it.

# Artifact Type Registry {#artifacttypes}

This section hosts the Artifact Type Registry: the registry of the
artifact types that may appear in the `type` field of a CPB typed digest
reference {{I-D.mih-sokolov-scitt-payload-binding}}. Per the charter
scoping that separates CPB's binding mechanism from the payload-content
vocabularies that use it, this registry moves here from CPB as of this
revision; CPB retains only the canonicalization-algorithm registry. The
registration template, the purpose-label vocabulary a multi-context
artifact type's digest contexts draw from, and the resolution rules a
verifier applies to a `type` (and, where needed, `purpose`) value remain
CPB's mechanism and are not restated here — see
{{I-D.mih-sokolov-scitt-payload-binding}} for the full template and the
present-but-not-verified handling of an unregistered `type`.

This registry's hosting by this document is a charter-scope consequence,
not a scope narrowing of the registry itself: any party MAY register an
artifact type here under the same Specification Required policy and the
same third-party-registration rules CPB defined, whether or not the
artifact type is a Capsule-family record. The two entries below are the
entries carried over from CPB's registry as of this revision.

## `agent-action-capsule` {#art-agent-action-capsule}

Reference: this document.

Digest context (`identifier`):

* Profile version: `draft-mih-scitt-agent-action-capsule-03` and later
  revisions that do not change this digest context.
* Canonicalization algorithm: `jcs` (plain RFC 8785, no normalization
  pass) applied after this profile's own Presence Rule ({{presence}}).
* Field set: all capsule fields.
* Exclusion set: `{capsule_id, chain}`.
* Domain separation: none.
* Pre-image encoding: JCS UTF-8 octets, per `jcs`.
* Representation: 64-char lowercase hex.

This digest context supersedes the prior revision's `jcs-n`-algorithm
context. The two are byte-identical for every value already in this
profile's Presence-Rule normal form ({{presence}}), because Presence and
`jcs-n`'s normalization pass perform the same bottom-up removal; the
change is which document defines the removal step and what the
combination is named, not what bytes it produces ({{changes}}). `jcs-n`
is withdrawn in the current revision of
{{I-D.mih-sokolov-scitt-payload-binding}}; a Capsule or reference naming
it MUST be treated as unverifiable per that document's fail-closed rule
for a withdrawn algorithm.

## `machine-mandate` {#art-machine-mandate}

Owner: Anton Sokolov, Tyche Institute. Reference: `tyche-institute/machine-mandate`
@ `524e6a3129b7f1ab850dd9471967458d3cb6f4cd`. This entry is carried over
from CPB's registry unchanged in substance; its provenance, disclosure,
and vector pins remain as CPB recorded them, and this document does not
restate or re-confirm them independently. This entry is not a
Capsule-family artifact type; it is hosted here solely because this
document is now the Artifact Type Registry's host document under the
charter split ({{cpb-relationship}}), and remains the owner's construction
in every other respect.

Digest context (`identifier`):

* Profile version: N/A
* Canonicalization algorithm: `as-transmitted`
* Field set: byte-boundary selector — the issuer-signed JWS component of
  the SD-JWT (RFC 7515 §7.1 compact serialization; the first
  `~`-separated component exactly as transmitted); everything after the
  first `~` (salted disclosures and the KB-JWT) is outside the pre-image.
* Exclusion set: N/A — `as-transmitted` has no field set and therefore
  no exclusion set.
* Domain separation: none.
* Pre-image encoding: N/A — the pre-image is the exact transmitted
  octets.
* Representation: bare 64-char lowercase hex.

Digest context (`equivalence`):

* Profile version: N/A
* Canonicalization algorithm: `jcs`
* Field set: `{action_id, outcome}`, closed.
* Exclusion set: none.
* Domain separation: none.
* Pre-image encoding: JCS UTF-8 octets, per `jcs`.
* Representation: `sha256:` + 64-char lowercase hex, as carried in the
  in-document `action_hash` claim.

Conformance vectors: `tyche-institute/machine-mandate`, branch
`feat/cpb-registry-vectors-v0.1`, commit `5605783a` (supersedes
`640f2a668cfc4a357f9b34ecb0add5faf8bbdda1`),
`vectors/cpb-registry/machine-mandate-vectors-v0.1.json`, file SHA-256
`06572fccb7afa3eda4c68604221a83476faac8f8509b7165724553d58384d816`.

Proposed Artifact Type entries awaiting their owners' confirmation
continue to be tracked in the source repository's provisional-registry
document, independent of which document hosts the live tables.

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
Parameters", containing the registries below. The registration
policy for each is Specification Required ({{RFC8126}}, Section 4.6).
The Artifact Type Registry ({{artifacttypes}}) is requested as a
separate registry, migrated from {{I-D.mih-sokolov-scitt-payload-binding}}
under the charter split ({{cpb-relationship}}); it is not one of the
registries in this group, since its scope is not limited to vocabulary
this document itself defines.

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

Binding invariant for all eight registries: verifiers MUST treat
unregistered values as informational and MUST NOT reject a Capsule for
carrying one. Registration governs shared meaning, never acceptance.

Initial contents are the seeded values of this document, verbatim:

1. "verdict_class" registry ({{verdictclass}}): executed, blocked,
   hitl_dispatched, denied, timeout, errored, engine_failure, deferred,
   needs_decision, expired, escalated, resolved, epoch_boundary.
   The `deferred` token's semantics are OWNED by this registry; the
   entry of the same spelling in the "disposition.decision" registry is
   a cross-reference to it. The `epoch_boundary` token denotes an
   administrative Capsule (`action_type: "fyi"`) that marks a
   configuration-epoch transition ({{epochboundary}}); it REQUIRES
   `effect_mode: "not_applicable"` (no effect is dispatched by an
   administrative epoch record).
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
6. "chain.relation" registry ({{hitl}}): supersedes, epoch_opens.
   Designated-expert guidance: `supersedes` is the single terminal
   relation; `epoch_opens` is a non-terminal relation for configuration-
   epoch boundaries ({{epochboundary}}). Additional non-terminal
   relations (for example, deposit-toward-open and effort-toward-open
   relations, or amends / contradicts) are expected future registrations,
   each admitted once its semantics and any verifier consequence are
   pinned in a publicly available specification.
7. "observation_mode" registry ({{observationmode}}): in_path,
   event_stream.
   Designated-expert guidance: `in_path` and `event_stream` record
   observation posture, not assurance quality — both are producer
   testimony and carry no additional cryptographic guarantee beyond the
   Signed Statement's signature. Future registrations SHOULD state
   whether the mode implies any ordering or sequencing constraint on the
   sealed action.
8. "citation_purpose" registry ({{xref}}): acted_on, responds_to.
   This registry is distinct from, and never a repurposing of, CPB's own
   `purpose` field on a typed digest reference
   ({{I-D.mih-sokolov-scitt-payload-binding}}), which selects among an
   artifact type's registered digest contexts and is orthogonal to any
   role a companion profile assigns a digest within a cross-document
   citation. Designated-expert guidance: both seeded values name a
   citation whose target is outside the citing Capsule's own chain and
   order — a different producer, a different stream, or a different
   order's dispatch ({{xref}}); a citation to the producer's own
   same-stream `chain` parent is never expressed here. Additional values
   are expected future registrations, each admitted once its semantics
   are pinned in a publicly available specification.

Interim registry of record: until this document is published as an RFC,
the registry of record is the `REGISTRY.md` file of the source
specification repository, seeded with the same initial contents and the
same policy; on publication the IANA registries become the registry of
record. Change controller: Action State Group, Inc. (interim); the IETF
on publication.

## Artifact Type Registry (registry request) {#iana-art-request}

IANA is requested to create the Artifact Type Registry described in
{{artifacttypes}}, under Specification Required policy
({{RFC8126}}, Section 4.6), with a Designated Expert. Entries are
immutable: a behavior change registers a new entry rather than modifying
an existing one, consistent with the immutability rule
{{I-D.mih-sokolov-scitt-payload-binding}} states for this registry.
This request migrates the registry from CPB per the charter split
({{cpb-relationship}}); it does not by itself relocate the interim
living record from wherever it is currently kept, which remains an
implementation and process decision for the document editors rather
than a normative statement of this document.

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
  ({{RFC9943}}) producers and verifiers recording and
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
  ({{RFC9943}}) producers and verifiers recording
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

Input integrity is a composable upstream concern. This profile records
what the producer observed and bound at seal time; it does not
authenticate the provenance of inputs delivered to the agent before
sealing. A response spoofed on-path induces an honest `confirmed`
Capsule for an effect that did not land. Input integrity — binding the
authenticity of request bytes and upstream grounding sources to the
authorization before the seal — is a separate guarantee that composes
with this profile at the digest layer: a producer that holds
input-integrity evidence (a signed tool response, an attested transport
record, a C2PA-style content credential, or an action-body HMAC with
memory provenance attestation) MAY reference it by digest in the Capsule
payload, preserving the verifier's disinterest — the verifier checks the
binding without trusting the producer's claim about upstream systems it
cannot observe. This profile partially addresses the grounding dimension
via the `value_grounded` constraint ({{constraints}}), which checks that
a quoted value matches its cited source, and via `model_attestation`
({{identity}}), which constrains the emitter identity. The remaining
input-integrity surface is out of scope for this profile and is addressed
by composing a dedicated input-integrity mechanism upstream.

Payload-level identity is stable across signing-key rotation. The
`operator` and `developer` fields in the Capsule payload ({{identity}})
are plain strings committed to the `capsule_id` digest. They are
independent of the signing key: a producer that rotates its COSE signing
key (and therefore changes the `iss` claim in the protected header) without
changing `operator` or `developer` preserves payload-level identity
continuity across the rotation. A verifier accumulating long-horizon history
SHOULD correlate Capsules by payload `operator` — and, when present,
`epoch_id` ({{epochs}}) — rather than by the SCITT-layer `iss` claim, which
may change on key rotation. Absent a recorded linkage, pre- and post-rotation
Capsules are distinguishable by payload `operator` alone but not correlatable
at the SCITT-header layer; a producer SHOULD treat a key rotation that
coincides with a configuration change as an epoch boundary ({{epochboundary}})
to make the transition explicit in the record.

# Privacy Considerations {#privacy}

Redaction is unfixable by design — the more durable the record, the
higher the bar for admission. A Capsule is content-addressed: every
field participates in the `capsule_id` digest, so removing or altering
a field after sealing destroys the identity of the record and breaks
any chain or registration built on it. Registration in a Transparency
Service extends that permanence beyond the producer's custody. Privacy
in this profile is therefore an admission-time discipline, not a
retention-time one: the only reliable moment to protect a value is
before it enters the record. This section applies the correlation,
identification, and disclosure concerns of {{RFC6973}} to that
admission decision. Producer context divides into three admission
classes.

Clear-safe: opaque correlation handles. An agent name, an invocation
or run identifier MAY appear in clear. Correlation handles exist so a
verifier can join related Capsules; they identify workflow, not
people. Two constraints keep that true. First, a handle SHOULD be
opaque, and producers MUST NOT derive one from end-user identity,
directly or through a handle that is itself bound to one person: an
identifier computed from an email address, an account name, or a
per-user thread handle is an end-user identifier regardless of its
format. Second, linkage makes
identity out of reuse — a handle that recurs across many Capsules
belonging to one person becomes a stable pseudonymous identifier by
correlation alone, so producers SHOULD scope correlation handles to an
invocation or workflow rather than to a user or long-lived session —
minting a fresh random run identifier per invocation rather than
propagating the runtime's session handle.
The class test is binding, not naming: a runtime's randomly generated
run or thread handle that resolves only to a workflow is a correlation
handle; a session identifier that resolves to a person or account is
end-user identity and belongs to the never-enters class below.
Resolution here means from the record and public context alone —
with operator-held auxiliary data every handle eventually resolves,
which is precisely why that mapping stays operator-side.

Digest-only: action payloads. Tool inputs and outputs MUST NOT appear
in clear; they are committed by digest, which preserves provability
without disclosure, and selective disclosure
({{selectivedisclosure}}) is the mechanism for revealing a committed
value later under the holder's control. Digest commitment hides only
high-entropy values; low-entropy payload fields inherit the
dictionary-attack exposure and the salting guidance of {{security}}.

Never-enters: end-user identity and secrets. Identifiers that resolve
to a person or account, credentials, tokens, and keys MUST NOT enter a
Capsule in any form — including as digests, salted or otherwise. The
exclusion is categorical, not entropy-contingent: a bare digest of a
low-entropy identifier re-identifies under a dictionary attack, and
salting does not cure the class — a salted identity digest is
identity-derived material baked into an unerasable record,
re-identifiable by whoever holds the salt and dependent on salt
secrecy forever: harvest now, re-identify later.
Identity also carries obligations that digests do not discharge:
erasure, retention limits, and purpose binding cannot be honored
against an append-only, content-addressed record, so the only
admission decision compatible with those obligations is absence.
This prohibition governs identity as record structure — fields and
standalone commitments whose preimage is the identifier itself.
Identity occurring inside action payload content (an email address in
a tool argument) is governed by the digest-only class: it is committed
only within the payload digest, never separately addressable, and
revealed only through selective disclosure under the holder's control
({{selectivedisclosure}}), with the low-entropy guidance of
{{security}} applying where a payload is small enough to enumerate.
Identity resolution belongs in operator-side systems with retention
control, correlated to the record through opaque handles — a
severable arrangement in a way no digest can be: because a
never-derived handle places no function of the identity in the
record, erasing the operator-side mapping fully severs
re-identification, whereas identity-derived material baked into the
record depends on secrecy forever. The Capsule proves conduct; it
does not name the human behind the session.

Producers SHOULD construct record context by allow-list — enumerating
the fields that may enter — rather than by block-list. A block-list
fails open: when a runtime adds a new context field, a block-list
admits it silently, while an allow-list excludes it until a deliberate
decision admits it. Implementation experience favors expressing the
allow-list in code rather than in documentation: a list enforced
structurally cannot admit a new runtime field without a deliberate
change.

--- back

# Acknowledgments
{:numbered="false"}

The author thanks the reviewers and contributors who shaped the design
recorded here, and the SCITT and COSE working groups whose substrate this
profile builds on.
