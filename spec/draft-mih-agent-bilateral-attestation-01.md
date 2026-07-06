---
title: "Bilateral Attestation of Cross-Organization Agent Actions"
abbrev: "Bilateral Agent Attestation"
docname: draft-mih-agent-bilateral-attestation-01
category: info
submissiontype: IETF
ipr: trust200902
area: Security
keyword: [agent, attestation, bilateral, cross-organization, SCITT, transparency, refusal]
stand_alone: yes
date: 2026-07-06
author:
 -
    name: Steven Mih
    org: Action State Group, Inc.
    email: spec@actionstate.ai
normative:
  RFC9943:
  RFC8785:
  I-D.mih-scitt-agent-action-capsule:
informative:
  I-D.mih-agent-reputation-predicates:
  I-D.mih-sato-agent-accountability-composition:
  I-D.mih-scitt-agent-action-capsule-sel-disc:
  I-D.nelson-agent-delegation-receipts:
  I-D.kuehlewind-audit-architecture:
  I-D.schrock-ep-authorization-receipts:
  RFC9334:
--- abstract

When an agent operated by one organization requests a consequential action
from an agent operated by another, today's record of that exchange — if one
exists — is kept by one side, editable by that side, and deniable by the
other. Disputes reduce to my-log-versus-your-log. This document describes a
bilateral attestation exchange for such actions: the requesting organization
signs a request attestation binding it to the action and its material terms;
the performing organization evaluates the request against deterministic
constraints at the boundary where the action takes effect and signs an action
attestation recording the constraint results and the disposition — performed,
declined, or escalated to a human — by reference to the request; and each
party acknowledges the other's attestation. The combined record binds each
organization to its part, gives each proof of the other's, and can be
anchored to a transparency service so that a third party who trusts neither
organization can verify the record end-to-end. The exchange records refusals
with the same fidelity as performance, and degrades gracefully when a
counterparty cannot attest, marking the record's reduced assurance rather
than blocking the transaction.

--- middle

# Introduction

Agents increasingly transact with agents of other organizations with no human
present at the moment of delegation. The transports are standardized — RPC
conventions, tool-call protocols, message queues — but transports answer
*how* agents communicate, not *who is accountable* for what was requested and
what was done. Each side keeps its own log, written by an interested party,
alterable by that party, and carrying no assent from the other. When the
payment posts twice, when the deletion was out of scope, when the delivery
never happened, the evidence is two self-interested logs that need not agree.

Classical signed B2B messaging — AS2/EDIINT signed MDNs, AS4/ebMS3 signed
receipts with non-repudiation-of-receipt — binds parties to *transmissions*:
it attests that a message was sent and received, not what an agent then *did*
about it. Such schemes do not gate execution on verifying the requester's
organizational identity at the boundary where the action takes effect, do not
bind constraint evaluation into the performer's record, and do not record a
disposition distinguishing an executed action from a refusal from a human
escalation at the moment of action. The distinction this document draws is
action-level, not transport-level.

This document describes an exchange producing a **bilaterally attested action
record**: each organization's signature over its part of the exchange is
durable, independently verifiable evidence that it produced that part, each
holds proof of the other's, and the combined record can be anchored so third
parties can verify it. It is an individual submission. It
composes with the existing agent action record layer
{{I-D.mih-scitt-agent-action-capsule}} rather than defining a new one, and
its records are designed to be consumable by the layers above the record —
accountability composition
{{I-D.mih-sato-agent-accountability-composition}} and reputation
{{I-D.mih-agent-reputation-predicates}}.

# Motivating Scenarios

**Cross-organization procurement.** Org A's purchasing agent requests a
fulfillment action from org B's agent. A's request attestation binds A to the
order's material terms; B's action attestation binds B to what it did about
them. A later assertion of different terms by either party can be checked
against a record both parties signed, rather than argued over two private ones.

**Agent-to-agent service delegation.** An orchestrating agent subcontracts a
task across a trust boundary. Each hop produces its own bilateral record, so a
failure in a multi-hop chain is attributable to the hop where it occurred
rather than to the chain as a whole. Chain-linking semantics that make the
full responsibility path independently reconstructable are left to a future
revision.

**Refusal at the boundary.** B's agent declines A's request as out of policy.
B's action attestation records the decline and its constraint basis; A's
acknowledgment is verifiable evidence contradicting a later claim by A that
the request was never answered.
The refusal becomes durable, third-party-verifiable evidence — for B, that
its gate worked; for A, that the request was made and declined
(see {{refusal-across-the-boundary}}).

**Feeding reputation.** Every completed handshake yields a
counterparty-attested record — the highest-assurance evidence class a
reputation predicate can consume {{I-D.mih-agent-reputation-predicates}}.
Two organizations that transact build verifiable shared history as a side
effect of transacting.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Requesting party:
: The organization (via its agent) requesting a consequential action across
  an organizational boundary.

Performing party:
: The organization (via its agent) that evaluates and disposes of the
  requested action.

Request attestation:
: A signed statement by the requesting party describing the requested action
  and its material terms, bound to the requesting party's verifiable
  organizational identity and naming the intended performing party; including
  at minimum a content digest of the request, a nonce, a timestamp, and a
  validity window. A request attestation is valid only against the performing
  party it names, and only within its validity window (with an
  implementation-defined clock-skew tolerance the verifier applies).

Action attestation:
: A signed statement by the performing party, referencing a request
  attestation by digest, recording the deterministic constraint results
  evaluated at the effect boundary — each constraint identified by reference
  so a third party can tell which check produced which result — and the
  disposition of the request, bound to the performing party's verifiable
  organizational identity.

Acknowledgment:
: A signed statement by which a party records receipt of the counterparty's
  attestation, completing the bilateral record. Receipt does not assert
  agreement with the attestation's contents; a party disputing a disposition
  does so in a subsequent linked record.

Verifiable organizational identity:
: An organizational identity a relying party can validate independently of
  that organization's infrastructure — a credential chaining to a root of
  trust the relying party accepts (a certificate authority, federation
  operator, registry, or published trust list). This document does not
  nominate roots.

Reduced-assurance indicator:
: A marker recording that a given exchange completed with fewer than the full
  set of attestations (see {{graceful-degradation}}).

# The Bilateral Exchange

The exchange has four moves:

1. **Request attestation.** Before the performing party acts, the requesting
   party produces a request attestation over the action and its material
   terms. The requester is now bound: it cannot later deny having asked, or
   having asked on these terms.

2. **Constraint evaluation.** The performing party verifies the requester's
   organizational identity and evaluates the request against deterministic
   constraints *at the boundary where the action would take effect* — not at
   the transport edge. Verification gates execution: no verified request
   attestation, no consequential action (policy MAY permit degraded
   operation; see {{graceful-degradation}}).

3. **Action attestation.** The performing party produces an action
   attestation referencing the request attestation by digest and recording
   the constraint results and the disposition. Dispositions use the
   verdict-complete vocabulary of {{I-D.mih-scitt-agent-action-capsule}}
   verbatim — *executed, blocked, denied, timeout, errored, deferred, expired,
   escalated* — so the record covers every outcome, not only success. A
   performing party MUST produce at most one action attestation per request
   attestation; repeated execution of a single request is representable only
   as distinct request instances, each with its own request attestation.

4. **Acknowledgment.** Each party acknowledges the other's attestation. On
   completion, each organization is bound to its part and holds proof of the
   other's.

Attestations and acknowledgments SHOULD be anchored: registered to a
transparency service per {{RFC9943}} — carried, for
example, as the payload of a profiled Signed Statement per
{{I-D.mih-scitt-agent-action-capsule}} — so that inclusion and
non-equivocation are verifiable by a party who trusts neither organization.
An unanchored bilateral record still binds the two parties to each other;
anchoring is what makes it evidence for everyone else.

Wire encodings for the four objects are TBD for a future revision; this
document fixes the exchange, the binding obligations, and the disposition
semantics. A future revision fixing wire encodings MUST specify JCS
({{RFC8785}}) as the deterministic canonicalization for attested objects and
carry an explicit hash-algorithm identifier for hash agility (see
{{canonicalization}}).

# Refusal Across the Boundary {#refusal-across-the-boundary}

A declined request is not a failed exchange; it is a completed exchange with
a decline disposition. The action attestation records *that* the request was
declined and *on what constraint basis*; the requester's acknowledgment
completes the record. This has two consequences.

For the performing party, a bilaterally-acknowledged decline is evidence,
verifiable by an auditor who trusts neither party, that its boundary
enforcement works — the strongest
form of the refusal-as-positive-signal reputation input described in
{{I-D.mih-agent-reputation-predicates}}, because here even the *counterparty
that was refused* has signed the record.

For the requesting party, a history of acknowledged declines is legible too:
a pattern of out-of-policy requests is now provable by its counterparties.
Bilateral records cut both ways by construction; parties should expect their
requesting behavior, not only their performing behavior, to become
reputation-bearing.

# Graceful Degradation {#graceful-degradation}

Counterparties will be of mixed capability for years. A performing party
whose counterpart cannot produce request attestations MAY proceed under
policy, producing its own action attestation unilaterally and recording a
reduced-assurance indicator in place of the missing attestations. The record
format is the same; the assurance marking differs. This keeps one protocol
across mixed peers while preserving the distinction relying parties need:
a fully-bilateral record and a degraded record are never confusable, and
consumers such as reputation predicates can require a minimum assurance
(cf. the assurance ordering in {{I-D.mih-agent-reputation-predicates}}).
Degradation MUST be recorded, never silent.

# Relationship to Existing Work

**Record layer.** This document defines an exchange, not a record format:
its attestations are designed to be carried in existing agent action records
— the Agent Action Capsule {{I-D.mih-scitt-agent-action-capsule}} supplies
the disposition vocabulary, effect binding, and anchoring path this document
relies on, and its selective-disclosure profile
{{I-D.mih-scitt-agent-action-capsule-sel-disc}} applies to cross-boundary
privacy ({{privacy-considerations}}).

**Delegation receipts.** {{I-D.nelson-agent-delegation-receipts}} binds a
*principal* (the delegating user) to an authorization before any action, on
one side of the boundary. This document binds two *organizations* to a
specific action at the moment of action. The two compose: a request
attestation may reference the delegation receipt authorizing the requesting
agent.

**Remote attestation.** RATS {{RFC9334}} attests platform and workload
*state* — what software is running where. This document attests *actions* —
what was requested and what was done. A deployment may use RATS evidence to
strengthen confidence in a counterparty's agent runtime; the two are
orthogonal layers.

**Audit and approval records.** The audit architecture
{{I-D.kuehlewind-audit-architecture}} describes recording agent interactions
across parties, and {{I-D.schrock-ep-authorization-receipts}} records
human authorization of high-risk actions; both are complementary record
sources this exchange can feed and reference. The accountability composition
{{I-D.mih-sato-agent-accountability-composition}} describes how such records
compose by shared action digest; a bilateral record naturally fills its
cross-party leg.

# Security Considerations

## Identity Is the Floor

The evidentiary weight of a bilateral record is
bounded by the binding of keys to organizations. This document inherits, and does not
solve, the organizational-identity problem; it requires only that the
credential chain to a root the relying party accepts, and that identity be
bound to the *record*, not merely the transport session.

## Half-Completed Exchanges

A party that aborts mid-exchange (requests,
then never acknowledges the decline; performs, then withholds the action
attestation) creates an asymmetric record. Timeout dispositions and
anchoring deadlines bound the asymmetry: an unacknowledged attestation
anchored with a timeout marking is itself evidence of the counterparty's
non-completion. Policies SHOULD treat chronic non-completion as
reputation-bearing.

## Downgrade Attacks

If degraded operation is permitted, an attacker
prefers to be recorded at reduced assurance. Reduced-assurance records MUST
be unambiguously marked, acceptance of degraded exchanges is a policy
decision of the performing party, and consumers SHOULD weight degraded
records accordingly. Silent downgrade is the failure mode to design out.
A performing party MUST NOT accept an exchange at reduced assurance without
explicit policy authorization to do so; policy MUST be configured, never
inferred from the absence of a request attestation.

## Replay and Cross-Binding

Nonces and digests bind each attestation to
one request instance; an action attestation MUST NOT be verifiable against
any request other than the one it references. Specifically: if a request
attestation's requester_org or action_digest differs from the performing
party's record at the time it evaluates constraints, the performing party
MUST reject the exchange and produce a ``denied`` attestation, not a reduced-
assurance indicator. The distinction matters: reduced assurance records a
capability gap; denial records a protocol violation. Two independent verifiers
deriving disposition from the same canonical bytes MUST reach the same
verdict.

## Key Establishment

This document does not specify how parties establish
mutual trust in each other's organizational keys. First-use acceptance
(TOFU) is a documented-risk convenience — it does not establish verifiable
organizational identity and MUST NOT be treated as conformant with the
identity requirements of this document. Conformant deployments bind signing
keys to organizational identity via a credential chaining to a root the
relying party accepts, independent of the communicating parties'
infrastructure.

## Key Compromise and Revocation

A signature valid at attestation time may
be produced under a key compromised by verification time. A verifier SHOULD be
able to establish key validity *as of the attestation's anchored time*, not
only at verification time; revocation and rotation semantics for organizational
keys are inherited from the identity layer and are out of scope here, but a
record without an anchored time cannot support this distinction.

## Canonicalization and Hash Agility {#canonicalization}

Because every binding is by digest, the
canonicalization of the attested objects is security-relevant: divergent
serializations of the "same" terms produce different digests, and ambiguous
canonicalization enables terms-substitution disputes. A future revision fixing
wire encodings MUST specify JCS ({{RFC8785}}) as the deterministic
canonicalization and carry an explicit hash-algorithm identifier for agility.
Until wire encodings are fixed, implementations SHOULD document the
canonicalization they apply and treat any divergence from a counterparty as a
protocol error.

## Verification-Cost DoS

Verifying a request attestation (identity-chain plus
anchor inclusion) is more expensive than producing one. A performing party
SHOULD be able to cheaply reject unverifiable request attestations before
performing full verification, so request-attestation flooding cannot exhaust a
performer at the effect boundary.

# Privacy Considerations {#privacy-considerations}

A bilateral record discloses, by construction, that two organizations
transacted — to each other, and if anchored with cleartext identifiers, to
anyone. Deployments SHOULD anchor commitments rather than cleartext
(selective-disclosure structures per
{{I-D.mih-scitt-agent-action-capsule-sel-disc}}), disclose material terms
only to the counterparty and auditors, and treat counterparty identity
itself as a selectively-disclosable field where the use case allows.
Correlation of anchored records across a party's exchanges (client-list
reconstruction) is the residual risk; mitigations are TBD alongside the
reputation layer's, which faces the same problem from the consumption side.

# IANA Considerations

This document has no IANA actions at this time. A future revision defining
wire encodings is expected to register media types for the four exchange
objects and a registry for reduced-assurance indicator values. TBD.

--- back

# Acknowledgments
{:numbered="false"}

This exchange pattern owes its framing to discussions in the SCITT and
agent-accountability communities, and composes with the work of the authors
cited above.
