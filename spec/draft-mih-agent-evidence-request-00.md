---
title: "An Interaction Model for Requesting Verifiable Evidence"
abbrev: "Evidence Request"
docname: draft-mih-agent-evidence-request-00
category: info
submissiontype: IETF
ipr: trust200902
area: Security
keyword:
  - transparency
  - audit
  - evidence
  - interaction model
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
  RFC8785:
  RFC8949:

informative:
  RFC9942:
  RFC9943:
  I-D.mih-scitt-checkpointed-local-log:
    title: "The Checkpointed Local Log"
    author:
      - ins: S. Mih
        name: Steven Mih
    date: 2026-08
    refcontent: Work in Progress
  I-D.mih-zhang-agent-action-capsule-evidence-bundle:
    title: "AAC Evidence Bundle"
    author:
      - ins: S. Mih
        name: Steven Mih
      - ins: Y. Zhang
        name: Yiqun Zhang
    date: 2026-09
    refcontent: Work in Progress

--- abstract

Parties increasingly need to request verifiable evidence from a counterparty
they do not trust — an audit trail, an interaction history, an account of
actions taken — and to receive an answer they can check rather than believe.
Evidence formats for the answer exist; the ask has no standard shape, and
today one system's silence, another's error, and a third's stale cache are
indistinguishable to a relying party. This document defines a
transport-agnostic request/response interaction for verifiable evidence: a
request that names its subject and a coverage anchor, and a set of possible
outcomes that is exactly one of three things — the evidence artifact, a
signed refusal carrying a machine-readable reason, or a recorded absence.
The interaction makes asking, granting, and refusing each attributable and
checkable, and requires that the same subject under the same coverage yield
a byte-identical artifact for every requester. The interaction is symmetric:
any party to a recorded exchange may ask the other, anchored on its own
record of that exchange. A responder may additionally commit, in a
signed statement, to keep a subject answerable until a stated time, so that
a later absence is attributable rather than merely recorded. The document
deliberately defines no evidence format, no identity or principal scheme,
no trust policy, no availability guarantee, and no rule about who may ask.

--- middle

# Introduction

A growing class of systems — autonomous agents, multi-party computation
pipelines, registries of signed claims — accumulate evidence about their own
actions: signed statements, receipts, transparency-log inclusion
proofs. Formats for these artifacts exist and continue to
mature; the SCITT architecture {{RFC9943}} and COSE Receipts {{RFC9942}} are
representative examples, and this document depends on neither. What has no
standard shape is the **ask**. Each ecosystem invents its own convention for
"give me your evidence": a bespoke query endpoint here, an ad-hoc agent
command there, a static file by private agreement somewhere else. The
answers are not comparable. When a relying party asks two counterparties the
same question, one counterparty's silence, another's transport error, and a
third's stale cached answer all look alike — and none of the three leaves a
record that the question was asked.

This document standardizes the interaction, not the evidence. It defines a
request — a small map naming a **subject** (what evidence is wanted) and a
**coverage anchor** (the commitment the answer must verify against) — and
constrains the outcome to exactly one of three states: the evidence
artifact itself, a signed refusal with a machine-readable reason, or a
recorded absence. Each outcome is something the requester can record and
later cite. The evidence artifact remains opaque to this specification; it
is identified by digest and verified against the anchor by format-specific
means outside this document. A deployment that already has a format for the
artifact — for example an Evidence Bundle
({{I-D.mih-zhang-agent-action-capsule-evidence-bundle}}) — carries it inside
the artifact response envelope this document defines ({{artifact}});
nothing here restates that format.

Two further properties follow from deployments of this interaction shape,
sketched in {{field-evidence}}. First, the interaction is symmetric: the
party that served a request may later ask the party that made it, and each
side's strongest coverage anchor is its own sealed record of the exchange
({{symmetric}}). Second, the useful default answer to "show me your history"
is not the records but a constant-size summary of the commitments over them
— checkpoints, receipts, and consistency proofs — from which any individual
record can later be verified ({{history-card}}). A third property is
optional: a responder may sign a commitment that a subject will remain
answerable until a stated time ({{retention}}). Absence against an
outstanding commitment is evidence against the responder; absence
otherwise is evidence only of the requester's attempt.

## Two Failure Modes {#failures}

The interaction is designed to close two specific failure modes this shape
exists to prevent, sketched in {{field-evidence}}:

**The flattering version.** A responder that serves evidence through an
unconstrained query interface can serve *different* evidence to different
requesters — a fuller history to an auditor it expects, a curated one to a
counterparty in a dispute. Nothing in the transport reveals the divergence.
The caller-invariance requirement addresses this, conditional on the
anchor-consistency requirement of {{invariance}}: the artifact
is a function of the subject and the coverage anchor, never of who is
asking.

**The unaccountable refusal.** A responder that declines by silence, by
generic error, or by an unsigned message leaves the requester with nothing
citable: "I asked and they refused" is an assertion, not a record. The
signed refusal ({{refusal}}) constrains this: a refusal is a first-class,
signed, machine-readable answer that the requester can record — and the
three-state discipline ({{discipline}}) keeps genuine non-response
distinguishable from refusal, so neither can be laundered into the other.

## Non-Goals {#nongoals}

This document deliberately does not define:

- **Any evidence format.** The artifact is an opaque byte string identified
  by digest. Signed statements, receipts, log entries, bundles of proofs —
  all are carried, none are specified here.
- **Any identity or principal scheme.** Where a deployment binds a request
  or its response to a principal — the requester, the responder, or both —
  the reference's scheme (a key, a DID, an account identifier, a
  host-native name) is defined by the host or deployment, never by this
  document ({{principal}}).
- **Requester identity, purpose, authorization, or disclosure policy carried
  in the artifact.** These belong to the request/relationship layer — a
  deployment's own account, contract, or relationship model — and are
  referenced by this interaction, never embedded in the evidence artifact
  itself. What a `principal` field ({{principal}}) names, and what
  relationship or contract a request cites, is deployment-defined and
  outside this document.
- **Any trust decision.** Receiving an artifact, a refusal, or nothing
  implies no judgment about the responder. What a requester does with each
  outcome is its own policy.
- **Authorization or standing.** Who may ask, and what any requester is
  entitled to receive, is the responder's policy and is out of scope. This
  document constrains only the *form* of the answer, whichever answer policy
  selects.
- **Any availability guarantee.** The interaction makes loss detectable
  and, where a responder has committed to retention ({{retention}}),
  attributable. It never makes evidence available.

# Conventions and Definitions {#terms}

{::boilerplate bcp14-tagged}

**Requester:** the party asking for evidence.

**Responder:** the party holding evidence and answering.

**Evidence artifact:** the byte string a responder serves in the granting
case. Opaque to this specification; identified by its digest.

**Evidence stream:** the append-only body of evidence a responder holds
and answers from — the ordered records over which its coverage anchors
commit. A responder MAY hold several streams; a request is answered
against exactly one.

**Anchored:** verifying against a coverage anchor by the
mechanism-specific means of the deployment's evidence format.

**Coverage anchor:** a commitment — for example, a signed checkpoint over an
append-only log, or a receipt from a transparency service {{RFC9943}} — that
the evidence artifact must verify against. The anchor is what turns an
artifact from a story into something checkable: an artifact that verifies
against an anchor the requester obtained or constrained independently is
tamper-evident with respect to that anchor.

**Checkpoint / commitment:** used generically for any signed, compact
representation of a body of evidence at a point in its history, such that
inclusion and consistency of evidence against it are checkable.
{{I-D.mih-scitt-checkpointed-local-log}} describes one example of such a
mechanism; this document depends on no particular one.

**Freshness:** how recent a coverage anchor is, measured in a
mechanism-specific unit (a log size, a timestamp).

**Exchange half:** a party's own sealed record of one interaction with a
counterparty — its request, or its response — citing the counterparty's
record by digest.

**History card:** the derivation `history_card/1` ({{history-card}}): the
checkpoints over an evidence stream, their external receipts, and the
consistency proofs between consecutive checkpoints. Constant size in the
number of records; discloses no record content.

**Retention commitment:** a signed statement by a responder that a named
subject will remain answerable under this interaction until a stated time
({{retention}}).

**Route:** a locator — a resolver, a URL, an endpoint identifier — for
reaching a responder. Routes are hints. They are never subjects and never
identity.

**Principal reference:** an opaque value identifying a party — requester,
responder, or a party named in a retention commitment — in a scheme this
document does not define ({{principal}}). Distinct from a route: a route is
where a party can be reached; a principal reference is who it is under
whatever identity scheme the deployment recognizes.

**The three interaction outcomes:** artifact ({{artifact}}), signed refusal
({{refusal}}), recorded absence ({{absence}}).

**Pending:** the state of a request, before its waiting window closes,
that has received neither an artifact response nor a signed refusal. Not
one of the three interaction outcomes; resolves to recorded absence only
once the window closes ({{pending}}).

# The Request {#request}

A request is a map — CBOR {{RFC8949}} in bindings that use CBOR, JSON in
bindings that use JSON, with the same field names — with the following
fields:

| Field | Presence | Description |
|---|---|---|
| `subject` | REQUIRED | what evidence is asked for ({{subject}}) |
| `coverage` | REQUIRED | the anchoring constraint the response must satisfy ({{coverage}}) |
| `derivation` | OPTIONAL | identifier of a named computation over the subject ({{derivation-field}}) |
| `deadline` | OPTIONAL | latest useful response time ({{deadline}}) |
| `nonce` | RECOMMENDED | requester-supplied nonce or timestamp ({{nonce}}) |
| `route` | OPTIONAL | where the requester believes the responder can be reached ({{route-field}}) |

A responder MUST ignore request fields it does not understand. A requester
MUST NOT rely on any field not defined by this document being understood. A
deployment MAY bind a request to a principal reference ({{principal}}) by a
mechanism outside this document — for example, the signature that
authenticates the transport, or a field a deployment profile adds; this
document defines no such field and takes no position on how the binding is
made or checked.

A request that is malformed — not a well-formed map, missing a REQUIRED
field, or carrying a defined field whose value does not conform — is
refused with reason `request_malformed` ({{iana}}), except where this
document assigns a more specific reason (as for `coverage`, {{coverage}}).

[[EDITOR: whether the request map is expressed in CDDL is open for -01. The
field names in the table above are fixed; the semantics are as specified in
this document.]]

## Subject {#subject}

The `subject` names what is asked for, in one of six forms:

| Form | Content | Meaning |
|---|---|---|
| `full_history` | (none) | the responder's entire evidence body for this evidence stream |
| `checkpoints` | (none) | the responder's checkpoints and their receipts for this stream; no records |
| `record` | digest | the single record identified by this digest |
| `range` | (a, b) | the records at positions a through b inclusive, under the coverage anchor's ordering |
| `correlation` | identifier | all records the responder holds that carry this correlation identifier |
| `exchange` | digest of the requester's own half | every record the responder holds that cites this exchange half ({{symmetric}}) |

Subjects are digests, positions, and opaque identifiers — never display
names. Names drift; digests do not. A requester that holds only a name has
a resolution problem this document does not solve, and a responder MUST NOT
attempt fuzzy or best-effort matching of a subject: a subject that does not
resolve exactly is answered with a refusal carrying reason
`no_such_subject` ({{refusal}}).

The `range` form presupposes a coverage-anchor mechanism that defines
record positions; under a mechanism defining no positional ordering it
cannot be satisfied and is refused with reason `coverage_unsatisfiable`.

The `checkpoints` form asks for commitments only. It is the cheapest
question a stranger can ask and the one a responder can always safely
answer; the `history_card/1` derivation ({{history-card}}) is its
proof-carrying form.

The `exchange` form names the requester's own sealed half of a prior
interaction. A responder that recorded its side of that interaction holds a
record citing that half by digest; the subject resolves to exactly those
records. A responder holding no record citing the half answers
`no_such_subject` — which, when the requester holds a signed reply from
that responder citing the same half, is itself a contradiction the
requester can cite ({{symmetric}}).

## Coverage {#coverage}

The `coverage` field carries **exactly one** of the following two members.
A request carrying both, or neither, is malformed, and the responder MUST
refuse it with reason `coverage_unsatisfiable`.

**`expected_pin` (digest):** the requester already holds, obtained out of
band, a specific coverage anchor — for example a published checkpoint — and
requires the response to verify against exactly that anchor. This is the
strongest form: the anchor's integrity does not depend on the responder at
all, because the responder never chose it. A requester's own exchange half
is a valid pin for an `exchange` subject: the responder's record cites it,
and the requester sealed it before the responder's answer existed.

**`min_freshness` (size or time):** the requester holds no specific anchor
and instead requires that the response be covered by a commitment at least
this fresh — at least this log size, or issued no earlier than this time.
The responder selects a qualifying anchor and identifies it in the
response. This form trades the pin's independence for availability: the
requester can always form the request, but the anchor's independence now
rests on whatever external witnessing or publication that anchor has,
outside this protocol ({{security}}).

The two forms are mutually exclusive by design. A pinned request that also
stated a freshness floor would invite the responder to substitute "fresher"
coverage for the coverage the requester actually demanded; forbidding the
combination keeps the requester's constraint unambiguous.

A responder MAY perform work to satisfy `min_freshness` — for example,
issue a new commitment covering evidence produced since its last one — and
SHOULD do so when a `deadline` permits. A responder that cannot satisfy the
coverage constraint MUST refuse with reason `coverage_unsatisfiable` rather
than serve an artifact under weaker coverage. Serving under
weaker-than-requested coverage is not a degraded success; it is a
different answer to a different question, and this document forbids it.

## Derivation {#derivation-field}

The `derivation` field, when present, names a computation over the subject
— by a registered token ({{iana}}) for the derivations this document
defines, or by the digest of a definition for any other — and
asks for that computation's *result*, re-derivable by the requester,
instead of the raw evidence. A count of records matching a predicate, a
sum over a declared field, a projection of specific fields: each is a named
computation whose definition declares exactly which fields of the
underlying evidence it reads.

Derivation is also the disclosure mechanism of this document: the declared
field set of the named computation bounds what the responder reveals
({{derivation}}). A responder that supports a derivation MUST evaluate it
over exactly the subject as anchored by `coverage` — a derivation is a view
of the anchored evidence, not an independent report — and the result MUST
be accompanied by whatever the requester needs to check that binding
(format-specific, out of scope here beyond the requirement that the binding
be checkable). A responder that does not support the named derivation at
all refuses with reason `derivation_unsupported`; a responder that supports
the derivation in general but not for this subject refuses with reason
`no_such_subject`, per {{subject}}.

## Deadline {#deadline}

The `deadline` field states the latest time at which a response is useful
to the requester. It is advisory in the sense that no transport can enforce
it, and normative in one respect: a responder that determines it cannot
answer by the deadline SHOULD send a refusal with reason `deadline_unmet`
before the deadline rather than let the exchange lapse into absence. A
refusal is cheap and citable; an absence is neither party's record of
anything except the requester's attempt.

## Nonce {#nonce}

The `nonce` field carries a requester-chosen nonce or timestamp; its use
is RECOMMENDED. It makes each transmitted request instance distinct, so a
refusal — identified by request digest, with a signed issuance time
({{refusal}}) — binds to *this* instance of asking, not replayable against
a fresh one. Covered by the request digest, it MUST NOT influence the
artifact ({{invariance}}).

## Route {#route-field}

The `route` field carries the requester's belief about where the responder
can be reached — a resolver name, a URL, a peer endpoint identifier. It is
a hint for the transport binding and nothing more: it MUST NOT influence
the artifact ({{invariance}}), it is not a subject, and it is not identity.
A responder reached through a route is authenticated by its signature on
the response, never by the route ({{security}}). The field exists so that
the route actually attempted is part of the requester's record of asking,
and so a failed route is part of any absence recorded ({{absence}}).

## Principal Reference {#principal}

This document distinguishes a **route** (where a party can be reached,
{{route-field}}) from a **principal reference** (who a party is). It
defines the former and not the latter. Where a deployment needs to say
"this request came from, or this response is addressed to, this
particular party," it binds a principal reference into the exchange by
whatever mechanism it already has — a signature key, a DID, an account
identifier, or any other host-native scheme — and this document takes no
position on that scheme, its resolution, or its trust. A retention
commitment ({{retention}}) similarly names an answerable party without
this document defining what a name is.

Two consequences for implementers. First, a requester or responder MAY be
authenticated at the transport layer (by the signature over a response, for
example, {{security}}) without either party ever appearing as a field in
the request or response maps this document defines: authentication and
`subject` resolution are independent, and a responder MUST NOT let
knowledge of the requester's principal change the artifact served for a
given (subject, coverage) pair ({{invariance}}). Second, a deployment
profile that adds a principal field to the request or response — to carry
purpose, authorization context, or a relationship reference alongside the
identity — does so as an extension this document neither requires nor
constrains; such a field is request/relationship-layer material and MUST
NOT appear inside the evidence artifact itself ({{nongoals}}).

## Recording the Request {#request-recording}

The request itself is evidence: it is the requester's proof of *having
asked*. Requesters SHOULD record each request they send — in their own
evidence stream, signed, in the encoding actually transmitted — before or
at transmission time. Where requests are recorded or their digests
exchanged, deterministic encoding SHOULD be used: CBOR Core Deterministic
Encoding ({{Section 4.2 of RFC8949}}) for CBOR, JCS {{RFC8785}} for JSON,
so that the recorded bytes and the transmitted bytes are the same bytes.
A requester that retains neither the transmitted request bytes nor their
digest cannot correlate a refusal — identified only by digest — with its
own record of having asked.

Request recording is a SHOULD, not a MUST: {{recording}}'s "I asked; they
refused" property is empty without it, but this document does not require
a requester to keep records it has no use for.

# Interaction Outcomes {#response}

An interaction produces exactly one of three outcomes: the artifact
response, a signed refusal, or a recorded absence. Only the first two are
messages a responder sends; the third is not a message at all — it is the
requester's own record that no response arrived within its waiting window.
Treating these as **outcomes** rather than as three things a responder
chooses among matters: a responder can grant or refuse, full stop; it
cannot "respond with absence," because absence is precisely the case in
which nothing arrived to be a response. There is no fourth outcome, and no
outcome is ever converted into another ({{discipline}}).

## The Artifact Response {#artifact}

The artifact response is the signed response envelope for the granting
outcome. The object it carries is opaque to this specification and MAY be
an Evidence Bundle ({{I-D.mih-zhang-agent-action-capsule-evidence-bundle}})
or any other evidence artifact the deployment's evidence format defines;
this document specifies the envelope and its binding to the request and
the coverage anchor, never the carried object's internal shape.

The envelope carries:

1. **The artifact:** the evidence bytes themselves, or a derivation result
   ({{derivation-field}}), identified by digest.
2. **The coverage anchor resolved:** under `expected_pin`, confirmation of
   the pinned anchor; under `min_freshness`, the anchor the responder
   selected, which MUST satisfy the requested freshness.
3. **Verification material:** whatever proofs let the requester verify the
   artifact against the anchor **offline** — inclusion proofs, consistency
   proofs, countersignatures, receipts {{RFC9942}}. An anchor MAY carry
   receipts from more than one transparency service; each receipt is
   verified on its own terms, and how many independent services a
   requester requires is requester policy, not a property of this
   interaction. The formats are evidence-mechanism-specific and out of
   scope; the requirement is that the artifact be verifiable against the
   anchor by the requester alone, with no further round trip to the
   responder and no appeal to the responder's honesty.

For the `checkpoints` subject and the `history_card/1` derivation the
artifact *is* the verification material: there is no separate record to
verify, only commitments and the proofs between them. Implementations
MUST NOT serve an empty artifact alongside proofs in these cases; the
proofs are the artifact, and caller invariance ({{invariance}}) binds them.

An artifact response MAY be accompanied by a retention commitment
({{retention}}) covering the subject served.

An artifact response that cannot be verified against the anchor is, to the
requester, not evidence but an unverifiable story, and requesters SHOULD
treat a verification failure as adverse — equivalent to discovering the
exchange was not what it claimed — rather than as a retryable transport
fault.

## The Signed Refusal {#refusal}

A refusal is an answer, not an error. It carries:

1. **The request identified:** the digest of the request being refused,
   computed over the request bytes as received.
2. **A reason:** exactly one machine-readable token from the registry
   established in {{iana}}. The initial tokens are `not_authorized`,
   `no_such_subject`, `coverage_unsatisfiable`, `derivation_unsupported`,
   `policy_declined`, `deadline_unmet`, `request_malformed`, and
   `retention_expired`. The last is distinct from `no_such_subject` by
   design: it states that the responder once committed to answer this
   subject ({{retention}}) and the commitment has lapsed, so a lapsed
   promise cannot be presented as never having held the evidence.
3. **An issuance time:** the time the refusal was issued, which MUST be
   present and MUST be covered by the signature. It binds the refusal to
   a moment, so a recorded refusal cannot be presented as current policy
   nor replayed against a fresh request ({{nonce}}).
4. **A signature:** the refusal is signed by the responder, in whatever
   signature format the deployment's evidence mechanism already uses, such
   that the requester can record the refusal and later demonstrate to a
   third party that this responder refused this request for this stated
   reason.

Human-readable detail MAY accompany the reason token; the token, not the
prose, is the machine-readable answer. A responder MUST select the most
specific applicable token, with one deliberate exception noted in
{{privacy}}: a responder MAY uniformly answer `policy_declined` wherever a
more specific token would disclose information its policy protects,
overriding the most-specific-token rule. That choice is policy, made by
the responder, applied
uniformly; it is not a license to select tokens per-requester in a way that
leaks by differentiation ({{privacy}}).

A refusal refuses the request, once. It creates no standing obligation and
no standing prohibition; the same request MAY be made again and MAY be
answered differently as the responder's policy or evidence changes.

## Pending {#pending}

Before the requester's waiting window closes, a request that has received
neither an artifact response nor a signed refusal is **pending**:
outstanding, not yet resolved, and not yet evidence of anything. Pending is
not one of the three interaction outcomes — it is the state of a request
between issuance and either an answer or the close of the window — and
MUST NOT be recorded or cited as if it were an absence. A requester MAY
track a request as pending, for its own bookkeeping or to display
outstanding requests to an operator, without that tracking implying
anything about the eventual outcome.

Only once the waiting window closes with neither an artifact nor a refusal
received does a request's state resolve to absence ({{absence}}). Until
that boundary, delay, slow transport, and a responder about to answer are
indistinguishable from one another, and none of them MUST be recorded as
if the outcome were already known.

## Recorded Absence {#absence}

Absence is the outcome in which no response — neither artifact nor refusal
— arrives within the requester's waiting window (its `deadline` if it set
one, or its local timeout otherwise); before that window closes, the
request is pending, not absent ({{pending}}). Absence is not sent by
anyone; it is *recorded by the requester*: the request digest, the
transport attempted, and the window in which no answer came.

Absence is an outcome about the exchange, not about the responder's intent.
A network partition, a crashed responder, and a responder deliberately
ignoring the request produce identical absences, and the requester's record
SHOULD NOT embellish the absence with an inferred intent.

An absence record SHOULD cite any retention commitment ({{retention}})
the requester holds for the subject, and the `route` attempted. Absence
inside an outstanding commitment is chargeable to the responder that
signed it; absence without one is evidence of nothing but the attempt. The
commitment changes whom the absence is evidence *against*; it does not
change what the absence *is*, and the requester still MUST NOT infer
intent.

## The Three-State Discipline {#discipline}

The three outcomes are mutually exclusive and are never synthesized into
one another:

- **Absence is NEVER synthesized into refusal.** No party — not the
  requester, not a transport intermediary, not a recording system — may
  manufacture a refusal object from a timeout. A refusal exists only if the
  responder signed one. A requester's records MUST keep "they refused"
  (their signature, their reason) and "they did not answer" (my attempt,
  my window) as distinct, differently-evidenced facts.
- **Refusal is never degraded into absence.** A requester that receives a
  valid signed refusal SHOULD record it as such; discarding a refusal and
  recording an absence misstates the exchange.
- **An unverifiable artifact is not a fourth outcome.** An artifact
  response that fails verification against the anchor is recorded as what
  it is: a response received and failed. It is neither a grant nor an
  absence, and requesters SHOULD NOT record it as a successful grant.
- **A commitment never converts an absence into a refusal.** A retention
  commitment ({{retention}}) makes an absence attributable; it does not
  make it a signed act of the responder, and no party may record it as one.
- **Pending is never recorded as absence.** A request still inside its
  waiting window is pending ({{pending}}), not absent; only the close of
  the window resolves it one way or the other.

The discipline exists because the three outcomes carry different
evidentiary weight — a refusal is the responder's signed act, an absence is
only the requester's attempt — and any synthesis between them forges the
stronger from the weaker.

## Mapping to a Requirement-Satisfaction Status {#status-mapping}

This document defines no requirement-satisfaction vocabulary; a deployment
composing this interaction with an evidence-contract or evidence-bundle
layer typically derives one from the three outcomes above. The mapping
shape — not a specific registry — is informative:

| Outcome | Typically maps to (illustrative) |
|---|---|
| Artifact response, verified | requirement satisfied |
| Artifact response, verification fails | requirement status indeterminate — never treated as satisfied |
| Refusal: `no_such_subject`, `coverage_unsatisfiable` | evidence not found, or not yet committed |
| Refusal: `not_authorized`, `policy_declined`, `derivation_unsupported` | evidence withheld by policy, not absent |
| Refusal: `retention_expired` | a prior commitment lapsed; distinct from never having held the evidence |
| Pending | request outstanding; the window has not closed, nothing yet to map |
| Recorded absence | status unknown to the requester; not evidence of non-satisfaction |

A deployment's own vocabulary MAY be coarser or finer than this table; the
table exists to show that the three outcomes carry enough distinction to
support one, not to define it.

# Caller Invariance {#invariance}

This is the normative core of the document.

For a given responder, the same `subject` under the same coverage anchor
MUST yield a byte-identical evidence artifact, regardless of the
requester's identity, the transport binding used, or any other property of
the request. Formally: the artifact MUST be a deterministic function of
(subject, resolved coverage anchor, derivation if present), and MUST NOT be
a function of the requester, its principal reference ({{principal}}), or
the channel.

Under `expected_pin` the resolved anchor is fixed by the requester, so two
requesters pinning the same anchor and naming the same subject MUST receive
identical bytes. Under `min_freshness` the responder selects the anchor;
two requests resolved against the *same* selected anchor MUST receive
identical bytes, and the anchor identification in the response
({{artifact}}) is what lets requesters compare notes across resolutions.

Caller invariance is the anti-flattering-version property ({{failures}}).
It is what makes the artifact *evidence* rather than a per-audience story:
any two requesters — or one requester over two channels — can detect a
responder serving divergent versions by comparing artifact digests for the
same (subject, anchor) pair, without trusting each other's verification and
without any authority adjudicating. A responder MAY refuse a requester
outright ({{refusal}}); what it MUST NOT do is grant different requesters
different bytes for the same anchored subject. Access control is a
policy; per-audience evidence is a forgery of the interaction.

**Anchor consistency.** Caller invariance would be hollow if a responder
could hand each requester its own anchor. All coverage anchors a
responder serves for a given evidence stream MUST lie on one mutually
consistent append-only history, and the responder MUST be able to
produce, on request, a consistency proof between any two anchors it has
served for that stream, in the proof format of the deployment's evidence
mechanism. The limits of this requirement are discussed in {{security}}.

Two consequences for implementers:

- The artifact serialization MUST be deterministic. An artifact assembled
  with nondeterministic map ordering, timestamps of assembly, or per-request
  nonces violates invariance even with honest intent. Deterministic
  encodings ({{Section 4.2 of RFC8949}}; {{RFC8785}} for JSON) are the
  practical tool.
- Verification material ({{artifact}} item 3) is NOT required to be
  byte-identical across requesters — a consistency proof, for instance, may
  legitimately depend on which earlier anchor a particular requester holds.
  Invariance binds the artifact; the proofs bind the artifact to the
  anchor.

One subject form needs its own statement. An `exchange` subject is
invariant per (exchange-half digest, anchor) like any other, but no two
requesters can hold the same half, so cross-requester comparison is
unavailable there. Invariance for `exchange` is instead checked by the
responder's own recorded ask ({{recording}}) against the artifact it
served: the responder's record and the requester's record must name the
same artifact digest. The subject does not weaken invariance; it changes
who holds the second copy.

# The Symmetric Ask {#symmetric}

Nothing in this document distinguishes the party that originally requested
an action from the party that performed it. Once both have sealed their
halves of an exchange — each citing the other's record by digest — either
MAY ask the other for evidence about that exchange, using the `exchange`
subject anchored on its own half. A provider asking its former requester
is the same interaction with the roles swapped; no new message, no new
state.

The consequence is the one property no single-responder interaction can
otherwise provide. A responder's log, however well witnessed, proves only
the integrity of what the responder chose to write. A counterparty that
sealed its own half of every exchange can prove an *omission* by
arithmetic: it holds a signed reply citing a half the responder now claims
not to have. Coverage is a property of the counterparty's record, not of
the log, and the symmetric ask is how that record is exercised.

Deployments MAY condition interaction on evidence — for example, a policy
that serves only to peers whose history card ({{history-card}}) verifies
against an independently obtained checkpoint. Such a policy is a
requiring-party decision and is outside this document; the interaction
only makes it expressible.

# Recording the Exchange {#recording}

Each side SHOULD seal its half of the exchange into its own records: the
requester its request, and whichever of the three outcomes followed; the
responder the requests it received and the artifacts or refusals it served.
Both sides' recording is a SHOULD: requester-side recording is what gives
absence any meaning at all, and responder-side recording is the
responder's own counter-record when a response it sent never arrived
({{security}}).

The consequence worth naming: once both the ask and the answer are
recordable, **"I asked; they refused" becomes citable material** — a signed
refusal in the requester's records, a recorded ask in the responder's — and
each party can grade the other's conduct over time from its own records,
with no authority anywhere in the loop. A requester's policy might treat a
counterparty's pattern of `policy_declined` refusals differently from a
pattern of absences; a responder's policy might treat a requester's
recorded asks as standing to receive more. This document enables those
policies and defines none of them ({{nongoals}}).

# Derivation-Scoped Disclosure {#derivation}

When `derivation` names a computation, the computation's declared field set
defines the **minimal disclosure** needed to re-derive it: the responder
reveals exactly the fields the named computation reads, and nothing more.
The responder MUST NOT disclose fields outside the declared set as part of
a derivation response, and MUST NOT evaluate a computation whose declared
field set it is unwilling to disclose — the correct answer in that case is
a refusal, not a silently truncated evaluation.

Three disclosure tiers fall out naturally:

1. **Digests-only** — no derivation; subjects and artifacts identified and
   verified by digest, content never disclosed. Always safe to serve
   (subject to {{privacy}} on low-entropy content).
2. **Derivation-scoped** — a named computation's declared fields, and only
   those. Minimal content disclosure, deliberate, and recorded: the
   derivation identifier in the recorded request states exactly what was
   revealed and why.
3. **Full** — the raw evidence bytes. The rare tier, appropriate where the
   requester's role requires the whole record.

## The History Card {#history-card}

This document registers one derivation, `history_card/1`, defined as
follows. For the named evidence stream, the result is the ordered list of
tuples (checkpoint, receipts for that checkpoint, consistency proof from
the previous checkpoint), from the stream's first checkpoint to the one
resolved by `coverage`. Its declared field set contains no record content:
the card discloses commitments, external receipts over those commitments,
and the proofs that each commitment extends the last. Its size is linear
in the number of checkpoints and independent of the number of records.

The history card is the default first question. It is the thing a
stranger checks before deciding whether to ask for anything else; it is
safe to serve to anyone under the digests-only tier; and it is sufficient
to verify any individual record the responder later serves, by inclusion
proof against a checkpoint the requester already holds. A card that fails
to verify — a consistency proof that does not chain, a receipt that does
not cover its checkpoint — is treated as an unverifiable artifact
({{discipline}}).

The derivation registry and definition format for other computations are
expected to grow in a subsequent version. [[EDITOR: whether a second
derivation, the result of a sampled recomputation of a subject by a third
party, is registered in -00 or deferred to -01 — open.]]

# Retention Commitments {#retention}

A responder MAY issue a **retention commitment**: a signed statement that
a named subject will remain answerable under this interaction until a
stated time. It carries:

1. the subject, in one of the forms of {{subject}}, and the evidence
   stream it belongs to;
2. `until`: the time after which the commitment lapses, covered by the
   signature;
3. optionally, a `route` at which the responder expects to be reachable,
   and optionally a principal reference ({{principal}}) naming who is
   answerable, when that differs from the signer;
4. the responder's signature, in the signature format of the deployment's
   evidence mechanism.

A commitment is a promise about *answerability under this interaction*.
It says nothing about whether the bytes exist anywhere else, and it does
not make the subject available; it makes a later failure to answer
attributable to the party that promised.

A commitment MAY be carried alongside an artifact response
({{artifact}}), published with the responder's checkpoints, or placed in
a citing record's reference block as an optional member beside the digest
of the thing cited. It MUST NOT appear in a request. A commitment that
names a subject by anything other than a digest or a position under a
checkpoint is malformed: the digest remains the identity, and the
commitment is a route with a promise attached, never an address.

Within `until`, an absence for the committed subject is recorded citing
the commitment ({{absence}}). Within `until`, a refusal carrying
`not_authorized`, `coverage_unsatisfiable`, `request_malformed`, or
`derivation_unsupported` reflects a property of the request or of this
responder's capabilities, not a failure to honor the commitment, and is
not a breach. Any other refusal reason — `no_such_subject`,
`policy_declined`, or `deadline_unmet` — within `until` is a broken
commitment: the responder promised this subject would remain answerable
and is refusing it on a ground the promise foreclosed; the refusal is
signed, so the breach documents itself. After `until`, the correct
refusal is `retention_expired`.

The separation this section preserves is the one that a reference field
promising only "resolvable" cannot express: that a name staying resolvable
and the bytes staying unchanged are two different promises. The digest
keeps the second. The commitment, when present, names who is answerable
for the first, and for how long.

# Transport Bindings {#transports}

The interaction is transport-agnostic; a binding maps the request map, the
three outcomes, and the recording discipline onto a concrete transport.
Bindings are intentionally thin. Two are defined here and one is reserved.

**Peer-to-peer stream binding.** On a multiplexed peer transport that
negotiates named subprotocols at connection time, this interaction is the
subprotocol `evidence-request/1`. One request frame, one response frame;
each frame is the deterministic CBOR encoding ({{Section 4.2 of RFC8949}})
of the maps in {{request}} and {{response}}. Absence is the stream closed
or timed out without a response frame. The subprotocol identifier is what
lets any two peers implementing it interoperate without prior
arrangement; a peer that does not offer it has not refused — it has not
answered, and the requester records that as absence, not as
`policy_declined`. Message-oriented agent protocols bind the same way,
with the request as a named message type and the three outcomes as three
reply types. The identifier `evidence-request/1` is a document constant of
this specification; it does not require registration in a separate
subprotocol registry.

**HTTP binding.** Pinned, parameterless requests (a `full_history` or
`checkpoints` subject under `expected_pin`) map onto GET of a static
resource: the URL identifies the subject, the pin travels as a query
parameter or is implied by the resource, and caller invariance is
trivially auditable because the resource is the same bytes for every
client. Parameterized requests (ranges, correlations, exchanges,
derivations, `min_freshness`) map onto POST with the request map as the
body. A responder SHOULD publish a manifest — its evidence stream
identifiers, the subject forms and derivations it supports, and where
retention commitments ({{retention}}) can be fetched — so a requester can form a
well-formed request without a prior round trip. A refusal is an HTTP
response carrying the signed refusal object: a successful transport
exchange carrying a refusal answer. Bindings MUST NOT conflate
transport-level errors with refusals ({{discipline}}).

**Registry query.** A registry or query service exposing stored claims can
expose this same interaction over its query path, so that a query answer
arrives as an anchored artifact, a signed refusal, or a recordable absence
rather than as a bare result set. This binding is reserved: its concrete
mapping onto a specific query protocol is left to a future companion
document rather than specified here.

# Security Considerations {#security}

**The coverage anchor is the whole game.** Every checkable property of this
interaction flows through the anchor. A response that is not verifiable
against an anchor the requester obtained or constrained independently of
the responder is a story with a signature on it: internally consistent,
attributable, and worth exactly the responder's word. Requesters SHOULD
prefer `expected_pin` with independently obtained anchors wherever the
deployment makes anchors available out of band — published checkpoints,
transparency-service receipts {{RFC9943}}, mutually recorded prior
exchanges. `min_freshness` responses inherit only whatever independence the
responder-selected anchor has from its own witnessing or publication.

**Split views: per-requester anchor forks defeat invariance.** Caller
invariance binds the artifact to (subject, anchor), not the anchor to a
single history: a responder that maintains divergent histories and steers
each requester to an anchor on "its" fork — a split-view (equivocation)
attack — serves individually verifiable, per-anchor-invariant answers
while defeating invariance in substance. The anchor-consistency rule of
{{invariance}} makes any fork a provable violation once two served
anchors are compared; but detection ultimately requires that comparison —
anchor gossip among requesters, or external witnessing of anchors —
infrastructure outside this protocol. This protocol constrains the
attack but cannot alone close it.

**Freshness of an anchor is not recency of evidence.** An anchor's
issuance freshness never implies recency or completeness of the evidence
it covers: a just-issued anchor can commit to a history omitting
everything the responder chose never to record. A time-based
`min_freshness` satisfied by a responder-issued anchor is, absent
external witnessing, responder self-attestation about its own clock and
log.

**Requester-side anchor staleness is a discipline, not a guarantee.** A
requester pinning a cached anchor gets exactly what that anchor covers —
including nothing the responder has done since. The protocol cannot make a
stale pin fresh; it can only make the staleness visible (the anchor is
identified in every response). Requesters for whom recency matters must
maintain their anchor supply — refreshing pins from independent sources, or
using `min_freshness` and accepting its weaker independence — and that
maintenance is operational discipline outside this protocol.

**Integrity is not coverage.** This protocol can establish that an artifact
verifies against an anchor, and that it is the same artifact for every
asker. It **never proves that the responder's evidence is complete
coverage of reality**: a responder that simply never recorded an event, or
that maintains a second evidence stream it is never asked about, produces
perfectly verifiable, perfectly caller-invariant answers with the event
absent. No request/response interaction with a single responder can close
this; the complement is counterparty-held records — each party to an
interaction recording its own half — so that omission by one holder is
contradicted by the other's evidence ({{symmetric}}). Deployments SHOULD
NOT represent a verified artifact response as proof that nothing else
happened.

**A principal reference is not authenticated by this document.** Where a
deployment binds a request or a commitment to a principal reference
({{principal}}), verifying that binding is the deployment's own mechanism
(typically a signature check outside the fields this document defines);
this document neither strengthens nor weakens whatever guarantee that
mechanism provides.

**Refusals and absences carry weight only when recorded.** The
accountability properties of {{recording}} exist only for parties that
actually record. A requester that discards refusals has no citable record
of them; the protocol makes the record possible, not automatic.

**Absence is unauthenticated; suppression is invisible.** An absence
records only the requester's own attempt: an on-path adversary that
suppresses a response the responder actually sent produces exactly the
same absence as a responder that never answered, so absence carries
minimal evidentiary weight against the responder. Responder-side
recording ({{recording}}) is the counter-record for this case, and
deployments SHOULD use integrity-protected transports so suppression
requires active interference.

**Refusal partitioning is the residual per-audience channel.** Caller
invariance constrains the artifact, not who receives one: a responder can
serve the friendly requester and refuse everyone else — each refusal
well-formed, signed, and permitted — recreating a per-audience view
through the pattern of refusals. Authorization remains responder policy
({{nongoals}}); the countermeasure is the recording discipline: signed
refusals make a partitioning pattern demonstrable from the accumulated
records of the refused.

**Signed refusals are commitments.** A responder's refusal is a signed
statement it may later be confronted with — including a `no_such_subject`
refusal for a subject the responder later serves. Responders SHOULD treat
reason-token selection with the same care as any other signed statement.

**A retention commitment is a promise, not availability.** A responder
that commits to retention ({{retention}}) and then loses the bytes has
breached. The interaction records the breach; it does not prevent it, and
deployments SHOULD NOT present a retention commitment as a guarantee that
the evidence will be there.

**The symmetric ask closes omission, not fabrication.** A counterparty's
half ({{symmetric}}) proves that an exchange existed and what each side
committed to; it does not prove that the content either side recorded is
true. Corroboration of content — a second party recomputing the same work
— is a different witness and is outside this document.

**Routes are attack surface.** A `route` ({{route-field}}) is chosen by
the requester and may be wrong, stale, or supplied by an adversary. A
requester MUST NOT treat a route as the responder's identity, and MUST
authenticate every response by the responder's signature. A response
signed by the wrong key is not a response from the responder, whatever
route it arrived by.

**Denial of service.** Requests are cheap to send; artifact assembly,
fresh-commitment issuance under `min_freshness`, and derivation evaluation
are not. Responders MAY apply rate and cost policy freely — refusing with
`policy_declined` is always available and always honest — but MUST NOT let
load-shedding take the form of caller-variant artifacts, which would
violate {{invariance}} where refusal would not.

# Privacy Considerations {#privacy}

**Digests-only is the default posture.** The base interaction discloses
digests, positions, and anchors — not content. Content disclosure happens
only through derivation ({{derivation}}) or a full-tier artifact, is
deliberate, and — where the exchange is recorded — leaves a record of
exactly what was disclosed, to whom, under which request.

**Low-entropy content defeats digest opacity.** A digest of a
low-entropy value (an enumerable identifier, a small-range field) can be
reversed by dictionary: an observer holding candidate values checks each
against the digest. Subjects, correlation identifiers, and
digests-only responses over low-entropy content SHOULD therefore be
constructed with salting or equivalent hardening, per the conventions of
the deployment's evidence format; this document does not define the salt
discipline but requires deployments to have one wherever digests are
relied on to conceal enumerable content.

**Leakage through reason tokens.** The difference between
`no_such_subject` and `not_authorized` reveals whether the subject exists;
other token distinctions leak analogously. A responder MAY answer
`policy_declined` uniformly wherever a more specific token would disclose
information its policy protects ({{refusal}}). The uniformity is the
point: a per-requester choice of token leaks by differentiation exactly
what the uniform token conceals.

**Coverage probing leaks log size.** A size-based `min_freshness` is a
threshold query on current log size — granted at or above the threshold,
refused `coverage_unsatisfiable` below it — so a requester can
binary-search it to learn the log's size and, over time, its growth rate,
without ever seeing content. Responders for whom activity volume is
sensitive can extend the uniform-`policy_declined` posture to coverage
refusals.

**History cards leak cadence and volume.** A card ({{history-card}})
discloses the number and spacing of checkpoints, and thereby an
approximation of activity over time, without any record content.
Responders for whom that is sensitive have the same option as for
coverage probing: a uniform `policy_declined` for the derivation.

**Exchange subjects reveal a relationship.** An `exchange` request names a
half that only the two parties could hold, so any intermediary that sees
the request learns that they interacted. Both parties already know;
transport confidentiality is the only mitigation for everyone else.

**Correlation identifiers SHOULD be non-identifying.** A `correlation`
subject is visible to the responder and to any transport intermediary;
identifiers that name persons or otherwise carry meaning outside the
exchange leak that meaning to every party that sees the request.

**The request itself leaks interest.** Asking about a subject reveals that
the requester cares about it — to the responder, and to intermediaries on
an unprotected transport. Requesters with sensitive interest patterns
should weigh the ask itself as a disclosure; transport confidentiality
protects against intermediaries but never against the responder.

**A principal reference, once bound, is itself disclosure.** Any
deployment mechanism that binds a request or response to a principal
reference ({{principal}}) discloses that reference to whoever observes the
exchange. Whether that reference is itself sensitive — a persistent
identifier versus a fresh one-time key — is a property of the host's
identity scheme, outside this document's control.

# IANA Considerations {#iana}

This document requests that IANA establish a registry titled "Evidence
Request Refusal Reasons". The registration policy is Specification
Required. Each entry consists of a reason token (lowercase ASCII,
underscore-separated), a one-line description, and a reference. The
initial contents are:

| Token | Description | Reference |
|---|---|---|
| `not_authorized` | the responder's policy does not authorize this requester for this subject | This document |
| `no_such_subject` | the subject does not resolve to evidence the responder holds | This document |
| `coverage_unsatisfiable` | the responder cannot satisfy the coverage constraint as stated | This document |
| `derivation_unsupported` | the responder does not support the named derivation | This document |
| `policy_declined` | the responder declines without further characterization | This document |
| `deadline_unmet` | the responder cannot answer within the stated deadline | This document |
| `request_malformed` | the request is not well-formed as specified by the defining document | This document |
| `retention_expired` | the responder's retention commitment for this subject has lapsed | This document |

This document further requests a registry titled "Evidence Request
Derivations", registration policy Specification Required. Each entry
consists of a derivation token (lowercase ASCII, underscore-separated,
with a `/N` version suffix), a one-line description, the declared field
set or a reference to it, and a reference. The initial contents are:

| Token | Description | Declared fields | Reference |
|---|---|---|---|
| `history_card/1` | checkpoints, receipts, and consistency proofs for a stream | none (no record content) | {{history-card}} |

This document makes no other requests of IANA.

--- back

# Example Deployments {#field-evidence}

The properties above are sketched, not proved, against four kinds of
deployment. Each is described by capability only, at a length that omits
implementation detail; none is a conformance requirement, and none names a
specific product or organization.

**An enterprise system-of-record** answers audit requests for a business
unit's transaction history from a counterparty's compliance function. The
same `full_history` request, pinned against the same published checkpoint,
is served identically whether it arrives over the system's internal
case-management API or a batch export a partner fetches nightly — the same
bytes both paths, exercising caller invariance ({{invariance}}) across
transports operated by different teams within one organization. Requests
and their outcomes are recorded in the system's own audit log, giving the
compliance function a citable record of what was asked and answered,
independent of the case file itself.

**A peer-to-peer inference mesh** runs a sidecar responder on every serving
node, answering `checkpoints`, `record`, and `exchange` subjects over a
subprotocol negotiated at connection time. Both halves of every served
exchange are sealed — the requester's commitment before sending, the
provider's reply citing it — and checkpoints go to a witness no serving
node operates. This deployment shape exercises the symmetric ask
({{symmetric}}) and the history card as the constant-size default
({{history-card}}).

**A decentralized social protocol** — clients publish signed events through
nodes they do not operate and do not fully trust — uses this interaction
for a client to ask a node for the interaction history tied to one of its
own signing keys. `subject` names the key, `coverage` pins a checkpoint the
client obtained from a different node, and the node answers with the same
bytes regardless of which node served the request, refuses
`coverage_unsatisfiable` if it has not yet observed enough events to
satisfy the pin, or refuses `no_such_subject` if it holds nothing under
that key at all. Because a client can run the same request against several
nodes and compare artifact digests, caller invariance ({{invariance}})
turns "my node says X" into something checkable rather than trusted.

**A continuous-integration pipeline** requests build-provenance evidence
for one artifact from an upstream stage before promoting it: `subject`
names the artifact by its build digest, `coverage` pins the upstream
stage's checkpoint recorded when the artifact was produced, and `deadline`
bounds how long the promotion step will wait before treating the request
as absence rather than blocking indefinitely. A stage that cannot produce
the provenance in time refuses `deadline_unmet` rather than let promotion
discover only a timeout; whether a promotion step proceeds anyway on
absence, rather than treating it as a blocked release, is a policy
decision this document does not make for it.

None of the four sketches above is a claim of conformance or of deployed
practice; retention commitments ({{retention}}) in particular remain a
design proposal here, not a description of running code. The divergences a
real deployment of any of these shapes would show — different refusal
conventions, different freshness expressions, no common recording
discipline — are precisely the gaps the normative sections above close.

# Reference Blocks and This Interaction {#refblocks}

Evidence formats that cite other artifacts commonly carry a reference
block of roughly the shape {relation, identifier, resolver, retention,
digest}, in which the identifier is a name in the resolver's system and
the digest is optional. Read against this interaction, the required and
optional halves swap, and each member maps onto one thing defined here:

| Reference member | Maps to | Status under this interaction |
|---|---|---|
| digest | `record` subject | REQUIRED; the identity of the cited thing |
| position under a checkpoint | `range` subject with `expected_pin` | OPTIONAL; a positional address, never a second identity |
| identifier + resolver | `route` | OPTIONAL; a hint for reaching a responder |
| retention | retention commitment ({{retention}}) | OPTIONAL; a signed promise by a named party, with an expiry |

The inversion this produces is deliberate: a producer that cannot name a
resolver may still cite, and a producer that cannot compute a digest may
not. A reference that promises only that a name stays resolvable cannot
say whether the bytes behind it are the ones present at issue time; a
digest can, and a commitment beside it says who is answerable for
serving them and until when. This appendix defines no reference-block
format; it shows how one of the common shapes lands on the interaction so
that the two can cite each other without either defining the other.

# Acknowledgments {#acknowledgments}
{:numbered="false"}

The author thanks the participants in early discussions that helped
shape this model.

The evidence formats this interaction carries, and the transparency
mechanisms its anchors lean on, are the work of the SCITT and COSE
communities ({{RFC9943}}, {{RFC9942}}); this document exists because those
answers made the shape of the ask the remaining gap.
