---
title: "Evidence Layer"
abbrev: "Evidence Layer"
docname: draft-mih-agent-evidence-layer-00
date: 2026-10-03
category: info
submissiontype: IETF
ipr: trust200902
area: Security
keyword:
 - evidence
 - transparency
 - audit
 - local store
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
  RFC8126:
  RFC8259:
  RFC8785:

informative:
  RFC9942:
  RFC9943:
  I-D.mih-scitt-agent-action-capsule:
    title: "An Agent Action Capsule Profile for SCITT"
    seriesinfo:
      Internet-Draft: draft-mih-scitt-agent-action-capsule-05
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.
    date: 2026-09
  I-D.mih-scitt-checkpointed-local-log:
    title: "The Checkpointed Local Log (CLL)"
    seriesinfo:
      Internet-Draft: draft-mih-scitt-checkpointed-local-log-01
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group
    date: 2026-09
  I-D.mih-agent-evidence-request:
    title: "An Interaction Model for Requesting Verifiable Evidence"
    seriesinfo:
      Internet-Draft: draft-mih-agent-evidence-request-00
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.
    date: 2026-09
  I-D.mih-zhang-agent-disclosure-bundle:
    title: "AAC Evidence Bundle"
    seriesinfo:
      Internet-Draft: draft-mih-zhang-agent-disclosure-bundle-00
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.
      - ins: Y. Zhang
        name: Yiqun Zhang
        organization: Independent
    date: 2026-09
  I-D.mih-agent-disclosure-envelope:
    title: "Disclosure Envelope Profile for Agent Action Capsules"
    seriesinfo:
      Internet-Draft: draft-mih-agent-disclosure-envelope-00
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.
    date: 2026-09
  I-D.mih-agent-settlement-records:
    title: "Two-Party Settlement Records for Agent Payments"
    seriesinfo:
      Internet-Draft: draft-mih-agent-settlement-records-00
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.
    date: 2026-10

--- abstract

This document defines the evidence layer: the conformance requirements for
a local evidence store that records evidence and the relationships between
records, keeps digests committed while payloads are separately referenced,
and preserves how each record came to be known well enough that a later
reader can tell an observation from a claim. This document defines the
record model, typed links between records, disclosure and retention
semantics, the three classes of index a store may maintain, and the minimum
interface any commitment substrate must supply for a store to conform to
this layer. It exists so that a request for evidence can be answered
honestly from what a store actually holds, and so that an evidence bundle
assembled in response is assembled from committed material rather than
assembled and then made to look committed. Conformance to this layer MUST
NOT require any particular implementation or commitment substrate: a
Checkpointed Local Log is one conforming profile; registration with a SCITT
Transparency Service is another; any other append-only transparency log, or
an implementer's own authenticated log, also qualifies. This document defines
neither evidence sufficiency policy, request routing, settlement, nor any
specific host-identity, signing, payload-storage, or replication mechanism.

--- middle

# Introduction

A request for evidence ({{I-D.mih-agent-evidence-request}}) says how to ask.
An evidence bundle ({{I-D.mih-zhang-agent-disclosure-bundle}})
says what a granting answer looks like. Neither says what a responder must
have held, and preserved, beforehand for that answer to be honest rather
than assembled to order. A responder that can produce a byte-identical
artifact for any requester, refuse with a citable reason, or truthfully
report that it has nothing needs a local substrate with specific properties:
records that do not change meaning after the fact, a place to say how one
record relates to another without editing either, and a way to distinguish
"I have never had this" from "I once had this and no longer do" from "I have
this and will not show you."

This document names that substrate an **evidence store**, defines the
**evidence layer** a store must conform to, and states nothing about how a
store is implemented beyond that. Conformance to the evidence layer MUST
NOT require any particular implementation or commitment substrate: a
Checkpointed Local Log ({{I-D.mih-scitt-checkpointed-local-log}}) is one
mechanism satisfying the interface in {{substrate}}; registration with a
SCITT Transparency Service {{RFC9943}} is another; any other append-only
transparency log, or an implementer's own authenticated log, also qualifies.

# Non-Goals {#nongoals}

This document deliberately does not define:

- **Evidence sufficiency, requirements, or verdicts.** Whether a set of
  records satisfies a requirement, and what a contract requires in the
  first place, is a policy layer that consumes what a store can produce. It
  is out of scope here.
- **Request routing or transport policy.** How a request reaches a store,
  and what a store's operator decides to answer, are deployment and policy
  questions this document does not reach.
- **Settlement.** Any obligation, payment, or remedy that follows from a
  recorded fact is outside this document; a store records that something is
  true of its own history, never what should happen as a result. Records
  of a settlement, such as those of {{I-D.mih-agent-settlement-records}},
  are ordinary records to a store.
- **A host-identity scheme.** What a `principal_ref` ({{record}}) names,
  and how a party's key relates to any role or standing, is host- or
  deployment-defined. This document states only what a `principal_ref`
  cannot be taken to mean ({{security}}).
- **A signing, payload-storage, or replication mechanism.** How a record or
  a checkpoint is signed, how payload bytes are stored and retrieved by
  digest, and how records travel between stores, delivery intermediaries,
  or fleets are implementation seams a host plugs in beneath a conforming store. This
  document does not define any of the three, and a store's conformance to
  this document does not depend on which implementation of any of them it
  uses.

# Conventions and Definitions {#terms}

{::boilerplate bcp14-tagged}

**Evidence layer:** the conformance requirements this document defines for a
local evidence store — the record model, typed links, disclosure and
retention semantics, the index classes, and the commitment-substrate
interface. Conformance to the evidence layer MUST NOT require any
particular implementation or commitment substrate.

**Evidence store (a "store"):** a local store that conforms to the evidence
layer: it records evidence and typed links between records ({{links}}),
keeps a durable, append-ordered commitment to what it has recorded, and can
answer a request against that commitment. The subject of this document.

**Record:** one committed entry in a store: a header ({{record}}) and,
optionally, digests referencing payload bytes held or resolved separately
({{retention}}). A record MAY be an Agent Action Capsule
{{I-D.mih-scitt-agent-action-capsule}}; this document does not require it.

**Digest:** unless a deployment's evidence format states otherwise, the
lowercase-hexadecimal SHA-256 digest of a value's canonical form — for a
JSON {{RFC8259}} value, `UTF8(JCS(value))` per {{RFC8785}}.

**Link:** a typed, directed reference from one record to another, itself
part of a committed record and never a mutation of either record it
relates ({{links}}).

**Commitment substrate:** the mechanism a store uses to assign append order
to records and to produce checkpoints against which inclusion and
consistency are checkable by a party other than the store ({{substrate}}).

**Checkpoint:** a value, produced by the commitment substrate, naming one
committed state of a store's history at one point in time.

**Epistemic type:** a closed value naming how a record's content came to be
known or asserted, preserved end to end regardless of what is later signed
or checkpointed about the record ({{record}}).

**Retention state:** a value naming whether, and how, a record's payload
can currently be resolved to bytes ({{retention}}).

**Transparency Service, Registration Policy, Receipt:** as defined in
{{RFC9943}}. A Receipt {{RFC9942}} proves that a statement is included in a
Transparency Service's log. It proves nothing else: not consistency between
two states of that log, and not that the statement is true.

**Witness:** a party other than the store that receives the store's
checkpoints and checks that each one extends the previous one it saw. A
Transparency Service whose Registration Policy admits a checkpoint only when
it is consistent with the previously registered one is one kind of witness.
"Witness" is not a term defined by {{RFC9943}}.

**Countersignature:** a signature over a record, or over a set of records,
by a party other than its producer, made after that party independently
recomputed named checks, in the manner of an Auditor {{RFC9943}}. It is not a
Receipt and not a Transparency Service function.

**Self-attested:** signed only by the record's own producer, with neither a
witness nor a countersignature.

# The Record Model {#record}

A record's durable header carries at least:

~~~
record:
  seq: <substrate-assigned append position>
  record_id: <content-derived or profile-assigned identifier>
  record_type: <open token, e.g. "observation", "claim", "close">
  epistemic_type: <one of the eight values below>
  committed_at: <time this store committed the record>
  event_time_claim: <claimed time of the underlying event, if any>
  payload_commitments: [ <digest>, ... ]
  retention_state: <AVAILABLE|PARTIAL|WITHHELD|DELETED|LEGAL_HOLD>
  links: [ { type: <link type>, target: <digest> }, ... ]
  subject_ref: <opaque correlation identifier>
  principal_ref: <opaque identifier, scheme host-defined>
~~~

`seq`, `record_id`, `record_type`, and `epistemic_type` are REQUIRED.
`retention_state` is REQUIRED whenever `payload_commitments` is present.
`links` is REQUIRED to be present, possibly empty, on any record that
carries no separate representation of its typed links. All other fields
are OPTIONAL. A profile or deployment MAY add further header fields; this
document takes no position on their semantics, except that no additional
field may change the meaning of `record_id`, `epistemic_type`,
`retention_state`, or any committed link once the record exists.

`record_type` is an open, deployment-extensible token describing what kind
of thing a record is. `epistemic_type` is closed and is this document's
central classification: it states how the record's content came to be
known, independent of what the record is about.

`principal_ref` is an opaque reference; the scheme that gives it meaning is
host-defined and out of scope here ({{nongoals}}, {{security}}).
`committed_at` is this store's own local time of commitment and is never a
substitute for `event_time_claim`, which is itself only a claim: nothing in
this document verifies that an `event_time_claim` is accurate.

## Epistemic Type {#epistemic-type}

| Value | Meaning |
|---|---|
| `observed_event` | directly observed by the recording system or actor |
| `system_of_record_fact` | asserted by an external system of record |
| `producer_claim` | asserted by the record's own producer, unverified by the store |
| `human_report` | asserted by a human, not machine-observed |
| `semantic_judgment` | a judgment or classification reached by interpretation, not direct observation |
| `derived_metric` | a value computed or aggregated from other records |
| `adjudication` | a ruling on a matter that was disputed or required judgment |
| `obligation_reference` | a reference to an obligation the record does not itself discharge |

**`epistemic_type` is assigned once, at commit, and is never upgraded.** No
signature, checkpoint, Receipt, witnessing, or countersignature attached to
a record after it is committed changes what kind of statement it was when it
was made, and neither does the assurance a record later reaches
(self-attested, witnessed, or countersigned). Those attach to a record;
they attest to who signed it and when it was committed. They do not attest
to how its content was known, which is what `epistemic_type` alone states.
A record misclassified at commit is corrected only by a later record
({{retention}}); the original's `epistemic_type` does not change.

The registry for this value set is established in {{iana}}.

# Typed Links {#links}

A link is a typed, directed reference from a record to a target record,
identified by the target's digest:

~~~
link:
  type: cites|adjudicates|supersedes|acknowledges|rebuts|closes
  target: <digest of the target record>
~~~

**A link is itself part of a committed record and MUST NOT mutate its
target.** The target's own header and commitment stand unchanged; a link
adds a new, separately committed fact about a relationship between two
records. Multiple links, of the same or different types, MAY name the same
target. A link's carrying record has whatever `epistemic_type`
({{epistemic-type}}) accurately describes what asserting the link is; a
record carrying an `adjudicates` link MUST have `epistemic_type`
`adjudication`.

The six link types are:

**`cites`:** the carrying record's claim depends on, or is intelligible
only with reference to, the target's committed content. A `cites` link
lifts nothing about the target beyond the target's own committed claim: it
does not inherit whatever the target record itself cites, and a reader
that wants to know what the target's own citations say must resolve them
independently.

**`adjudicates`:** the carrying record — necessarily `epistemic_type`
`adjudication` — renders a judgment about the target's claim. The judgment
covers exactly the target's own committed claim. It does not extend to
claims made inside records the target itself cites; a citing record's
adjudication is not an adjudication of what is cited two hops away.

**`supersedes`:** the carrying record replaces the target's content for
current use, without mutating the target. The target's original commitment
stands as part of the store's history; `supersedes` is how a store represents
a correction as a new fact rather than an edit ({{retention}}).

**`acknowledges`:** the carrying record states that its author has seen and
holds the target — establishing receipt, not agreement.

**`rebuts`:** the carrying record disputes the target's claim.

**`closes`:** the carrying record — a Close record ({{reconcile}}) — binds a
stated range or set of records as reconciled.

A link type is closed vocabulary, registered in {{iana}}. A deployment that
needs a relationship this list does not name registers a new link type; it
MUST NOT overload an existing token to mean something else for some of its
records.

These link types relate records of an evidence store. They are distinct
from the `chain.relation` and `citation_purpose` vocabularies of
{{I-D.mih-scitt-agent-action-capsule}}, which govern fields inside a
Capsule. The token `supersedes` appears in both this registry and
`chain.relation`; the two are separate registrations, and neither defines
the other. When a store's records are Capsules, how each link type is
carried in a Capsule's fields is not defined by this revision.

# Record/Payload Separation, Retention, and Disclosure {#retention}

A record's commitment — its presence in the store's committed history, its
`record_id`, its digest — is permanent once committed and is never mutated.
Payload bytes are a separate, possibly-absent resource that
`payload_commitments` point at by digest; a store's durable header commits
to digests, never to storage locations, and losing or withholding payload
bytes never un-commits the record that referenced them.

A correction to a record's content is represented by a later record
carrying a `supersedes` link ({{links}}), or, where the change is to
availability rather than content, by a lifecycle record changing
`retention_state`. Neither ever rewrites what was already committed.

## Retention States

| `retention_state` | Meaning | Resolving the payload |
|---|---|---|
| `AVAILABLE` | the payload can be resolved under current policy | returns bytes |
| `PARTIAL` | only some fields or preimages remain | returns the remaining fields; the record's own digest still verifies against what existed at commit time even though full reproduction is no longer possible |
| `WITHHELD` | the payload may exist but the requester is not authorized | returns nothing; a policy refusal, not a claim the payload is gone |
| `DELETED` | the payload was intentionally destroyed or has expired | returns nothing; commitment integrity survives, semantic reproducibility does not |
| `LEGAL_HOLD` | deletion is suspended by policy or legal requirement | behaves as `AVAILABLE` or `PARTIAL` per the payload's actual state; the hold blocks a future transition to `DELETED`, it does not itself change resolvability |

**`WITHHELD` MUST NOT be conflated with `DELETED`.** Both currently return no
bytes; only one of them is permanent. A party that needs to distinguish
"ask again under different authorization" from "the bytes are gone" reads
`retention_state`, never a resolution failure alone. A responder answering an
Evidence Request ({{I-D.mih-agent-evidence-request}}) for a `WITHHELD`
payload MUST NOT refuse it with reason `no_such_subject` or
`retention_expired`; those reasons state that the subject does not resolve
or that retention has lapsed, which is the `DELETED` case.

## Disclosure Records

A **disclosure record** documents an act of disclosing payload material —
for example, when a store assembles the artifact response to a request
({{I-D.mih-agent-evidence-request}}) or the disclosures overlay of an
evidence bundle
({{I-D.mih-zhang-agent-disclosure-bundle}}). Its
`epistemic_type` is `producer_claim`: it is the store's own statement of what
it chose to reveal. It carries:

~~~
disclosure:
  payloads: all|selected
  suppressed_fields: [ <field name>, ... ]
~~~

`payloads` states whether the disclosure carried all payload material the
store chose to consider, or only a selected subset. `suppressed_fields`
names fields intentionally not carried by this disclosure. For any
suppressed field the store chooses to acknowledge exists at all, the
disclosure record MAY carry that field's committed digest rather than
nothing: a withheld field disclosed with its digest is never reported as
blank and never as if it did not exist, mirroring the target record's own
`WITHHELD` handling above.

For one Capsule, the Disclosure Envelope
({{I-D.mih-agent-disclosure-envelope}}) carries disclosed values beside the
Capsule that commits to their digests. A disclosure record is the store's
own record that such a disclosure was made; it does not replace the
envelope's own verification.

A disclosure record carries a `cites` link to each record whose payload it
discloses. It states what was revealed about those records; it does not
change their own `retention_state`, and it is not itself evidence that the
underlying record is more, or less, available than its own
`retention_state` says.

# Index Classes {#indexes}

A store MAY maintain any or all of three classes of index over its committed
records. Each makes a different claim, and none MAY be substituted for
another:

1. **Operational index.** Fast local query support — by `record_id`,
   `subject_ref`, or any other field. Rebuildable from committed history at
   any time. Carries no independent trust value: a result from an
   operational index is only as trustworthy as the store producing it, and
   is not itself checkable by a party that does not trust the store.
2. **Authenticated index.** A deterministic structure whose root is
   committed into the store's commitment substrate ({{substrate}}).
   Supports membership, range, non-membership, and completeness properties
   that a party other than the store can check against a checkpoint,
   independent of trusting the store's own operational query results.
3. **Semantic or vector index.** Approximate discovery only, always
   rebuildable, and never proof of anything. A result from a semantic
   index MUST NOT be cited as proof of completeness, and MUST NOT be cited
   as proof that a matched record is true — it is a way to find candidates,
   never a statement about what exists or what is correct.

# The Commitment-Substrate Interface {#substrate}

A conforming store's commitment substrate MUST supply four properties,
regardless of mechanism:

1. **Append order.** Each record receives a position in a monotonic order
   the substrate itself assigns and fixes; the store does not renumber
   positions after the fact.
2. **Inclusion.** For any committed record, the substrate can produce a
   proof that it occupies its stated position — checkable by a party that
   does not trust the store.
3. **Consistency / continuity.** The substrate can produce a proof that one
   checkpoint's committed state is a well-defined extension of an earlier
   checkpoint's, never a silent rewrite of history already committed.
4. **Checkpoint identity.** A checkpoint names one committed state by a
   value independent of the store that produced it, so a checkpoint obtained
   from any source — the store, a peer, a witness — identifies the same
   state.

This document requires these four properties and no specific mechanism. A
Checkpointed Local Log ({{I-D.mih-scitt-checkpointed-local-log}}) is the
worked example used throughout the evidence family: append, a Merkle
Mountain Range, and periodic signed checkpoints supply all four locally.
Registration with a SCITT Transparency Service {{RFC9943}} is an alternate
profile. The Transparency Service's log supplies append order and checkpoint
identity, in place of a log the store itself maintains. A Receipt
{{RFC9942}} proves inclusion of a registered statement, and only inclusion.
Consistency comes from consistency proofs between two states of the
Transparency Service's log, never from a Receipt. **Conformance to this
document MUST NOT require any particular implementation or commitment
substrate.** A Checkpointed Local Log, registration with a SCITT
Transparency Service, any other append-only transparency log, or an
implementer's own authenticated log all qualify: a
store conforms by satisfying the four properties above under whichever
substrate it uses, and states which substrate that is.

# Answering a Request {#answers}

{{I-D.mih-agent-evidence-request}} defines six subject forms and three
mutually exclusive interaction outcomes. This section states, for each
subject form, the store-level capability that answers it — it does not
restate that document's own rules about coverage anchors or refusal
reasons.

| Subject | Store capability |
|---|---|
| `record` | resolve one record by `record_id`/digest — operational or authenticated index |
| `range` | resolve records at stated positions under the substrate's append order, with an inclusion or range proof from the authenticated index |
| `correlation` | resolve every record whose `subject_ref` (or an equivalent correlation field) matches — operational index |
| `exchange` | resolve every record carrying a `cites` link ({{links}}) whose target is the named exchange half's digest |
| `full_history` | the store's entire evidence body, subject to whatever disclosure policy governs the interaction ({{retention}}) |
| `checkpoints` | the commitment substrate's checkpoints and any Receipts or witness records for them ({{substrate}}), requiring no record-level resolution |

## Three Kinds of "No" {#answers-absence}

A store capable of producing these answers distinguishes three different
things that could be reported as "no evidence for this subject":

1. **Non-membership:** a proof, from an authenticated index
   ({{indexes}}), that no record occupies the stated position or carries
   the stated identity. This is the only one of the three that is itself
   checkable by a party other than the store.
2. **Withheld:** a record or its payload exists but is not disclosed under
   current policy ({{retention}}). This is a policy refusal, not an
   absence, and MUST NOT be reported as if the record did not exist.
3. **Asserted absence:** the store's own unproven claim that it holds no
   such record, offered when no authenticated index covers the subject.
   This is a `producer_claim` about the store's local state; it is not
   proof, and it is not a claim about anything on the requester's side.

None of the three is the "recorded absence" outcome of
{{I-D.mih-agent-evidence-request}}, which is the requester's own record that
no response arrived. A store that holds no such record answers with a
signed refusal carrying reason `no_such_subject`; a store that withholds
answers with a policy refusal. Neither is ever reported as a recorded
absence.

A `no_such_subject` refusal ({{I-D.mih-agent-evidence-request}}) MAY be
backed by a non-membership proof where the store's authenticated index
supports one. Where it does not, the refusal is honest only if the store
does not present its own asserted absence as if it carried the same weight.

# Reconcile and Close {#reconcile}

Two independently held stores are compared under a declared contract or
profile external to this document. Comparing corresponding candidates
assigns each pairing one of six states:

- `MATCHED`: both sides hold a corresponding record, and the records agree
  under the declared contract or profile.
- `A_ONLY`, `B_ONLY`: a corresponding record was found on one side only.
- `CONFLICTING`: both sides hold a corresponding record, and the records
  disagree.
- `INSUFFICIENT`: a candidate was found, but it lacks what the declared
  contract or profile needs in order to compare it.
- `UNRESOLVED`: the comparison was not, or could not be, decided.

The precise rules for each state are those of the declared contract or
profile. These are per-pairing states. They are not a judgment over the
reconciliation as a whole, which is a policy layer this document does not
define ({{nongoals}}).

**One half unavailable is not disagreement.** `A_ONLY` and `B_ONLY` state
that a corresponding record was not found on the other side — it may not
yet be committed there, may be withheld, or may never have existed for that
side. `CONFLICTING` states that both sides hold a corresponding record and
the records disagree. A reconciliation process MUST NOT report `A_ONLY` or
`B_ONLY` as `CONFLICTING`, and MUST NOT infer a substantive dispute from
the mere absence of a counterpart record.

A **Close** is a record — `record_type` `close`, `epistemic_type`
`producer_claim` — carrying a `closes` link ({{links}}) to the range or set
of records it binds, together with the period's inputs and the
contract/profile versions used to reach the state population above. Close
status is read from the links other records make to it, not from a field
the Close itself sets.

Only a counterparty record counts: a record committed by the counterparty's
store and signed under a key other than the Close's. A link from any record
of the Close's own store, or from a third party, never changes Close
status. How a reader establishes which store committed a record, and under
which key, is profile-defined; the record header of {{record}} names
neither.

- **CONTESTED:** a counterparty record carries a `rebuts` link to this
  Close. While such a link stands, the Close is not AGREED, whatever else
  links to it.
- **AGREED:** the Close is not CONTESTED, and a counterparty record carries
  an `acknowledges` link to this Close.
- **UNILATERAL:** neither.

Whether a later counterparty record can withdraw an earlier `rebuts` is not
defined by this revision.

**A Close is never rewritten.** Later evidence, or a correction to a
Close's own population, is a new record carrying a `supersedes` link to the
prior Close and stating the adjustment; the prior Close's committed content
stands unchanged, exactly as {{retention}}'s rule for any other correction.

# Security Considerations {#security}

**A self-consistent fabricated history is possible until an external party
pins a checkpoint.** A store that both produces and consumes its own
checkpoints can present a byte-for-byte consistent, provably append-only
history that never happened as its author intends a reader to believe.
Internal consistency proves that the store has not silently rewritten what
it already committed to a witness; it does not prove that what it
committed the first time was true, and it does nothing for a checkpoint no
external party has ever seen. The commitment-substrate properties of
{{substrate}} close the rewrite path once a checkpoint has left the store's
control; they do nothing for one that has not.

**Key control is not authority.** That a signature over a record verifies
against the key named by `principal_ref` establishes only that the signer
controlled that key at signing time. It establishes nothing about whether
the signer held any role, standing, or authority a relying party cares
about; any such binding is host policy this document does not define
({{nongoals}}).

**Non-membership is checkable; asserted absence is not.** A relying party
that cannot tell the two apart ({{answers-absence}}) can be handed a
fabricated "no evidence" with no way to check it. Recording which of the
three kinds of "no" a store actually returned matters as much as recording
the digest of whatever it did return.

**`epistemic_type` is assigned once and is load-bearing.** A record
misclassified at commit — a `producer_claim` recorded as an
`observed_event`, for instance — is not corrected by anything happening
later: no signature, checkpoint, or countersignature changes what kind of
statement a record was when it was made. Any correction is a new record;
the miscategorized original stands and remains readable as what it was.

**Signing, payload storage, and replication are out of scope, and that is
itself a boundary.** This document takes no position on how a record is
signed, how payload bytes are stored, or how records travel between stores
({{nongoals}}). A relying party's trust in a record obtained through any of
these mechanisms is exactly its trust in the signature and the commitment
substrate checkpoint it verifies against — never in the fact that a
particular mechanism was used to produce or move it.

# Privacy Considerations {#privacy}

The durable record header ({{record}}) MUST be privacy-minimized: it
carries what the store's own operation requires — identifiers, digests, and
typed references — and no low-entropy sensitive value beyond that. A
low-entropy value MUST NOT be treated as safe to carry merely because it
has been hashed; a small input space makes a digest invertible by
exhaustive search, so hashing alone is not minimization.

## What a Checkpoint Reveals {#privacy-checkpoints}

A store hands checkpoints ({{substrate}}) to parties outside its control:
witnesses, and counterparties receiving a record with an inclusion proof. A
checkpoint carries no record content, but it is not free of information.

**What a checkpoint reveals.** Every checkpoint states the size of the
store's committed history: the number of records appended since the store's
first record, not since the previous checkpoint (in a Checkpointed Local Log
({{I-D.mih-scitt-checkpointed-local-log}}), its `log_size`). A party holding
two checkpoints from one store therefore learns how many records the store
committed between them, across every subject and counterparty the store
records, not only those it shares with that party. A checkpoint also
carries a time, and the times at which a store issues checkpoints reveal its
activity pattern.

**What a checkpoint does not reveal.** A checkpoint and an inclusion proof
reveal no record content. The sibling values in an inclusion proof are
digests over other records; they reveal nothing about those records only if
those records cannot be guessed and confirmed by recomputing a digest. To
make that hold, every record MUST include, within the bytes from which its
commitment-substrate entry is derived, a value of at least 128 bits drawn
from a cryptographically secure random source, generated by the store for
that record alone and never reused. A value supplied by or known to another
party (such as a client- or counterparty-supplied nonce), a time, a
sequence number, or a digest of content does not satisfy this requirement.

**Mitigations.** A store SHOULD, before a checkpoint leaves its control,
append **padding records** so that the checkpoint's size falls on a bucket
boundary: for example, the next multiple of a configured bucket size. Two
such checkpoints then reveal the count between them only to within the
bucket size. This document reserves the `record_type` value `padding` for
this purpose. A padding record has `epistemic_type` `producer_claim`; its
only content is a freshly generated random value meeting the requirement
above; and it carries no `payload_commitments`, no links, no `subject_ref`,
and no `principal_ref`. A padding record MUST NOT be the target of any
link. It is appended like any other record and changes none of the
properties of {{substrate}}.

A store SHOULD coarsen every time value that leaves its control inside
signed or committed bytes, such as a checkpoint's time or a disclosed
record's `committed_at`, to a granularity no finer than one minute. Such a
value is covered by a signature or a commitment, so it is coarsened when
those bytes are produced; coarsening a copy afterwards invalidates the
signature or the record's inclusion. A store MAY keep finer-grained times
in local state that is neither committed nor disclosed.

A store operator MAY keep separate stores, each with its own commitment
substrate and checkpoints, for separate scopes (for example, per
counterparty), so that a checkpoint shown within one scope reveals nothing
about record volume in another.

A verifier MUST treat a padding record as an ordinary record when it checks
inclusion, consistency, or a checkpoint, and MUST NOT reject a checkpoint,
proof, or range because it contains padding records. A reader that counts,
lists, or summarizes records MUST NOT count a padding record as a record,
and a store MUST NOT return one as responsive to a `record`, `correlation`,
or `exchange` subject ({{answers}}).

# IANA Considerations {#iana}

IANA is requested to create the "Evidence Layer Parameters" registry group
with the two registries below. For both, the registration policy is
Specification Required ({{RFC8126}}, Section 4.6), and the change controller
is the IETF. Each entry consists of a token (lowercase ASCII,
underscore-separated), a one-line description, and a reference.

Until IANA creates these registries, the interim registry of record is
`REGISTRY.md` in the source repository of
{{I-D.mih-scitt-agent-action-capsule}}. It records the same values and
policy, and the same designated-expert criteria it applies to its other
registries.

Neither registry duplicates an existing one. "Evidence Layer Link Types" is
not the `chain.relation` or `citation_purpose` registry of
{{I-D.mih-scitt-agent-action-capsule}}, which govern fields inside a Capsule
({{links}}). "Evidence Layer Epistemic Types" is not that document's
`domain` registry, which states what kind of act a Capsule records, not how
its content came to be known.

## Evidence Layer Epistemic Types

Initial contents, from {{epistemic-type}}:

| Token | Description | Reference |
|---|---|---|
| `observed_event` | directly observed by the recording system or actor | This document |
| `system_of_record_fact` | asserted by an external system of record | This document |
| `producer_claim` | asserted by the record's own producer, unverified by the store | This document |
| `human_report` | asserted by a human, not machine-observed | This document |
| `semantic_judgment` | a judgment or classification reached by interpretation, not direct observation | This document |
| `derived_metric` | a value computed or aggregated from other records | This document |
| `adjudication` | a ruling on a matter that was disputed or required judgment | This document |
| `obligation_reference` | a reference to an obligation the record does not itself discharge | This document |

## Evidence Layer Link Types

Initial contents, from {{links}}:

| Token | Description | Reference |
|---|---|---|
| `cites` | the carrying record depends on the target's committed content | This document |
| `adjudicates` | the carrying record renders a judgment about the target's claim | This document |
| `supersedes` | the carrying record replaces the target's content for current use, without mutating it | This document |
| `acknowledges` | the carrying record states its author has seen and holds the target | This document |
| `rebuts` | the carrying record disputes the target's claim | This document |
| `closes` | the carrying record binds a range or set of records as reconciled | This document |

This document makes no other requests of IANA. The `record_type` value
`padding` ({{privacy-checkpoints}}) is reserved by this document;
`record_type` is an open token and has no registry.

--- back

# Acknowledgments

This document distills operational experience running local evidence
stores against the interaction model of
{{I-D.mih-agent-evidence-request}} and the presentation format of
{{I-D.mih-zhang-agent-disclosure-bundle}} into the substrate
layer both depend on.
