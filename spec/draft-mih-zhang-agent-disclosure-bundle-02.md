---
title: "AAC Evidence Bundle"
abbrev: "AAC Evidence Bundle"
docname: draft-mih-zhang-agent-disclosure-bundle-02
date: 2026-10-29
category: std
submissiontype: IETF
ipr: trust200902
area: "Security"
workgroup: "SCITT"
keyword:
 - SCITT
 - evidence
 - AI agent
 - transparency
 - audit
stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 - ins: S. Mih
   name: Steven Mih
   organization: Action State Group, Inc.
   email: spec@actionstate.ai
 - ins: Y. Zhang
   name: Yiqun Zhang
   organization: Independent
   email: zhangyiqun9164@gmail.com

normative:
  RFC2119:
  RFC8174:
  RFC8126:
  RFC8259:
  RFC8785:
  RFC4648:
  RFC3339:
  RFC8032:
  RFC8610:
  RFC6901:
  RFC9943:
  RFC9942:
  I-D.mih-scitt-agent-action-capsule:
    title: "An Agent Action Capsule Profile for SCITT"
    seriesinfo:
      Internet-Draft: draft-mih-scitt-agent-action-capsule-05
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.
  I-D.mih-agent-disclosure-envelope:
    title: "Disclosure Envelope Profile for Agent Action Capsules"
    seriesinfo:
      Internet-Draft: draft-mih-agent-disclosure-envelope-00
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.
  I-D.mih-agent-evidence-request:
    title: "An Interaction Model for Requesting Verifiable Evidence"
    seriesinfo:
      Internet-Draft: draft-mih-agent-evidence-request-01
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.
    date: 2026-10-29

informative:
  I-D.mih-agent-evidence-layer:
    title: "Evidence Layer"
    seriesinfo:
      Internet-Draft: draft-mih-agent-evidence-layer-00
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.
    date: 2026-10-03
  I-D.mih-sokolov-scitt-payload-binding:
    title: "Canonicalization Declaration for SCITT Signed Statements"
    seriesinfo:
      Internet-Draft: draft-mih-sokolov-scitt-payload-binding-05
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.
      - ins: A. Sokolov
        name: Anton Sokolov
        organization: Tyche Institute
    date: 2026-09-13

--- abstract

This document defines the AAC Evidence Bundle, a portable presentation and
verification container for an Agent Action Capsule and the records that make
its evidentiary claim intelligible. A permalink carries a bundle in its URL
fragment, an offline HTML report carries a bundle in its shell, and a hosted
report serves a bundle at its URL. The bundle does not alter any enclosed
Capsule. It declares its citation closure and any missing cited records,
carries verified disclosure preimages as a bundle-level overlay, separates
three different completeness claims, can carry the producer's signed
declaration of what it offers in each category of evidence, and permits
independently specified
extension blocks and countersignatures: signatures by a party other than the
producer over the bundle digest, each accompanied by a statement of which
claims that party recomputed and with what result.

--- middle

# Introduction

A Capsule proves the identity and claimed content of one action. An audit
report normally needs more: the report Capsule, its chain of judgments or
adjudications, the turns cited by those records, selected disclosed preimages,
and the log evidence that supports a claim about coverage. Passing these
items as unrelated files produces a presentation that a verifier cannot
describe precisely.

The AAC Evidence Bundle is that unit of evidence. It is deliberately a
presentation-layer object: the Capsules in `records` retain their original
bytes, identities, signatures, and registrations. The same bundle can be
encoded in a URL fragment, embedded in an offline HTML shell, or obtained
from a hosted report URL. These are transports for one object, not distinct
evidence formats.

# Conventions and Definitions {#conventions}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals,
as shown here.

Bundle:
: An AAC Evidence Bundle as defined in {{bundle-object}}.

Root Capsule:
: The Capsule identified by the Bundle's `root` member. The Bundle's evidence
  claim is made from this Capsule outward through its declared closure.

JSON-DIGEST:
: The lowercase-hex SHA-256 digest of `UTF8(JCS(value))`, using {{RFC8785}}
  over the whole recursively canonicalized JSON value with no member filtering,
  as defined by {{I-D.mih-scitt-agent-action-capsule}}.

Countersignature:
: A countersignature is a signature by a party other than the producer over a
  bundle digest, accompanied by a statement of which claims that party
  recomputed and with what result. A report is a bundle.

Countersigner:
: The party that makes a countersignature. A countersigner works in the
  manner of an Auditor {{RFC9943}}: it independently recomputes checks over a
  Bundle it was given and signs a statement of the results -- a list of what
  it recomputed, never an opinion. A countersigner MAY register that
  statement as a Signed Statement with a Transparency Service, in which case
  the entry carries the Receipt; the Receipt proves that the statement is in
  that log and says nothing about the Bundle. Which producers a countersigner
  accepts Bundles from is its own admission rule, outside this document.

Self-countersignature:
: An entry in `countersignatures` whose signer key is the producer's key
  ({{self-countersignature}}). It is well-formed and is rendered as not
  independent.

`countersignatures` is a member name. An entry is a statement by a party
other than the producer that it recomputed named checks over the bundle
digest, in the manner of an Auditor {{RFC9943}}. It is not a COSE
countersignature {{?RFC9338}}, not a Receipt {{RFC9942}}, and not a
Transparency Service function.

WITHHELD:
: The disclosure state of an eligible member absent from the Bundle-level
  disclosure overlay. It is neither an empty value nor a verification failure.

The terms "Capsule", "capsule_id", `chain.parent_capsule_id`, `references`,
`seq`, `leaf_index`, and `log_coordinates` are as defined in
{{I-D.mih-scitt-agent-action-capsule}}.

# Evidence Bundle Object {#bundle-object}

A Bundle is a JSON {{RFC8259}} object with this shape. Ellipses denote values
defined by this document or a registered extension; they do not authorize
untyped replacement formats.

~~~
{
  "bundle_version": "2",
  "bundle_kind": "evidence-bundle/v2",
  "root": "<capsule_id>",
  "records": [ ... ],
  "completeness": {
    "closure_depth": 2,
    "records_mode": "complete|declared_incomplete",
    "payloads_mode": "all|selected|none",
    "suppressed_fields": [ ... ],
    "missing": [ "<cited capsule digest>", ... ],
    "selection": "producer-selected"
  },
  "disclosures": {
    "<capsule_id>": { "<member>": "<revealed preimage>" }
  },
  "disclosure_record": "<capsule_id>",
  "completeness_certificate": { ... },
  "checkpoint": { ... },
  "category_coverage": { ... },
  "verification": { ... },
  "extensions": { "<registered kind>": { ... } },
  "countersignatures": [ ... ]
}
~~~

`bundle_version` and `bundle_kind` are REQUIRED and MUST be respectively
`"2"` and `"evidence-bundle/v2"`. `root`, `records`, and `completeness` are
REQUIRED. `root` is the lowercase-hex `capsule_id` of one record in `records`.
Every `records` element MUST be an unmodified Capsule object conforming to
{{I-D.mih-scitt-agent-action-capsule}}; duplicate `capsule_id` values are
not permitted. All other members shown are OPTIONAL unless a claim in this
document requires them. A receiver MUST reject an object with an unknown
`bundle_version` or `bundle_kind` as an AAC Evidence Bundle, rather than
silently applying version-2 verification rules.

`payloads_mode` states whether the producer included all payload material it
chose to carry (`all`), only a selected subset (`selected`), or none
(`none`). A Bundle whose `payloads_mode` is `none` carries no `disclosures`
member. `selection`, when present, names the certificate mode of
`completeness_certificate` ({{certificate-modes}}).
`suppressed_fields` names fields intentionally not carried by the Bundle; it
does not turn an absent disclosure into an empty value or a failure.

# Citation Closure {#closure}

Citation closure is declared, not assumed. Starting at `root`, a producer
MUST traverse `chain.parent_capsule_id` and every `references[].digest`
transitively through `completeness.closure_depth` edges. The default depth is
2 when the member is absent: report to judgments or adjudications, then to
turns. A producer using a different depth MUST state that non-negative JSON
integer explicitly.

For each target reached within that depth, the Bundle MUST either supply the
cited Capsule in `records` with a matching identity or list its digest once in
`completeness.missing`. A target MUST NOT be silently dropped. `records_mode`
MUST be `complete` exactly when `missing` is absent or empty, and MUST be
`declared_incomplete` exactly when it is non-empty. A verifier MUST report
the latter as declared incomplete, not as complete and not as an unexplained
failure. A supplied record whose computed `capsule_id` does not match the
chain target or reference digest is not supplied evidence for that target.

The closure declaration says nothing about records beyond its stated depth.
A verifier MUST report the depth it applied and MUST NOT infer unbounded
ancestry or citation completeness from the presence of a short chain.

# Bundle-Level Disclosures {#disclosures}

`disclosures` is a Bundle-level overlay keyed first by the enclosed Capsule's
`capsule_id`, then by the disclosure member name:

~~~
"disclosures": {
  "<capsule_id>": {
    "agent_input": { ... },
    "agent_output": { ... }
  }
}
~~~

It has the same eligibility and DE-3 digest rule as the per-Capsule
Disclosure Envelope in
{{I-D.mih-agent-disclosure-envelope}}. The member name
selects that draft's registered committed-digest path in the specified
Capsule. For every disclosed member, a verifier MUST compute
`JSON-DIGEST(revealed preimage)` and compare it to the committed digest at
that registered path in that `records` element. A match is REVEALED; a
mismatch is a failed verification of that disclosed content. A member absent
from this overlay is WITHHELD, never blank and never failed.

The overlay is carried once per Bundle rather than by wrapping each Capsule
in `{capsule, disclosures}`. It MUST NOT alter an enclosed Capsule or its
`capsule_id`. An overlay key not naming a supplied record, or a member not
eligible under the Disclosure Envelope registry, is a disclosure finding and
MUST NOT be treated as a successful revelation. `disclosure_record`, when
present, identifies the Capsule that records the act of sealing or issuing
these disclosures; it is evidence about that act and does not replace the
DE-3 check.

# Completeness Claims and Log Membership {#completeness}

`completeness_certificate` and `checkpoint`, when supplied, support three
separate claims. A verifier MUST report each claim independently. The
`composed/v1` extension adds a fourth claim, composition closure
({{composed-closure}}), which is reported separately from these three.

1. **Graph closure**: every citation reached under {{closure}} is supplied
   with matching identity or explicitly listed in `completeness.missing`.
2. **Interval coverage**: the claimed sequence interval is bound to a
   checkpointed range root. Without a verified Receipt {{RFC9942}} over the
   checkpoint from a Transparency Service, or a verified checkpoint
   signature, this is only relative to a producer-asserted checkpoint.
3. **Per-record membership**: every supplied record is bound to its claimed
   log position under that range root, and, for a range, every other leaf in
   the interval is accounted for ({{non-record-leaves}}).

Per-record membership is the claim a range certificate makes about the
records in its interval: interval coverage binds the leaf values, and per-record
membership says what each leaf is. A verifier MUST ignore members of
`completeness_certificate` that this document does not define; they MUST NOT
change any result it reports.

The certificate MUST state its `log_id`, range root, first and last `seq`,
and the proof material that binds that range root to `checkpoint`. A signed
range proof that binds only the first and last record proves endpoint
inclusion only: an interior record can be deleted or replaced while such a
proof still passes. A verifier MUST NOT report whole-range completeness from
endpoint inclusion alone. A verifier MUST verify an included Receipt
{{RFC9942}} over the checkpoint, or the checkpoint signature, before reporting
interval coverage or per-record membership as independently verified.
Otherwise it MUST explicitly label those claims `checkpoint_unverified` and
describe them as relative to a producer-asserted checkpoint.
The portable checkpoint signature member is `checkpoint.cose`, an unpadded
base64url CLL COSE checkpoint. A verifier that implements this member MUST
verify it and require its log identifier, MMR size, and root to equal the
certificate and checkpoint values before removing the qualifier.

For the third claim, every supplied record MUST either carry a membership entry
within the declared interval or be explicitly listed in `completeness.missing`.
A membership entry or record whose `seq` is outside the interval MUST be
rejected. Each membership entry MUST carry `log_coordinates` stating its
claimed position and an inclusion proof to the certificate's range root. The
base profile's terms apply exactly:
`seq` is the 1-based log position and `leaf_index = seq - 1` is the zero-based
MMR index. `log_coordinates` states which index is used. The verifier MUST
verify every inclusion proof at its stated `leaf_index`, require the proof's
`leaf_index` to equal that coordinate and its `size` to equal
`checkpoint.mmr_size`, and bind the record to
the range root; it MUST NOT substitute an endpoint proof for a missing
per-record proof. A record without a valid proof may remain usable for graph
closure but does not satisfy per-record membership.

## Certificate Modes {#certificate-modes}

`completeness.selection` names the mode in which `completeness_certificate`
is read:

- **Absent**: a range certificate, as described above. Its interval ends at
  the checkpoint's last leaf.
- **`producer-selected`**: a producer-selected certificate
  ({{producer-selected}}).

This document defines no other value. A verifier that meets a `selection`
value it does not implement, including a value that is not a string, MUST
report interval coverage and per-record membership as not established
(finding `certificate_mode_unsupported`). It MUST NOT report either claim as
failed because of the mode, MUST NOT read the certificate under another mode,
and MUST NOT report the Bundle as invalid on that ground. Graph closure,
disclosures, extensions and countersignatures are unaffected.

The same rule applies to a verifier that predates a mode: a verifier that does
not implement producer-selected certificates reports such a Bundle's interval
coverage and per-record membership as not established, never as failed. A
Bundle in a mode the verifier lacks is unverified in that respect; it is not
evidence of tampering, and reporting it as invalid would make an honest Bundle
indistinguishable from an altered one.

## Producer-Selected Certificates {#producer-selected}

A producer-selected Bundle carries records that its producer chose from a log,
each proven on its own, and makes no claim about the records between them. Its
`completeness.selection` is `producer-selected`. Its certificate carries
`log_id`, `range_root` and `memberships`. It carries no range: `first_seq`,
`last_seq`, `body_digests` and `range_proof` are not part of it, and a
verifier does not read them. It MUST NOT carry `non_record_leaves`
({{non-record-leaves}}).

~~~
"completeness": {
  "closure_depth": 0,
  "records_mode": "complete",
  "payloads_mode": "none",
  "suppressed_fields": [],
  "missing": [],
  "selection": "producer-selected"
},
"completeness_certificate": {
  "log_id": "<log identifier>",
  "range_root": "<checkpoint root>",
  "memberships": { "<capsule_id>": { "log_coordinates": { ... },
                                      "inclusion_proof": { ... } } }
}
~~~

A verifier that implements this mode:

- reports interval coverage as not established (finding
  `selection_not_checkable`): there is no interval;
- verifies per-record membership record by record. `range_root` MUST equal the
  checkpoint's root. Each record's membership entry MUST carry
  `log_coordinates` naming the checkpoint's `log_id`, a `seq` of at least 1
  that no other entry claims, and `leaf_index = seq - 1`, and an inclusion
  proof at that index whose `size` equals `checkpoint.mmr_size` and that binds
  the record's `capsule_id` to the root. A membership entry for a record the
  Bundle does not carry is a failure. Otherwise the rules of
  {{completeness}} apply, including the `checkpoint_unverified` label;
- reports a certificate that carries `non_record_leaves` as invalid.

A producer-selected Bundle is therefore never complete as to its log: a
verifier MUST NOT report it as such, and its best result is that every carried
record is a member of the checkpointed log. A changed record or proof fails
per-record membership exactly as in a range Bundle. Graph closure, which is
about citations, not log positions, is unaffected by the mode.

## Non-Record Leaves {#non-record-leaves}

A log can hold leaves that are not records. The Evidence Layer
{{I-D.mih-agent-evidence-layer}} reserves the `record_type` value `padding`
for records a store appends so that a checkpoint's size falls on a bucket
boundary (its Section 12.1). A store that pads before every checkpoint usually
has a padding leaf at the checkpoint's last leaf, so a range ending there
always covers one. A range certificate covers such leaves in its member
`non_record_leaves`, which carries each one in full:

~~~
"non_record_leaves": [
  { "seq": 6,
    "content": { "capsule_id": "<64 hex>", "record_type": "padding",
                 "epistemic_type": "producer_claim",
                 "store_nonce": "<64 hex>" } }
]
~~~

`non_record_leaves` is an array. Each element is an object with `seq`, the
leaf's 1-based log position within `[first_seq, last_seq]`, and `content`, the
leaf's content. A digest alone is not accepted in place of `content`: a bare
leaf value could be the identifier of a Capsule that the Bundle thereby hides.
Members of an element other than `seq` and `content` are ignored.

**The padding leaf.** This document defines one non-record leaf type,
padding. The members of a padding record are those of
{{I-D.mih-agent-evidence-layer}} Section 12.1: `record_type` `padding`,
`epistemic_type` `producer_claim`, and `store_nonce`, 32 bytes as 64 lowercase
hexadecimal characters. That document fixes the members but not their
serialization or the record's identifier, so this document states both for a
padding leaf in a Bundle. Its `content` is a JSON object with exactly four
members: those three and `capsule_id`. `capsule_id` is 64 lowercase
hexadecimal characters, and is the JSON-DIGEST ({{conventions}}) of the object
formed by the other three members. The leaf value is `capsule_id`. A store's
local-only producer envelope (`signature`, `key_id`) is not part of `content`.
(Moving this rule into the Evidence Layer awaits a later revision of that
document.)

**Checking an element.** A verifier reads the elements in order. For each one:

1. An element that is not an object is malformed (finding
   `non_record_leaf_element_invalid`).
2. A `seq` that is not an integer within `[first_seq, last_seq]`, or that is
   the `seq` of a record's membership entry or of an earlier element, is
   invalid (finding `non_record_leaf_seq_invalid`); the element accounts for
   no position.
3. Otherwise the element accounts for its `seq`. Then:
   - when `content` is not an object, or its `record_type` is not a string,
     the element is malformed (finding `non_record_leaf_malformed`);
   - when `record_type` is not `padding`, the leaf is of a type this document
     does not define (finding `non_record_leaf_type_unsupported`);
   - when the padding `content` does not have exactly the four members above,
     each in the form above, with `epistemic_type` equal to `producer_claim`,
     it is malformed (finding `non_record_leaf_malformed`);
   - the verifier recomputes the leaf value from the other three members and
     requires it to equal both `content.capsule_id` and
     `body_digests[seq - first_seq]`; otherwise the leaf does not match
     (finding `non_record_leaf_mismatch`).

A `non_record_leaves` value that is not an array is malformed (finding
`non_record_leaves_malformed`) and accounts for no position.

**Per-position accounting.** For per-record membership over a range, every
`seq` in `[first_seq, last_seq]` MUST be accounted for by exactly one of a
record's membership entry and a `non_record_leaves` element. Each position is
then:

- **verified**: a record's verified membership, or a padding leaf that
  recomputes to its body digest;
- **unsupported**: a leaf of a type the verifier does not implement; or
- **unaccounted**: neither, or an element that failed a check above
  (finding `membership_record_missing` for a position with neither).

Any failure fails per-record membership, whatever else is unsupported. When
nothing fails and some position is unsupported, per-record membership is not
established: the verifier MUST NOT report it as established, and MUST NOT
report it as failed. Otherwise the rules of {{completeness}} apply. A
verifier that implements this member therefore no longer rejects a range
because it contains padding records, as {{I-D.mih-agent-evidence-layer}}
Section 12.1 requires. A verifier that does not implement the member ignores
it, as it ignores any member it does not know, and then reports every padding
position as missing, which fails per-record membership. A producer therefore
SHOULD NOT emit `non_record_leaves` to readers that do not implement this
revision; until it can, a producer-selected certificate states what it can
prove without it.

A non-record leaf is not a record. It never appears in `records`, never
counts as a record for graph closure, disclosures or any count a verifier
reports, and is never the target of a citation. Leaves other than padding,
such as a store's checkpoint stamps, are not covered by this document. A range
over a log that contains one is reported, at best, as not established through
`non_record_leaf_type_unsupported`; a producer that needs a Bundle over such a
log without that result uses a producer-selected certificate.

# Category Coverage {#category-coverage}

`category_coverage`, when present, is the producer's signed declaration of
what it offers in each category of a named category set: for each category,
exactly one status. It answers the `categories` field of an Evidence Request
({{I-D.mih-agent-evidence-request}}), and a producer MAY include it without
one. **It declares; it does not prove.** A verifier checks that it is well
formed, who signed it, and whether it is consistent with what the Bundle
carries. It never establishes that the producer offers everything it
declares, or that nothing exists in a category declared absent.

~~~
"category_coverage": {
  "set": "<category set identifier>",
  "categories": {
    "<category name>": { "status": "AVAILABLE" },
    "<category name>": { "status": "UNDISCLOSED",
                         "policy_uri": "<absolute URI>" }
  },
  "request_digest": "<64 hex>",
  "signer": { "key_id": "<64 hex>" },
  "signature": "<128 hex>"
}
~~~

`set` is REQUIRED, a non-empty string naming a category set
({{iana}}). A set whose identifier begins `x-` is private: it is not
registered, and a verifier never treats it as known. `categories` is
REQUIRED, a non-empty object keyed by category name; each value is an object
with `status` and, where required, `policy_uri`. `request_digest`,
OPTIONAL, is the digest of the Evidence Request this declaration answers,
computed as {{I-D.mih-agent-evidence-request}} computes a request digest, in
lowercase hexadecimal. `signer` and `signature` are OPTIONAL, and present
together or not at all. Members not defined here are ignored.

The member is part of the bundle digest ({{bundle-digest}}), so a
countersignature binds it.

## Statuses {#category-statuses}

Each category has exactly one `status`, written in upper case:

| status | Meaning |
|---|---|
| `AVAILABLE` | evidence in this category is offered |
| `PARTIAL` | only some evidence in this category is offered |
| `WITHHELD` | evidence in this category may exist and is not released to this requester |
| `DELETED` | evidence in this category was destroyed or has expired |
| `ABSENT` | the producer states that it holds nothing in this category |
| `UNDISCLOSED` | the producer does not state which of the other statuses applies, under the policy `policy_uri` names |

`AVAILABLE`, `PARTIAL`, `WITHHELD`, `DELETED` and `UNDISCLOSED` are the
retention states of the Evidence Layer {{I-D.mih-agent-evidence-layer}}, with
the same meanings, applied to a category rather than to one record's payload.
`ABSENT` is the producer's asserted absence in that document's sense: its own
unproven claim about its own store, never a non-membership proof and never
the requester's recorded absence of {{I-D.mih-agent-evidence-request}}. The
retention state `LEGAL_HOLD` is not a status: it changes what may happen to
evidence, not what is offered.

`UNDISCLOSED` MUST carry `policy_uri`, an absolute URI ({{!RFC3986}},
Section 4.3) naming the policy under which the status is not disclosed;
`policy_uri` MAY accompany any other status. `WITHHELD` and `UNDISCLOSED` are
different statements and MUST NOT be conflated: `WITHHELD` says evidence may
exist and is not released; `UNDISCLOSED` says nothing about whether any
exists.

## Signature {#category-signature}

`signer.key_id` is a 32-byte Ed25519 {{RFC8032}} public key as 64 lowercase
hexadecimal characters. `signature` is the Ed25519 signature, as 128
lowercase hexadecimal characters, under that key over the signing input

~~~
UTF8(JCS({"category_coverage": <the member without signature>,
          "root": <the Bundle's root>}))
~~~

Including `root` binds the declaration to the Bundle it was made for, so a
signed declaration copied into another Bundle does not verify. The signature
attributes the declaration to the holder of the key. It does not establish
who that holder is; a verifier MAY compare `signer.key_id` with the
producer's keys ({{self-countersignature}}) and report the result.

## Verifier Properties {#category-properties}

A verifier that implements this member reports the following properties,
each as exactly one of `PASS`, `FAIL`, `NOT_PRESENT`, `NOT_CHECKED` and
`INCONCLUSIVE`, with the meanings of the countersignature results
({{countersign-entry}}): the check held, did not hold, had nothing to operate
on, could not run, or resolved only in part. A Bundle without the member has
no category properties.

`category_coverage_form`:
: `PASS` when the member is as described above, including a `policy_uri` for
  every `UNDISCLOSED` status; otherwise `FAIL`. When it is `FAIL`, every other
  property is `NOT_CHECKED`.

`category_coverage_signature`:
: `NOT_PRESENT` when the member carries no signature; `PASS` when the
  signature verifies; `FAIL` otherwise.

`category_coverage_set_registered`:
: `NOT_PRESENT` for a private (`x-`) set; `INCONCLUSIVE` when the verifier
  does not know the set; `FAIL` when it knows the set and a declared category
  is not one of its names; `PASS` otherwise.

`category_coverage_request`:
: `NOT_CHECKED` when the verifier does not have the Evidence Request;
  `FAIL` when `request_digest` is present and is not that request's digest;
  `NOT_PRESENT` when the request has no `categories` field; `FAIL` when the
  request names another set, or a requested category has no entry; `PASS`
  otherwise.

`category_coverage_consistency`:
: `NOT_CHECKED` when the verifier cannot assign the Bundle's records to
  categories (the set's definition says how); `FAIL` when a record the Bundle
  carries belongs to a category declared `ABSENT` or `WITHHELD`; `PASS`
  otherwise. A record in a `DELETED` or `UNDISCLOSED` category is not a
  contradiction, and an `AVAILABLE` category with no record in the Bundle is
  not one either: the Bundle may cover less than the producer offers.

Each property stands alone. A verifier MUST report them separately and MUST
NOT combine them, or the statuses, into a count, a percentage, a score or a
claim of completeness. It MUST NOT report a `PASS` of every property as proof
that the producer offered everything it holds. A `FAIL` of
`category_coverage_form`, `category_coverage_signature` or
`category_coverage_consistency` is a failed check of the Bundle; the other
properties are reported and change no other result. Category coverage is
reported apart from the completeness claims of {{completeness}} and changes
none of them.

A verifier that does not implement this member follows the rule for any
member it does not know: it reports nothing about it, and the member stays
covered by the bundle digest.

# Typed Extensions {#extensions}

`extensions`, when present, is an object keyed by a registered Evidence Bundle
extension kind. The member name declares the kind and its value is that kind's
block. The extension kind registry is Specification Required. A registered
specification defines its block shape and any semantic checks. For example, a
company-side row model such as `report/v1` is permitted only as such an
extension; this neutral core does not define, parse, or own its rows.

Extensions are included in the bundle digest ({{bundle-digest}}). A verifier
that does not implement a registered extension kind MUST preserve its
integrity status as digest-covered, report the block as uninterpreted, and
MUST NOT apply that block's semantics. An unknown kind MUST NOT alter the
core Capsule, closure, disclosure, or membership checks.

## The producer-key/v1 Extension {#producer-key}

The `producer-key/v1` extension kind declares the key of the producer that
assembled the Bundle:

~~~
"extensions": {
  "producer-key/v1": { "public_key": "<64 lowercase hex>" }
}
~~~

`public_key` is the producer's 32-byte Ed25519 {{RFC8032}} public key as 64
lowercase hexadecimal characters. The block carries one key. A producer MUST
NOT add other members to the block, and a verifier MUST ignore any it finds.
Like every extension, the block is covered by the bundle digest, so a
countersignature's `over` binds the declaration, and adding, removing, or
changing the declaration afterwards makes that entry `invalid`.

A verifier that implements this kind uses `public_key` for one purpose only:
it adds the key to the producer's keys when determining independence
({{self-countersignature}}), so that a `countersign/v1` entry whose
`signer.key_id` equals it is reported as `not independent`. The declaration
can only cause an entry to be reported as `not independent`. It MUST NOT
cause any entry to be reported as independent, `resolved`, or valid, and it
MUST NOT change any other result. It is not a claim of identity or of
authority, and a verifier MUST NOT present it as one. The absence of this
extension says nothing about whether any entry is independent.

The block is malformed when it is not an object, or when `public_key` is
absent, is not a string, or is not exactly 64 lowercase hexadecimal
characters. A verifier MUST ignore a malformed block when determining
independence, MUST NOT fail the Bundle or any claim because of it, and still
treats the block as digest-covered.

## The composed/v1 Extension {#composed}

The `composed/v1` extension kind carries an evidence set built from the
answers of several responders as one portable object. Each responder answered
one Evidence Request ({{I-D.mih-agent-evidence-request}}) with exactly one of
three outcomes:

- an artifact, here an Evidence Bundle;
- a signed refusal;
- a recorded absence.

Each answer is a *member* of the composition. The block declares:

- each member's digest and outcome;
- the observer that produced each member;
- the joins between members;
- a *composed digest* that a judgment or other record can cite as the exact
  evidence set it was made from.

The containing Bundle is an ordinary `evidence-bundle/v2`. Its `root` is the
composing party's own record, and its core checks apply unchanged. The
extension adds a set of member bundles alongside that record; it does not
change what `records`, `root` or `completeness` mean.

~~~
"extensions": {
  "composed/v1": {
    "members": [
      { "id": "<member id>", "observer": "<observer id>",
        "request_digest": "<64 hex>", "outcome": "artifact",
        "digest": "<64 hex>", "bundle": { ... } },
      { "id": "<member id>", "observer": "<observer id>",
        "request_digest": "<64 hex>", "outcome": "refusal",
        "digest": "<64 hex>", "refusal": { ... } }
    ],
    "observers": [
      { "id": "<observer id>", "role": "<role>",
        "custody_domain": "<label>" }
    ],
    "joins": [
      { "members": ["<member id>", "<member id>"],
        "basis": "pre_agreed_identifier",
        "pointer": "<JSON Pointer>",
        "identifier_digest": "<64 hex>",
        "compare": ["<JSON Pointer>"],
        "state": "agree" }
    ],
    "not_requested": [ "<participant id>" ],
    "missing": [ "<member id>" ],
    "composed_digest": "<64 hex>"
  }
}
~~~

### Block {#composed-block}

The block is a JSON object conforming to this CDDL {{RFC8610}}:

~~~ cddl
composed-v1 = {
  members: [+ composed-member],
  observers: [+ composed-observer],
  ? joins: [* composed-join],
  ? not_requested: [* label-id],
  ? missing: [* label-id],
  composed_digest: digest-hex,
}

composed-member = artifact-member / refusal-member / absence-member

member-common = (
  id: label-id,
  observer: label-id,             ; an observers[].id
  request_digest: digest-hex,     ; the Evidence Request this answers
  digest: digest-hex,             ; see "Members and Outcomes"
)

artifact-member = { member-common, outcome: "artifact",
                    ? bundle: { * tstr => any },   ; a Bundle
                    ? response: artifact-response }
refusal-member  = { member-common, outcome: "refusal",
                    ? refusal: signed-refusal }
absence-member  = { member-common, outcome: "absence",
                    ? absence: recorded-absence }

signed-refusal = {                ; as received, unmodified
  request_digest: digest-hex,
  reason: tstr,                   ; Evidence Request refusal reason
  issued_at: tstr,                ; RFC 3339
  * tstr => any,                  ; deployment signature members
}

artifact-response = {             ; as received, minus artifact bytes
  request_digest: digest-hex,
  artifact_digest: digest-hex,
  * tstr => any,                  ; deployment members and signature
}

recorded-absence = {              ; the requester's own record
  request_digest: digest-hex,
  window: { from: tstr, to: tstr },   ; RFC 3339
  ? route: tstr,
  ? commitment: digest-hex,       ; a retention commitment it held
}

composed-observer = {
  id: label-id,
  role: tstr,                     ; see "Observers and Redundancy"
  custody_domain: tstr,           ; opaque, compared octet-for-octet
}

composed-join = {
  members: [label-id, label-id],  ; two distinct ids, ascending
  basis: join-basis,
  ? pointer: tstr,                ; RFC 6901 JSON Pointer
  ? identifier_digest: digest-hex,
  ? compare: [+ tstr],            ; RFC 6901 JSON Pointers
  state: join-state,
}

join-basis = "pre_agreed_identifier" / "shared_artifact_digest" /
             "issued_receipt" / "same_interval" /
             "controller_binding"
join-state = "agree" / "mismatch" / "unjoined" / "one_sided"

label-id   = text .regexp "[A-Za-z0-9._:-]{1,128}"
digest-hex = text .regexp "[0-9a-f]{64}"
~~~

A join's `pointer` and each `compare` element are JSON Pointers {{RFC6901}}.
Member `id` values are unique, and so are observer `id` values. Every member's
`observer` names a declared observer. Every join names two distinct declared
members, in ascending order. No two joins share the same `members`, `basis`
and `pointer`. `not_requested` names participants that the composing party
knew of but did not ask. A participant listed there is not a member, and its
identifier MUST NOT also appear as a member `id`. A block that violates any of
these rules is malformed. A verifier reports a malformed block as a failed
`composed/v1` check and MUST NOT report any composition result from it.

### Members and Outcomes {#composed-members}

A member records the outcome of one request to one responder, and nothing
else. The three outcomes are those of {{I-D.mih-agent-evidence-request}}. They
are never converted into one another:

- A refusal member exists only when the responder signed a refusal.
- A timeout is an `absence`, never a `refusal`.
- A received refusal is never recorded as an `absence`.
- A request still inside its waiting window is pending. Pending is not an
  outcome, so a pending request MUST NOT be composed as a member.

`digest` depends on the outcome:

- For `artifact`, it is the member Evidence Bundle's bundle digest
  ({{bundle-digest}}).
- For `refusal` and `absence`, it is the lowercase hexadecimal SHA-256 of the
  UTF-8 JCS {{RFC8785}} serialization of the refusal or absence object, as
  carried.

When the body (`bundle`, `refusal` or `absence`) is carried, a verifier MUST
recompute `digest` from it. For a refusal or absence, it MUST also require the
body's `request_digest` to equal the member's. A refusal's signature is
verified under the deployment's signature profile. A verifier that does not
implement that profile reports the refusal as signature-unverified. It does
not report it as failed, and it does not report it as absent.

An artifact member MAY carry `response`: the responder's signed response
to the request, as received, with the artifact bytes removed. A response
signature that names the artifact by digest therefore still verifies without
them. When the bundle and `response` are both carried, a verifier MUST require
the response's `request_digest` to equal the member's, and its
`artifact_digest` to equal the member's `digest`. Either mismatch is a failed
`composed/v1` check. This binds the artifact to the request it answered, as a
refusal's or absence's own `request_digest` does. The response's signature is
verified under the deployment's signature profile, exactly as a refusal's is.
A verifier that does not implement that profile reports the response as
signature-unverified, which is neither failed nor absent. `response` is not
part of the composed digest ({{composed-digest}}).

An artifact that fails verification is still an `artifact` member. The
verifier reports the failure on that member. It is not a fourth outcome, and
the verifier MUST NOT report it as a successful grant.

**Each member keeps its own claims.** A verifier MUST verify every carried
member bundle as an Evidence Bundle under this document. It MUST report that
bundle's graph closure, interval coverage and per-record membership
({{completeness}}), and its disclosures and countersignatures, *per member*.

The verifier MUST NOT merge one member's claims with another member's, or with
the containing Bundle's. The containing Bundle's claims are about its own
`records` only. A refusal or absence member is not a failed claim: a verifier
reports it as what it is.

### Composition Closure {#composed-closure}

A `composed/v1` block makes a fourth completeness claim, *composition
closure*. It holds when every member is either:

- present, meaning its body is carried and reproduces its `digest`; or
- declared missing, meaning its `id` is listed in `missing` and it carries no
  body.

The claim has three results:

- **`pass`**: every member is present and `missing` is absent or empty.
- **`withheld`** (finding `declared_incomplete`): every member is present or
  declared missing, and at least one is declared missing.
- **`fail`**: in any of these cases:
  - a member neither carries a body nor is listed in `missing`;
  - a listed member carries a body;
  - a carried body does not reproduce its `digest`;
  - `missing` names an undeclared member.

A verifier MUST report composition closure separately from the three
per-member claims and from the containing Bundle's claims. It MUST NOT report
it as one of them.

Declaring a member missing withholds its body, not its existence. Its `id`,
`observer`, `request_digest`, `outcome` and `digest` remain in the composed
digest.

Composition closure covers declared members only. A participant that is in
neither `members` nor `not_requested` is not visible to a verifier from this
block ({{composed-security}}).

### Joins {#composed-joins}

A join declares that two members' records are about the same thing, and how
that is established. The producer DECLARES a state; a verifier DERIVES it
again from the carried members. A declaration that does not match the
derivation is a failed `composed/v1` check (finding `join_state_mismatch`). It
is never a pass.

The states derive as follows:

- **`one_sided`**: exactly one of the two members has outcome `artifact`.
- **`unjoined`**: neither member has outcome `artifact`; or both do, but the
  linkage basis does not establish that their records are about the same
  thing.
- **`agree`**: both members are artifacts and are linked, and every `compare`
  pointer resolves in both root records to values with identical JCS
  serializations. A join with no `compare` and a link is `agree`.
- **`mismatch`**: both members are artifacts and are linked, and at least one
  `compare` pointer resolves to different values, or does not resolve on one
  side.

Linkage is evaluated on each artifact member's root record (its bundle's
`root`). This document defines the derivation for two bases:

- **`pre_agreed_identifier`**: `pointer` selects a string in each root record.
  The members are linked when SHA-256 of that string's UTF-8 octets equals
  `identifier_digest` on both sides. The identifier itself never enters the
  block.
- **`shared_artifact_digest`**: `pointer` selects a digest string in each root
  record. The members are linked when the two values are identical.

The bases `issued_receipt` (the two records cite one Receipt),
`same_interval` (the two records fall in one declared interval) and
`controller_binding` (the holders of the two root records' signing keys
jointly signed a statement binding the keys) are reserved for a later
specification that defines their derivation. A block MAY declare
joins on them; such joins are digest-covered. A verifier that does not
implement a derivation for the basis reports such a join as `not_derivable`.
It MUST NOT report the join as a derived agreement, and MUST NOT count it as
corroboration.

A join one of whose artifact members is declared missing is also
`not_derivable`.

On a derived `mismatch`, a verifier reports each member's value at each
differing pointer, and names no winner.

### Observers and Redundancy {#composed-observers}

`observers[]` states, for each member, which observer produced it, in what
`role`, and in which `custody_domain`. `role` is a short token naming where
the observer sits, for example `responder`, `runtime` or `network_boundary`; this document does
not define a role vocabulary, and a verifier reports the role without
interpreting it. A custody domain is an opaque label that the composing party
assigns. Two observers are in the same custody domain exactly when their
labels are identical octet sequences.

**Same custody is redundant, not corroborating.** For every join that derives
`agree`, a verifier MUST report the pair as `redundant` in any of these cases:

- both members name the same observer;
- the two observers have the same `custody_domain`;
- the two members' root records carry the same `key_id`.

It MUST present the result as "redundant, not corroborating", with the reason.
Otherwise it MAY report the pair as corroborating, and it MUST qualify that as
resting on *declared* custody.

Custody labels are the composing party's declaration. Like `producer-key/v1`
({{producer-key}}), they can only downgrade a result. Identical labels make a
pair redundant. Distinct labels never establish that two observers are
independent, and a verifier MUST NOT present them as doing so.

Corroboration is derived; it is never declared, and it is not part of the
block. A verifier lists results per pair. It MUST NOT combine them into a
count or score.

### Composed Digest {#composed-digest}

The composed digest is the digest a judgment cites as the evidence set it was
made from. It is computed only from the declarations in the block, so it
recomputes from the containing Bundle alone. It stays the same whether or not
the member bodies are carried.

1. Build the *digest input* `D`, a JSON object with exactly these five
   members:
   - `kind`: the string `"composed/v1"`.
   - `members`: for each member, an object with exactly its `id`, `observer`,
     `request_digest`, `outcome` and `digest`. Sort the objects in ascending
     order of `id`.
   - `observers`: for each observer, an object with exactly its `id`, `role`
     and `custody_domain`. Sort in ascending order of `id`.
   - `joins`: for each join, an object with its `members`, `basis` and
     `state`, plus whichever of `pointer`, `identifier_digest` and `compare`
     the join carries (absent members stay absent, never `null`). Sort in
     ascending order of `members[0]`, then `members[1]`, then `basis`, then
     `pointer` (the empty string when absent). `compare` keeps its carried
     order. Use `[]` when the block has no `joins`.
   - `not_requested`: the block's `not_requested` sorted ascending, or `[]`
     when it has none.

   Identifiers are ASCII (`label-id`), so ascending order is octet order. The
   order in which arrays are carried does not affect the digest.
2. `composed_digest` is the lowercase hexadecimal SHA-256 of the UTF-8 octets
   of the JCS {{RFC8785}} serialization of `D`. This is the canonicalization
   algorithm `jcs` of {{I-D.mih-sokolov-scitt-payload-binding}}: RFC 8785 with
   no normalization pass, SHA-256, bare hex. `D` contains no numbers.
3. Member bodies, each member's `response`, `missing` and `composed_digest`
   itself are excluded.

A verifier MUST recompute `composed_digest` and report a mismatch as a failed
`composed/v1` check. It MUST NOT report the recomputed value as the digest of
any member, nor as the containing Bundle's digest.

The containing Bundle's own digest ({{bundle-digest}}) still covers the whole
block, bodies included. A countersignature over the containing Bundle
therefore binds the composition and everything carried with it. The composed
digest binds only the evidence set.

Because the composed digest covers each member's `outcome`, `observer` and
`digest`, all observers' roles and custody labels, and every join
declaration, changing any of them changes the composed digest. A judgment
that cites a composed digest therefore also binds the declared custody, and
with it the redundancy result a verifier derives from that custody.

### Verifying composed/v1 {#composed-verify}

A verifier that implements `composed/v1` MUST report each of the following
separately:

1. the recomputed composed digest, and whether it matches;
2. per member: outcome, body carried or declared missing, digest reproduced,
   and, for a carried member bundle, its own three completeness claims and,
   when it carries `response`, whether the response's digests match and its
   signature state;
3. composition closure;
4. per join: the declared state, the derived state (or `not_derivable`), and
   whether they match;
5. per derived `agree`: `redundant` (with reason) or corroborating on
   declared custody.

A verifier that does not implement `composed/v1` follows {{extensions}}: it
reports the block as uninterpreted and integrity-covered. It MUST NOT present
any member, join or composed digest as checked.

## Provisional Extension Kinds {#provisional-kinds}

The interim registry ({{iana}}) also records two extension kinds held for
ratification and not registered: `sd-jwt-issuers/v1`, the issuer keys under
which SD-JWT presentations {{?RFC9901}} in a revealed `agent_input` are
verified offline, and `disclosure-policy-decisions/v1`, the per-Capsule
disclosure-policy decision that a constraint record binds by digest. This
document does not define them. A verifier that does not implement them treats
them as it treats any extension kind it does not implement ({{extensions}}):
digest-covered and uninterpreted.

# Bundle Digest and Countersignatures {#bundle-digest}

The bundle digest is `SHA-256(UTF8(JCS(canonical bundle form)))`, rendered as
64 lowercase hexadecimal characters. The canonical bundle form is the Bundle
with `countersignatures` omitted. `countersignatures` is excluded so that
independent parties can add signatures without changing the digest they sign;
every other present Bundle member, including `extensions`, participates.

`countersignatures`, when present, is an array of objects. Each object MUST
carry `type` and the type's signature encoding, and signs the bundle digest.
An object whose signer is a party other than the producer is a
countersignature ({{conventions}}). This document does not define who
populates the slot or whether a relying party should rely on a given signer.

The registered types are `cose-sign1` and `countersign/v1`. A `cose-sign1`
object is `{type: "cose-sign1", signature: "<base64url tagged COSE_Sign1>"}`.
It is a reserved neutral slot whose population and verification are future
scope; a current verifier MUST surface each such entry as `unverified` and
MUST NOT present pass-through data as a verified countersignature. The
`countersign/v1` object is defined in {{countersign-entry}}. A verifier MUST
report an entry of a type it does not implement as `unverified` and MUST NOT
let it change any other result.
An entry with no `type` member is the legacy form of `countersign/v1`.
A verifier MUST process it as `countersign/v1`, and its signing input then
uses the value `countersign/v1` for `type`. A producer MUST NOT emit the
legacy form.

## The countersign/v1 Entry {#countersign-entry}

~~~
{
  "type": "countersign/v1",
  "signer": { "id": "<signer identifier>", "key_id": "<64 hex>" },
  "over": "<bundle digest>",
  "statement": {
    "checks": [ {"name": "<check>", "result": "<result>"}, ... ],
    "recomputed_at": "<RFC 3339 UTC timestamp>",
    "scope": {
      "ledger_id": "<ledger identifier>",
      "period": { "from": "<RFC 3339>", "to": "<RFC 3339>" },
      "closure_depth": 2
    }
  },
  "signature": "<128 hex>",
  "receipt": { ... }
}
~~~

`type`, `signer`, `over`, `statement`, and `signature` are REQUIRED;
`receipt` is OPTIONAL.

`signer.id` identifies the countersigner, for example a `did:web`
identifier. `signer.key_id` is the countersigner's
32-byte Ed25519 {{RFC8032}} public key as 64 lowercase hexadecimal
characters: the key itself, not a digest of it, so that a verifier holding
only the entry can check the signature offline.

`over` is the bundle digest ({{bundle-digest}}) of the Bundle the
countersigner recomputed.

`statement` says what the countersigner recomputed and with what result.

- `checks` is a non-empty array. Each element names one check in `name`, a
  short phrase for what was recomputed, and gives its `result`, which is
  exactly one of the five values below. A check name is unique within a
  statement.
- `recomputed_at` is the {{RFC3339}} UTC time, with a "Z" suffix, at which
  the countersigner finished recomputing.
- `scope.ledger_id` identifies the ledger whose records the Bundle carries, as
  the issuer identified it to the countersigner. `scope.closure_depth` is the
  closure depth the countersigner applied ({{closure}}). `scope.period`, when
  present, is the `{from, to}` interval of {{RFC3339}} timestamps the checks
  covered; it is absent when the Bundle declares no such interval.

| result | Meaning |
|---|---|
| established | The check ran and its condition held. |
| failed | The check ran and its condition did not hold. |
| not present | The Bundle carries nothing this check operates on. |
| not checked | The check could not run, for example because there was nothing to compare against. |
| inconclusive | The check ran but resolved only in part. |

Each result stands alone. A statement MUST NOT carry an aggregate result, a
score, a rating, or a claim of compliance, and a verifier MUST NOT derive one
from the checks. Capture coverage, meaning whether every action that occurred
was recorded, cannot be recomputed from the records a Bundle carries; a
statement MUST NOT report it as a check result. Profile identifiers naming a
recomputation policy, when a later revision adds them, use the
`countersign.` prefix; this document defines none.

`signature` is the Ed25519 signature, as 128 lowercase hexadecimal
characters, over the signing input
`UTF8(JCS({"over": over, "signer": signer, "statement": statement, "type": type}))`. The
signature binds the Bundle, the signer's identity and what the countersigner
says about it; `signer` is the entry's `signer` object exactly as it appears
on the wire.

`receipt`, when present, is a Receipt {{RFC9942}} showing the statement was
registered with a Transparency Service, in that service's receipt encoding. A verifier that cannot verify it MUST report it as unverified; its
absence does not invalidate the entry.

A verifier MUST ignore entry members not defined here, and they MUST NOT
change any result it reports.

## Verifying a countersign/v1 Entry {#countersign-verify}

A verifier MUST, for each `countersign/v1` entry:

1. recompute the bundle digest and compare it to `over`. An entry whose `over`
   differs is not a countersignature of this Bundle and MUST be reported as
   `invalid`;
2. verify `signature` over the signing input under `signer.key_id`. An entry
   whose signature fails is invalid, and its checks MUST NOT be displayed as
   results;
3. determine independence as in {{self-countersignature}}.

A verifier MAY resolve `signer.key_id` against a directory of countersigners
that it or the relying party chooses, to put a name to the key. No directory
is privileged, and this document defines none. A verifier reports each
`countersign/v1` entry as exactly one of `invalid`, `not independent`,
`unresolved signer` (independent, and the key is in no directory consulted),
or `resolved` (independent, and the key is found). It MUST attribute each
check and result to the signer, as the signer's statement, and MUST NOT
present them as its own findings.

## Self-Countersignature {#self-countersignature}

A countersignature is a self-countersignature when `signer.key_id` equals the
producer's key: the `kid` of a Producer Envelope over any record in `records`
({{I-D.mih-scitt-agent-action-capsule}}), the `public_key` of a well-formed
`producer-key/v1` extension ({{producer-key}}), or any other key the verifier
holds for that producer. A self-countersignature is a well-formed entry that does
not meet the definition of a countersignature, because its signer is the
producer. A verifier MUST NOT reject it for being one, and MUST render it as
not independent, never as a countersignature by a party other than the
producer. The verifier computes
independence itself for each entry; no entry member and no directory entry
can change that result, and a producer key declaration can only change it
to not independent.

# Fragment Codec {#fragment-codec}

The common permalink codec is exact. To encode a Bundle in a URL fragment, a
producer MUST serialize the whole Bundle with JCS, including recursive
`sort_keys` object-member ordering, UTF-8 encode the resulting JSON text, and
encode those bytes with RFC 4648 base64url {{RFC4648}} Section 5 without
padding. The resulting unescaped ASCII string is the fragment value after
`#`. A decoder MUST base64url-decode the unpadded fragment, UTF-8 decode it,
parse it as JSON, and then apply the Bundle checks in this document.

The `/v/<id>` route carries a Bundle of one using this same codec; `/bundle`
uses no different decoder. The path is a locator only. URL fragments are not
sent in HTTP requests, so a hosted service receives a Bundle only when it is
otherwise uploaded or embedded in the returned report.

# Verification {#verification}

`verification`, when present, is producer self-report. It MAY record tool
versions, performed checks, or findings, but it is not proof and MUST NOT
replace independent verification of Capsules, disclosures, closure,
certificates, checkpoints, or countersignatures. A verifier MUST label it as
producer self-report.

A conforming verifier MUST at minimum compute the Bundle digest, verify each
enclosed Capsule under the base profile, apply {{closure}} and {{disclosures}},
and report graph closure, interval coverage, and per-record membership as
separate results. It MUST distinguish WITHHELD, REVEALED-match,
REVEALED-mismatch, declared incomplete, and absent or invalid membership
proofs. It MUST apply {{certificate-modes}} to every Bundle, so that a
certificate mode it does not implement is reported as not established, never
as failed.

# Security Considerations {#security}

The Bundle does not make omitted evidence disappear. Its explicit missing
declaration is necessary to prevent a short report from being represented as a
complete closure. Range endpoints are not a substitute for per-record
membership: endpoint-only proofs leave interior substitution and deletion
undetected. Disclosures are not signatures and are untrusted until their DE-3
digest comparison succeeds. Fragments can be copied or changed by a party
hosting a link, so every received Bundle requires independent verification.
Unknown extension kinds are integrity-covered but semantically untrusted.

A producer-selected certificate proves that each carried record is in the
log; it says nothing about the records the producer left out, so a verifier
never presents one as complete ({{producer-selected}}). Reporting an
unimplemented certificate mode as not established rather than invalid keeps a
failure meaningful: a verifier that reported every unfamiliar mode as invalid
would report an honest Bundle and an altered one identically. A non-record
leaf is accepted only with its full content, never as a bare digest, because
a bare leaf value could be the identifier of a Capsule the producer chose not
to show; recomputing the value from padding content, whose only free member is
a random nonce, rules that out ({{non-record-leaves}}).

A countersignature's `statement` and `signer` are what a relying party reads,
so both are inside the signing input ({{countersign-entry}}); a signature over
the bundle digest alone would let anyone holding the Bundle rewrite a `failed`
result as `established`, or attribute the entry to a different signer
identifier, without detection. A verified signature establishes who made
the statement, not that the relying party should rely on that party: signer
trust, and the choice of any directory used to put a name to a key, are
outside this document. A self-countersignature is not a second party's
check, and rendering it as one would present the producer's own claim as
independent corroboration; {{self-countersignature}} forbids that. A
`producer-key/v1` declaration can only cause an entry to be reported as not
independent: a producer that declares a key it does not hold weakens only
its own Bundle's countersignatures, and a producer that countersigns with a
key it does not declare is still reported at most as an `unresolved signer`
unless a directory the verifier chose lists that key. Results
are listed per check and never combined, because an aggregate would hide a
`failed` or `not checked` result behind a total.

## composed/v1 {#composed-security}

- **Omitted participants.** The composing party chooses whom to list.
  Composition closure proves that every *declared* member is present or
  declared missing. It cannot reveal a participant that the composing party
  never listed. `not_requested` makes a known omission explicit. Completeness
  against the real set of participants needs an independent statement of
  that set, such as a coordinator's sealed topology. A verifier MUST NOT
  describe composition closure as completeness of participation.
- **Declarations versus derivations.** Declared join states are re-derived;
  a mismatch fails. Declared custody can only downgrade
  ({{composed-observers}}). Nothing a producer declares can make two
  observers independent.
- **Outcomes.** Keeping refusal and absence distinct is evidentiary:
  synthesizing either one from the other forges the stronger record from the
  weaker.

## Category Coverage {#category-security}

A category declaration is the producer's statement about itself
({{category-coverage}}). A producer that chooses its own categories can
declare whatever is favorable to it; this is why a private set is never
reported as registered, and why a verifier reports properties rather than a
verdict of completeness. A signed `ABSENT` is attributable and can be
contradicted by records a counterparty holds, but it is not evidence that
nothing exists. Including the Bundle's `root` in the signing input stops a
declaration made for one Bundle from being presented with another.

# Privacy Considerations {#privacy}

A Bundle reveals a preimage only through its disclosure overlay
({{disclosures}}); a member absent from the overlay stays WITHHELD.

A range that carries padding leaves ({{non-record-leaves}}) shows where padding
runs begin and end, and padding is appended before a checkpoint is cut. Such a
range therefore reveals some of the log's earlier checkpoint sizes, which
padding exists to blur (Section 12.1 of {{I-D.mih-agent-evidence-layer}}).
A producer that does not want to show them uses a producer-selected
certificate ({{producer-selected}}), which carries no positions other than
those of the records it carries.

For the `composed/v1` extension ({{composed}}):

- Join identifiers enter only as digests (`identifier_digest`).
- `custody_domain` is an opaque label and SHOULD NOT be a network address, an
  account identifier or a personal name.
- Withholding a member's body (`missing`) keeps the composed digest stable. A
  judgment can therefore be checked against a composition presented to an
  audience that may not see every member.

# IANA Considerations {#iana}

IANA is requested to create the "AAC Evidence Bundle Parameters" registry
group with these Specification Required registries, using {{RFC8174}} and
{{RFC2119}} terminology and the designated-expert criteria of {{RFC8126}}:

1. "Evidence Bundle kind", initial value `evidence-bundle/v2`.
2. "Evidence Bundle extension kind", initial values `producer-key/v1`
   ({{producer-key}}) and `composed/v1` ({{composed}}). A registered
   specification defines each block; private `x-` prefixed kinds are not
   registered. The kinds `sd-jwt-issuers/v1` and
   `disclosure-policy-decisions/v1` ({{provisional-kinds}}) are not initial
   values.
3. "Evidence Bundle countersignature type", initial values `cose-sign1`
   ({{bundle-digest}}) and `countersign/v1` ({{countersign-entry}}).
4. "Evidence Bundle category set", with no initial values. Each entry
   registers a category set identifier for `category_coverage`
   ({{category-coverage}}), its category names, and how a record is assigned
   to a category. The registering specification names any external source of
   the categories by version. Identifiers beginning `x-` are private and are
   not registered.

Until IANA registry creation, the interim registry of record is `REGISTRY.md`
in the source repository of {{I-D.mih-scitt-agent-action-capsule}}. It records
the same values and policy.

--- back

# Change Log
{:numbered="false"}

Since -01:

- Certificate modes ({{certificate-modes}}): `completeness.selection` names
  the mode of `completeness_certificate`; a verifier reports a mode it does not
  implement as not established (`certificate_mode_unsupported`), never as
  failed or invalid.
- Defined the producer-selected certificate ({{producer-selected}}), in the
  shape producers already emit: `selection` `producer-selected`, no range,
  each record proven on its own; interval coverage is never established for
  it. Added `none` to `payloads_mode`.
- Non-record leaves ({{non-record-leaves}}): a range covers padding leaves in
  `completeness_certificate.non_record_leaves`, each carried in full; stated
  the padding leaf's serialization and identifier, the per-position accounting
  rule for per-record membership, and that a leaf of an undefined type leaves
  the claim not established, never established. Stated that per-record
  membership is the claim, and that unknown `completeness_certificate` members
  are ignored. Privacy Considerations: what a padded range reveals.
- Category coverage ({{category-coverage}}): the OPTIONAL `category_coverage`
  member, a producer's signed declaration of one status per category of a
  named category set (`AVAILABLE`, `PARTIAL`, `WITHHELD`, `DELETED`, `ABSENT`,
  `UNDISCLOSED`; `UNDISCLOSED` requires `policy_uri`), answering the Evidence
  Request `categories` field; five verifier properties, reported separately and
  never combined; it declares and does not prove. Created the "Evidence Bundle
  category set" registry, with no initial values.
- `composed/v1`: added `controller_binding` to the reserved join bases.
- Cites Evidence Request -01 and, informatively, Evidence Layer -00.

Since -00:

- Countersignatures: defined the `countersign/v1` countersignature entry, its
  statement, and its five check results; defined countersignature,
  countersigner, and self-countersignature, and required a
  self-countersignature to be rendered as not independent; registered
  `countersign/v1` as a second countersignature type; an entry with no
  `type` is processed as `countersign/v1` (the legacy form).
- Defined and registered the `producer-key/v1` extension kind, which declares
  the producer's key and can only cause a countersignature to be reported as
  not independent.
- Defined and registered the `composed/v1` extension kind: one member per
  responder carrying its Evidence Request outcome (`artifact`, `refusal` or
  `absence`); observers with a role and a custody domain; joins whose
  declared state (`agree`, `mismatch`, `unjoined` or `one_sided`) a verifier
  re-derives; a fourth completeness claim, composition closure; same-custody
  agreement reported as redundant, not corroborating; and a composed digest
  (JCS, SHA-256) over the member, observer, join and `not_requested`
  declarations. Added Privacy Considerations.
- Noted two provisional extension kinds, `sd-jwt-issuers/v1` and
  `disclosure-policy-decisions/v1`, held for ratification in the interim
  registry and not defined by this document.

# Acknowledgments
{:numbered="false"}

The authors thank the SCITT working group and the Action State Group
architecture review for the evidence-bundle starting shape.
