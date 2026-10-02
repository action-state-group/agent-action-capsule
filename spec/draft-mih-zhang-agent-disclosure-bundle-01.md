---
title: "AAC Evidence Bundle"
abbrev: "AAC Evidence Bundle"
docname: draft-mih-zhang-agent-disclosure-bundle-01
date: 2026-10-01
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
   email: zhangyiqun-spec@gmail.com

normative:
  RFC2119:
  RFC8174:
  RFC8126:
  RFC8259:
  RFC8785:
  RFC4648:
  RFC3339:
  RFC8032:
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

--- abstract

This document defines the AAC Evidence Bundle, a portable presentation and
verification container for an Agent Action Capsule and the records that make
its evidentiary claim intelligible. A permalink carries a bundle in its URL
fragment, an offline HTML report carries a bundle in its shell, and a hosted
report serves a bundle at its URL. The bundle does not alter any enclosed
Capsule. It declares its citation closure and any missing cited records,
carries verified disclosure preimages as a bundle-level overlay, separates
three different completeness claims, and permits independently specified
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
    "payloads_mode": "all|selected",
    "suppressed_fields": [ ... ],
    "missing": [ "<cited capsule digest>", ... ]
  },
  "disclosures": {
    "<capsule_id>": { "<member>": "<revealed preimage>" }
  },
  "disclosure_record": "<capsule_id>",
  "completeness_certificate": { ... },
  "checkpoint": { ... },
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
chose to carry (`all`) or only a selected subset (`selected`).
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
separate claims. A verifier MUST report each claim independently.

1. **Graph closure**: every citation reached under {{closure}} is supplied
   with matching identity or explicitly listed in `completeness.missing`.
2. **Interval coverage**: the claimed sequence interval is anchored to a
   checkpointed range root. Without a verified Receipt {{RFC9942}} over the
   checkpoint from a Transparency Service, or a verified checkpoint
   signature, this is only relative to a producer-asserted checkpoint.
3. **Per-record membership**: every supplied record is bound to its claimed
   log position under that range root.

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
An entry with no `type` member MUST be processed as `countersign/v1`,
and its signing input then uses the value `countersign/v1` for `type`.

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
proofs.

# Security Considerations {#security}

The Bundle does not make omitted evidence disappear. Its explicit missing
declaration is necessary to prevent a short report from being represented as a
complete closure. Range endpoints are not a substitute for per-record
membership: endpoint-only proofs leave interior substitution and deletion
undetected. Disclosures are not signatures and are untrusted until their DE-3
digest comparison succeeds. Fragments can be copied or changed by a party
hosting a link, so every received Bundle requires independent verification.
Unknown extension kinds are integrity-covered but semantically untrusted.

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

# IANA Considerations {#iana}

IANA is requested to create the "AAC Evidence Bundle Parameters" registry
group with these Specification Required registries, using {{RFC8174}} and
{{RFC2119}} terminology and the designated-expert criteria of {{RFC8126}}:

1. "Evidence Bundle kind", initial value `evidence-bundle/v2`.
2. "Evidence Bundle extension kind", initial value `producer-key/v1`
   ({{producer-key}}). A registered specification defines each block;
   private `x-` prefixed kinds are not registered.
3. "Evidence Bundle countersignature type", initial values `cose-sign1`
   ({{bundle-digest}}) and `countersign/v1` ({{countersign-entry}}).

Until IANA registry creation, the interim registry of record is `REGISTRY.md`
in the source repository of {{I-D.mih-scitt-agent-action-capsule}}. It records
the same values and policy.

--- back

# Change Log
{:numbered="false"}

Since -00: defined the `countersign/v1` countersignature entry, its
statement, and its five check results; defined countersignature,
countersigner, and self-countersignature, and required a self-countersignature
to be rendered as not independent; registered `countersign/v1` as a second
countersignature type; defined and registered the `producer-key/v1`
extension kind, which declares the producer's key and can only cause a
countersignature to be reported as not independent.

# Acknowledgments
{:numbered="false"}

The author thanks the SCITT working group and the Action State Group
architecture review for the evidence-bundle starting shape.
