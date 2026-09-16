---
title: "AAC Evidence Bundle"
abbrev: "AAC Evidence Bundle"
docname: draft-mih-zhang-agent-action-capsule-evidence-bundle-00
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
  RFC6234:
  RFC8949:
  RFC9052:
  I-D.mih-scitt-agent-action-capsule:
    title: "An Agent Action Capsule Profile for SCITT"
    seriesinfo:
      Internet-Draft: draft-mih-scitt-agent-action-capsule-04
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

--- abstract

This document defines the AAC Evidence Bundle, a portable presentation and
verification container for an Agent Action Capsule and the records that make
its evidentiary claim intelligible. A permalink carries a bundle in its URL
fragment, an offline HTML report carries a bundle in its shell, and a hosted
report serves a bundle at its URL. The bundle does not alter any enclosed
Capsule. It declares its citation closure and any missing cited records,
carries verified disclosure preimages as a bundle-level overlay, separates
three different completeness claims, and permits independently specified
extension blocks and neutral third-party countersignatures.

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
  "disclosures": { "<capsule_id>": { "<member>": "<revealed preimage>" } },
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
{{I-D.mih-scitt-agent-action-capsule-disclosure-envelope}}. The member name
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
   checkpointed range root. Without a verified witness receipt or checkpoint
   signature, this is only relative to a producer-asserted checkpoint.
3. **Per-record membership**: every supplied record is bound to its claimed
   log position under that range root.

The certificate MUST state its `log_id`, range root, first and last `seq`,
and the proof material that binds that range root to `checkpoint`. A signed
range proof that binds only the first and last record proves endpoint
inclusion only: an interior record can be deleted or replaced while such a
proof still passes. A verifier MUST NOT report whole-range completeness from
endpoint inclusion alone. A verifier MUST verify an included, verifiable
witness receipt or checkpoint signature over the checkpoint before reporting
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

# Bundle Digest and Countersignatures {#bundle-digest}

The bundle digest is `SHA-256(UTF8(JCS(canonical bundle form)))`, rendered as
64 lowercase hexadecimal characters. The canonical bundle form is the Bundle
with `countersignatures` omitted. `countersignatures` is excluded so that
independent parties can add signatures without changing the digest they sign;
every other present Bundle member, including `extensions`, participates.

`countersignatures`, when present, is an array of objects. Each object MUST
carry `type` and the type's signature encoding. A countersignature is made by
a party other than the producer and signs the bundle digest. This document
does not define who populates the slot or what a valid countersignature means
for a relying party.

The initial registered type is `cose-sign1`. Its object is
`{type: "cose-sign1", signature: "<base64url tagged COSE_Sign1>"}`. This is a
reserved neutral slot. Population and countersignature verification, including
COSE signature and payload verification, are future scope. A current verifier
MUST surface each entry as `unverified`; it MUST NOT present pass-through data
as a verified countersignature.

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

# IANA Considerations {#iana}

IANA is requested to create the "AAC Evidence Bundle Parameters" registry
group with these Specification Required registries, using {{RFC8174}} and
{{RFC2119}} terminology and the designated-expert criteria of {{RFC8126}}:

1. "Evidence Bundle kind", initial value `evidence-bundle/v2`.
2. "Evidence Bundle extension kind", with no initial value. A registered
   specification defines each block; private `x-` prefixed kinds are not
   registered.
3. "Evidence Bundle countersignature type", initial value `cose-sign1`.

Until IANA registry creation, the interim registry of record is `REGISTRY.md`
in the source repository of {{I-D.mih-scitt-agent-action-capsule}}. It records
the same values and policy.

--- back

# Change Log
{:numbered="false"}

Since -00 (this document): initial publication.

# Acknowledgments
{:numbered="false"}

The author thanks the SCITT working group and the Action State Group
architecture review for the evidence-bundle starting shape.
