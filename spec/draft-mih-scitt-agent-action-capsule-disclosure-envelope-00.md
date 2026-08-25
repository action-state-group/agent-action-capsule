---
title: "Disclosure Envelope Profile for Agent Action Capsules"
abbrev: "AAC Disclosure Envelope"
docname: draft-mih-scitt-agent-action-capsule-disclosure-envelope-00
category: std
submissiontype: IETF
ipr: trust200902
area: "Security"
workgroup: "SCITT"
keyword:
 - SCITT
 - disclosure
 - digest
 - AI agent
 - transparency
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
  RFC8259:
  RFC6234:
  I-D.mih-scitt-agent-action-capsule:
    title: "An Agent Action Capsule Profile for SCITT"
    seriesinfo:
      Internet-Draft: draft-mih-scitt-agent-action-capsule-04
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.

informative:
  RFC9052:
  RFC9943:
  I-D.mih-scitt-agent-action-capsule-selective-disclosure:
    title: "Selective Disclosure Profile for Agent Action Capsules"
    seriesinfo:
      Internet-Draft: draft-mih-scitt-agent-action-capsule-sel-disc-00
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.

--- abstract

This document defines the Disclosure Envelope, an out-of-band wrapper
structure for revealing the raw content behind a digest-only Agent Action
Capsule field to a verifier, without altering the Capsule's own bytes or
recomputing its `capsule_id`. The Capsule profile
{{I-D.mih-scitt-agent-action-capsule}} commits some fields as a
{{RFC8785}}-canonicalized SHA-256 digest only — the content itself is never
carried in the signed, registered record. The initial disclosable fields are
`model_attestation.compute_attestation.agent_input_digest` and
`.agent_output_digest`. A Disclosure Envelope wraps an unmodified Capsule
alongside a sibling `disclosures` object; a verifier recomputes the
JSON-DIGEST of each disclosed value using the same canonicalization the base
profile already uses for `capsule_id`, and compares it to the digest
committed inside the Capsule. This mechanism is distinct from the per-field
selective-disclosure profile
{{I-D.mih-scitt-agent-action-capsule-selective-disclosure}}: that mechanism
conceals and later reveals whole payload fields that would otherwise be
carried in clear; this one reveals the content behind a field that was
always present in clear, as a digest, from the moment the Capsule was
signed.

--- middle

# Introduction {#introduction}

Some Agent Action Capsule fields are, by design, digest-only: the field
carries a {{RFC8785}} JSON-DIGEST commitment to a value, not the value
itself. `model_attestation.compute_attestation.agent_input_digest` and
`.agent_output_digest` ({{I-D.mih-scitt-agent-action-capsule}}, Observation
mode) are the motivating case — a producer commits to the exact agent input
and output that produced an action without carrying that (potentially
large, sensitive, or independently-lifecycled) content in the signed,
anchored record.

A producer who later chooses to prove that committed content to a specific
verifier needs a wire format for doing so. Sharing the raw content
out-of-band already works informally, but an ad hoc format invites two
failures this document exists to close: first, a viewer that renders a
disclosed value without recomputing and checking its digest is asserting a
match it never verified; second, a format that embeds the disclosed content
inside the digest-bearing region of the Capsule itself changes the bytes
that were signed, so the Capsule no longer content-addresses to its own
`capsule_id` — the artifact silently stops being the thing that was
anchored.

This document defines a companion wrapper, the Disclosure Envelope, that
keeps the Capsule's bytes untouched and carries disclosed content as a
sibling structure outside them, together with the verifier checks that
recompute and compare each disclosure against its committed digest. The
default posture is WITHHELD: a Disclosure Envelope with an absent or empty
`disclosures` object is equivalent to sharing the Capsule alone, and
disclosure of any one field is opt-in and independent of any other.

# Conventions and Definitions {#conventions}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals,
as shown here.

Disclosure Envelope:
: A JSON object with a `capsule` member and an OPTIONAL `disclosures`
  member, as defined in {{structure}}.

Disclosable field:
: A named entry in the disclosure-eligibility table ({{eligible}}) pairing
  a `disclosures` member name with the Capsule field that carries its
  committed digest.

Disclosure:
: The raw JSON value of one disclosable field, carried as the corresponding
  member of the `disclosures` object.

JSON-DIGEST:
: As defined in {{I-D.mih-scitt-agent-action-capsule}}: the lowercase-hex
  SHA-256 digest of the {{RFC8785}} JCS serialization of a value, after
  selecting the embedded Capsule's identity profile. Format 3 uses plain JCS.
  Vintage format 2 applies absent-field normalization.

JCS:
: JSON Canonicalization Scheme per {{RFC8785}}.

SHA-256:
: The SHA-256 hash function per {{RFC6234}}.

The terms "Capsule", "capsule_id", "Producer", and "Verifier" are as
defined in {{I-D.mih-scitt-agent-action-capsule}}.

# Relationship to Selective Disclosure {#relationship}

{{I-D.mih-scitt-agent-action-capsule-selective-disclosure}} and this
document both let a producer share less than the full Capsule content, but
they solve different problems and share no vocabulary.

Selective disclosure conceals a payload field that would otherwise be
carried in clear at signing time, replacing it with a salted-hash
commitment in an `_sd` array; later disclosure reveals the concealed field
and reconstructs the plain payload. The field's clear-text value was never
in the signed record to begin with.

The Disclosure Envelope instead applies to a field that is a digest
**by design**, unconditionally, in every Capsule that carries it — the
field is never concealed, because it never carried the raw value in the
first place. There is nothing to reconstruct and no `_sd`/`_sd_alg`
structure; the Capsule is unmodified in both its disclosed and undisclosed
states, and disclosure is a wrapper added around it, not a transformation
of it.

The two mechanisms compose without conflict: a Capsule may simultaneously
be an SD-Capsule (per the selective-disclosure profile) and be wrapped in a
Disclosure Envelope (per this document). A verifier applies each
mechanism's checks independently; neither mechanism's structure is visible
to or interpreted by the other.

# Disclosure Envelope Structure {#structure}

## Envelope Object {#envelope-object}

A Disclosure Envelope is a JSON {{RFC8259}} object:

~~~
{
  "capsule": { ... },
  "disclosures": {
    "agent_input": { ... },
    "agent_output": { ... }
  }
}
~~~

`capsule` (REQUIRED): the Capsule payload, byte-for-byte identical in its
JCS-canonicalized form to the payload that was signed and, if registered,
anchored. `capsule_id` ({{I-D.mih-scitt-agent-action-capsule}} §5.1) is
computed over `capsule` alone, exactly as the base profile defines,
using the base profile's own canonical-capsule-form exclusion set
unmodified. No member of the Disclosure Envelope other than `capsule` is
part of any digest computation the base profile defines, and no member of
the envelope other than `capsule` was part of the COSE_Sign1
{{RFC9052}} signature.

`disclosures` (OPTIONAL): an object whose members are disclosable fields
({{eligible}}) the producer has chosen to reveal. A member's absence from
`disclosures` — including the absence of the whole `disclosures` object —
means that field is WITHHELD; this is the default posture and requires no
signal in the envelope. A member's presence means REVEALED; its value is
the exact JSON value whose JSON-DIGEST the corresponding Capsule field
committed to at signing time.

A Disclosure Envelope MUST NOT be submitted for SCITT registration; the
registrable, signable artifact is the COSE_Sign1 Signed Statement whose
payload is `capsule`, registered (if at all) with a SCITT Transparency
Service {{RFC9943}} before any envelope is constructed around it. The envelope is a presentation-layer structure a
producer constructs after the fact, for a verifier that already trusts (or
is independently verifying) the underlying Capsule.

A Capsule with no accompanying Disclosure Envelope — the base profile's
existing whole-envelope posture — remains fully valid; this document adds
an opt-in wrapper, not a requirement.

## Disclosure-Eligible Fields {#eligible}

The following table defines the disclosable fields this document
specifies. A `disclosures` member name not in this table is non-conforming;
a verifier MUST treat it as an unrecognized member ({{verification}},
check DE-1) rather than attempting to verify it.

| `disclosures` member | Committed-digest field (in `capsule.model_attestation.compute_attestation`) |
|---|---|
| `agent_input` | `agent_input_digest` |
| `agent_output` | `agent_output_digest` |

Both fields are defined in
{{I-D.mih-scitt-agent-action-capsule}} (Observation mode). A future
revision of this profile MAY extend the table with additional digest-only
fields (for example, a disclosable form of a Constraint Record's
`evidence_digest`), following the same Specification Required registration
policy as the base profile's registries.

## Reserved Wrapper Member Names {#reserved-names}

`capsule` and `disclosures` are wrapper-level member names defined by this
document. Neither is a Capsule payload member defined or reserved by
{{I-D.mih-scitt-agent-action-capsule}} or its companions, so no collision
is possible: a Disclosure Envelope's `capsule` member and the Capsule
payload it contains are always syntactically distinguishable from a bare
Capsule payload, because a Capsule payload has no member of either name.

# Verifier Checks {#verification}

Verification of a Disclosure Envelope is performed in two independent
phases: base Capsule verification ({{I-D.mih-scitt-agent-action-capsule}}
§6, Class 1) over `capsule` alone, and Disclosure verification ({{de-phase}})
over the `disclosures` object. The two phases do not gate each other: a
disclosure mismatch MUST NOT be reported as a `capsule_id` or Class 1
failure, and a Class 1 failure does not suppress disclosure verification.
A verifier surface MUST report both results and MUST NOT conflate them —
in particular, MUST NOT let a matching disclosure upgrade the Capsule's own
verification status, and MUST NOT let the Capsule's own valid, anchored
status be read as implying anything about a disclosure it has not itself
recomputed and checked.

## Phase DE: Disclosure Verification {#de-phase}

For each member `disclosures` carries:

### DE-1: Eligibility Check

If the member name is not in the disclosure-eligibility table
({{eligible}}), report `disclosure_ineligible_field` and skip it.

### DE-2: Committed-Digest Presence Check

Locate the committed-digest field for this member per {{eligible}}. If
`capsule` does not carry that field (or it is not a well-formed JSON-DIGEST
— 64 lowercase hex characters), report `disclosure_no_committed_digest`
and treat the member as WITHHELD-equivalent: it MUST NOT be reported as
matching or mismatching, because there is no commitment to check it
against.

### DE-3: Digest Recomputation and Comparison

Compute `computed = JSON-DIGEST(value)` using the embedded Capsule's identity
profile. Format 3 computes the lowercase-hex SHA-256 of `UTF8(JCS(value))`
without normalization. Vintage format 2 applies the same absent-field
normalization used for its `capsule_id`. This document introduces no second
profile-selection or hashing path.

Compare `computed` to the committed digest located in DE-2:

- If they match: report `disclosure_match` for this member. The verifier
  MAY present this as "REVEALED — match" or equivalent.
- If they do not match: report `disclosure_mismatch` for this member. The
  verifier MUST present this as a failed verification of the disclosed
  content specifically — for example "REVEALED — MISMATCH" — and MUST NOT
  present the disclosed value as if it were confirmed.

A value that cannot be JCS-canonicalized (for example, one carrying a raw
JSON float, forbidden in digest-bearing content by
{{I-D.mih-scitt-agent-action-capsule}} §5.1) MUST NOT be treated as
matching; a verifier MUST report `disclosure_mismatch` for it rather than
raising an error, consistent with the base profile's structured-result,
never-throw contract.

## Verification Result Fields

A verifier implementing this profile SHOULD include, alongside the base
Class 1 result, a structured per-member disclosure result:

| Field | Type | Meaning |
|---|---|---|
| `disclosures_checked` | integer | Count of `disclosures` members present in the envelope. |
| `disclosures_matched` | integer | Count that produced `disclosure_match`. |
| `disclosure_findings` | array | One finding per `disclosures` member: `{member, code}` where `code` is one of `disclosure_match`, `disclosure_mismatch`, `disclosure_ineligible_field`, `disclosure_no_committed_digest`. |

# Security Considerations {#security}

## The Envelope Is Not Signed

Only `capsule` was covered by the Capsule's COSE_Sign1 signature and, if
registered, by the Transparency Service's Receipt. `disclosures` is added
after the fact by whichever party constructs the envelope and is not
itself signed. This is why {{de-phase}} MUST always recompute and compare
rather than trust a disclosed value's mere presence: presence alone proves
nothing, and a party who can modify the envelope in transit or at rest
(for example, anyone re-hosting a URL-fragment-carried envelope) can insert
an arbitrary value for any disclosure member. The digest recompute against
the value already committed inside the signed Capsule is the entire trust
basis; a verifier that renders "REVEALED" without performing DE-3 is
asserting a check it did not perform.

## No Confidentiality Beyond WITHHELD

Once a `disclosures` member is populated, its value is in clear to
anyone who receives the envelope; there is no per-recipient concealment,
salting, or decoy mechanism as in
{{I-D.mih-scitt-agent-action-capsule-selective-disclosure}}. A producer's
only confidentiality control is which members it chooses to populate for a
given recipient. Producers serving multiple verifiers with different
disclosure needs from the same Capsule construct a distinct envelope per
recipient, omitting members that recipient is not entitled to.

## capsule_id Stability

Because `disclosures` is never part of the `capsule_id` computation,
disclosing content to one verifier does not change, invalidate, or require
re-anchoring the Capsule for any other verifier; every envelope built
around the same `capsule` value shares the same `capsule_id`, regardless of
which `disclosures` members each carries. This is the property that makes
disclosure a strictly additive, reversible-per-recipient operation rather
than a mutation of the anchored record.

## Digest-Only Fields Remain Digest-Only Under Non-Disclosure

A Capsule with no accompanying envelope, or an envelope with no
`disclosures` object, reveals nothing about `agent_input_digest` or
`agent_output_digest` beyond the digest itself — a 32-byte commitment does
not leak the committed content. Producers that never intend to disclose
these fields incur no format change and no additional exposure by this
document's existence.

# IANA Considerations {#iana}

This document reserves the wrapper member names `capsule` and
`disclosures` ({{reserved-names}}) and the disclosure-eligible field table
({{eligible}}). Neither is a member of the Agent Action Capsule payload
registries of {{I-D.mih-scitt-agent-action-capsule}} §12; both are
wrapper-level names that are, by construction, never present in a Capsule
payload. IANA is not requested to create a new registry for these members
at this time. The interim registry of record is the `REGISTRY.md` file of
the source repository of {{I-D.mih-scitt-agent-action-capsule}}, updated to
list the wrapper member names and the disclosure-eligible field table
defined by this document.

# Test Vectors {#test-vectors}

The following non-normative examples illustrate the mechanism. See the
source repository's `disclosure-envelope-vectors/pos-disclosure-envelope-match/`
and `disclosure-envelope-vectors/neg-disclosure-envelope-mismatch/` for
frozen, machine-checked vectors covering these two cases (kept in a
directory of their own, separate from the base profile's cross-language
`test-vectors/` corpus — see that directory's README).

## Example: Matching Disclosure

Given a Capsule whose `model_attestation.compute_attestation` carries
`"agent_input_digest": "<D>"` where `D = JSON-DIGEST({"amount": "500.00"})`,
the envelope

~~~
{
  "capsule": { ... "agent_input_digest": "<D>" ... },
  "disclosures": { "agent_input": {"amount": "500.00"} }
}
~~~

recomputes `JSON-DIGEST({"amount": "500.00"})`, which equals `<D>` — a
verifier reports `disclosure_match` for `agent_input`.

## Example: Mismatching Disclosure

Replacing the disclosed value with `{"amount": "999.00"}` while leaving
`capsule` (and therefore `<D>`) unchanged produces a `disclosures.agent_input`
whose recomputed digest differs from `<D>` — a verifier reports
`disclosure_mismatch` for `agent_input`, while `capsule`'s own
`capsule_id` recomputation and Class 1 verification are unaffected and
still pass.

--- back

# Change Log
{:numbered="false"}

Since -00 (this document): initial publication.

# Acknowledgments
{:numbered="false"}

The author thanks the SCITT working group for the Signed Statement and
Transparency Service model this document's disclosure boundary is drawn
against.
