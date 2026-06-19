---
title: "Selective Disclosure Profile for Agent Action Capsules"
abbrev: "Capsule SD-CWT Profile"
docname: draft-mih-scitt-agent-action-capsule-sd-cwt-00
category: std
submissiontype: IETF
ipr: trust200902
area: "Security"
workgroup: "SCITT"
keyword:
 - SCITT
 - selective disclosure
 - SD-CWT
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
  RFC4648:
  RFC8259:
  RFC6234:
  I-D.ietf-spice-sd-cwt:
  I-D.mih-scitt-agent-action-capsule:
    title: "An Agent Action Capsule Profile for SCITT"
    seriesinfo:
      Internet-Draft: draft-mih-scitt-agent-action-capsule-01
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.

informative:
  RFC9052:
  RFC8392:
  RFC8949:
  I-D.ietf-scitt-architecture:
  I-D.ietf-oauth-selective-disclosure-jwt:

--- abstract

This document normatively profiles the per-field selective-disclosure
extension point reserved in draft-mih-scitt-agent-action-capsule-01
Section 6.2.  It defines the salted-hash commitment encoding, decoy-digest
construction, disclosure format, producer requirements, and verifier
checks for selectively disclosable fields in Agent Action Capsule
payloads.  The mechanism is aligned with draft-ietf-spice-sd-cwt (the
SPICE WG CWT selective-disclosure draft), adapted for the JSON payload
format of a Capsule using JCS (RFC 8785) canonicalization.  Verifier
checks are deterministic and reproducible from the Capsule bytes plus a
provided disclosure set alone; no clock, network access, model invocation,
or external lookup beyond the provided disclosures is required.

--- middle

# Introduction {#introduction}

The base confidentiality posture of an Agent Action Capsule
{{I-D.mih-scitt-agent-action-capsule}} is whole-envelope: a producer
either discloses the full Capsule payload to a verifier or withholds it
entirely.  This posture is sufficient when the unit of trust decision is
the Capsule as a whole.

Two kinds of scenario require finer granularity.  First, a producer may
need to demonstrate that a gate fired — that a `blocked` or `denied`
verdict was recorded — to a verifier who is not entitled to learn which
operator initiated the action or what the specific constraint verdict was.
Second, a producer may serve multiple verifiers with different disclosure
needs from the same signed artifact: a regulator who receives all fields
and an auditing partner who receives only the disposition.

This document profiles a per-field selective-disclosure mechanism for
Capsule payloads that addresses these scenarios.  The mechanism follows
the conceptual model of {{I-D.ietf-spice-sd-cwt}} — salted-hash
commitments, decoy digests, and disclosed `[salt, name, value]` triples —
adapted for the JSON encoding of the Capsule payload.  The adaptation uses
{{RFC8785}} (JCS, JSON Canonicalization Scheme) to produce the byte string
that SHA-256 is applied to, ensuring the commitment is deterministic across
implementations.

An SD-Capsule is identical to a plain Capsule in its COSE_Sign1 envelope
and its `content_type` header; the SD structure is a payload-level feature
signaled by the presence of the `_sd_alg` member in the Capsule payload.
A verifier unaware of this profile processes an SD-Capsule as a plain
Capsule and encounters missing REQUIRED fields where disclosures were not
provided; the SD-aware verifier reconstructs the payload from provided
disclosures before performing base verification.

# Conventions and Definitions {#conventions}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals,
as shown here.

SD-Capsule:
: A Capsule payload containing the `_sd_alg` member and one or more `_sd`
  arrays with salted-hash commitments over concealed fields.

Disclosure:
: A base64url-encoded byte string that encodes a JSON array
  `[salt, claim_name, claim_value]` (for a concealed object member) or
  `[salt, claim_value]` (for a concealed array element), where `salt` is
  a base64url-encoded 16-byte random value, and the encoding is the
  base64url of the UTF-8 encoding of the JCS serialization of the array.

Digest:
: A base64url-encoded (without padding) SHA-256 hash of the UTF-8
  encoding of the JCS serialization of the disclosure array.

Eligible field:
: A Capsule payload member or array element that this profile permits to
  be selectively disclosed.  See {{eligible}}.

Reconstructed payload:
: The Capsule payload obtained after applying a set of disclosures to an
  SD-Capsule: concealed members are re-inserted, `_sd` arrays and the
  `_sd_alg` member are removed, and `{"...": digest}` array placeholders
  are replaced with their disclosed values.

BASE64URL:
: Base64url encoding without padding, as defined in Section 5 of
  {{RFC4648}} (the "URL and Filename Safe" alphabet, "="-stripped).

JCS:
: JSON Canonicalization Scheme per {{RFC8785}}.  The JCS of a value is
  the unique byte string produced by the deterministic serialization
  algorithm defined therein.

SHA-256:
: The SHA-256 hash function per {{RFC6234}}.

The terms "Capsule", "Producer", "Verifier", "JSON-DIGEST", "Class 1
verifier", and "Class 2 verifier" are as defined in
{{I-D.mih-scitt-agent-action-capsule}}.

# Design Rationale {#rationale}

The SD-CWT mechanism ({{I-D.ietf-spice-sd-cwt}}) operates over CBOR
payloads using deterministic CBOR (dCBOR) encoding for its hash inputs.
Agent Action Capsule payloads are JSON objects, so a direct application of
the SD-CWT byte-level construction is not available.  This profile adopts
the same logical structure — salted-hash commitments in `_sd` arrays,
disclosed triples, decoy digests — and substitutes JCS ({{RFC8785}}) for
dCBOR as the canonicalization layer.  JCS is already used in the base
Capsule profile for the `JSON-DIGEST` construction, making it the natural
choice for consistency.

The commitment algorithm ({{commitment}}) hashes `UTF8(JCS(disclosure))`,
where the disclosure array is the same `[salt, name, value]` or
`[salt, value]` structure as in {{I-D.ietf-spice-sd-cwt}}.  This
alignment ensures that the logical properties of the SD-CWT mechanism
carry over: a commitment is binding under SHA-256's collision resistance;
salts make commitments unlinkable across verifiers; decoy digests hide the
count of concealed fields; and the `_sd_alg` member permits algorithm
agility.

A future revision of this profile MAY specify additional hash algorithms
under the same `_sd_alg` mechanism; SHA-256 is the only algorithm defined
here.

# Selective Disclosure Structure {#structure}

## Algorithm Identifier {#alg-id}

An SD-Capsule MUST carry the member

~~~
"_sd_alg": "sha-256"
~~~

as a top-level member of the Capsule JSON object.  A Capsule without
`_sd_alg` is a plain Capsule and MUST NOT contain any `_sd` arrays or
`{"...": digest}` placeholders.

The value `"sha-256"` identifies SHA-256 as the hash algorithm applied
to the UTF-8 encoding of the JCS-serialized disclosure array.  No other
value is defined by this profile.

## Salted-Hash Commitment Construction {#commitment}

For each eligible member ({{eligible}}) that the producer wishes to
conceal, the producer performs the following steps:

1. Generate a 16-byte (128-bit) cryptographically random salt `s`.
   Encode `s` as a BASE64URL string (no padding), yielding a 22-character
   string.

2. Construct the disclosure array:
   - For an object member with name `n` and value `v`:
     `disclosure = [salt_b64url, n, v]`
   - For an array element with value `v` (see {{array-elements}}):
     `disclosure = [salt_b64url, v]`

   where `salt_b64url` is the base64url string from step 1, `n` is a
   JSON string, and `v` is any JSON value (string, number, boolean,
   object, or array).

3. Compute the commitment digest:
   `digest = BASE64URL(SHA-256(UTF8(JCS(disclosure))))`

   This is a base64url string (no padding).

4. Append the `digest` to the `_sd` array of the enclosing JSON object.

5. Remove the member `n: v` from the object (for an object member), or
   replace the array element with the `{"...": digest}` placeholder
   (for an array element).

The `_sd` member of a JSON object is a JSON array of base64url strings
(no padding), each of which is a commitment digest over one concealed
member of that object.  The `_sd` array MUST be sorted in lexicographic
byte order to prevent the position of a digest from leaking information
about the order in which members were concealed.

## Decoy Digests {#decoy}

A producer MAY insert additional commitment digests — decoy digests —
into an `_sd` array to obscure the count of concealed members.  A decoy
digest is structurally identical to a commitment digest but has no
corresponding disclosure: it is computed over a random byte string that
the producer does not record.

Producers SHOULD generate at least one decoy digest per `_sd` array.
The number of decoy digests SHOULD NOT be deterministically derivable
from the number of eligible fields in the object.

A verifier that does not receive a disclosure for a given digest treats
it as a decoy and MUST silently ignore it.  Verifiers MUST NOT report
unconsumed digests as errors.

## SD-Eligible Fields {#eligible}

The set of eligible fields — those that MAY be placed in an `_sd` array
and thereby concealed — is enumerated below.  Producers MUST NOT conceal
any field not in this set.  A Capsule with an `_sd` array that conceals a
non-eligible field is non-conforming; verifiers MUST treat such a Capsule
as a structural verification failure.

### Top-Level Capsule Members {#eligible-top}

The following top-level Capsule payload members MAY be concealed:

| Member | Description |
|--------|-------------|
| `operator` | The accountable tenant. |
| `developer` | The agent identity and version. |

### `disposition` Sub-Object Members {#eligible-disposition}

Within the `disposition` object, the following members MAY be concealed:

| Member | Description |
|--------|-------------|
| `verdict_class` | Terminal-verdict reason-class. |
| `authority` | Opaque authority reference. |
| `reason_digest` | Digest of the structured private reason. |

### `effect` Sub-Object Members {#eligible-effect}

Within the `effect` object, the following members MAY be concealed:

| Member | Description |
|--------|-------------|
| `type` | Logical action type (registry-governed). |
| `external_ref` | Join key for external outcome correlation. |
| `irreversibility_class` | Consequence class (registry-governed). |
| `effect_attestation` | Evidence grade of the effect claim. |

### `constraints` Array Elements {#array-elements}

Individual elements of the top-level `constraints` array MAY be
individually concealed using the array-element mechanism ({{commitment}},
step 2b): the element is replaced by `{"...": digest}` in the array.
The disclosure for such an element is the two-element array
`[salt_b64url, constraint_record_value]`, where
`constraint_record_value` is the full JSON object of the concealed
Constraint Record.

The `constraints` array itself MUST NOT be removed or placed in an `_sd`
array; the array with zero or more `{"...": digest}` placeholders MUST
remain present.

### `compliance` Sub-Object Members {#eligible-compliance}

Within the `compliance` object (if present), the following members MAY
be concealed:

| Member | Description |
|--------|-------------|
| `framework_tags` | Compliance framework tags. |

### Non-Eligible Fields {#non-eligible}

The following fields MUST remain in plain text in the Capsule payload and
MUST NOT appear in any `_sd` array:

- `spec_version`, `format_version`: structural integrity.
- `capsule_id`: the content-address; it is excluded from its own
  computation and concealing it is incoherent.
- `action_id`: the stable action identifier required for correlation and
  chain linkage.
- `action_type`: required for SCITT registration policy evaluation.
- `timestamp`: required for temporal ordering and deferral-expiry
  computation.
- `disposition.decision`: the core verdict field.
- `disposition.approver`: the disposition type.
- `disposition.human_disposed`: the honest in-the-loop flag.
- `effect.status`: the effect state; required for the effect-attestation
  matrix and confirmed-effect binding check.
- `effect.request_digest`, `effect.response_digest`: digest commitments
  whose presence and value are checked by the base verifier; concealing
  them would make the confirmed-effect binding check non-performable.
- `assurance.*`: derived summary modes; rederivable by any verifier from
  checked evidence and MUST remain visible.
- `chain.*` (`parent_capsule_id`, `relation`): linkage integrity fields
  required for chain verification.
- `_sd_alg`, `_sd`: SD structure fields.

A verifier MUST treat any `_sd` array entry that, when a disclosure is
provided, resolves to a non-eligible field name as a structural failure.

# SD-Capsule Production {#production}

## Payload Encoding {#payload-encoding}

To produce an SD-Capsule from a fully-constructed plain Capsule payload,
the producer performs the following steps:

1. Add `"_sd_alg": "sha-256"` to the top-level Capsule object.

2. For each eligible field chosen for concealment:
   a. Compute the commitment per {{commitment}}.
   b. Remove the member from its containing object (or replace the array
      element with the `{"...": digest}` placeholder).
   c. Add the digest to the containing object's `_sd` array, creating
      it if absent.

3. Optionally, add decoy digests per {{decoy}}.

4. Sort each `_sd` array in lexicographic byte order.

5. Compute `capsule_id` per {{capsule-id-coverage}}.

## capsule_id Coverage {#capsule-id-coverage}

An SD-Capsule's `capsule_id` is computed over the SD-encoded payload
(the payload with concealed members absent and `_sd` arrays and `_sd_alg`
present), not over the fully-revealed payload.  This follows the same
construction as the base profile: `JSON-DIGEST` of the canonical capsule
form (the full payload minus `capsule_id` and chain-linkage fields) after
absent-field normalization, applied to the SD-encoded form.

This design means the `capsule_id` is stable regardless of which fields
are later revealed to which verifiers.  The commitment set (the `_sd`
arrays) is part of the content-addressed form and is therefore
tamper-evident via `capsule_id`.

A verifier reconstructing the payload from disclosures MUST NOT
recompute `capsule_id` over the reconstructed plain form; the recomputed
`capsule_id` check (base profile Class 1 check 2) is performed over the
SD-encoded form before disclosure application.

## Disclosure Encoding {#disclosure-encoding}

A disclosure for an object member `n` with value `v` is:

~~~
encoded_disclosure = BASE64URL(UTF8(JCS([salt_b64url, n, v])))
~~~

A disclosure for a `constraints` array element with value `elem` is:

~~~
encoded_disclosure = BASE64URL(UTF8(JCS([salt_b64url, elem])))
~~~

where `salt_b64url` is the 22-character base64url string generated in
{{commitment}} step 1.

The `encoded_disclosure` is the string that the producer shares with a
verifier when revealing the corresponding concealed field.  A set of
disclosures for a single Capsule is a JSON array of `encoded_disclosure`
strings.

## Disclosure Delivery {#disclosure-delivery}

The transport mechanism for disclosures is out of scope for this
profile.  Disclosures are application-layer material delivered alongside
the Capsule (e.g., in a separate response body, a trusted side-channel,
or an out-of-band credential protocol).  This profile defines only the
encoding and verification of disclosures, not their conveyance.

A producer MUST retain all disclosure arrays (including salts) for as
long as selective-disclosure presentations of the signed Capsule may be
required.  A producer MUST NOT embed disclosures in the COSE_Sign1
unprotected header or the Capsule payload.

# Verifier Checks {#verification}

Verification of an SD-Capsule is performed in two ordered phases:
SD-structure verification ({{sd-phase}}) followed by base verification
({{base-phase}}) on the reconstructed payload.  The overall result is
`ok: true` only when both phases pass.  A verifier MUST return a
structured result as defined by the base profile; the SD phase MAY add
additional findings to that result.

## Phase 1: SD Structure Verification {#sd-phase}

The following checks are performed on the SD-encoded Capsule bytes and
the provided disclosure set.  Each check is deterministic from those
inputs alone.

### SD-1: Algorithm Identifier Check

If `_sd_alg` is absent from the Capsule payload:
- If any `_sd` arrays or `{"...": digest}` placeholders are present,
  report a structural failure (`sd_structure_error`).
- Otherwise, process the Capsule as a plain Capsule ({{base-phase}}).

If `_sd_alg` is present and its value is not `"sha-256"`:
- Report a structural failure (`sd_unsupported_algorithm`).

If `_sd_alg` is present and equals `"sha-256"`, continue to SD-2.

### SD-2: Digest Format Check

For each string `d` in each `_sd` array at any nesting level:
- `d` MUST be a base64url string (no padding, no whitespace) of length
  43 characters (the base64url encoding of 32 bytes).
- Report `sd_malformed_digest` for any digest that does not conform.

For each `{"...": v}` object in the `constraints` array:
- `v` MUST be a base64url string conforming to the same length requirement.
- Report `sd_malformed_placeholder` for any that does not conform.

### SD-3: Disclosure Parsing

For each provided `encoded_disclosure` string:

1. BASE64URL-decode it to obtain a byte string; if decoding fails, report
   `sd_disclosure_decode_error` for that disclosure and skip it.

2. Interpret the decoded bytes as UTF-8; if UTF-8 parsing fails, report
   `sd_disclosure_utf8_error` and skip it.

3. Parse the UTF-8 string as JSON; if parsing fails, report
   `sd_disclosure_json_error` and skip it.

4. Verify the parsed value is a JSON array; otherwise report
   `sd_disclosure_not_array` and skip it.

5. Classify by array length:
   - Length 3: object-member disclosure `[salt, name, value]`.
     `salt` MUST be a non-empty string; `name` MUST be a string;
     `value` may be any JSON value.
   - Length 2: array-element disclosure `[salt, value]`.
     `salt` MUST be a non-empty string; `value` may be any JSON value.
   - Any other length: report `sd_disclosure_bad_length` and skip it.

### SD-4: Commitment Verification and Reconstruction

For each valid object-member disclosure `[salt, name, value]`:

1. Compute `computed = BASE64URL(SHA-256(UTF8(JCS([salt, name, value]))))`.

2. Search the `_sd` array of the appropriate containing object for
   `computed`.  The containing object for top-level member disclosures
   is the Capsule root object; for `disposition` members it is the
   `disposition` object; for `effect` members it is the `effect` object;
   for `compliance` members it is the `compliance` object.

3. If `computed` is not found in the appropriate `_sd` array: report
   `sd_commitment_mismatch` for this disclosure.

4. If `computed` is found but was already consumed by a prior disclosure
   in this verification run: report `sd_duplicate_disclosure`.

5. Otherwise: mark `computed` as consumed; insert `name: value` into the
   target object.

6. Verify that `name` is an eligible field name for the target object
   ({{eligible}}).  If not, report `sd_ineligible_field`.

For each valid array-element disclosure `[salt, value]`:

1. Compute `computed = BASE64URL(SHA-256(UTF8(JCS([salt, value]))))`.

2. Search the `constraints` array for a `{"...": computed}` placeholder.

3. If not found: report `sd_commitment_mismatch` for this disclosure.

4. If found but already consumed: report `sd_duplicate_disclosure`.

5. Otherwise: mark the placeholder as consumed; replace it in the array
   with `value`.  Verify that `value` is a well-formed Constraint Record
   object (has `id`, `result`, `severity`, `blocking` members); if not,
   report `sd_constraint_record_malformed` as an informational finding.

### SD-5: Residual Check

After all provided disclosures have been processed, the remaining
(unconsumed) entries in every `_sd` array and every remaining
`{"...": digest}` placeholder in the `constraints` array are treated as
decoy digests.  Verifiers MUST silently ignore them and MUST NOT report
unconsumed digests as errors.

### SD-6: Reconstruction Cleanup

Remove `_sd_alg` and all `_sd` arrays from the reconstructed object.
Replace any remaining `{"...": digest}` placeholders in the `constraints`
array with nothing (i.e., remove them from the array); the resulting
`constraints` array reflects only those Constraint Records for which
disclosures were provided.

Verifiers MUST report the count of concealed-but-not-disclosed Constraint
Records as an informational finding (`sd_undisclosed_constraints: N`) so
that consumers know the visible constraint list may be incomplete.

## Phase 2: Base Verification on Reconstructed Payload {#base-phase}

After Phase 1 completes without a structural failure, perform the full
Class 1 verification check set of {{I-D.mih-scitt-agent-action-capsule}}
on the reconstructed payload.

There is one adaptation to base Class 1 check 2 (capsule_id recomputation):
the verifier MUST recompute `capsule_id` over the SD-encoded form (the
original payload bytes as received, before disclosure application), not
over the reconstructed plain form.  All other Class 1 checks are
performed on the reconstructed payload.

If a REQUIRED field was concealed and no disclosure was provided for it,
the reconstructed payload is missing that field and the base structural
check (check 1) will fail.  The verifier MUST report this as
`sd_required_field_not_disclosed: ["operator", ...]` (listing the missing
REQUIRED field names) in addition to the base structural failure, so that
the consumer can distinguish the missing-disclosure case from a
malformed-payload case.

## Class 1-SD Verifier {#class1-sd}

A Class 1-SD verifier performs:
- Phase 1 SD structure verification ({{sd-phase}}).
- Base Class 1 verification per {{I-D.mih-scitt-agent-action-capsule}}
  on the reconstructed payload, with the capsule_id adaptation above.

The overall `ok` result is `true` if and only if Phase 1 reports no
structural failure (SD-1 through SD-4 produce no error-level findings)
and the base Class 1 check set reports `ok: true`.

## Class 2-SD Verifier {#class2-sd}

A Class 2-SD verifier performs Class 1-SD verification and additionally
the Class 2 manifest-aware checks of {{I-D.mih-scitt-agent-action-capsule}}
on the reconstructed payload.  The Class 2 checks may apply only to
disclosed Constraint Records; a verifier MUST report
`sd_undisclosed_constraints` before applying Class 2 checks so that the
consumer understands the completeness of the manifest check.

## Verification Result Fields

In addition to the base profile result fields, a verifier implementing
this profile SHOULD include in its structured result:

| Field | Type | Meaning |
|-------|------|---------|
| `sd_alg` | string or null | The `_sd_alg` value from the Capsule (`"sha-256"` or null if absent). |
| `sd_disclosures_provided` | integer | Count of disclosure strings provided to the verifier. |
| `sd_disclosures_applied` | integer | Count of disclosures successfully matched and applied. |
| `sd_undisclosed_constraints` | integer | Count of `constraints` array elements still concealed after disclosure application. |
| `sd_findings` | array | List of finding codes from Phase 1 (e.g., `sd_duplicate_disclosure`, `sd_ineligible_field`). |
| `sd_required_field_not_disclosed` | array of strings | REQUIRED field names absent in the reconstructed payload because their disclosure was not provided. |

# Test Vectors {#test-vectors}

The following non-normative examples illustrate the SD construction.
Values are abbreviated for readability.

## Example: Concealing `operator` {#tv-operator}

Given a plain Capsule with `"operator": "acme-corp"` at the top level,
the producer:

1. Generates salt: `rIdm2xVvGT-yKjLWOXXJfg` (22 base64url characters,
   encoding 16 random bytes).

2. Constructs the disclosure array:
   `["rIdm2xVvGT-yKjLWOXXJfg", "operator", "acme-corp"]`

3. Computes JCS of the array:
   `["rIdm2xVvGT-yKjLWOXXJfg","operator","acme-corp"]`
   (JCS sorts object keys; array members are ordered as given.)

4. Computes `SHA-256(UTF8(JCS(disclosure)))`, base64url-encodes it:
   `digest = BASE64URL(SHA-256(b"[\"rIdm2xVvGT-yKjLWOXXJfg\",\"operator\",\"acme-corp\"]"))`
   (exact value depends on UTF-8 byte sequence; implementations MUST use
   JCS for byte-exact reproduction).

5. Adds `digest` to top-level `_sd` array; removes `"operator"` member.

Resulting SD-Capsule (excerpt):

~~~
{
  "spec_version": "draft-mih-scitt-agent-action-capsule-01",
  "format_version": "2",
  "capsule_id": "<computed over SD-encoded form>",
  "action_id": "act-001",
  "action_type": "decide",
  "_sd_alg": "sha-256",
  "_sd": ["<digest_of_operator_disclosure>", "<decoy_digest>"],
  "timestamp": "2026-06-18T00:00:00Z",
  ...
}
~~~

Encoded disclosure string (what the producer sends to reveal `operator`):

~~~
encoded = BASE64URL(UTF8(JCS(
  ["rIdm2xVvGT-yKjLWOXXJfg", "operator", "acme-corp"]
)))
~~~

## Example: Concealing a Constraint Record {#tv-constraint}

Given a `constraints` array element:
~~~
{
  "id": "spend_limit",
  "check_type": "threshold",
  "result": "pass",
  "severity": "critical",
  "blocking": true
}
~~~

The producer:

1. Generates salt: `aBcDeFgHiJkLmNoPqRsTuV` (illustrative; replace with
   actual random bytes).

2. Constructs array-element disclosure:
   `["aBcDeFgHiJkLmNoPqRsTuV", {the constraint record object}]`

3. Computes `digest = BASE64URL(SHA-256(UTF8(JCS(disclosure))))`.

4. Replaces the array element with `{"...": "<digest>"}`.

The disclosure string reveals the full Constraint Record to a verifier
who receives it.

# Security Considerations {#security}

## Commitment Binding

The salted-hash commitment is binding under SHA-256's collision resistance:
a producer cannot find two different disclosures that produce the same
digest.  Salts are 128 bits; this exceeds the NIST guidance for
preimage-resistance purposes.

## Salt Entropy

Salts MUST be generated from a cryptographically secure pseudorandom
number generator (CSPRNG).  A salt generated from a weak source enables
a dictionary attack: an adversary who can enumerate the salt space can
attempt to link digests to known values.  Each (salt, name, value) triple
MUST be used for exactly one commitment; reusing a salt for the same name
and value across different Capsules allows correlating otherwise unlinkable
digests.

## Decoy Digests and Unlinkability

Decoy digests reduce the precision of the lower bound on the count of
concealed fields, but they do not hide structural information such as the
nesting depth of `_sd` arrays or the presence of a `compliance` object.
Producers with high unlinkability requirements SHOULD generate decoy
digests at every `_sd` array level, not only at the top level.

## capsule_id Binding

The `capsule_id` commits to the SD-encoded form.  A verifier that accepts
a capsule_id as identifying a Capsule is accepting the SD form — including
the commitment set.  If the producer later delivers different disclosures
to different verifiers, all resulting reconstructed payloads share the
same `capsule_id`.  This is intentional: `capsule_id` identifies the
event, not the view of the event.

## Partial Disclosure and Missing Required Fields

A verifier that receives disclosures for only a subset of concealed
REQUIRED fields MUST NOT treat the partial view as a fully verified
Capsule.  The structured result MUST reflect which required fields were
absent (`sd_required_field_not_disclosed`), and `ok` MUST be `false` in
that case.  A consumer that trusts a partial view without checking
`sd_required_field_not_disclosed` is relying on more than the profile
guarantees.

## Ineligible Field Concealment

A producer that places a non-eligible field in an `_sd` array produces
a non-conforming SD-Capsule.  Verifiers treat this as a structural
failure ({{sd-phase}}, SD-4, step 6).  This prevents a producer from
concealing fields (such as `effect.status` or `effect.response_digest`)
whose visibility is required for the base verification invariants to hold.
Concealing `effect.response_digest`, for example, would make the
confirmed-effect binding check non-performable, undermining the `may/did`
distinction.

## Relationship to the Base Profile Security Considerations

The security considerations of {{I-D.mih-scitt-agent-action-capsule}}
apply without modification.  Selective disclosure does not change the
tamper-evidence properties of the COSE_Sign1 envelope, the
append-only properties of a SCITT Transparency Service, or the honesty
invariant of the `human_disposed` flag.  An SD-Capsule registered with
a Transparency Service has its SD-encoded form logged and receipted;
the commitment set is therefore tamper-evident and non-repudiable.

# IANA Considerations {#iana}

## Capsule Payload Reserved Members

This document reserves the following members of the Agent Action Capsule
payload.  These members MUST NOT be used for any purpose other than as
defined in this document.

| Member name | Type | Location | Defined in |
|-------------|------|----------|------------|
| `_sd_alg` | string | Top-level Capsule object | {{alg-id}} |
| `_sd` | array of string | Any eligible JSON object | {{commitment}} |

These members use the underscore-prefixed naming convention to avoid
collision with existing or future Capsule payload members, following the
same convention as SD-CWT ({{I-D.ietf-spice-sd-cwt}}).

IANA is not requested to create a new registry for these members at this
time.  The interim registry of record for Agent Action Capsule Parameters
(the `REGISTRY.md` file of the source repository of
{{I-D.mih-scitt-agent-action-capsule}}) is updated to list `_sd_alg` and
`_sd` as reserved members defined by this companion document.

--- back

# Relationship to SD-CWT {#rel-sd-cwt}
{:numbered="false"}

{{I-D.ietf-spice-sd-cwt}} defines selective disclosure for CBOR Web
Tokens (CWTs) using deterministic CBOR (dCBOR) as the canonicalization
layer.  This document adapts the same mechanism for JSON payloads by
substituting JCS ({{RFC8785}}) for dCBOR.  The logical structure —
salted-hash commitments, decoy digests, `[salt, name, value]` disclosure
triples, and the `_sd`/`_sd_alg` payload vocabulary — is preserved.

The key differences are:

1. Byte-string input to SHA-256: this profile uses `UTF8(JCS(array))`
   instead of `dCBOR(array)`.

2. Payload medium: Capsule payloads are JSON objects, not CBOR maps.

3. `_sd` array ordering: this profile requires lexicographic sort;
   SD-CWT requires no specific ordering.

4. Array-element disclosures: this profile limits array-element SD to
   the `constraints` array; SD-CWT applies it uniformly to any array.

Implementations that also implement SD-CWT MUST use the correct
canonicalization layer for each context.  A JCS-encoded disclosure is
not compatible with a dCBOR-encoded commitment, and vice versa.

# Change Log
{:numbered="false"}

Since -00 (this document):  initial publication.

# Acknowledgments
{:numbered="false"}

The author thanks the SCITT and SPICE working groups for the substrate
and selective-disclosure mechanism this profile builds on.
