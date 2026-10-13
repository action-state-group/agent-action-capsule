# Minimum Evidence Interoperability Profile — v0

**Status.** Informational profile, pre-Internet-Draft, kept in this repository. It is not part of
any Internet-Draft revision and changes no posted draft. It **pins** existing documents: it picks
one reading wherever they leave a choice open, and fixes the concrete bytes a requester and a
verifier need. It does not redefine anything those documents define. Where this profile needs
something no pinned document says, it states the requirement as its own and lists it under
[Open points](#13-open-points) (P-1, P-2, …), so a later draft revision can adopt it, change it, or
drop it.

This revision covers versions (§3), naming (§4), canonical bytes (§5), the digest and signature
binding of every message (§6), per-property verification statuses (§7), the mapping from
outcomes to an Evidence Result (§8), and error codes (§9). Sections 11.1–11.5 are placeholders
for parts that later revisions fill in.

The documents this profile pins are Internet-Drafts, work in progress, or specifications kept in
this repository. Open-source repositories, this one included, are implementations of them.

No IPR disclosures are in effect against the Internet-Drafts this profile pins as of 2026-10-13.
Each draft's Datatracker IPR page:

- `draft-mih-agent-evidence-request`:
  <https://datatracker.ietf.org/ipr/search/?submit=draft&id=draft-mih-agent-evidence-request>
- `draft-mih-agent-disclosure-envelope`:
  <https://datatracker.ietf.org/ipr/search/?submit=draft&id=draft-mih-agent-disclosure-envelope>
- `draft-mih-agent-settlement-records`:
  <https://datatracker.ietf.org/ipr/search/?submit=draft&id=draft-mih-agent-settlement-records>

## Dependency boundary

**Owns:** the profile version identifier and its negotiation (§3), the name table (§4), the
member names and signing input of the artifact response envelope (§6.2), the absence record
shape (§6.4), the identity of recipient-specific disclosures and their salted-digest commitments
(§6.5), the per-property verification status vocabulary and property catalogue (§7), and
the outcome-to-status mapping (§8).

**Pins, never redefines:**

| Tag | Document | Revision pinned | What this profile takes from it |
|---|---|---|---|
| ER | `draft-mih-agent-evidence-request` | -00 (`spec/draft-mih-agent-evidence-request-00.md`) | the request, the six subject forms, coverage, the three outcomes, caller invariance, the refusal registry, the transport bindings |
| ERV | Evidence Request conformance vectors | `vectors/evidence-request/`, README readings A1–A14 | the wire readings of ER that -00 leaves open |
| DE | `draft-mih-agent-disclosure-envelope` | -00 (`spec/draft-mih-agent-disclosure-envelope-00.md`) | the JSON value digest rule |
| SR | `draft-mih-agent-settlement-records` | -00 (`spec/draft-mih-agent-settlement-records-00.md`) | the as-transmitted rule for wrapped foreign objects |
| RES | Evidence Result v0 | `spec/evidence-result-v0.md` | the claim, sufficiency, verdict and presentation carrier rules |
| EC | Evidence Contract v0 schema | `evidence-contract-v0.json`, `$defs/bundleAssertionStatus`, `$defs/contractResult` and the requirement `uncertainty` member | the eight-value status, its four-value projection, and per-requirement handling of missing and conflicting evidence |

Section numbers for ER, DE and SR are those of the rendered `.txt` of the pinned revision. In
this document a requirement written as `[ER §4.2]` pins that section, and `[P-n]` marks a
requirement this profile adds (§13).

**Does not define:** any evidence format, any identity or trust scheme, any commitment or log
mechanism, who may ask, or any requirement-satisfaction rule beyond the mapping in §8. ER's
non-goals [ER §1.2] apply unchanged.

**Three things kept distinct.** This profile never treats any one of them as another:

1. the **canonical Evidence Artifact** and the **signed response envelope** that binds it to one
   request (§6.2);
2. an **Evidence Bundle** (`draft-mih-zhang-agent-disclosure-bundle`), which MAY be what an
   Artifact's bytes are but is not itself the envelope and is not a recipient-specific
   disclosure (§6.6);
3. any **HTML or other presentation** of evidence, which is never an Artifact, is never covered
   by the envelope signature, and is never what a verifier checks (§6.6).

## 1. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

Terms from ER §2 are used unchanged: requester, responder, evidence artifact, evidence stream,
coverage anchor, pending, route, principal reference, and the three interaction outcomes.

This profile adds:

- **Envelope:** the signed response envelope of §6.2.
- **Verifier:** the code, run by or for the requester, that checks a response against this
  profile and reports per-property statuses (§7).
- **Property:** one named check a verifier runs, reported with exactly one status (§7.1).
- **Response received and failed:** ER uses this for an artifact response that fails verification
  [ER §4.5]. This profile uses the same term for any envelope or refusal that arrives in reply to
  a request and does not verify [P-21]. It is not a fourth outcome.
- **Message type:** a reply object carrying `artifact_digest` is an envelope (§6.2), and one
  carrying `reason` is a refusal (§6.3). One carrying both is a response received and failed. A
  reply carrying neither is not a response under this profile. It is a transport condition
  (§9.2): the request stays pending, then becomes an absence [P-21].

## 2. Roles and the exchange, in one paragraph

A requester sends a request (§6.1) naming a subject and a coverage anchor, and records its
digest. The responder answers with exactly one of two messages: an envelope (§6.2) that carries
the canonical Artifact and binds it to the request, or a signed refusal (§6.3). If neither arrives
before the requester's waiting window closes, the requester writes an absence record (§6.4). Until
the window closes the request is pending, which is not an outcome [ER §4.3]. The verifier checks
whichever message arrived, property by property (§7), and maps the result to an Evidence Result
claim (§8).

## 3. Versions

### 3.1 Profile identifier

This revision is identified by the text string `evidence-interop/0`. The identifier names this
exact document revision. Any change to a signing input, a canonical byte rule, a member name, the
status vocabulary or the mapping in §8 requires a new identifier [P-1]. v0 has no minor
versions.

### 3.2 Pinned revisions

`evidence-interop/0` pins the revisions in the Dependency boundary table. A new revision of
any of those documents does not change what `evidence-interop/0` means. Adopting a new revision
requires a new profile identifier [P-1].

### 3.3 Negotiation

1. A responder that advertises this profile MUST list every profile identifier it supports in the
   manifest that ER §10 says a responder SHOULD publish in the HTTP binding, as a `profiles` member:
   an array of text strings [ER §10; P-2]. The rest of the manifest is outside this revision
   (§11.4).
2. A requester following this profile MUST put the identifier it wants in the request's `profile`
   member (§6.1) [P-2]. ER requires a responder to ignore request fields it does not understand, and
   forbids a requester to rely on an undefined field being understood [ER §3]. So a responder that
   does not implement this profile ignores `profile`, and the requester detects that from the
   response (step 5). `profile` is REQUIRED of a requester following this profile [P-2]. A responder
   implementing this profile still has to handle requests from requesters that do not follow it.
   It answers a request that carries no `profile` as `evidence-interop/0`, the only version this
   revision defines [P-2]. A verifier checking such a reply compares against `evidence-interop/0`.
3. `profile` MUST NOT influence the artifact [ER §5]. The artifact is a function of (subject,
   resolved anchor, derivation) only [ER §5]. `profile` governs the envelope, not the artifact.
4. A responder that implements this profile but not the requested identifier MUST refuse with reason
   `request_malformed` [P-3]. ER assigns that token to a request carrying a non-conforming value
   [ER §3]. `profile` is a field this profile defines, not ER, so this is the profile's reading.
   ER allows human-readable detail beside the token [ER §4.2]. The responder SHOULD use it to list
   its supported identifiers [P-3]. ER registers no more specific token for this case (§9.1).
5. A verifier that receives an envelope whose `profile` is not the identifier the requester sent
   MUST report `profile_version` as `FAIL` [P-4]. One that receives an envelope naming an identifier
   it does not implement MUST report `profile_version` as `NOT_CHECKED` and MUST NOT check the
   envelope under any other version's rules [P-4]. In the second case every other envelope property
   is also `NOT_CHECKED` (§7.2). An artifact response that lacks this profile's `profile` member,
   as from a responder implementing ER alone, is reported `profile_version` `NOT_PRESENT`, and
   every other envelope property is then `NOT_CHECKED` [P-4].

Each case maps to an Evidence Result through §8. None of them is ever read as a refusal or as an
absence [ER §4.5].

## 4. Naming

Every member name and every enumerated value in this profile is a text string. It is used
verbatim as a CBOR map key (major type 3) in the stream binding [ER §10] and as a JSON member name
in JSON bindings: JSON bindings reuse the CBOR stream binding's string identifiers verbatim.
There is one name table, below, with no integer map keys, no aliases, and no case variants [P-5]. ER
already gives the request one set of field names for both encodings [ER §3]. This profile extends
that to every object it defines.

| Object | Names (exact strings) | Pinned by |
|---|---|---|
| Request fields | `subject`, `coverage`, `derivation`, `deadline`, `nonce`, `route`; profile extension `profile` | ER §3; P-2 |
| Subject forms | `full_history`, `checkpoints`, `record`, `range`, `correlation`, `exchange` | ER §3.1 |
| Coverage members | `expected_pin`, `min_freshness` | ER §3.2 |
| Refusal members | `request_digest`, `reason`, `issued_at`, `key_id`, `sig`; optional `detail` | ER §4.2; ERV A7; P-6 |
| Refusal reasons | the eight tokens of §9.1 | ER §13 |
| Envelope members | `profile`, `request_digest`, `subject`, `derivation`, `anchor`, `artifact_digest`, `verification`, `responder`, `issued_at`, `sig`, `artifact`, `verification_content`, `retention` | P-7 |
| Anchor members | `digest`, `freshness` | P-7 |
| Verification entry members | `kind`, `digest` | P-7 |
| Absence record members | `outcome`, `request_digest`, `route`, `window`, `opened`, `closed`, `recorded_at`, `retention`, `key_id`, `sig` | ER §4.4; P-8 |
| Property report members | `property`, `status`, `method`, `detail` | P-16 |
| Outcome names | `artifact`, `refusal`, `recorded_absence`; the state `pending` | ER §4; ERV `registry.json` |
| Property statuses | `PASS`, `FAIL`, `NOT_PRESENT`, `NOT_CHECKED`, `INCONCLUSIVE` | §7.1 |
| Property names | the names in §7.2 | §7.2 |
| Subprotocol | `evidence-request/1` | ER §10 |
| Manifest member | `profiles` | P-2 |

The one value type that differs between encodings is opaque bytes (`artifact`, and each entry
of `verification_content`). CBOR carries them as a byte string (major type 2). JSON carries them
as base64url without padding (RFC 4648 §5). Digests, times and every other value have the same
type in both encodings (§5.2).

## 5. Canonical bytes

### 5.1 Encoding per object

| Object | Bytes that are hashed or signed | Rule |
|---|---|---|
| Request | the octets as transmitted | deterministic CBOR in the stream binding [ER §10]; elsewhere ER says SHOULD [ER §3.8], and a requester following this profile MUST encode deterministically: RFC 8949 §4.2.1 for CBOR, RFC 8785 (JCS) for JSON [P-9] |
| Request digest | SHA-256 over the request octets **as received** | [ER §4.2]; never over a re-canonicalized form [ERV `digest.json`] |
| Stream binding frame | the whole response or request map | deterministic CBOR, RFC 8949 §4.2 [ER §10] |
| Canonical Artifact | the artifact octets exactly as carried | MUST be deterministic [ER §5]; its encoding is fixed by its own format; its digest is SHA-256 over those octets [P-10] |
| Envelope signing input | UTF-8 of JCS (RFC 8785) of the signed-members object (§6.2) | [P-7]; same rule as the refusal |
| Refusal signing input | UTF-8 of JCS of `{issued_at, reason, request_digest}` | ER leaves the format to the deployment [ER §4.2 item 4]; the vectors fix this one [ERV A7] |
| Absence record digest | SHA-256 over UTF-8 of JCS of the record, `sig` included when present | [P-8] |
| A JSON value whose digest a Disclosure Envelope commits to | SHA-256 over UTF-8 of JCS of the value | [DE §2, §5.1.3] |
| A foreign signed object | the octets as the originating protocol delivered them | as-transmitted, below |

**The as-transmitted rule for foreign objects.** A signed object produced by another protocol,
carried inside an Artifact or cited by one, is digested over the exact octets that protocol
delivered. It is never parsed and re-serialized, never re-signed, and never canonicalized with
RFC 8785 unless its own type definition says so [SR §8, rule 1 and the section's opening
paragraph]. SR §8 rule 1 identifies this as
the `as-transmitted` rule of the Canonicalization Declaration
(`draft-mih-sokolov-scitt-payload-binding`, Section 4.4). Carrying a foreign object by digest
proves possession of those octets and nothing more. SR §8 lets a verifier check a wrapped object
under its own protocol. This profile makes that a MUST: a verifier MUST run the object's native
check before it reports any property of the object's signature or meaning (§7.2,
`native_check`) [P-11].

**The signature is always over JCS, whatever the frame.** A refusal or envelope carried in a
deterministic CBOR frame is signed over the same JCS body as its JSON form [ERV A7; P-7]. Every
signed member is `null`, a text string, an integer in the range 0 to 2^53 − 1, an array or a map
(§5.2). So the CBOR value and the JSON value have one meaning and one JCS serialization, and one
signature verifies in both bindings.

### 5.2 Value conventions

| Value | Form | Pinned by |
|---|---|---|
| Digest | SHA-256, 64 lowercase hexadecimal characters, a text string in both encodings | ERV A2 |
| Time | RFC 3339 UTC with `Z`, seconds precision, no fractional part: `YYYY-MM-DDTHH:MM:SSZ` | ERV A5; P-12 |
| Key identifier | the raw 32-byte Ed25519 public key, 64 lowercase hexadecimal characters | ERV A7 |
| Signature | Ed25519 (RFC 8032), 64 bytes, 128 lowercase hexadecimal characters | ERV A7 |
| Subject | a map with exactly one member, named by the form token: `null` for `full_history` and `checkpoints`, a digest for `record` and `exchange`, `[a, b]` (two unsigned integers, `a` ≤ `b`) for `range`, a text string for `correlation` | ERV A1, A6 |
| Coverage | `{"expected_pin": <digest>}` or `{"min_freshness": <unsigned integer log size, or time>}` | ER §3.2; ERV A3 |
| Derivation | a registered token with a `/N` suffix, or a 64-hex definition digest | ER §3.3; ERV A14 |
| `deadline` | a time | ERV A5 |
| `nonce`, `route` | text strings | ERV A5 |
| Numbers | unsigned integers from 0 to 2^53 − 1 only, so that JCS represents them exactly; no floating-point value appears in any object this profile defines | P-12 |

A JSON object or CBOR map received under this profile with a duplicate member name MUST be rejected
as not well-formed [P-12]. For a request, that is a refusal with `request_malformed` [ER §3]. For a
response, the verifier reports the signature property for that object as `FAIL`.

## 6. Messages, and what binds them

### 6.1 Request

The request is the ER request map [ER §3], with one added member:

| Field | Presence | Value |
|---|---|---|
| `subject` | REQUIRED | §5.2 [ER §3.1] |
| `coverage` | REQUIRED | exactly one of the two members [ER §3.2] |
| `derivation` | OPTIONAL | §5.2 [ER §3.3] |
| `deadline` | OPTIONAL | a time [ER §3.4] |
| `nonce` | RECOMMENDED | a text string [ER §3.5] |
| `route` | OPTIONAL | a text string [ER §3.6] |
| `profile` | REQUIRED of a requester following this profile; a responder handles its absence (§3.3) | a profile identifier [P-2] |

Responder validation order (the first failing rule decides the refusal):

1. Not a well-formed map: `request_malformed` [ER §3].
2. `subject` missing, an unknown form, more than one form, or non-conforming content:
   `request_malformed` [ER §3, §3.1; ERV A1, A2, A6].
3. A member of `coverage` present with a non-conforming value, or `coverage` not a map:
   `request_malformed`. This check runs before the both-or-neither check [ER §3.2; ERV A4].
4. `coverage` absent, or carrying both members, or neither: `coverage_unsatisfiable`
   [ER §3.2; ERV A4].
5. `profile` naming an identifier the responder does not implement: `request_malformed` (§3.3)
   [P-3].
6. Resolution: a subject that does not resolve exactly is `no_such_subject`, with no fuzzy or
   prefix matching [ER §3.1]. A `range` under a mechanism with no positional order is
   `coverage_unsatisfiable` [ER §3.1]. A derivation the responder does not support is
   `derivation_unsupported`, and one it supports but not for this subject is `no_such_subject`
   [ER §3.3]. A pin naming an anchor the responder never issued, or a freshness floor it cannot
   meet, is `coverage_unsatisfiable` [ER §3.2].

A requester following this profile MUST retain the octets it transmitted, or their digest,
until the request resolves [P-9]. ER makes recording a SHOULD [ER §3.8]. Without those octets the
requester cannot check `request_binding` on any answer.

In the HTTP binding, a requester following this profile sends every request as a POST whose body is
the request map [P-22]. That includes the pinned, parameterless requests ER maps onto GET [ER §10]:
this profile overrides ER on that point. Only a body gives the request octets that `request_binding`
needs. ER defines no request field naming the evidence stream [ER §2]. In v0 a responder holding
several streams says how each is addressed outside this profile (P-23).

### 6.2 Artifact response: canonical Artifact and signed envelope

ER requires the artifact response to carry the artifact identified by digest, the resolved
anchor, and verification material [ER §4.1]. It requires the artifact to be byte-identical for
every requester for the same (subject, resolved anchor, derivation) [ER §5]. It names no members
and no signature profile for the envelope [ERV A12]. This profile pins them [P-7].

**The response object.**

| Member | Signed | Value |
|---|---|---|
| `profile` | yes | the profile identifier, `evidence-interop/0` |
| `request_digest` | yes | SHA-256 over the request octets as received [ER §4.2 item 1, applied to the envelope by P-7] |
| `subject` | yes | the request's `subject`, by value |
| `derivation` | yes, when present | the request's `derivation`; absent when the request had none |
| `anchor` | yes | `{"digest": <digest of the resolved coverage anchor>}`; under `min_freshness` also `"freshness"`: the size or time the anchor attains, in the type the request used [ER §4.1 item 2] |
| `artifact_digest` | yes | SHA-256 over the artifact octets [ER §4.1 item 1] |
| `verification` | yes, when present | an array of `{"kind": <text>, "digest": <SHA-256 of the entry's octets>}`, one entry per item of verification material [ER §4.1 item 3]; absent when there is none |
| `responder` | yes | the responder's key identifier (§5.2) |
| `issued_at` | yes | the time the envelope was issued |
| `sig` | — | Ed25519 by `responder` over the signing input |
| `artifact` | no | the artifact octets (§4 for the per-encoding form); its digest is signed |
| `verification_content` | no | the octets of each verification item, in the order of `verification`; their digests are signed |
| `retention` | no | OPTIONAL; a retention commitment [ER §9], itself signed by its issuer (shape: §11.4) |

The **signing input** is UTF-8 of JCS over the object made of the signed members that are present
(§5.1). `sig` is not part of it.

**Why each member is signed.**

- `request_digest` and `issued_at` bind this answer to one instance of asking, at one time. Two
  envelopes for the same subject and anchor always differ in these two members. They can also
  differ in `verification` (point 3 below) and, under `min_freshness`, in how `anchor.freshness`
  is expressed. They never differ in `artifact_digest`.
- `subject`, `derivation` and `anchor` let any two holders of envelopes see that they asked the
  same question, without exchanging their requests.
- `artifact_digest` names the canonical Artifact.
- `verification` binds the material that is sent to this one envelope. ER describes the artifact
  response as a signed envelope that carries the verification material [ER §4.1].
- `responder` binds the key. The signature verifies only under that key.

**What is invariant and what is not.**

1. The artifact octets, and therefore `artifact_digest`, MUST be identical for every requester
   and every binding, for the same responder, subject, resolved anchor and derivation [ER §5].
   `nonce`, `route`, `profile`, the requester's principal and the transport MUST NOT influence
   them [ER §3.5, §3.6, §3.7, §5].
2. `request_digest` and `issued_at` differ per request. That difference is what an envelope is
   for.
3. Verification material is not required to be byte-identical across requesters. For example, a
   consistency proof may depend on that requester's earlier anchor [ER §5]. The material binds the
   artifact to the anchor. The envelope binds the anchor, the material's digests and the artifact
   digest to the responder.
4. For the `checkpoints` subject, and for the derivation ER registers in §8.1, the artifact *is*
   the verification material. A responder MUST NOT send an empty `artifact` with the proofs in
   `verification_content` [ER §4.1]. For these, `verification` is absent and the verifier checks
   `anchor_inclusion` over the `artifact` itself (§7.2). The absence of `verification` is then
   not `NOT_PRESENT`. In v0 that check is still `NOT_CHECKED` unless the verifier implements the
   commitment mechanism from elsewhere, because this revision names none (P-13).

**Verification material kinds.** `kind` names an evidence-mechanism-specific proof format
[ER §4.1 item 3]. This revision registers no kinds (§11.4, P-13). A verifier that does not
implement a `kind` reports `anchor_inclusion` as `NOT_CHECKED` (§7.2). A verifier MAY implement
a mechanism defined elsewhere, such as a checkpointed log's inclusion proof, and name it in
`method`.

**Consequence for v0.** `anchor_inclusion` is required (§7.2). So a verifier built from this
document alone, with no mechanism from elsewhere, never reaches `PASS` on an envelope. It reports
`anchor_inclusion` as `NOT_CHECKED` (§8: `UNKNOWN`), or as `NOT_PRESENT` when no material was
sent (§8: `INSUFFICIENT`). It can never produce `met` or `not_met` from an artifact response.
Request binding, signature, artifact digest, anchor match and caller invariance are all fully
checkable from this document. Whether the artifact is in the anchor is not, until §11.4 fixes a
kind.

### 6.3 Signed refusal

The refusal object is pinned exactly as the existing conformance vectors fix it, so that the
existing cross-implementation refusal vector (`vectors/evidence-request/refusal-imported.json`)
verifies unchanged [ER §4.2; ERV A7]:

| Member | Signed | Value |
|---|---|---|
| `request_digest` | yes | SHA-256 over the request octets **as received** [ER §4.2 item 1] |
| `reason` | yes | exactly one token from the registry (§9.1) [ER §4.2 item 2] |
| `issued_at` | yes | REQUIRED and covered by the signature [ER §4.2 item 3] |
| `key_id` | — | the responder's key identifier |
| `sig` | — | Ed25519 over UTF-8 of JCS of the three signed members [ERV A7]; ER leaves the format to the deployment [ER §4.2 item 4] |
| `detail` | no | OPTIONAL human-readable text. The token, not the prose, is the answer [ER §4.2; P-6] |

A refusal carries no `profile` member, so refusals made under ER alone and under this profile
are the same object. Its binding to a request is the request digest alone [P-6]. A refusal
signed over an unregistered or mis-cased reason, or over two reasons, has a valid signature and
is still not a conforming refusal [ERV A13]. It is recorded as a response received and failed
[P-21], never as an absence [ER §4.5].

A responder MUST select the most specific applicable reason, except that it MAY answer
`policy_declined` uniformly wherever a more specific token would disclose what its policy
protects [ER §4.2, §12].

### 6.4 Absence record

Absence is not a message. It is the requester's own record that neither an envelope nor a
refusal arrived in its waiting window [ER §4.4]. This profile fixes its shape so a verifier
can consume it [P-8]:

| Member | Presence | Value |
|---|---|---|
| `outcome` | REQUIRED | the text `recorded_absence` |
| `request_digest` | REQUIRED | SHA-256 over the transmitted request octets |
| `route` | OPTIONAL | the route attempted, when the request named one or the binding used one |
| `window` | REQUIRED | `{"opened": <time the request was transmitted>, "closed": <the request's deadline, or the requester's local timeout>}` |
| `recorded_at` | REQUIRED | the time the record was written |
| `retention` | OPTIONAL | the digest of a retention commitment the requester holds for the subject |
| `key_id`, `sig` | OPTIONAL | the requester's own key and Ed25519 signature over UTF-8 of JCS of every other member, as in §6.3 |

The record is a JSON object (or the same map in CBOR).

Rules:

- An absence record MUST NOT be written before `window.closed`, so `recorded_at` is never earlier
  than `window.closed` [ER §4.3, §4.5]. Before then the request is pending, and a transport
  failure inside the window leaves it pending [ERV A8].
- It MUST NOT carry a `reason`, a signature by the responder, or anything that reads as the
  responder's act [ER §4.5]. `key_id` and `sig`, when present, are the requester's. They
  attribute the record to the requester only.
- It SHOULD cite a retention commitment the requester holds, and the route attempted [ER §4.4].
  The commitment changes whom the absence counts against. It never turns the absence into a
  refusal [ER §4.5, §9].
- No inferred intent: a partition, a crash and a deliberate non-answer produce the same record
  [ER §4.4].

### 6.5 Recipient-specific disclosures

A projection made for one recipient is a **new derivation, identified by the digest of its
definition**. It is not a new subject form.

ER already lets a request name a derivation "by the digest of a definition" [ER §3.3]. A
derivation's declared field set bounds what is revealed [ER §8]. This profile uses that
mechanism, and keeps ER's six subject forms closed [P-14]:

1. A recipient-specific projection is defined by a JSON definition document. The document declares
   the computation, its declared field set, and the principal reference of the recipient it is
   prepared for [ER §3.7]. Its derivation identifier is the SHA-256 of UTF-8 of JCS of that document
   [ER §3.3; DE §2; P-14]. Because the recipient is in the definition, projections for two
   recipients have two identifiers, even when their computations are the same.
2. The artifact for (subject, anchor, that derivation) is itself caller-invariant [ER §5]. Anyone
   who may ask for that derivation gets the same bytes.
3. Because `derivation` is a signed envelope member (§6.2), two projections with different
   definitions never carry the same signed identity. A projection's artifact MUST NOT be presented
   as the canonical Artifact of the underived subject, or of any other derivation [ER §5; P-14].
4. Authorization decides **whether** to answer and **which** derivations a requester may name. It
   never changes **what** a given (subject, anchor, derivation) yields [ER §3.7, §5].
5. Text that a projection withholds but must still be able to reveal later, to a party the holder
   chooses, is carried as a salted-digest commitment and never as a bare digest of the text [ER §12;
   P-20]. ER §12 requires deployments to salt digests that conceal enumerable content, and leaves
   the salt discipline to them. The commitment is `JSON-DIGEST({"nonce": N, "text": T})`, where `N`
   is a 256-bit nonce written as 64 lowercase hexadecimal characters, `T` is the text as a JSON
   string, and JSON-DIGEST is the lowercase-hex SHA-256 of `UTF8(JCS(value))` [DE §2]. It is opened
   by disclosing `{"nonce": N, "text": T}`, and checked with the Disclosure Envelope's DE-3
   computation: recompute JSON-DIGEST of the disclosed object and compare it with the commitment. A
   different value means the text is not confirmed [DE §5.1.3]. DE-3 compares the exact strings, so
   a checker MUST NOT case-fold, trim or Unicode-normalize either side [P-20]. The nonce is chosen
   once, when the commitment is made and sealed into the projected content. It MUST NOT be drawn per
   request, because the artifact would then vary per request [ER §5; P-20]. Only DE-3's computation
   is reused. DE-1 and DE-2 look up Capsule fields, and this commitment is a member of the
   projection's own content.

The definition document's member names and its declared-field-set syntax are not fixed in this
revision (P-14).

### 6.6 Artifact, Evidence Bundle, presentation

- An Artifact MAY be the octets of an Evidence Bundle or of any other evidence format [ER §4.1].
  Then `artifact_digest` is SHA-256 over the bundle octets as carried. The digests inside the
  bundle are the bundle's own, and are checked by the bundle's own rules. Checking a bundle's
  internal digests does not check the envelope, and checking the envelope does not check the
  bundle's contents.
- A presentation (an HTML page or any rendering) built from an Artifact is a separate object. The
  envelope signature does not cover it. A verifier MUST check the artifact octets and the
  envelope, never a rendering of them [P-15].
- A recipient-specific disclosure is a derivation (§6.5). It is not a rendering of the canonical
  Artifact and not a variant of it.

## 7. Per-property verification statuses

### 7.1 Vocabulary

A verifier reports each property it was asked to check as exactly one of five values, with the
method that produced it [P-16]:

| Status | Meaning |
|---|---|
| `PASS` | the check ran and succeeded |
| `FAIL` | the check ran and definitively failed |
| `NOT_PRESENT` | the input the check needs is absent from what was received |
| `NOT_CHECKED` | the input is present, and the verifier did not run the check: unsupported version, unsupported method, an online check made offline, or excluded by the relying party's policy |
| `INCONCLUSIVE` | the check ran and could not decide, for example the trust policy could not resolve the key's status at `issued_at` |

A property report is `{property, status, method}`. `method` is a text string naming the
algorithm or procedure, for example `Ed25519 over JCS signing input`. A report MAY add `detail`.

This vocabulary is distinct from the Evidence Contract's eight-value per-requirement status
[EC `bundleAssertionStatus`] and from sufficiency [RES §1]. A property status describes one
check. It never states whether a requirement is satisfied. §8 is the only bridge between the two.

### 7.2 Property catalogue

| Property | Applies to | Check | Required for the message to count |
|---|---|---|---|
| `profile_version` | envelope | §3.3 step 5 | yes |
| `envelope_signature` | envelope | `sig` verifies under `responder` over the §6.2 signing input | yes |
| `refusal_signature` | refusal | `sig` verifies under `key_id` over the §6.3 signing input [ERV A7] | yes |
| `responder_trust` | envelope, refusal | the key is accepted by the relying party's trust policy as of `issued_at` | yes |
| `responder_key_current` | envelope, refusal | the key's status now; online. `NOT_CHECKED` when offline | no; reported separately |
| `request_binding` | envelope, refusal | `request_digest` equals SHA-256 of the requester's own transmitted request octets | yes |
| `subject_binding` | envelope | `subject` and `derivation` equal the request's, by value | yes |
| `artifact_digest` | envelope | SHA-256 of the received `artifact` octets equals `artifact_digest` | yes |
| `verification_binding` | envelope | each `verification_content` item hashes to the `digest` at the same position in `verification`, and the counts match | yes, when `verification` is present |
| `anchor_match` | envelope | under `expected_pin`: `anchor.digest` equals the pin; under `min_freshness`: `anchor.freshness` is present and meets the floor [ER §3.2, §4.1 item 2] | yes |
| `anchor_inclusion` | envelope | the artifact verifies against `anchor.digest` using `verification_content`, by the method each `kind` names [ER §4.1 item 3]; for the `checkpoints` subject and the derivation of ER §8.1, the `artifact` is itself the material [ER §4.1] | yes |
| `caller_invariance` | two or more envelopes | for envelopes with the same `responder`, `subject`, `derivation` and `anchor.digest`, each of which has passed `envelope_signature`, `responder_trust` and `artifact_digest`: identical `artifact_digest` [ER §5]. `NOT_CHECKED` with fewer than two such envelopes [P-17] | a `FAIL` is adverse (§8) |
| `reason_registered` | refusal | `reason` is exactly one token of §9.1, exact case [ERV A13] | yes |
| `issued_at_form` | envelope, refusal | present and of the §5.2 time form. ER requires it on a refusal [ER §4.2 item 3]; for the envelope and for the form, see [ERV A5; P-12] | yes |
| `native_check` | each foreign object in a verified Artifact | the object's own verification method over its as-transmitted octets (§5.1); `method` names that method | per requirement (§8) |

When `profile_version` is not `PASS`, every other envelope property is `NOT_CHECKED` [P-4].
`native_check` is not an envelope property: it applies to foreign objects inside an Artifact
whose envelope properties all passed.

An absence record has no responder properties. A verifier checks only its form (§6.4) and maps it
by §8.

### 7.3 Verification, step by step

**Envelope.** Parse the object and reject duplicate members (§5.2). Check `profile_version`.
Rebuild the signing input from the signed members present and check `envelope_signature`, then
`responder_trust` and `issued_at_form`. Recompute SHA-256 over the retained request octets and
check `request_binding`. Compare `subject` and `derivation` for `subject_binding`. Hash the
`artifact` octets for `artifact_digest`. Hash each `verification_content` item for
`verification_binding`. Check `anchor_match`, then `anchor_inclusion`. If other envelopes for the
same (responder, subject, derivation, anchor) are held, check `caller_invariance`. Report
`responder_key_current` if online. Then, for each foreign object the Artifact carries that a
requirement depends on, run `native_check` over its as-transmitted octets (§5.1).

**Refusal.** Parse the object and reject duplicate members (§5.2). Recompute SHA-256 over the
retained request octets and check `request_binding`. Rebuild `{issued_at, reason, request_digest}`
with JCS and check `refusal_signature`, then `responder_trust`, `reason_registered` and
`issued_at_form`. Report `responder_key_current` if online. Keep the signature check and the
registry check apart: a valid signature over an unregistered token is still the responder's signed
act [ERV A13].

**Absence.** Confirm that `recorded_at` is not earlier than `window.closed`, and that the record
carries no responder act (§6.4). Verify the requester's `sig` if present.

## 8. Result mappings

Request outcome → per-property statuses (§7) → Evidence Result claim [RES §1]. This section
gives the eight-value status [EC `bundleAssertionStatus`] that one outcome contributes when that
request is the only evidence source for the requirement. Sufficiency then follows mechanically
from the Evidence Contract's projection [EC `contractResult`]: `SATISFIED`→`SATISFIED`;
`NOT_FOUND`, `NOT_COMMITTED`, `WITHHELD` and `CONTRADICTED`→`GAP`; `INSUFFICIENT`→`INSUFFICIENT`;
`UNKNOWN`→`UNKNOWN`; `NOT_APPLICABLE` is excluded from the evaluated population. When other
evidence exists, the contract evaluates all of it together.

The statuses below are this profile's defaults [P-17]. A requirement's own contract can declare
how to treat missing or conflicting evidence, through `uncertainty.on_missing` and
`uncertainty.on_conflict` [EC requirement `uncertainty`]. Where it does:

- **Missing rows.** These are envelope rows 3 and 4, and the `no_such_subject`, `UNKNOWN`-mapped
  refusal and recorded-absence rows. `on_missing: insufficient` gives `INSUFFICIENT`, and
  `on_missing: unknown` gives `UNKNOWN`.
- **Conflict row.** This is envelope row 1. `on_conflict: contradicted` gives `CONTRADICTED`.
- **`escalate`.** This value leaves the default status in place. What escalation does is outside
  this profile [P-17]. ER §4.6 is informative [ER §4.6]. This profile adopts
its distinctions as its own normative mapping [P-17].

### 8.1 The mapping

| Outcome and properties | Status | Sufficiency | Verdict |
|---|---|---|---|
| 1. Envelope, `caller_invariance` `FAIL` | `CONTRADICTED` | `GAP` | `not_evaluable` |
| 2. Envelope, any other required envelope property `FAIL` | `INSUFFICIENT` | `INSUFFICIENT` | `not_evaluable` |
| 3. Envelope, any required envelope property `NOT_PRESENT` (including `profile_version`) | `INSUFFICIENT` | `INSUFFICIENT` | `not_evaluable` |
| 4. Envelope, any required envelope property `NOT_CHECKED` or `INCONCLUSIVE` | `UNKNOWN` | `UNKNOWN` | `not_evaluable` |
| 5. Envelope, every required envelope property `PASS`; a `native_check` `FAIL`; the requirement **is** that check | `SATISFIED`: the evidence needed to judge it is present and verified, and it shows the check failed | `SATISFIED` | `not_met` |
| 6. Envelope, every required envelope property `PASS`; a `native_check` `FAIL`; the requirement is one the check only **supports** | `INSUFFICIENT`, unless other evidence settles it | `INSUFFICIENT` | `not_evaluable` |
| 7. Envelope, every required envelope property `PASS`, and no row 5 or 6 applies | as the contract evaluates the Artifact's content | by projection | `met` / `not_met` only if `SATISFIED`, else `not_evaluable` [RES §1] |
| Conforming refusal, `no_such_subject` | `NOT_FOUND` | `GAP` | `not_evaluable` |
| Conforming refusal, `retention_expired` | `UNKNOWN`, with the reason kept in the claim's carrier | `UNKNOWN` | `not_evaluable` |
| Conforming refusal, `coverage_unsatisfiable` | `UNKNOWN`, with the reason kept in the claim's carrier | `UNKNOWN` | `not_evaluable` |
| Conforming refusal, `not_authorized`, `policy_declined` or `derivation_unsupported` | `WITHHELD` | `GAP` | `not_evaluable` |
| Conforming refusal, `deadline_unmet` or `request_malformed` | `UNKNOWN` | `UNKNOWN` | `not_evaluable` |
| Refusal with any required property not `PASS` (response received and failed, P-21) | `UNKNOWN` | `UNKNOWN` | `not_evaluable` |
| Recorded absence | `UNKNOWN` | `UNKNOWN` | `not_evaluable` |
| Pending | no claim is emitted | — | — |

Envelope rows are tried in order 1 to 7, and the first that matches decides.

Where each row comes from:

- The refusal rows follow ER's informative mapping [ER §4.6]. `no_such_subject` means evidence not
  found. `not_authorized`, `policy_declined` and `derivation_unsupported` mean withheld by policy,
  not absent.
- `retention_expired` is a lapsed commitment, which ER keeps distinct from never having held the
  evidence [ER §4.2 item 2]. So this profile maps it to `UNKNOWN`, not to `NOT_FOUND` [P-17].
- `coverage_unsatisfiable` covers several cases [ER §3.1, §3.2]:
  - evidence not yet committed under the coverage asked for;
  - coverage carrying both members or neither;
  - a `range` under a mechanism with no positional order;
  - a pin naming an anchor the responder never issued.

  Most of these say nothing about whether the evidence exists. `NOT_COMMITTED` would assert that
  it does [RES §2], so this profile maps the token to `UNKNOWN` [P-17].
- `caller_invariance` `FAIL` means the responder, under a trusted key, signed two different
  artifacts for one question. Only verified envelopes are compared (§7.2), so an unverified copy
  can never charge a conflict. This profile assigns `CONTRADICTED`, which the contract's
  projection takes to `GAP` [EC `contractResult`; P-17]. The conflict flag that projection
  mentions is outside this revision.
- Row 5 differs from ER §4.6's "verification fails" row. That row is about the artifact response
  failing verification. In row 5 the envelope and artifact verified, and a foreign object inside
  the Artifact failed its native check. That failure is what a requirement which *is* the check
  is judged on [P-17].
- ER §4.6 does not map `deadline_unmet` or `request_malformed`. This profile maps both to
  `UNKNOWN` [P-17].
- An absence maps to `UNKNOWN` because ER says absence is "status unknown to the requester; not
  evidence of non-satisfaction" [ER §4.6].
- Rows 5 and 6 apply only when every envelope property passed. A failure of the envelope itself
  means the Artifact is not usable evidence for any requirement, including one that is the check
  [P-17].

### 8.2 Invariants of the mapping

1. A verifier MUST NOT emit `met` or `not_met` for any status that projects to anything but
   `SATISFIED` [RES §1].
2. A verification failure never yields `SATISFIED` with `met` for a requirement that depends on
   the failed property [ER §4.6; RES §1].
3. A refusal is never mapped as an absence, and an absence is never mapped as a refusal
   [ER §4.5]. A pending request yields no claim [ER §4.3].
4. When the status is `WITHHELD` or `NOT_COMMITTED`, the claim's presentation carrier MUST be
   `analysis` or `story`, never `disclosure` [RES §2]. A recorded absence SHOULD use `story`,
   which is RES §2's own example [P-17].

### 8.3 Filling the claim

The claim's fields [RES §4, §5] are filled as follows:

- `evidence[]` [RES §5] names the outcome's object:
  - for an envelope, `artifact_digest`;
  - for a refusal, SHA-256 over the refusal octets as received [P-18];
  - for an absence, the absence record digest (§5.1).
- `proofs[]` [RES §5] lists the `verification` entries actually used. RES §5 closes `proof-ref.kind`
  to `inclusion_proof` and `receipt`. So only entries whose mechanism is one of those two can be
  listed, and v0 fixes no mechanism (P-13).
- `contract_ref` is the `<contract_id>@<version>` of the contract evaluated [RES §1]. The
  contract-digest binding of an accepted contract is §11.1.
- `tier` and `grade` are set by the evaluator as RES §1 defines. This profile does not set them.

The status in a `not_evaluable` claim's carrier tells the requester what kind of follow-up could
change the result: a corrected request, a different subject, or a later one. The claim itself
names no missing evidence [RES §1].

## 9. Error codes

### 9.1 Refusal reasons are the draft's registry

The only refusal reasons are the eight tokens of the "Evidence Request Refusal Reasons" registry
[ER §13], used verbatim:

`not_authorized` · `no_such_subject` · `coverage_unsatisfiable` · `derivation_unsupported` ·
`policy_declined` · `deadline_unmet` · `request_malformed` · `retention_expired`

This profile defines no additional refusal reason in v0 [P-3]. A new token requires registration
under ER's Specification Required policy [ER §13]. A responder MUST NOT emit an unregistered
token [ER §4.2 item 2].

### 9.2 Transport errors are not refusals

A transport condition is never a refusal, and no party manufactures a refusal from one
[ER §4.5, §10]:

| Transport condition | What the requester records |
|---|---|
| connection failure, reset, or timeout inside the waiting window | pending [ER §4.3; ERV A8] |
| the same, with the window closed and no answer received | recorded absence [ER §4.4] |
| peer does not offer the `evidence-request/1` subprotocol | absence once the window closes, never `policy_declined` [ER §10] |
| HTTP error status with no signed refusal body | pending, then absence; never a refusal [ER §10] |
| HTTP response carrying a signed refusal | a refusal: a successful transport exchange carrying a refusal answer [ER §10] |

In the HTTP binding a responder SHOULD send a refusal with a success status (`200`) and a JSON
body [P-19]. ER describes this as a successful transport exchange carrying a refusal answer, and
forbids bindings to conflate transport errors with refusals [ER §10]. So a verifier MUST classify
by the body, never by the status code [P-19].

### 9.3 Verifier findings are not error codes

A property report (§7) is a verifier's finding. It is not sent on the wire, it is never a refusal
reason, and it never appears in a responder's message.

## 10. Worked example (informative)

All values below are reproducible. The key is the fixed primary responder key of
`vectors/evidence-request/refusal.json`, derived from the seed
`SHA-256("draft-mih-agent-evidence-request-00 conformance vectors: primary responder key")`. The
record and anchor digests are that generator's `label_digest("record 1")` and
`label_digest("checkpoint at size 42")`.

```
key_id / responder   e84fed8190a6116016bf68ef2fc1780a919e9ed2d9f88efb895a954ffd7f0117
record digest R1     2ab350895f867d54a5cfdc1dd1aa214cbc723c659663460e7511dff16a5ccc85
anchor digest A      6441370955d2b408884793962a664daec6bb25e06d76a2f53d8a80f66a675202
```

**Request A, JSON binding** (JCS text, the transmitted octets):

```
{"coverage":{"expected_pin":"6441370955d2b408884793962a664daec6bb25e06d76a2f53d8a80f66a675202"},"nonce":"2026-10-12T00:00:00Z/a","profile":"evidence-interop/0","subject":{"record":"2ab350895f867d54a5cfdc1dd1aa214cbc723c659663460e7511dff16a5ccc85"}}
```

request digest `8620853807eecfc80e6056bb64aab0c2493aa9625a687f7780222e3b5aa0bd96`

**Request B, CBOR stream binding.** The same subject and anchor, nonce `2026-10-12T00:00:05Z/b`,
encoded as deterministic CBOR (hex):

```
a4656e6f6e636576323032362d31302d31325430303a30303a30355a2f626770726f66696c657265766964656e63652d696e7465726f702f30677375626a656374a1667265636f726478403261623335303839356638363764353461356366646331646431616132313463626337323363363539363633343630653735313164666631366135636363383568636f766572616765a16c65787065637465645f70696e784036343431333730393535643262343038383834373933393632613636346461656336626232356530366437366132663533643861383066363661363735323032
```

request digest `ba7fee76b7afe9f3ec5ce46975865e06040492f0da733b28cbc86bd2be609d5e`

**The canonical Artifact.** It is the same octets for both requests. The text is
`{"example":"evidence record","seq":1}`, base64url
`eyJleGFtcGxlIjoiZXZpZGVuY2UgcmVjb3JkIiwic2VxIjoxfQ`, and the artifact digest is
`2fbdb95bdeba62f949bcb6026061fcd66c021523a39e58fc2de1cd44ff631244`.

**Envelope for request A.** Signing input:

```
{"anchor":{"digest":"6441370955d2b408884793962a664daec6bb25e06d76a2f53d8a80f66a675202"},"artifact_digest":"2fbdb95bdeba62f949bcb6026061fcd66c021523a39e58fc2de1cd44ff631244","issued_at":"2026-10-12T00:00:01Z","profile":"evidence-interop/0","request_digest":"8620853807eecfc80e6056bb64aab0c2493aa9625a687f7780222e3b5aa0bd96","responder":"e84fed8190a6116016bf68ef2fc1780a919e9ed2d9f88efb895a954ffd7f0117","subject":{"record":"2ab350895f867d54a5cfdc1dd1aa214cbc723c659663460e7511dff16a5ccc85"}}
```

`sig` = `1ff596857fafdf74dcaf60b4ee5d02897368cdc2241947705500620d0d394c478fd7170ac6c046da41e5511bae5aaa1fb9bb0f982126a0c6cbf786ee9599d305`

The complete response object for request A, in the JSON binding, is below. Member order and
whitespace are not significant, because the signature is over the JCS signing input above.

```json
{
 "anchor": {"digest": "6441370955d2b408884793962a664daec6bb25e06d76a2f53d8a80f66a675202"},
 "artifact": "eyJleGFtcGxlIjoiZXZpZGVuY2UgcmVjb3JkIiwic2VxIjoxfQ",
 "artifact_digest": "2fbdb95bdeba62f949bcb6026061fcd66c021523a39e58fc2de1cd44ff631244",
 "issued_at": "2026-10-12T00:00:01Z",
 "profile": "evidence-interop/0",
 "request_digest": "8620853807eecfc80e6056bb64aab0c2493aa9625a687f7780222e3b5aa0bd96",
 "responder": "e84fed8190a6116016bf68ef2fc1780a919e9ed2d9f88efb895a954ffd7f0117",
 "sig": "1ff596857fafdf74dcaf60b4ee5d02897368cdc2241947705500620d0d394c478fd7170ac6c046da41e5511bae5aaa1fb9bb0f982126a0c6cbf786ee9599d305",
 "subject": {"record": "2ab350895f867d54a5cfdc1dd1aa214cbc723c659663460e7511dff16a5ccc85"}
}
```

**Envelope for request B.** It is the same, except `issued_at` is `2026-10-12T00:00:06Z` and
`request_digest` is `ba7fee76b7afe9f3ec5ce46975865e06040492f0da733b28cbc86bd2be609d5e`.

`sig` = `986dca488661a2519c11d8285e6d85871f164b30c5bd9b9211df25e6038d98197684f93bcbf989ebee0f38b596cdee757c73ee8c9db89766e9bb29ae812b810c`

The two envelopes differ in request digest and issuance and name one artifact digest. That pair
is the invariance property of §6.2. `verification` and `verification_content` are omitted here,
because no verification-material kind is fixed in this revision (§11.4). So in this example
`anchor_inclusion` is `NOT_PRESENT`, which maps to `INSUFFICIENT` (§8.1 row 3). That shows the
v0 limit stated in §6.2, not a defect in the example.

**Refusal.** Had the responder held no record R1, it would have answered request A with this
refusal. Signing input:

```
{"issued_at":"2026-10-12T00:00:01Z","reason":"no_such_subject","request_digest":"8620853807eecfc80e6056bb64aab0c2493aa9625a687f7780222e3b5aa0bd96"}
```

`sig` = `b2725d52678fb9a652e9033c5c0756936b2f5567f4b94b239210f14938932fa044fc90a7962d086789add8170397a80847cc8dcaaf5f3a455b8044e4f56d570c`

**Absence record.** Had nothing arrived for request B within a one-minute window, the requester
would record this (unsigned; JCS text):

```
{"outcome":"recorded_absence","recorded_at":"2026-10-12T00:01:05Z","request_digest":"ba7fee76b7afe9f3ec5ce46975865e06040492f0da733b28cbc86bd2be609d5e","route":"peer:example-responder","window":{"closed":"2026-10-12T00:01:05Z","opened":"2026-10-12T00:00:05Z"}}
```

absence record digest `82108c5666f4d2049d620cd9c799289bbb9f5f9bfe2801d7f51fd821df6848d5`

## 11. Parts filled by later revisions

These headings are placeholders. Nothing under them is specified yet.

### 11.1 Acceptance record

*Placeholder.* Scope: one signed acceptance record type with an optional session scope. The
ordering evidence named normatively is a counterparty-signed receipt, or a transparency-service
or witness receipt.

### 11.2 Lifecycle links

*Placeholder.* Scope: issuer rules for corrections and challenges. `amends`, `disputes` and
`resolves` are new link tokens, proposed for `draft-mih-agent-evidence-layer` -01. `contradicts`
maps to the registered `rebuts`.

### 11.3 Evidence Contract prose

*Placeholder.* Scope: the normative prose for the Evidence Contract, kept as a section of this
profile.

### 11.4 Carriage and discovery

*Placeholder.* This covers the A2A and MCP bindings, the full manifest, verification-material
kinds, and the shape of a carried retention commitment.

### 11.5 Conformance vectors

*Placeholder.*

## 12. Security considerations

ER's security and privacy considerations [ER §11, §12] apply unchanged. Four points are specific
to this profile:

- **The envelope does not make an anchor independent.** The envelope binds the anchor to the
  responder's key. An `expected_pin` the requester obtained independently is still the only
  strong form [ER §11].
- **`caller_invariance` needs a second copy.** A single requester holding one envelope cannot
  detect divergence. The property is `NOT_CHECKED` there, and that status is reported, not
  hidden.
- **Verification material is bound, not trusted.** The envelope signs the digest of each item
  of verification material (§6.2). The material can still make `anchor_inclusion` pass only if it
  actually proves the artifact against the signed anchor. A forged proof fails that check.
- **Trust is the relying party's.** `responder_trust` is decided by the relying party's own
  policy, and verifier code comes from a source the relying party trusts, never from the object
  under verification.

## 13. Open points

Each is a requirement this profile adds that no pinned document states. Each is a candidate for
a later draft revision.

- **P-1** The profile identifier names one exact revision. Any byte-level change requires a new
  identifier (§3.1, §3.2).
- **P-2** The `profile` request member and the `profiles` manifest member (§3.3, §6.1).
- **P-3** An unsupported profile version is refused `request_malformed`. ER has no dedicated token.
  Candidate for ER -01: register a token such as `version_unsupported` (§3.3, §9.1).
- **P-4** A verifier checks an envelope only under the version it names. Unknown version means every
  envelope property is `NOT_CHECKED` (§3.3, §7.2).
- **P-5** One name table across encodings: text keys only, verbatim (§4).
- **P-6** The refusal's optional `detail` member. The refusal is otherwise exactly the ERV A7
  object, with no profile member (§6.3).
- **P-7** The envelope's member names, signed members (including the digests of the verification
  material), signing input and signature profile (§6.2). ER §4.1 names the contents but no members
  (ERV A12). ER §4.1 does not state the binding of the request digest and issuance time into the
  artifact envelope.
- **P-8** The absence record shape, `recorded_at`, the optional requester signature, and its digest
  (§6.4).
- **P-9** Deterministic request encoding, and retention of the transmitted octets, both as MUSTs for
  a requester following this profile (§5.1, §6.1). ER has both as SHOULD.
- **P-10** The artifact digest is SHA-256 over the octets as carried (§5.1).
- **P-11** The verifier MUST run a foreign object's native check before reporting on it (§5.1).
- **P-12** Time form with seconds precision; unsigned integers no larger than 2^53 − 1 and no
  floats; duplicate members rejected in JSON and CBOR (§5.2).
- **P-13** Verification-material kinds: none registered in v0 (§6.2). Until one is, a verifier built
  from this document alone cannot check `anchor_inclusion`, never reaches `PASS` on an envelope, and
  cannot fill `proofs[]` (§6.2, §8.3, §11.4).
- **P-14** Recipient-specific disclosure as a definition-digest derivation whose definition names
  the recipient's principal reference. The definition document's member names are not fixed (§6.5).
- **P-15** A verifier checks octets and envelope, never a rendering (§6.6).
- **P-16** The five-value property status vocabulary and the property report shape (§7.1).
- **P-17** The §8.1 mapping as a whole, which adopts ER §4.6's informative distinctions as normative
  defaults. It includes the statuses for `coverage_unsatisfiable`, `deadline_unmet`,
  `request_malformed` and `retention_expired`, failed envelope properties, caller-invariance
  conflicts (computed over verified envelopes only) and failed foreign checks, and the use of
  `story` for absence. A contract's `uncertainty` declarations override it, and `escalate` keeps the
  default status (§8).
- **P-18** A refusal is cited by SHA-256 over its octets as received (§8.3).
- **P-19** HTTP refusals use a success status, and verifiers classify by body (§9.2).
- **P-20** Withheld text in a recipient-specific projection is a salted-digest commitment with a
  256-bit nonce, chosen once per commitment and never per request, checked by the DE-3 computation
  (§6.5).
- **P-21** "Response received and failed" covers any envelope or refusal that does not verify. The
  message type is decided by `artifact_digest` or `reason`. A reply with neither is a transport
  condition (§1).
- **P-22** HTTP requests under this profile are always POST with a body (§6.1).
- **P-23** ER has no request field naming the evidence stream. v0 leaves stream addressing to the
  responder (§6.1).

## References

- `draft-mih-agent-evidence-request-00`, `spec/draft-mih-agent-evidence-request-00.md`
  (Internet-Draft, work in progress).
- `vectors/evidence-request/` and its `README.md` readings A1–A14.
- `draft-mih-agent-disclosure-envelope-00`, `spec/draft-mih-agent-disclosure-envelope-00.md`
  (Internet-Draft, work in progress).
- `draft-mih-agent-settlement-records-00`, `spec/draft-mih-agent-settlement-records-00.md`
  (Internet-Draft, work in progress).
- `draft-mih-sokolov-scitt-payload-binding`, Section 4.4, as cited by SR §8 (Internet-Draft, work
  in progress).
- `draft-mih-zhang-agent-disclosure-bundle` (Internet-Draft, work in progress).
- Evidence Result v0, `spec/evidence-result-v0.md`.
- Evidence Contract v0 schema, `evidence-contract-v0.json`.
- RFC 2119, RFC 8174 (BCP 14); RFC 3339; RFC 4648; RFC 8032; RFC 8785; RFC 8949.
