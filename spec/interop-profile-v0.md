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
outcomes to an Evidence Result (§8), error codes (§9), and the acceptance record (§11.1).
Sections 11.2–11.5 are placeholders for parts that later revisions fill in.

The documents this profile pins are Internet-Drafts, work in progress, or specifications kept in
this repository. Open-source repositories, this one included, are implementations of them.

For IPR disclosures against the Internet-Drafts this profile pins, see each draft's Datatracker
IPR page:

- `draft-mih-agent-evidence-request`:
  <https://datatracker.ietf.org/ipr/search/?submit=draft&id=draft-mih-agent-evidence-request>
- `draft-mih-agent-disclosure-envelope`:
  <https://datatracker.ietf.org/ipr/search/?submit=draft&id=draft-mih-agent-disclosure-envelope>
- `draft-mih-agent-settlement-records`:
  <https://datatracker.ietf.org/ipr/search/?submit=draft&id=draft-mih-agent-settlement-records>
- `draft-mih-agent-bilateral-attestation`:
  <https://datatracker.ietf.org/ipr/search/?submit=draft&id=draft-mih-agent-bilateral-attestation>
- `draft-mih-agent-evidence-layer`:
  <https://datatracker.ietf.org/ipr/search/?submit=draft&id=draft-mih-agent-evidence-layer>
- `draft-mih-scitt-checkpointed-local-log`:
  <https://datatracker.ietf.org/ipr/search/?submit=draft&id=draft-mih-scitt-checkpointed-local-log>
- `draft-bryce-cose-receipts-mmr-profile`:
  <https://datatracker.ietf.org/ipr/search/?submit=draft&id=draft-bryce-cose-receipts-mmr-profile>

## Dependency boundary

**Owns:** the profile version identifier and its negotiation (§3), the name table (§4), the
member names and signing input of the artifact response envelope (§6.2), the verification-material
kind identifiers this profile adds and their check procedure (§6.2.1), the absence record
shape (§6.4), the identity of recipient-specific disclosures and their salted-digest commitments
(§6.5), the per-property verification status vocabulary and property catalogue (§7),
the outcome-to-status mapping (§8), and the acceptance record, acceptance receipt, ordering
evidence rules and acceptance findings (§11.1).

**Pins, never redefines:**

| Tag | Document | Revision pinned | What this profile takes from it |
|---|---|---|---|
| ER | `draft-mih-agent-evidence-request` | -00 (`spec/draft-mih-agent-evidence-request-00.md`) | the request, the six subject forms, coverage, the three outcomes, caller invariance, the refusal registry, the transport bindings |
| ERV | Evidence Request conformance vectors | `vectors/evidence-request/`, README readings A1–A14 | the wire readings of ER that -00 leaves open |
| DE | `draft-mih-agent-disclosure-envelope` | -00 (`spec/draft-mih-agent-disclosure-envelope-00.md`) | the JSON value digest rule |
| SR | `draft-mih-agent-settlement-records` | -00 (`spec/draft-mih-agent-settlement-records-00.md`) | the as-transmitted rule for wrapped foreign objects |
| RES | Evidence Result v0 | `spec/evidence-result-v0.md` | the claim, sufficiency, verdict and presentation carrier rules |
| BA | `draft-mih-agent-bilateral-attestation` | -02 (`spec/draft-mih-agent-bilateral-attestation-02.md`) | the requesting and performing parties, and acknowledgment as receipt without agreement |
| EL | `draft-mih-agent-evidence-layer` | -00 (`spec/draft-mih-agent-evidence-layer-00.md`) | what a Receipt proves, witnesses, and the `cites` and `acknowledges` links |
| EC | Evidence Contract v0 schema | `evidence-contract-v0.json`, `$defs/bundleAssertionStatus`, `$defs/contractResult` and the requirement `uncertainty` member | the eight-value status, its four-value projection, and per-requirement handling of missing and conflicting evidence |
| CLL | `draft-mih-scitt-checkpointed-local-log` | -01 as posted: <https://www.ietf.org/archive/id/draft-mih-scitt-checkpointed-local-log-01.txt>, SHA-256 of that file `2ef340206e6ba4260b84ba265f794ab9756aefa7cdaeac98e95cea646cfb678f` | the checkpoint and its claims, the peak-list commitment, the log identity, and the inclusion and consistency claims, behind the `cll-*` material kinds (§6.2.1) |
| MMR | `draft-bryce-cose-receipts-mmr-profile` | -02 as posted: <https://www.ietf.org/archive/id/draft-bryce-cose-receipts-mmr-profile-02.txt>, SHA-256 of that file `c6dc055aa61bcdea1566db5a754d055a199a89c9900810b336d99202a44e9893` | the inclusion and consistency proof encodings and the algorithms that check them; CLL -01 cites this revision normatively |

**Why these CLL and MMR bytes.** CLL and MMR are pinned to the text posted in the IETF
Internet-Draft archive and identified by the SHA-256 of that `.txt` file. CLL's canonical source
repository is not settled, and copies kept beside implementations can differ from what was posted.
No unposted CLL revision is pinned. MMR -02 is pinned because it is the revision CLL -01 cites.

Section numbers for ER, DE, SR, BA, EL, CLL and MMR are those of the rendered `.txt` of the pinned revision. In
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
versions. Until `evidence-interop/0` is first published, filling a placeholder of §11 under it is
allowed, provided it changes no existing signing input or byte rule and only adds objects, rows
and properties [P-1].

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
| Verification material kinds | `cll-checkpoint`, `cll-inclusion-proof`, `cll-consistency-proof` | CLL §3; P-31 |
| Absence record members | `outcome`, `request_digest`, `route`, `window`, `opened`, `closed`, `recorded_at`, `retention`, `key_id`, `sig` | ER §4.4; P-8 |
| Property report members | `property`, `status`, `method`, `detail` | P-16 |
| Outcome names | `artifact`, `refusal`, `recorded_absence`; the state `pending` | ER §4; ERV `registry.json` |
| Property statuses | `PASS`, `FAIL`, `NOT_PRESENT`, `NOT_CHECKED`, `INCONCLUSIVE` | §7.1 |
| Property names | the names in §7.2 | §7.2 |
| Subprotocol | `evidence-request/1` | ER §10 |
| Manifest member | `profiles` | P-2 |
| Acceptance record members | `profile`, `state`, `contract_ref`, `contract_digest`, `transaction`, `proposer`, `acceptor`, `proposal_digest`, `counter_contract_digest`, `session`, `authority`, `issued_at`, `sig` | P-25 |
| Acceptance states | `proposed`, `accepted`, `declined`, `countered` | P-24 |
| Transaction reference members | `scheme`, `id` | P-25 |
| Session members | `not_before`, `not_after`, `policy`, `terms` | P-26 |
| Acceptance receipt members | `profile`, `acceptance_digest`, `received_at`, `receiver`, `sig` | P-27 |
| Authority label | `agent_origin_assertion` | P-29 |
| Acceptance findings | `not_accepted`, `accepted_after_action`, `accepted_not_cited`, `accepted_before_action`, `accepted_execution_cites` | P-30 |

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
   not `NOT_PRESENT`. No kind in this revision applies to these subjects (§6.2.1), so in v0 the
   check is `NOT_CHECKED` unless the verifier implements a mechanism from elsewhere (P-13).

**Verification material kinds.** `kind` names an evidence-mechanism-specific proof format
[ER §4.1 item 3]. This revision registers three kinds, all for one mechanism, the Checkpointed
Local Log (§6.2.1). A verifier that does not implement a `kind` it receives reports
`anchor_inclusion` as `NOT_CHECKED` (§7.2). A verifier MAY implement a mechanism defined
elsewhere and name it in `method` [P-13].

**Consequence for v0.** `anchor_inclusion` is required (§7.2). With the kinds of §6.2.1, a
verifier built from this document alone can check every required envelope property of a
`record` subject with no derivation, served from a Checkpointed Local Log, and can reach `PASS`
on all of them. §10.1 shows that path with real bytes. For every other subject form, for any
derivation, and for the `checkpoints` subject, no kind in this revision applies. There the
verifier reports `anchor_inclusion` as `NOT_CHECKED` (§8: `UNKNOWN`) unless it implements a
mechanism from elsewhere, and so it cannot produce `met` or `not_met` (P-13). An envelope sent
with no material reports `NOT_PRESENT` (§8: `INSUFFICIENT`).

#### 6.2.1 Checkpointed Local Log material

A responder whose evidence stream is a Checkpointed Local Log [CLL §2, §3] proves an artifact
against an anchor with the three kinds below. CLL defines the checkpoint and its commitment, and
takes its proof formats from MMR [CLL §1, §4]. The anchor is a checkpoint, and `anchor_inclusion`
checks that the artifact's digest is a committed entry under it.

**Identifiers.** `cll-checkpoint` is CLL's own string, the value of the checkpoint's `kind` claim
[CLL §3], reused verbatim (§4). Neither CLL nor MMR gives the inclusion proof or the consistency
proof a text identifier. MMR labels them only with the integers -1 and -2 inside a COSE Receipt's
`vdp` header [MMR §5, §7]. So `cll-inclusion-proof` and `cll-consistency-proof` are this
profile's own identifiers (P-31).

**The bytes.**

| `kind` | Octets of the `verification_content` item | Presence |
|---|---|---|
| `cll-checkpoint` | the checkpoint as a COSE_Sign1 (RFC 9052) in one fixed form: CBOR tag 18, an empty unprotected header, and an attached payload. The payload is the CBOR claims map of [CLL §3], keyed by the text claim names of CLL's Table 1. `commitment` and `prev_commitment` are byte strings whose content is the deterministic CBOR of the peak list [CLL §3.1]. The protected header carries the RFC 9052 parameters `alg` (label 1) and `kid` (label 4), and CWT_Claims (label 15, RFC 9597) with `iss` (1) and `sub` (2), as CLL requires [CLL §3, §3.3] | REQUIRED, exactly one |
| `cll-inclusion-proof` | the MMR `inclusion-proof` array `[index, inclusion-path]` in deterministic CBOR (RFC 8949 §4.2.1): the octets that MMR's `bstr .cbor` wraps, not that byte string [MMR §4]. `index` is the zero-based MMR node index of the leaf. Each path element is a 32-octet byte string | REQUIRED, exactly one |
| `cll-consistency-proof` | the MMR `consistency-proof` array `[tree-size-1, tree-size-2, consistency-paths, right-peaks]` in deterministic CBOR, again the octets inside `bstr .cbor` [MMR §6]. It proves that the checkpoint's `commitment` extends its own `prev_commitment` [CLL §3, §3.2 item 2] | OPTIONAL, at most one |

**One form per checkpoint.** CLL lets a witness's countersignature ride in the checkpoint's
unprotected header [CLL §3.3 item 2], and COSE allows a tagged and an untagged form. Either would give
one signed checkpoint several digests. So the `cll-checkpoint` item MUST be the tagged form with an
empty unprotected header [P-31]. A responder holding a countersigned copy removes the
countersignature before sending it. Witness confirmations are not a kind in this revision (P-13).

**What the envelope's `verification` covers.** Each entry's `digest` is SHA-256 over that item's
octets as carried, as for every kind (§6.2). Through the `cll-checkpoint` entry, the envelope
signature covers the exact checkpoint, including its own signature. Under this mechanism
`anchor.digest` MUST equal the `digest` of the `cll-checkpoint` entry [P-31]. The coverage anchor
is that checkpoint, identified by SHA-256 over its octets in the form above. A requester pins a
CLL checkpoint in `expected_pin` by that same digest [ER §3.2; P-31]. The two proofs are bound
only as octets. They carry no signature of their own, and they count only once the procedure
below recomputes the signed commitment from them [MMR §5.1].

**The logged entry.** CLL entries are opaque byte strings, typically the digest of a record
[CLL §1.1]. MMR leaves are a hash H(x) of a value x that the caller defines [MMR §8.1]. Neither
draft fixes how an entry becomes a leaf, so this profile fixes it [P-31]:

- the entry E for an artifact is the 32 raw octets of `artifact_digest`;
- the leaf value is SHA-256(0x00 || E). So x is one zero octet followed by E, a 33-octet
  preimage, which never has the 72-octet shape of an interior node's preimage [MMR §8.2.1].

**Scope.** These kinds prove one artifact that is one log entry: the `record` subject, with no
`derivation`, whose record digest is the artifact's own digest (`subject.record` equal to
`artifact_digest`). ER lets a record be named by a digest that is not the SHA-256 of the octets
served [ER §3.1]. These kinds cannot tie such a name to the artifact, so they do not apply to it.
They also define no method for the other five subject forms, for a derivation (including a
recipient-specific projection, §6.5), or for the `checkpoints` subject and the derivation of
ER §8.1, whose artifact is itself the material (point 4 above) (P-13).

**What the relying party must trust.** The checkpoint is signed by the key its `kid` names, for the
log identity (`iss`, `sub`) in its CWT_Claims [CLL §3, §3.3]. Whether that key is the right one
for that log identity is the relying party's policy, as `responder_trust` is for the responder's
key. This profile does not decide it, and the log key need not be the responder's key.

- A `PASS` shows that the artifact's digest is committed under a checkpoint signed by a key the
  policy accepts for that log identity.
- It does not show which of the responder's streams was asked about, because the request names
  none (P-23). Under `expected_pin` the requester chose the checkpoint itself. Under
  `min_freshness` the responder chose it, so a relying party SHOULD accept a log key only for
  the log identities it expects that responder to answer from [P-31].
- It does not show that the checkpoint was witnessed. A witness Receipt or countersignature
  [CLL §3.3] is not a kind in this revision (P-13). An unwitnessed checkpoint is only as strong as
  its producer [CLL §3.2 item 4, §4].
- It never shows that the entry's content is true [CLL §5].

**Check procedure for `anchor_inclusion`.** Steps run in order, and the first that yields a status
decides. Each status means what §7.1 says. MMR's functions are used as MMR defines them [MMR §5.2,
§7.1, §7.1.1, §9]:

1. If `subject` is not the `record` form, or `derivation` is present: `NOT_CHECKED`. No kind in
   this revision defines that method (P-13). For the `checkpoints` subject, point 4 above applies.
2. If `verification` is absent or empty: `NOT_PRESENT`.
3. If any entry's `kind` is not one of the three above: `NOT_CHECKED`, by the rule for
   unimplemented kinds (§6.2). If one kind appears more than once: `FAIL`. If there is no
   `cll-checkpoint` entry, or no `cll-inclusion-proof` entry: `NOT_PRESENT`.
4. If `envelope_signature`, `artifact_digest` or `verification_binding` is not `PASS`:
   `NOT_CHECKED`. Material that is not bound to a verified envelope is never checked.
5. If `subject.record` differs from `artifact_digest`: `NOT_CHECKED`. This is outside the scope
   above, not a failure of the artifact [P-31].
6. If the `cll-checkpoint` entry's `digest` differs from `anchor.digest`: `FAIL`.
7. Decode the checkpoint. Any of the following is `FAIL` [CLL §3, §3.1, §3.2 item 2, §3.3;
   P-12; P-31]:
   - it is not well formed: not tag 18 over a four-element array, a non-empty unprotected header,
     a detached (`nil`) payload, or a map with a duplicate key;
   - the protected header lacks `alg`, lacks `kid`, or lacks CWT_Claims with `iss` and `sub`;
   - the `kind` claim is not `cll-checkpoint`;
   - `log_size` or `prev_size` is not an unsigned integer, `prev_size` exceeds `log_size`, or
     `issued_at` is not an RFC 3339 text string;
   - `commitment` is not a byte string holding the deterministic CBOR of an array of one or more
     32-octet byte strings;
   - `prev_size` is 0 and `prev_commitment` is not zero-length, or `prev_size` is above 0 and
     `prev_commitment` is not of the same form as `commitment`.
8. If `alg` is not EdDSA (-8), or the protected header carries `crit`: `NOT_CHECKED`. This
   revision checks Ed25519 checkpoint signatures with no critical extensions only (P-31).
9. The relying party's policy resolves (`iss`, `sub`, `kid`) to an Ed25519 public key it accepts
   for that log identity as of the checkpoint's `issued_at`. If the policy rejects the key:
   `FAIL`. If it cannot resolve the key's status: `INCONCLUSIVE`. If it excludes the check:
   `NOT_CHECKED`.
10. Verify the COSE_Sign1 signature under that key. Its input is the `Signature1` Sig_structure
    with an empty external AAD (RFC 9052 §4.4). If it does not verify: `FAIL`.
11. If `anchor.freshness` is present, it must name what the checkpoint commits. A size must equal
    the checkpoint's `log_size`. A time must equal the checkpoint's `issued_at` converted to UTC
    with any fractional seconds dropped (§5.2). Otherwise: `FAIL` [ER §4.1 item 2; P-31].
12. Inclusion. Decode the inclusion proof; if it is malformed, `FAIL`. If `index_height(index)` is
    not 0, so that `index` is not a leaf: `FAIL`. Compute
    `r = included_root(index, SHA-256(0x00 || E), inclusion-path)`. If `r` is not one of the peaks
    in `commitment`: `FAIL` [MMR §5.2; P-31].
13. Consistency, only when a `cll-consistency-proof` entry is present. Any of the following is
    `FAIL` [MMR §7.1, §7.1.1; CLL §3.2 item 2]:
    - the proof is malformed, or `tree-size-1` exceeds `tree-size-2`;
    - `prev_size` is 0, so there is no earlier commitment to extend;
    - the number of peaks for `tree-size-1`, the number of `consistency-paths` and the number of
      peaks in `prev_commitment` are not all equal;
    - after `consistent_roots(tree-size-1 − 1, <peaks of prev_commitment>, consistency-paths)`,
      the number of `right-peaks` is not the number of peaks for `tree-size-2` minus the number
      of roots;
    - those roots followed by `right-peaks` are not the peak list of `commitment`, element for
      element.
14. Otherwise: `PASS`. `method` names the pinned drafts and the checks run, for example
    `CLL-01 checkpoint (Ed25519) + MMR-02 inclusion + MMR-02 consistency`.

**Notes on the procedure.**

- A consistency proof that verifies shows only the producer's internal relation: the
  checkpoint's history extends the history its own `prev_commitment` commits to. It does not show
  that no divergent history exists [CLL §3.2 item 2], and a responder may omit it. Its value is to
  a requester holding the predecessor checkpoint, which can compare that checkpoint's
  `commitment` with `prev_commitment`. A failed proof is a `FAIL`, because the producer has
  signed a relation its own log contradicts, which CLL treats as evidence of mutation
  [CLL §3.2 item 2]. A proof from some other earlier anchor the requester holds (ER §5) is not
  expressible in v0, because the request has no member naming that anchor (P-13).
- The procedure shows membership, not position. It does not compare the proofs' tree sizes with
  `log_size` and `prev_size`. MMR counts tree size in nodes [MMR §6, §7.1], and CLL -01 describes
  `log_size` as a number of entries [CLL §3]. When the inclusion path is not empty, a recomputed
  root equal to a committed peak also fixes the leaf's node position, because every interior
  node's hash covers its position [MMR §8.2]. When the path is empty, so the leaf is itself a
  peak, `index` is not verified (P-31).
- MMR's misprinted `all_ones` primitive (Appendix B.4) is read as intended: `pos` has all bits set
  below its most significant bit, that is `pos & (pos + 1) == 0` (P-31).

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
| `anchor_inclusion` | envelope | the artifact verifies against `anchor.digest` using `verification_content`, by the method each `kind` names [ER §4.1 item 3]; for the `cll-*` kinds, the procedure of §6.2.1 [P-31]; for the `checkpoints` subject and the derivation of ER §8.1, the `artifact` is itself the material [ER §4.1] | yes |
| `caller_invariance` | two or more envelopes | for envelopes with the same `responder`, `subject`, `derivation` and `anchor.digest`, each of which has passed `envelope_signature`, `responder_trust` and `artifact_digest`: identical `artifact_digest` [ER §5]. `NOT_CHECKED` with fewer than two such envelopes [P-17] | a `FAIL` is adverse (§8) |
| `reason_registered` | refusal | `reason` is exactly one token of §9.1, exact case [ERV A13] | yes |
| `issued_at_form` | envelope, refusal | present and of the §5.2 time form. ER requires it on a refusal [ER §4.2 item 3]; for the envelope and for the form, see [ERV A5; P-12] | yes |
| `native_check` | each foreign object in a verified Artifact | the object's own verification method over its as-transmitted octets (§5.1); `method` names that method | per requirement (§8) |
| acceptance properties | acceptance records and receipts | §11.1.7 | decide the acceptance finding (§11.1.8), never a status of §8 |

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
- `proofs[]` [RES §5] lists those `verification` entries actually used whose shape RES can name,
  each by its `digest` with `digest_alg` `SHA-256`. RES §5 closes `proof-ref.kind` to
  `inclusion_proof` and `receipt`. A `cll-inclusion-proof` entry is listed with `kind`
  `inclusion_proof` [RES §5; P-31]. A `cll-checkpoint` or `cll-consistency-proof` entry is
  neither shape, so it is not listed. So in v0 the claim does not name the checkpoint, or the
  envelope, that the inclusion proof resolves against: `evidence[]` names only the artifact
  digest, which can appear under many anchors. The listed inclusion proof is checkable only by a
  party that also holds the envelope (P-13).
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
and anchor A is a label digest, not a real checkpoint. So for envelopes A and B
`anchor_inclusion` is `NOT_PRESENT`, which maps to `INSUFFICIENT` (§8.1 row 3). Their record digest
R1 is not the artifact's digest, so even with material the kinds of §6.2.1 would report
`NOT_CHECKED` for them (§6.2.1, scope). §10.1 asks for the same artifact by its own digest and
reaches `PASS` with real verification material.

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

### 10.1 PASS path with Checkpointed Local Log material

This example serves the artifact above from a real seven-entry log, with the material of §6.2.1.
Every value is reproducible. The log key is derived from the seed
`SHA-256("evidence-interop/0 worked example: CLL log key")`. Entry E<sub>k</sub>, for k from 0 to 6,
is `SHA-256("evidence-interop/0 worked example: log entry k")`, except that E<sub>2</sub> is the
artifact digest. Each leaf value is SHA-256(0x00 || E<sub>k</sub>), and interior nodes follow MMR
§8.2.1.

```
log key seed     996d8b3da69fec3bb7d43956f2ea30228ce427628e17f90f75b8c31dc2670f6f
log key (kid)    c82acf66ef2bdc106017544b91873dfbdc92f0963b099d49b0f621bedf76e2af
entry E2         2fbdb95bdeba62f949bcb6026061fcd66c021523a39e58fc2de1cd44ff631244
node 0   9dd6fa16eda8001ef682c41b1a85486abbfa7d3c6671f0e1b67188ac711c5c13
node 1   c350182577d6c73e06e21cd8b495cd64b2ff6c065b5248e7eb58f8c61671f466
node 2   17752cda0f5ae552687612bfe2edb35ce414b769d27de369b3860e04475c2e1f
node 3   614c868161c3d559bf541d1966141ea1b7269da3c4215504eda9fd4882263f8d
node 4   4533a265601326452641c2c27001175afc7c240733ffa9f4ed7a8fb535233d75
node 5   5fd6bcdffa11db57a68be512c36d09ce0abd0044845724b6379d1c77e1af8edc
node 6   361efe575f427af6b6cee7de0f21a4c5ac4bb768741ba10495ca03023d854a22
node 7   b3d51096fbe67bc5e7c8da6703552171684e4427ff2db63628019665a2e8a81a
node 8   a85021d96677a01944104a0b618836427db205a81734bd2d04c3d88f18402c9b
node 9   00606ac0b2fbff9aea2afaee91782d5fdf59b23c6c1dc80faf18528094c8a5d3
node 10  41c3925fe360c20b027ba9429cd61455902efb32b1096e3d412d1eeb42184d3f
```

The leaves are nodes 0, 1, 3, 4, 7, 8 and 10, and E<sub>2</sub>'s leaf is node 3. After three entries
the MMR has 4 nodes and peaks at nodes 2 and 3. After seven it has 11 nodes and peaks at nodes 6, 9
and 10.

**The checkpoint.** It is a COSE_Sign1 with CBOR tag 18 and an EdDSA signature under the log key.
The protected header is `{1: -8, 4: <log key>, 15: {1: "https://producer.example", 2:
"evidence-stream-1"}}`, and the unprotected header is empty. The payload claims are `kind`
`"cll-checkpoint"`, `log_size` 7, `prev_size` 3, `issued_at` `"2026-10-12T00:00:00Z"`, `cadence`
3600, `commitment` = the deterministic CBOR of `[node 6, node 9, node 10]`, and `prev_commitment`
= the deterministic CBOR of `[node 2, node 3]`. `log_size` and `prev_size` count entries, as CLL -01
describes them (P-31). The checkpoint octets, in hex:

```
d2845856a30127045820c82acf66ef2bdc106017544b91873dfbdc92f0963b099d49b0f621bedf76e2af0fa201781868747470733a2f2f70726f64756365722e6578616d706c65027165766964656e63652d73747265616d2d31a059011fa7646b696e646e636c6c2d636865636b706f696e7467636164656e6365190e10686c6f675f73697a6507696973737565645f617474323032362d31302d31325430303a30303a30305a69707265765f73697a65036a636f6d6d69746d656e745867835820361efe575f427af6b6cee7de0f21a4c5ac4bb768741ba10495ca03023d854a22582000606ac0b2fbff9aea2afaee91782d5fdf59b23c6c1dc80faf18528094c8a5d3582041c3925fe360c20b027ba9429cd61455902efb32b1096e3d412d1eeb42184d3f6f707265765f636f6d6d69746d656e74584582582017752cda0f5ae552687612bfe2edb35ce414b769d27de369b3860e04475c2e1f5820614c868161c3d559bf541d1966141ea1b7269da3c4215504eda9fd4882263f8d5840ef5f2f56ba5f5ed2c497274bcc942d8193a7d318d11989de3b409009fa895e739e8fa08adb12406de5f2b6be2e77e9f33988fb19c7cdf57344083306fc8eb30b
```

Their SHA-256, the anchor digest A<sub>C</sub>, is `16f15dd5475d5e8ec1fb7a84470391e11d7663232365c1749c60ca7489cffe99`.

**The inclusion proof** is `[3, [node 4, node 2]]`, in hex:

```
82038258204533a265601326452641c2c27001175afc7c240733ffa9f4ed7a8fb535233d75582017752cda0f5ae552687612bfe2edb35ce414b769d27de369b3860e04475c2e1f
```

`included_root(3, leaf of E2, [node 4, node 2])` gives node 6, the first peak in `commitment`.

**The consistency proof** is `[4, 11, [[node 5], [node 4, node 2]], [node 9, node 10]]`, in hex:

```
84040b828158205fd6bcdffa11db57a68be512c36d09ce0abd0044845724b6379d1c77e1af8edc8258204533a265601326452641c2c27001175afc7c240733ffa9f4ed7a8fb535233d75582017752cda0f5ae552687612bfe2edb35ce414b769d27de369b3860e04475c2e1f82582000606ac0b2fbff9aea2afaee91782d5fdf59b23c6c1dc80faf18528094c8a5d3582041c3925fe360c20b027ba9429cd61455902efb32b1096e3d412d1eeb42184d3f
```

Both old peaks, nodes 2 and 3, lead to node 6. Node 6 followed by the right-peaks, nodes 9 and 10,
is exactly the peak list of `commitment`.

**Request C, JSON binding.** It pins the checkpoint and names the artifact's record digest:

```
{"coverage":{"expected_pin":"16f15dd5475d5e8ec1fb7a84470391e11d7663232365c1749c60ca7489cffe99"},"nonce":"2026-10-12T00:00:10Z/c","profile":"evidence-interop/0","subject":{"record":"2fbdb95bdeba62f949bcb6026061fcd66c021523a39e58fc2de1cd44ff631244"}}
```

request digest `3e68348cdf52d26447fff2ff47ec16b9539a93cee72497bf50a99f3d39c158cd`

**Envelope for request C.** Signing input:

```
{"anchor":{"digest":"16f15dd5475d5e8ec1fb7a84470391e11d7663232365c1749c60ca7489cffe99"},"artifact_digest":"2fbdb95bdeba62f949bcb6026061fcd66c021523a39e58fc2de1cd44ff631244","issued_at":"2026-10-12T00:00:11Z","profile":"evidence-interop/0","request_digest":"3e68348cdf52d26447fff2ff47ec16b9539a93cee72497bf50a99f3d39c158cd","responder":"e84fed8190a6116016bf68ef2fc1780a919e9ed2d9f88efb895a954ffd7f0117","subject":{"record":"2fbdb95bdeba62f949bcb6026061fcd66c021523a39e58fc2de1cd44ff631244"},"verification":[{"digest":"16f15dd5475d5e8ec1fb7a84470391e11d7663232365c1749c60ca7489cffe99","kind":"cll-checkpoint"},{"digest":"013ac5a3bdff9cf62a3ea2816b3cd197151930f6dd49d67d9286f12c3c47527a","kind":"cll-inclusion-proof"},{"digest":"06550cca75319242ea40e7f3fd9ff0b8e5e3bfa8a06122f678578a57cb4bdc71","kind":"cll-consistency-proof"}]}
```

`sig` = `d98fcb97d551c5accc5094baf58d8d6446d21b74228602a88392dcf1719cc9b9ab87f15e6f80792e1199e564a4f263dc35b2e8d015e65046bf2d095ec820800b`

The complete response object for request C, in the JSON binding:

```json
{
 "anchor": {
  "digest": "16f15dd5475d5e8ec1fb7a84470391e11d7663232365c1749c60ca7489cffe99"
 },
 "artifact": "eyJleGFtcGxlIjoiZXZpZGVuY2UgcmVjb3JkIiwic2VxIjoxfQ",
 "artifact_digest": "2fbdb95bdeba62f949bcb6026061fcd66c021523a39e58fc2de1cd44ff631244",
 "issued_at": "2026-10-12T00:00:11Z",
 "profile": "evidence-interop/0",
 "request_digest": "3e68348cdf52d26447fff2ff47ec16b9539a93cee72497bf50a99f3d39c158cd",
 "responder": "e84fed8190a6116016bf68ef2fc1780a919e9ed2d9f88efb895a954ffd7f0117",
 "sig": "d98fcb97d551c5accc5094baf58d8d6446d21b74228602a88392dcf1719cc9b9ab87f15e6f80792e1199e564a4f263dc35b2e8d015e65046bf2d095ec820800b",
 "subject": {
  "record": "2fbdb95bdeba62f949bcb6026061fcd66c021523a39e58fc2de1cd44ff631244"
 },
 "verification": [
  {
   "digest": "16f15dd5475d5e8ec1fb7a84470391e11d7663232365c1749c60ca7489cffe99",
   "kind": "cll-checkpoint"
  },
  {
   "digest": "013ac5a3bdff9cf62a3ea2816b3cd197151930f6dd49d67d9286f12c3c47527a",
   "kind": "cll-inclusion-proof"
  },
  {
   "digest": "06550cca75319242ea40e7f3fd9ff0b8e5e3bfa8a06122f678578a57cb4bdc71",
   "kind": "cll-consistency-proof"
  }
 ],
 "verification_content": [
  "0oRYVqMBJwRYIMgqz2bvK9wQYBdUS5GHPfvckvCWOwmdSbD2Ib7fduKvD6IBeBhodHRwczovL3Byb2R1Y2VyLmV4YW1wbGUCcWV2aWRlbmNlLXN0cmVhbS0xoFkBH6dka2luZG5jbGwtY2hlY2twb2ludGdjYWRlbmNlGQ4QaGxvZ19zaXplB2lpc3N1ZWRfYXR0MjAyNi0xMC0xMlQwMDowMDowMFppcHJldl9zaXplA2pjb21taXRtZW50WGeDWCA2Hv5XX0J69rbO594PIaTFrEu3aHQboQSVygMCPYVKIlggAGBqwLL7_5rqKvrukXgtX99ZsjxsHcgPrxhSgJTIpdNYIEHDkl_jYMILAnupQpzWFFWQLvsysQluPUEtHutCGE0_b3ByZXZfY29tbWl0bWVudFhFglggF3Us2g9a5VJodhK_4u2zXOQUt2nSfeNps4YOBEdcLh9YIGFMhoFhw9VZv1QdGWYUHqG3Jp2jxCFVBO2p_UiCJj-NWEDvXy9Wul9e0sSXJ0vMlC2Bk6fTGNEZid47QJAJ-olec56PoIrbEkBt5fK2vi536fM5iPsZx831c0QIMwb8jrML",
  "ggOCWCBFM6JlYBMmRSZBwsJwARda_HwkBzP_qfTteo-1NSM9dVggF3Us2g9a5VJodhK_4u2zXOQUt2nSfeNps4YOBEdcLh8",
  "hAQLgoFYIF_WvN_6EdtXpovlEsNtCc4KvQBEhFcktjedHHfhr47cglggRTOiZWATJkUmQcLCcAEXWvx8JAcz_6n07XqPtTUjPXVYIBd1LNoPWuVSaHYSv-Lts1zkFLdp0n3jabOGDgRHXC4fglggAGBqwLL7_5rqKvrukXgtX99ZsjxsHcgPrxhSgJTIpdNYIEHDkl_jYMILAnupQpzWFFWQLvsysQluPUEtHutCGE0_"
 ]
}
```

**Verification.** The verifier holds request C's octets. Its policy accepts the responder key, and
accepts the log key for (`https://producer.example`, `evidence-stream-1`). It runs offline.

| Property | Status | How |
|---|---|---|
| `profile_version` | `PASS` | `evidence-interop/0`, as sent |
| `envelope_signature` | `PASS` | Ed25519 over the signing input above |
| `responder_trust` | `PASS` | the policy accepts the responder key |
| `issued_at_form` | `PASS` | `2026-10-12T00:00:11Z` |
| `request_binding` | `PASS` | SHA-256 of request C's octets |
| `subject_binding` | `PASS` | the same `record` digest, and no derivation |
| `artifact_digest` | `PASS` | SHA-256 of the decoded `artifact` |
| `verification_binding` | `PASS` | three items, three matching digests, in order |
| `anchor_match` | `PASS` | `anchor.digest` equals the pin A<sub>C</sub> |
| `anchor_inclusion` | `PASS` | §6.2.1 steps 1 to 14: the checkpoint digest is A<sub>C</sub>, the signature verifies under the log key, E<sub>2</sub> is the artifact digest and the record digest, inclusion reaches node 6, and consistency reproduces the commitment |
| `caller_invariance` | `NOT_CHECKED` | only one envelope for anchor A<sub>C</sub> is held; not required (§7.2) |
| `responder_key_current` | `NOT_CHECKED` | offline; not required (§7.2) |

Every required envelope property is `PASS`, so §8.1 row 7 applies, and the contract evaluates the
Artifact's content. The claim's `evidence[]` cites the artifact digest. Its `proofs[]` is
`[{"kind": "inclusion_proof", "digest_alg": "SHA-256", "digest": "013ac5a3bdff9cf62a3ea2816b3cd197151930f6dd49d67d9286f12c3c47527a"}]`
(§8.3).

Changing any octet of the inclusion proof makes `verification_binding` `FAIL`. Re-signing the
envelope over the changed digest instead makes `anchor_inclusion` `FAIL` at step 12.

## 11. Parts filled by later revisions

§11.1 is specified. The headings from §11.2 on are placeholders, and nothing under them is
specified yet. §11.1 was filled before `evidence-interop/0` was published. It adds objects and
properties, and adds rows to the tables of §4 and §7.2. It changes no existing signing input or
byte rule, so it keeps the identifier (§3.1).

### 11.1 Acceptance record

An acceptance record is the signed answer of one party to an Evidence Contract version that the
other party proposed. Without an accepted record, a contract's requirements are only what the
requester expects. With one, they are also what the other party agreed to. This section defines
one record type with four states and an optional session scope, the receipt the proposer signs
for an answer, the evidence that can establish that an acceptance came before the action, and
what a verifier reports.

**Three things kept distinct.** This profile never treats any one of them as another:

1. an **acceptance**: the performing party's signed agreement to one contract version, for one
   transaction or one session (§11.1.1 to §11.1.3);
2. an **acknowledgment**: a signed record that a party received something. It records receipt
   and asserts no agreement with what was received [BA §3]. The acceptance receipt of §11.1.4 is
   one (§11.1.6);
3. **authority**: whether the party that accepted may spend for, bind or act for a principal.
   Acceptance never shows it (§11.1.6).

#### 11.1.1 Roles and states

The **proposer** is the requesting party, and is the requester whose expectations a contract's
requirements are until they are accepted. The **acceptor** is the performing party. Both roles
are those BA defines [BA §3]. BA identifies a party by an organizational identity. This profile
identifies each by a key identifier (§5.2), and the relying party's trust policy decides which
party a key belongs to [P-24].

| `state` | Signed by | Meaning |
|---|---|---|
| `proposed` | the proposer | offers contract version `contract_digest` for transaction `transaction` |
| `accepted` | the acceptor | agrees to that contract version for that transaction, answering one `proposed` record |
| `declined` | the acceptor | refuses it, answering one `proposed` record |
| `countered` | the acceptor | refuses it and names a different contract version it would accept, answering one `proposed` record |

Rules:

- The signer of a record is fixed by its `state`: the proposer for `proposed`, and the acceptor
  for the other three [P-24]. So an `accepted` record is always the acceptor's act.
- A counteroffer is a new contract version with its own digest, never an edit of the proposed
  one [P-24]. A `countered` record accepts nothing. For the counter version to be accepted, the
  proposer issues a new `proposed` record naming it, and the acceptor answers that record [P-24].
- An acceptor MUST NOT sign more than one answer to the same `proposed` record [P-24]. A verifier
  that holds two verified answers to one proposal, with different record digests, reports
  `acceptance_unique` as `FAIL` (§11.1.7).
- An acceptor MUST sign an `accepted` record before it takes the action the transaction names
  [P-24]. The record's own `issued_at` does not show that it did (§11.1.5).

#### 11.1.2 The record

| Member | Signed | Presence | Value |
|---|---|---|---|
| `profile` | yes | REQUIRED | the profile identifier, `evidence-interop/0` |
| `state` | yes | REQUIRED | exactly one of `proposed`, `accepted`, `declined`, `countered`, exact case |
| `contract_ref` | yes | REQUIRED | the contract version as `<contract_id>@<version>` [RES §1] |
| `contract_digest` | yes | REQUIRED | SHA-256 over UTF-8 of JCS of the contract version document, as for any JSON value (§5.1) [DE §2] |
| `transaction` | yes | REQUIRED | `{"scheme": <text>, "id": <text>}`: the exchange, or under `session` the session, this record is about |
| `proposer` | yes | REQUIRED | the proposer's key identifier |
| `acceptor` | yes | REQUIRED | the acceptor's key identifier |
| `proposal_digest` | yes, when present | REQUIRED in `accepted`, `declined` and `countered`; absent in `proposed` | the record digest of the `proposed` record answered |
| `counter_contract_digest` | yes, when present | REQUIRED in `countered`; absent otherwise | the digest, computed as for `contract_digest`, of the counter version |
| `session` | yes, when present | OPTIONAL | the session scope (§11.1.3) |
| `authority` | yes, when present | OPTIONAL | an array of digests, each over the as-transmitted octets (§5.1) of one principal authorization the signer cites (§11.1.6) |
| `issued_at` | yes | REQUIRED | the time the signer claims it signed the record |
| `sig` | — | REQUIRED | Ed25519 by the key the `state` names (§11.1.1) over the signing input |

Rules [P-25]:

- The **signing input** is UTF-8 of JCS over the object made of every member present except
  `sig` (§5.1).
- The **record digest** is SHA-256 over UTF-8 of JCS of the whole record, `sig` included, as for
  the absence record (§5.1). Every other object cites a record by this digest.
- `transaction.scheme` is a text string naming the kind of reference, for example a task
  identifier of an agent-to-agent protocol, a checkout or payment-authorization identifier, a
  payment resource, or a native exchange identifier. This revision registers no schemes. Two
  transaction references are equal only when both members are equal as exact strings.
- An answer MUST carry the same `contract_ref`, `contract_digest`, `transaction`, `proposer`,
  `acceptor` and `session` values as the `proposed` record its `proposal_digest` names [P-25].
- `contract_ref` is readable, and `contract_digest` is what binds. A verifier MUST check
  `contract_digest` against the contract version it evaluates, and MUST also check that
  `contract_ref` names that same version [P-25].
- The record is a JSON object, or the same map in CBOR (§4). It is not a reply to an evidence
  request, and the message types of §1 do not apply to it.

#### 11.1.3 Session scope

One accepted record MAY cover a bounded session of exchanges, so that each exchange cites the
agreement instead of negotiating again [P-26]. `transaction` then names the session, and
`session` is:

| Member | Presence | Value |
|---|---|---|
| `not_before` | REQUIRED | a time |
| `not_after` | REQUIRED | a time, not earlier than `not_before` |
| `policy` | OPTIONAL | the digest of a policy document the parties agree for the session |
| `terms` | OPTIONAL | the digest of further terms, for example a permitted spend |

The digest of `policy` or `terms` is computed by §5.1: over UTF-8 of JCS for a JSON document,
and over the octets as transmitted for any other document.

Rules [P-26]:

- The requirements of the session are the contract version's requirements. The session adds a
  time window, not requirements.
- Each exchange in a session is evaluated on its own, and gets its own finding (§11.1.8).
- An exchange is covered by a session acceptance only when its execution records cite the
  acceptance's record digest, and every time the verifier holds for the exchange lies within
  `not_before` and `not_after`, both inclusive [P-26].
- This profile does not interpret `policy` or `terms`. Neither is authority (§11.1.6).

#### 11.1.4 Acceptance receipt

The proposer MAY sign a receipt for an answer it received [P-27]. Every member is REQUIRED [P-27]:

| Member | Signed | Value |
|---|---|---|
| `profile` | yes | the profile identifier |
| `acceptance_digest` | yes | the record digest of the answer received |
| `received_at` | yes | the time the proposer received it |
| `receiver` | yes | the proposer's key identifier |
| `sig` | — | Ed25519 by `receiver` over UTF-8 of JCS of the other four members |

Its digest is SHA-256 over UTF-8 of JCS of the whole receipt, `sig` included. The receipt is an
acknowledgment: it records receipt only, and asserts no agreement with what was received
[BA §3; P-27]. Its only use under this profile is as ordering evidence (§11.1.5).

#### 11.1.5 Ordering evidence

A signature over a claimed time proves only that the signer asserted that time. An acceptance
written after the action can carry any earlier `issued_at`. So a verifier grants that an
acceptance came before the action only from evidence produced by a party other than the
acceptor [P-28].

Two points are compared:

- The **action reference point** is the earliest time the verifier holds for the action. That
  is the time the acceptor's own records claim for it, and every time at which a party other
  than the acceptor attests that the action or its record existed. An example of the second is a
  log checkpoint that covers the action's record, signed by an operator or witness other than
  the acceptor. Each of these shows only that the action had happened by then, so the earliest
  is used [P-28]. A relying party's trust policy MAY require that the action reference point
  include a time attested by a party other than the acceptor [P-28].
- The **ordering point** of one piece of ordering evidence is a time by which the accepted record
  existed. A party other than the acceptor asserts that time and signs it [P-28].

So "accepted before action" means that the acceptance existed before the earliest time the held
evidence gives for the action. §11.1.10 states what that leaves open.

| Form | Status | Ordering point |
|---|---|---|
| (i) Counterparty-signed acceptance receipt (§11.1.4) | **normative** | `received_at` |
| (ii) Transparency-service or witness receipt: a proof that the accepted record's digest is included in a log. It comes with a time that the transparency service, or a witness [EL §3], itself asserts and signs as the time it registered or observed that inclusion | **normative** | that signed time |
| Causal binding: execution records that commit to the acceptance's record digest and sit at a later position of an append-only log | **informative** | none |

Rules [P-28]:

- A form (i) receipt counts only when all of the following hold [P-28]:
  - `receipt_signature` and `receipt_signer` pass;
  - `acceptance_digest` equals the record digest of the accepted record being evaluated.
- A form (ii) object counts only when its inclusion proof verifies and the time's signer is
  neither the acceptor nor a key the acceptor controls, as the relying party's trust policy
  decides [P-28].
  - A receipt proves inclusion and nothing else [EL §3], so a receipt alone gives no ordering
    point.
  - A witness's countersignature over a checkpoint does not adopt any time the checkpoint's
    operator wrote. Only a time the witness itself signs is an ordering point [P-28].
  - This revision names no log or receipt mechanism (P-13). A verifier that does not implement
    the mechanism of a form (ii) object reports it as `NOT_CHECKED`.
- Before comparison, a time given at finer than seconds precision is reduced to the §5.2 form.
  An ordering point is rounded up and an action time is rounded down [P-28].
- An ordering point establishes the order only when it is strictly earlier than the action
  reference point, with no clock-skew allowance [P-28].
- Causal binding shows that the execution records were written after the acceptance existed. It
  does not show that the action was taken after, and the acceptor can write both the acceptance
  and those records. A verifier MAY report it in `detail`, and MUST NOT report
  `acceptance_ordering` as `PASS` on the strength of it [P-28].
- No other object is ordering evidence in this revision. A counterparty-signed object that cites
  the acceptance's digest for another purpose, such as a request for the action, never counts.
  Only the §11.1.4 receipt does [P-28].

**`acceptance_ordering` status.** The first rule that applies decides [P-28]:

1. `NOT_PRESENT`: the verifier holds no time for the action.
2. `FAIL`: the record's own `issued_at` is not earlier than some time the verifier holds for the
   action, including the acceptor's own claim. The acceptor's own record then states that it
   accepted at or after the action. This test is applied even when the trust policy requires a
   time from another party.
3. `NOT_PRESENT`: the trust policy requires a time for the action from a party other than the
   acceptor, and none is held.
4. `PASS`: at least one form (i) or form (ii) object counts, and its ordering point is earlier
   than the action reference point.
5. `INCONCLUSIVE`: at least one form (i) or form (ii) object counts, and none of their ordering
   points is earlier than the action reference point; or the trust policy could not resolve a
   form (i) or form (ii) signer. A receipt received after the action does not show that the
   acceptance was made after it.
6. `NOT_CHECKED`: the only ordering evidence held is form (ii) objects whose mechanism the
   verifier does not implement.
7. `NOT_PRESENT`: no form (i) or form (ii) object counts. Objects that fail the conditions above
   count as not held.

#### 11.1.6 An acknowledgment is a receipt; acceptance is not authority

- An acknowledgment records receipt only [BA §3]. So does an `acknowledges` link [EL §5] and an
  acceptance receipt (§11.1.4). A verifier MUST NOT treat any of them as an acceptance, and MUST
  NOT reach any finding other than `not_accepted` (§11.1.8) from them alone [P-29]. A BA action
  attestation records how a request was handled [BA §3]. It is not an acceptance either.
- An accepted record shows that the acceptor agreed to produce the evidence the contract version
  names. It does not show that the acceptor may spend for, bind, or act for any principal [P-29].
- A record **asserts authority** when it carries `authority`. A presentation asserts authority
  when it states that the acceptor may spend for, bind or act for a principal [P-29].
- A cited authorization supports the assertion only when two things hold [P-29]:
  - it passes `native_check` (§7.2) over its as-transmitted octets [P-11];
  - read by its own format, it names the acceptor's key, or a party the trust policy maps that
    key to, and covers the transaction.

  This profile does not define how a foreign format names a party or a scope. `method` names the
  reading used.
- Where no cited authorization supports it, the verifier MUST label the authority asserted, by
  the record or by a presentation of it, with the token `agent_origin_assertion` [P-29]. The
  verifier puts the token in the `detail` of the record's `acceptance_binding` report, and a
  presentation shows it next to the assertion.
- `policy`, `terms` and every other member of a record are agreement, never authority [P-29].

#### 11.1.7 Verification properties

These properties join the catalogue of §7.2 and use the vocabulary of §7.1 [P-30]. "Trust as of
evaluation" means the relying party's trust policy at the evaluation time. A policy MAY still
accept a key retired since, for a record whose `acceptance_ordering` passed with an ordering point
before the retirement [P-30]. "Accepts a key as the proposer" means three things. The policy
trusts the key, maps it to a party, and that party is not the one it maps the `acceptor` key to
[P-30]. "As the acceptor" is the same with the roles exchanged.

| Property | Applies to | Check | Decides the finding (§11.1.8) |
|---|---|---|---|
| `acceptance_form` | acceptance record | `profile` is `evidence-interop/0`; `state` is one of the four tokens in exact case; members are present or absent as §11.1.2 requires for that state; every time has the §5.2 form; under `session`, `not_after` is not earlier than `not_before` | yes |
| `acceptance_signature` | acceptance record | `sig` verifies over the §11.1.2 signing input under the key the `state` names | yes |
| `acceptance_signer_trust` | acceptance record | trust as of evaluation accepts the signing key as the proposer (for `proposed`) or as the acceptor (otherwise) | yes |
| `acceptance_binding` | acceptance record | `contract_digest` equals the digest of the contract version evaluated, and `contract_ref` names that version | yes |
| `proposal_binding` | answer and its `proposed` record | `proposal_digest` names a held `proposed` record; that record's `acceptance_signature` passes and trust as of evaluation accepts its signer as the proposer; the §11.1.2 equality rule holds. `NOT_PRESENT` when that record is not held | yes |
| `acceptance_unique` | two or more answers | among answers with the same `proposal_digest` and `acceptor`, each with `acceptance_signature` and `acceptance_signer_trust` passed: one record digest. `NOT_CHECKED` with fewer than two | a `FAIL` is adverse |
| `execution_cites_acceptance` | the execution records a requirement depends on | each is attributed to the `acceptor` key by its own signature, or by the trust policy; each commits to the accepted record's digest, by the citation its own format provides, for example a `cites` link [EL §5]; without `session` it names the record's `transaction`, and under `session` it lies within the window (§11.1.3). `method` names the citation. `NOT_PRESENT` when no execution record is held | yes |
| `acceptance_ordering` | accepted record | §11.1.5 | yes |
| `receipt_signature` | acceptance receipt | `sig` verifies under `receiver` over the §11.1.4 signing input | for form (i) |
| `receipt_signer` | acceptance receipt | `receiver` equals the record's `proposer` and differs from its `acceptor`, and trust as of evaluation accepts it as the proposer | for form (i) |

When a record or receipt names a `profile` the verifier does not implement, every property of that
object is `NOT_CHECKED`. This applies the envelope rule of §3.3 step 5 to these objects [P-30].

#### 11.1.8 Acceptance findings

A verifier reports one acceptance finding per contract version and transaction. Under `session`,
it reports one per exchange (§11.1.3). The candidates are the held `accepted` records whose
`contract_digest` is that version's digest, and whose `proposer` and `acceptor` are the
requester's and the performing party's keys for the transaction or exchange evaluated [P-30]:

- A transaction's candidates carry no `session`, and their `transaction` equals it.
- An exchange's candidates carry `session`, their `transaction` equals the session the exchange
  belongs to, and their window covers the exchange.

The verifier evaluates each candidate by the table below, where the first row that applies
decides [P-30]:

- If any candidate is `not_accepted` because `acceptance_unique` is `FAIL`, the finding is
  `not_accepted`. An acceptor that equivocates on one proposal is not credited with another.
- Otherwise, if any candidate is `accepted_after_action`, the finding is `accepted_after_action`.
- Otherwise the verifier reports the strongest result, in the order `accepted_before_action`,
  `accepted_execution_cites`, `accepted_not_cited`, `not_accepted`.

The property reports of every candidate are reported with the finding. A `declined` or
`countered` answer to a different proposal does not change the result for a candidate.

| Finding | When |
|---|---|
| `not_accepted` | there is no candidate; or `acceptance_form`, `acceptance_signature`, `acceptance_signer_trust`, `acceptance_binding` or `proposal_binding` is not `PASS`; or `acceptance_unique` is `FAIL` |
| `accepted_after_action` | `acceptance_ordering` is `FAIL` |
| `accepted_not_cited` | `execution_cites_acceptance` is not `PASS` |
| `accepted_before_action` | `acceptance_ordering` is `PASS` |
| `accepted_execution_cites` | otherwise: the acceptance exists and execution cites it, and the order is not established |

How a finding is used [P-30]:

- With `not_accepted`, the contract's requirements are the requester's own expectations. A
  verifier, and any presentation of its result, MUST present them as such, and MUST NOT present
  any of them as a commitment of the other party [P-30].
- With any other finding, the requirements MAY be presented as a commitment of the party the
  `acceptor` key belongs to, with the finding stated. A verifier or presentation MUST NOT state or
  imply that the acceptance came before the action unless the finding is `accepted_before_action`
  [P-30]. Even then, a presentation MUST say that the acceptance came before the earliest
  evidenced time of the action (§11.1.5), not before the action without qualification [P-30].
- A finding changes no requirement's status, sufficiency or verdict (§8). It says whom a
  requirement binds, not whether evidence meets it.
- Where the finding is not `not_accepted`, each claim's `contract_ref` MUST equal the accepted
  record's `contract_ref` [RES §1; P-30]. `acceptance_binding` makes this the same version §8.3
  names. The claim's `evidence[]` MUST list the accepted record's digest and the digest of each
  form (i) receipt relied on [RES §5; P-30]. A form (ii) receipt relied on is listed in
  `proofs[]` as kind `receipt` [RES §5; P-30]. Like every other mechanism, that receipt is outside
  v0 (P-13).

#### 11.1.9 The backdated acceptance, as a vector

§11.5 will hold the vectors, with their key seeds, contract bytes and execution-record format
fixed there. The case is fully expressible with the objects above. Its pinned inputs:

- trust roots: proposer key `P` and acceptor key `Q`, both trusted and mapped to two different
  parties, except in variant F; the trust policy does not require a time for the action from a
  party other than the acceptor;
- the contract version document and its digest `c`, under `contract_ref` `C@1`;
- one transaction reference `T`, and evaluation time `2026-10-12T01:00:00Z`;
- a `proposed` record by `P`, `issued_at` `2026-10-12T00:00:00Z`;
- one execution record signed by `Q`, naming `T`, claiming the action at `2026-10-12T00:10:00Z`,
  and citing the accepted record's digest, with no party other than `Q` attesting the action. The
  action reference point is therefore `2026-10-12T00:10:00Z`;
- an `accepted` record by `Q`, answering the proposal, written after the action but carrying
  `issued_at` `2026-10-12T00:05:00Z`. Variants A to C and E to G use these exact record bytes.
  Variant D replaces it: the 00:05 record is not held, and the execution record cites D's record.

| Variant | Ordering evidence held | `acceptance_ordering` | Finding |
|---|---|---|---|
| A. Backdated, no ordering evidence | none | `NOT_PRESENT` | `accepted_execution_cites` |
| B. Backdated, receipt signed by the acceptor | a receipt with `receiver` `Q` and `received_at` `2026-10-12T00:06:00Z` (`receipt_signature` `PASS`, `receipt_signer` `FAIL`) | `NOT_PRESENT` | `accepted_execution_cites` |
| C. Backdated, honest late receipt | a receipt by `P` with `received_at` `2026-10-12T00:20:00Z` (both receipt properties `PASS`) | `INCONCLUSIVE` | `accepted_execution_cites` |
| D. Self-admitted late acceptance | none; a different accepted record, whose `issued_at` is `2026-10-12T00:20:00Z` | `FAIL` | `accepted_after_action` |
| E. Control: the same record bytes, with the order shown | a receipt by `P` with `received_at` `2026-10-12T00:06:00Z` (both receipt properties `PASS`) | `PASS` | `accepted_before_action` |
| F. Backdated, receipt by a second key of the acceptor | a receipt with `receiver` `P` and `received_at` `2026-10-12T00:06:00Z`, where the trust policy maps `P` to the same party as `Q` (`receipt_signature` `PASS`, `receipt_signer` `FAIL`) | `NOT_PRESENT` | `not_accepted` |
| G. Limit: the action's time misstated late | as E, but the action truly took place at `2026-10-12T00:01:00Z` while the execution record claims `00:10:00Z` and no other party attests it | `PASS` | `accepted_before_action` |

In variant F the trust policy maps `P` to the same party as `Q`. Neither key is then accepted in
its role (§11.1.7), so `acceptance_signer_trust`, `proposal_binding` and `receipt_signer` are
`FAIL`, and the finding is `not_accepted`. In every other variant, `acceptance_form`,
`acceptance_signature`, `acceptance_signer_trust`, `acceptance_binding`, `proposal_binding` and
`execution_cites_acceptance` are `PASS`, and `acceptance_unique` is `NOT_CHECKED`.

Variant E differs from A only in the receipt. It shows what the ordering evidence adds: the bytes
of the accepted record cannot tell a backdated acceptance from an honest one. Variant G has the
same inputs as E, so it gets the same result. It records the limit of §11.1.10: the true action
time is not among the inputs. A policy requiring a time for the action from a party other than
the acceptor turns G into `NOT_PRESENT`. No variant except E and G may yield
`accepted_before_action`.

#### 11.1.10 Limits

- The order is shown only against the times the held evidence gives for the action. Each of those
  times is one by which the action had happened. None of them shows that it had not happened
  earlier. An action that took place before every time the evidence gives for it defeats the
  comparison. That happens when the acceptor's own record of the action carries a false later time,
  or when a third party logs or sees the action only late, and no party saw it earlier
  (variant G). No form of ordering evidence rules this out. A relying
  party that needs more requires evidence of the action from a party that observed it (§11.1.5).
- A trust policy that does not know a second key of the acceptor cannot tell it from the
  counterparty's. Form (i) is only as strong as the policy's mapping of keys to parties.
- A form (i) receipt is the counterparty's word. When proposer and acceptor act together, it
  shows a third party nothing. Form (ii) is then the only form independent of both, and the
  relying party's trust policy decides which signers count.
- A party able to sign freely can sign several answers in advance and show only the convenient
  one. Every answer must name a proposal signed by the proposer (`proposal_binding`), and the
  one-answer rule (§11.1.1) applies. Together they make two shown answers to one proposal
  detectable through `acceptance_unique`. A form (i) receipt also fixes which answer the proposer
  received.

### 11.2 Lifecycle links

*Placeholder.* Scope: issuer rules for corrections and challenges. `amends`, `disputes` and
`resolves` are new link tokens, proposed for `draft-mih-agent-evidence-layer` -01. `contradicts`
maps to the registered `rebuts`.

### 11.3 Evidence Contract prose

*Placeholder.* Scope: the normative prose for the Evidence Contract, kept as a section of this
profile.

### 11.4 Carriage and discovery

*Placeholder.* This covers the A2A and MCP bindings, the full manifest, verification-material
kinds beyond those of §6.2.1, and the shape of a carried retention commitment.

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

- **P-1** The profile identifier names one exact revision. Before first publication, filling a §11
  placeholder that only adds objects, rows and properties keeps it. Any byte-level change requires a new
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
- **P-13** Verification-material kinds cover only the Checkpointed Local Log, for a `record` subject
  with no derivation (§6.2.1). Still without a kind:
  - the other subject forms and every derivation;
  - the `checkpoints` subject and history_card/1, whose artifact is the material;
  - a witness Receipt or countersignature over a checkpoint;
  - a consistency proof from an earlier anchor the requester holds, which ER §5 allows but the
    request has no member to name.

  For these, a verifier built from this document alone reports `anchor_inclusion` as
  `NOT_CHECKED`. RES v0's closed `proof-ref.kind` has no value for a checkpoint or a consistency
  proof, so those entries are not listed in `proofs[]`, and a claim does not name the checkpoint
  or envelope its inclusion proof resolves against. Candidate for a later RES revision: a proof
  kind for a checkpoint, or an envelope-digest reference in `evidence[]` (§6.2, §8.3, §11.4).
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
- **P-24** One acceptance record type with four states, its signer fixed by the state; parties
  identified by key, mapped to parties by the trust policy; a counter is a new contract version
  answered through a new proposal; at most one answer per proposal; an acceptance is signed
  before the action (§11.1.1).
- **P-25** The acceptance record's members, signing input and record digest; transaction references
  compared as exact strings with no registered schemes; an answer repeats its proposal's terms;
  `contract_digest` binds, and `contract_ref` must name the same version (§11.1.2).
- **P-26** The session scope: a time window over one contract version, with each exchange citing
  the acceptance and evaluated on its own (§11.1.3).
- **P-27** The acceptance receipt the proposer signs, as an acknowledgment in BA's sense (§11.1.4).
- **P-28** Ordering evidence: the action reference point (optionally required by policy to include
  a time from a party other than the acceptor), the ordering point as a time a party other than the
  acceptor signs, the two normative forms, rounding and strict comparison with no skew allowance,
  causal binding as informative only, and the `acceptance_ordering` status rules (§11.1.5).
- **P-29** An acknowledgment is never an acceptance; acceptance is never authority; authority is
  supported only by a cited authorization that passes its native check and names the acceptor and
  the transaction, else it is labelled `agent_origin_assertion` (§11.1.6).
- **P-30** The acceptance properties, trust as of evaluation and the meaning of accepting a key in a
  role, the unknown-`profile` rule for records and receipts, the five acceptance findings and
  how candidates are chosen and ranked (equivocation and self-admitted late acceptance first), how a
  finding may be presented, and how it is bound into
  an Evidence Result claim (§11.1.7, §11.1.8).
- **P-31** The Checkpointed Local Log material kinds (§6.2.1). This profile adds:
  - the identifiers `cll-inclusion-proof` and `cll-consistency-proof`, since CLL -01 and MMR -02
    define none (`cll-checkpoint` is CLL's own);
  - `anchor.digest` as SHA-256 over the checkpoint's COSE_Sign1 octets as emitted;
  - the entry as the artifact digest and the leaf value SHA-256(0x00 || E), with the kinds
    applying only where `subject.record` equals `artifact_digest`;
  - one checkpoint form (tag 18, empty unprotected header), so one checkpoint has one digest;
  - a relying party's log-key acceptance scoped to the log identities it expects from a
    responder;
  - the proofs carried as the arrays inside MMR's `bstr .cbor`, and an empty inclusion path
    accepted where the leaf is itself a peak (MMR's CDDL writes `[ + bstr ]` and its prose
    allows an empty path);
  - Ed25519 (EdDSA, -8) checkpoints with no `crit` only, and `anchor.freshness` checked against
    the checkpoint's `log_size` or `issued_at`;
  - MMR's `all_ones` read as `pos & (pos + 1) == 0`.

  Left unchecked in v0: the proofs' tree sizes against `log_size` and `prev_size`. MMR counts
  nodes, while CLL -01 describes `log_size` as entries, and known implementations write the node
  count there. Candidates for CLL -02: register the two identifiers, fix the leaf construction,
  and settle the unit of `log_size`.

  This revision adds these kinds and two pins without changing the identifier
  `evidence-interop/0` (P-1), because no revision of this profile has been published yet.

## References

- `draft-mih-agent-evidence-request-00`, `spec/draft-mih-agent-evidence-request-00.md`
  (Internet-Draft, work in progress).
- `vectors/evidence-request/` and its `README.md` readings A1–A14.
- `draft-mih-agent-disclosure-envelope-00`, `spec/draft-mih-agent-disclosure-envelope-00.md`
  (Internet-Draft, work in progress).
- `draft-mih-agent-settlement-records-00`, `spec/draft-mih-agent-settlement-records-00.md`
  (Internet-Draft, work in progress).
- `draft-mih-agent-bilateral-attestation-02`, `spec/draft-mih-agent-bilateral-attestation-02.md`
  (Internet-Draft, work in progress).
- `draft-mih-agent-evidence-layer-00`, `spec/draft-mih-agent-evidence-layer-00.md`
  (Internet-Draft, work in progress).
- `draft-mih-sokolov-scitt-payload-binding`, Section 4.4, as cited by SR §8 (Internet-Draft, work
  in progress).
- `draft-mih-zhang-agent-disclosure-bundle` (Internet-Draft, work in progress).
- `draft-mih-scitt-checkpointed-local-log-01`,
  <https://www.ietf.org/archive/id/draft-mih-scitt-checkpointed-local-log-01.txt>, SHA-256
  `2ef340206e6ba4260b84ba265f794ab9756aefa7cdaeac98e95cea646cfb678f` (Internet-Draft, work in
  progress).
- `draft-bryce-cose-receipts-mmr-profile-02`,
  <https://www.ietf.org/archive/id/draft-bryce-cose-receipts-mmr-profile-02.txt>, SHA-256
  `c6dc055aa61bcdea1566db5a754d055a199a89c9900810b336d99202a44e9893` (Internet-Draft, work in
  progress).
- Evidence Result v0, `spec/evidence-result-v0.md`.
- Evidence Contract v0 schema, `evidence-contract-v0.json`.
- RFC 2119, RFC 8174 (BCP 14); RFC 3339; RFC 4648; RFC 8032; RFC 8785; RFC 8949; RFC 9052; RFC 9597.
