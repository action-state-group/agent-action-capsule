# Minimum Evidence Interoperability Profile — v2

**Status.** Informational profile, pre-Internet-Draft, kept in this repository. It is not part of
any Internet-Draft revision and changes no posted draft. Like v1, it **pins** existing documents
and states as its own, under [Open points](#13-open-points), every requirement that no pinned
document says.

This is revision v2, identified as `evidence-interop/2` (§3.1). It is `evidence-interop/1`
(`spec/interop-profile-v1.md`, frozen) with three changes: a refusal MAY carry `policy_digest`, the
digest of the policy its responder declares, and the refusal's signature covers it when present
(§6.3; P-69); the HTTP binding serves the evidence manifest at one fixed path (§11.4.2; P-70),
an additive rule that changes no signing input; and the Evidence Contract's obligation profile has
one shape, the native one, with EC re-pinned to the schema that drops the abstract obligation shape
(§11.3.2; P-71). `evidence-interop/1` and `evidence-interop/0` keep their meaning: a
responder or verifier that implements several identifiers checks each exchange under the
identifier it names.

## How to read this revision

v2 is written as the difference from v1. `evidence-interop/2` is the text of
`spec/interop-profile-v1.md` as of commit `5c2d42bcb58805dc8d70f9ff89adc9fd94c2b091` of this
repository, which is never edited again, read with the changes below. Section numbers are v1's, so
every citation of v1 (§6.3, §7.2, P-65 and the rest) names the same rule here.

1. **The identifier.** Wherever v1 names its own identifier as the identifier of this revision,
   read `evidence-interop/2`. Every signed object that names the identifier (the request, the
   envelope, the acceptance record and the lifecycle statement) names `evidence-interop/2`, and so
   does the manifest's `profiles` member of a responder that implements it (§3.3, §11.4.2). Where
   v1 says "v1" or "this revision" of a rule, read v2. Where v1 contrasts itself with
   `evidence-interop/0` (P-65, the §9.1 tokens of each identifier), `evidence-interop/1` keeps the
   rules v1 states for it, and `evidence-interop/2` has those rules too unless §6.3 below changes
   them.
2. **Replaced sections.** §3.1, §3.2, §6.3, §10 and §11.5 are replaced by the sections of the
   same number below. The EC row of the Dependency boundary table and §11.3.2 are replaced by the
   row and section below; §11.3.5 and §11.3.7 are replaced in part, by the amendments of [11.3
   Evidence Contract prose](#113-evidence-contract-prose) below. In the **Refusal** paragraph of
   §7.3, "Rebuild `{issued_at, reason, request_digest}` with JCS" reads "Rebuild the §6.3 signing
   input of the identifier the request asks for", and the `refusal_signature` row of §7.2 checks
   that signing input. §11.4.1, §11.4.2, §11.4.7, §11.4.8 and §11.4.9 are replaced in part, by the
   amendments of [11.4 Carriage and discovery](#114-carriage-and-discovery) below: v1's text of each
   stands except for the sentences and rows named there.
3. **Added open points.** §13 gains P-69, P-70 and P-71. P-1 to P-68 are carried over as written,
   except that P-52 is read as P-71 amends it.
4. **Unchanged.** Everything else: the Dependency boundary table and its pins (ER -02 included)
   except the EC row, naming, canonical bytes, the envelope and its material, the absence record,
   coverage declarations, the properties and statuses of §7, the mapping of §8, the ten §9.1 tokens,
   the acceptance record, lifecycle links, the Evidence Contract prose except for the amendments of
   11.3 below, carriage and discovery except for the amendments of 11.4 below, and the security
   considerations. ER -02's unavailable-window statements stay deferred (P-66); adopting them would
   take another identifier.

The host profiles that cite `evidence-interop/0` or `evidence-interop/1` stay on the identifier
they cite until they re-pin.

## Dependency boundary

The EC row of v1's table is replaced by this one. Every other row stands.

| Tag | Document | Revision pinned | What this profile takes from it |
|---|---|---|---|
| EC | Evidence Contract v0 schema | `schemas/evidence-contract-v0.json` in this repository, SHA-256 of the file `bf9a1cdee27c8cf6d35b2371fe3b778cf5e1db671dd9c4bce9f503e8842cb78b`: the capsule-engine copy v1 pins (commit `773ae9e96285e4442cab8139923b1479b103e14c`, SHA-256 `6b969610e6f120a9f5b98555aa5045644c62665f14075bb83fb9e78bab21b770`) with its `$id` changed and the abstract obligation shape (`requirementObligationGeneric`) dropped | the contract and every member and value of it (§11.3); the eight-value status, its four-value projection, and per-requirement handling of missing and conflicting evidence |

The pin names the file by its digest, so it fixes the bytes whatever commit carries them. v1's EC
pin stays v1's: `evidence-interop/0` and `evidence-interop/1` keep the capsule-engine copy, under
which both obligation shapes are valid [P-71].

## 3. Versions

### 3.1 Profile identifier

This revision is identified by the text string `evidence-interop/2`. The identifier names this
exact document revision, read as [How to read this revision](#how-to-read-this-revision) says. Any
change to a signing input, a canonical byte rule, a member name, the status vocabulary or the
mapping in §8 requires a new identifier [P-1]. v2 has no minor versions. `evidence-interop/1`
stays defined by `spec/interop-profile-v1.md` as of commit
`5c2d42bcb58805dc8d70f9ff89adc9fd94c2b091`, and `evidence-interop/0` by
`spec/interop-profile-v0.md` as of commit `1456285979bd759b7828fd3ccc4a24296074e552` [P-65; P-69].
Until `evidence-interop/2` is first published, filling a placeholder of §11 under it is allowed,
provided it changes no existing signing input or byte rule and only adds objects, rows and
properties [P-1].

### 3.2 Pinned revisions

`evidence-interop/2` pins the revisions in v1's Dependency boundary table, with the EC row
replaced as [Dependency boundary](#dependency-boundary) says. A new revision of any
of those documents does not change what `evidence-interop/2` means. Adopting a new revision
requires a new profile identifier, except before the profile is first published [P-1].

## 6. Messages, and what binds them

### 6.3 Signed refusal

The refusal object is the one v1 pins [ERV A7; P-6], with one optional member added [P-69]:

| Member | Signed | Value |
|---|---|---|
| `request_digest` | yes | SHA-256 over the request octets **as received** [ER §4.2 item 1] |
| `reason` | yes | exactly one token from the registry (§9.1) [ER §4.2 item 2] |
| `issued_at` | yes | REQUIRED and covered by the signature [ER §4.2 item 3] |
| `policy_digest` | yes, when present | OPTIONAL. A digest (§5.2): the SHA-256 of the policy document the responder declares, as the responder publishes it [P-69] |
| `key_id` | — | the responder's key identifier |
| `sig` | — | Ed25519 over UTF-8 of JCS of the signed members present; ER leaves the format to the deployment [ER §4.2 item 4] |
| `detail` | no | OPTIONAL human-readable text. The token, not the prose, is the answer [ER §4.2; P-6] |

The **signing input** is UTF-8 of JCS of the object made of `issued_at`, `reason` and
`request_digest`, and of `policy_digest` when the refusal carries it [P-69]. Without
`policy_digest` it is the ERV A7 signing input, byte for byte, so a refusal without one is the
same object under `evidence-interop/1` and `evidence-interop/2`.

A refusal carries no `profile` member, so the identifier whose signing input applies is the one
its request asks for (§3.3 step 2), as for its `reason` [P-65; P-69]:

- Under `evidence-interop/2`, a `policy_digest` the refusal carries is signed. A verifier rebuilds
  the signing input with it, so a `policy_digest` replaced, removed or added after signing makes
  `refusal_signature` `FAIL`. A `policy_digest` that is not of the §5.2 digest form also makes
  `refusal_signature` `FAIL`: the signed member is malformed.
- Under `evidence-interop/0` and `evidence-interop/1`, the signing input is the three ERV A7
  members, whatever else the refusal carries. A `policy_digest` beside them is outside the
  signature [P-69]. A refusal signed with the `evidence-interop/2` signing input answering such a request
  has `refusal_signature` `FAIL`.
- When the request asks for an identifier the verifier does not implement, `refusal_signature` is
  `PASS` when `sig` verifies over the signing input of an identifier the verifier implements and
  the refusal meets that identifier's rules: a signature that verifies only over the
  `evidence-interop/2` input brings its rule that a signed `policy_digest` is a digest.

Whatever the identifier, a `policy_digest` binds the responder only when the signing input that
`sig` verified over includes it. When `sig` verified over an input that excludes it, as the three
ERV A7 members do, the member binds nothing, and a verifier MUST NOT report it as the
responder's statement [P-69].

So a responder answers each request under the identifier it asks for, and a requester that needs
the responder's policy digest bound to the refusal asks for `evidence-interop/2`. A requester or
verifier that implements only `evidence-interop/0` or `evidence-interop/1` never asks for it, so it
never receives a refusal it cannot check.

`policy_digest` names a policy; it does not carry or check one. This profile fixes no policy
format, defines no property that compares `policy_digest` with a policy or with a commitment the
responder publishes, and changes no row of §8.1: a relying party that holds the policy compares
the digest itself. A refusal signed over an unregistered or mis-cased reason, or over two reasons,
has a valid signature and is still not a conforming refusal [ERV A13]. It is recorded as a
response received and failed [P-21], never as an absence [ER §4.5].

The rest of v1 §6.3 holds unchanged: the most-specific-reason rule and its exception, load
shedding as `capacity_exceeded`, and the reasons checked against the tokens of the identifier the
request asks for, here the ten of §9.1 under `evidence-interop/2` as under `evidence-interop/1`.

## 10. Worked example (informative)

The keys, records, anchors, logs and seed labels of v1 §10 and §10.1 are unchanged. Every value
that a signature or digest takes over an object naming the identifier differs. This section gives
the §10.1 request and envelope signature under `evidence-interop/2`, and a refusal that carries a
`policy_digest`; the log material of §10.1 (checkpoint, inclusion proof and consistency proof)
names no identifier and is v1's, byte for byte.

**Request C, JSON binding** (JCS text, the transmitted octets):

```
{"coverage":{"expected_pin":"16f15dd5475d5e8ec1fb7a84470391e11d7663232365c1749c60ca7489cffe99"},"nonce":"2026-10-12T00:00:10Z/c","profile":"evidence-interop/2","subject":{"record":"2fbdb95bdeba62f949bcb6026061fcd66c021523a39e58fc2de1cd44ff631244"}}
```

request digest `5f3986d13db4f50fbec30adcee78ee0787f37f34b0c28b79f78bfa938972f443`

**Envelope C** is v1's envelope C with `profile` `evidence-interop/2` and this request digest.

`sig` = `2ef37b260b599807fcd4efd889f8b74db02e0f1b8587b47887b539d439869b95ae4800c82942e8ef3fa2d5fe416a3b3c0378a9e091aa850e0e1f7cf28020f504`

**Refusal with a policy digest.** Had the responder held no record by that digest, it would have
answered request C with this refusal. Its policy digest is
`SHA-256("evidence-interop/2 vectors: responder policy file")`. Signing input:

```
{"issued_at":"2026-10-12T00:00:11Z","policy_digest":"ff551899dc992d7c3e34b239eb3ed1067ef0bb5dbaf219bb1539021c6cedee63","reason":"no_such_subject","request_digest":"5f3986d13db4f50fbec30adcee78ee0787f37f34b0c28b79f78bfa938972f443"}
```

`sig` = `718ee96fa71c2767fed466d0768854123db65ae3b3f95f2b8023a70721b5d79aaeb75eafd4dd08b0a65124c139f05916781e51d4be6ee7320394045112de890c`

`key_id` is the responder key of v1 §10. Without `policy_digest` the signing input would be the
three ERV A7 members, as in v1 §10.

## 11. Parts filled by later revisions

### 11.3 Evidence Contract prose

v1 §11.3 stands, read against the EC pin above, with the following amendments [P-71].

#### 11.3.2 Requirements and their profiles

This section replaces v1 §11.3.2.

Each entry of `requirements` MUST match exactly one of eight shapes [EC `$defs/requirement`,
`oneOf`]. The requirement's `profile` member names which. `profile` takes one of seven values, and a
contract MAY mix profiles across its requirements [EC].

The obligation profile has one shape, the native, pack-declared one [EC; P-71]. The reason is what
the native shape carries. It requires a structured `clause` (§11.3.4), which gives a claim its
`applies_from` (§8.3) and is checked for a calendar date before a contract is evaluated (§11.3.7,
P-62), and it can carry `out_of_scope_allowed`, which only the native shapes carry (§8.3, P-61).
The abstract obligation shape of the capsule-engine copy carried a free-form `clause_ref` and
none of these, so an obligation written in it could be evaluated with neither rule applied.

The outcome profile keeps two shapes, a native and an abstract one. The schema states that those
two spellings have not been reconciled [EC], and this revision does not choose between them
[P-52].

| Shape (`$defs`) | `profile` | Required members | Closed |
|---|---|---|---|
| native outcome (`requirementOutcomeNative`) | `outcome`, or absent | `id`, `statement`, `evidence_rule`, `forward_verdict`, `backward_verdict` | yes |
| native obligation (`requirementObligationNative`) | `obligation` | those five, `profile` and `clause` | yes |
| abstract outcome (`requirementOutcomeGeneric`) | `outcome` | `id`, `profile`, `statement` | yes |
| process (`requirementProcess`) | `process` | `id`, `profile`, `statement` | no: a typed stub |
| quality (`requirementQuality`) | `quality` | `id`, `profile`, `statement` | no: a typed stub |
| human role (`requirementHumanRole`) | `human_role` | `id`, `profile`, `statement` | no: a typed stub |
| attribution (`requirementAttribution`) | `attribution` | `id`, `profile`, `ref` | yes: a typed stub |
| settlement (`requirementSettlement`) | `settlement` | `id`, `profile`, `ref` | yes: a typed stub |

How a requirement selects its shape follows from the table. A requirement with no `profile` member
can only be a native outcome. For `outcome`, a requirement carrying `evidence_rule` can only be
native, because the abstract shape is closed and does not list it, and one without it can only be
abstract, because the native shape requires it. Every other value has one shape. So an obligation
requirement without `evidence_rule` or without `clause`, such as one that cites its clause only by
`clause_ref`, matches no shape. A contract carrying one is not valid against the pinned schema, so
it is not a contract version document under `evidence-interop/2` (v1 §11.3.7) [P-46; P-71]. A
typed stub is a profile whose fields are sketched but not yet normative [EC]. The open stubs
(process, quality, human role) accept members the schema does not list.

Members that appear in several shapes:

- `id`: non-empty text. The requirement's identifier within the contract. An Evidence Result claim
  names it as `requirement_ref` [RES §4].
- `profile`: text, one of `outcome`, `obligation`, `process`, `quality`, `human_role`,
  `attribution`, `settlement`, used as the table above shows [EC].
- `statement`: non-empty text. The claim the requirement asks to have established, in words. Every
  shape but attribution and settlement requires it [EC].
- `status`, `result`: forbidden in every shape, the open stubs included. The schema gives each the
  subschema `false`, so a requirement carrying either is invalid. A contract never declares its own
  outcome [EC `$comment`].
- `evidence_requirements`: the object of §11.3.3. Allowed in abstract outcome, process and human
  role.
- `obligation_refs`: array of non-empty text. References to obligations the requirement relates to.
  Allowed in abstract outcome, process, quality and human role.

#### 11.3.5 and 11.3.7 amendments

- **§11.3.5.** The title reads "Abstract outcome and stub profile members". Delete the
  **Abstract obligation** paragraph: the shape it describes is not in the pinned schema.
- **§11.3.7, Which shape.** Read: "A claim does not record whether an outcome requirement used the
  native or the abstract shape, and this profile reads both as EC accepts them [P-52]. An
  obligation requirement has only the native shape (§11.3.2) [P-71]."

### 11.4 Carriage and discovery

v1 §11.4 stands, with the following amendments. They fill the placeholder v1 §11.4.9 lists as
"where the HTTP binding serves the manifest", and they only add a requirement, a check and
vectors: no signing input, member, token or outcome word changes [P-70].

- **§11.4.1 table, Manifest row, native-stream column.** Read: "not carried; the HTTP binding serves
  it at `/.well-known/evidence-manifest`".
- **§11.4.2, new rule after "A responder MUST serve one manifest".** In that rule read "the HTTP
  binding (next rule)" for "the HTTP binding". Then add:

  > Over the HTTP binding the manifest is served at one fixed path, `/.well-known/evidence-manifest`,
  > relative to the origin of the responder's HTTP binding [ER §10; P-70]. A requester that knows
  > only that origin fetches it with `GET`. The response body is the JCS serialization of the
  > manifest and its media type is `application/json` (parameters such as `charset` do not change
  > the media type [RFC 9110 §8.3.1]), so its octets equal the JCS serialization of the A2A
  > `params` value and of the `evidence_manifest` result. The resource is static and carries no
  > envelope [ER §10]. A responder that serves the HTTP binding and publishes a manifest MUST
  > serve it at this path, unless it shares its origin with another responder. Authentication,
  > caller and request headers do not change the body (previous rule). The path adds no member,
  > token or outcome word to the manifest. The path belongs to an origin [RFC 8615], so responders
  > that share an origin do not use it.
- **§11.4.7, `manifest_form`.** After "A number, boolean or map anywhere in it is `FAIL`." add: for
  the copy fetched over HTTP it is also `FAIL` when the media type is not `application/json`, when
  the body does not parse as JSON without duplicate member names, or when the body octets are not
  exactly the JCS serialization of the value they parse to [P-45; P-70]. `manifest_consistency`
  compares the HTTP copy with the others as it compares any two copies. A copy whose body does not
  parse counts as a manifest unequal to every other copy, so `manifest_consistency` is `FAIL`.
- **§11.4.8.** The `carriage-invariance` vector also fetches the manifest over HTTP, as the body of
  a `GET` at `/.well-known/evidence-manifest`, and its expectation is that the three manifests give
  `manifest_form` `PASS` and `manifest_consistency` `PASS`. Four rows are added to its negative
  table:

  | Change | Result |
  |---|---|
  | the body at `/.well-known/evidence-manifest` is the same manifest, pretty-printed instead of in JCS | `manifest_form` `FAIL` for that copy and `PASS` for the others; `manifest_consistency` `PASS`, since the values are equal |
  | the body at `/.well-known/evidence-manifest` is the same manifest in JCS, served as `text/plain` | `manifest_form` `FAIL` for that copy and `PASS` for the others; `manifest_consistency` `PASS` |
  | the body at `/.well-known/evidence-manifest` repeats a member name | the body does not parse, so `manifest_form` `FAIL` for that copy and `manifest_consistency` `FAIL` |
  | the body at `/.well-known/evidence-manifest` is a different manifest (here another `subject_forms`) from the A2A `params` and the `evidence_manifest` result | `manifest_form` `PASS` for each copy; `manifest_consistency` `FAIL` |
- **§11.4.9.** Delete "where the HTTP binding serves the manifest" from the list of what is still
  unspecified.

### 11.5 Conformance vectors

The vectors are in `vectors/interop-profile-v2/`. `python/scripts/generate_interop_profile_v0_vectors.py
--profile 2` generates them deterministically, and `python/tests/test_interop_profile_v2_vectors.py`
checks them. They are the cases of v1 §11.5, with every request, envelope, acceptance record,
lifecycle statement and manifest naming `evidence-interop/2`, the version cases using
`evidence-interop/1` as the other identifier, and these cases added:

| Cases | What they show | Sections |
|---|---|---|
| `refusal-policy-digest-signed`, `refusal-policy-digest-absent` | a conforming refusal with a signed `policy_digest`, and one with none; every property `PASS` | §6.3, P-69 |
| `refusal-policy-digest-tampered`, `refusal-policy-digest-stripped`, `refusal-policy-digest-unsigned`, `refusal-policy-digest-not-a-digest` | a `policy_digest` replaced or removed after signing, one added outside the signature, and one signed but not a digest; `refusal_signature` `FAIL` | §5.2, §6.3, §8.1, P-69 |
| `refusal-under-v1-still-verifies`, `refusal-under-v1-policy-digest-unbound` | a request for `evidence-interop/1` and its ERV A7 refusal, without and with a `policy_digest` outside the signature, checked by a verifier implementing both identifiers; every property `PASS` | §3.3, §6.3, P-69 |
| `refusal-unimplemented-identifier-policy-digest-unbound`, `-signed`, `-not-a-digest` | a request for an identifier the verifier does not implement, answered by an ERV A7 refusal with a `policy_digest` outside the signature (every property `PASS`, and the member binds nothing), by the v2 signing input (`PASS`), and by the v2 signing input over a `policy_digest` that is not a digest (`refusal_signature` `FAIL`) | §5.2, §6.3, P-69 |
| `refusal-under-v1-policy-digest-signed`, `refusal-policy-digest-checked-by-v1-verifier` | the v2 signing input answering a request for `evidence-interop/1`, and a signed `policy_digest` checked by a verifier implementing only `evidence-interop/1`; `refusal_signature` `FAIL` | §3.3, §6.3, P-69 |
| `carriage-manifest-http-not-jcs`, `carriage-manifest-http-wrong-media-type`, `carriage-manifest-http-duplicate-member`, `carriage-manifest-http-differs` | the manifest fetched over HTTP, pretty-printed instead of in JCS or served as `text/plain` (that copy's `manifest_form` `FAIL`, `manifest_consistency` `PASS`), with a repeated member name (both `FAIL`), and another manifest (`manifest_consistency` `FAIL`); `carriage-invariance` gains the HTTP copy | §11.4.2, §11.4.7, §11.4.8, P-70 |

A second set, `vectors/interop-profile-v2-requirement-facts/`, is the v2 regeneration of the v1
requirement-facts set, from the same generator with `--set requirement-facts`. Both v2 sets record
the EC pin above as their contract's schema; their contract documents are unchanged from v1's and
valid under either pin. A third set, `vectors/evidence-contract-obligation/`, checks the one
obligation shape against the pinned schema: a native obligation requirement that is valid
(`pos-obligation-native`), the same obligation in the abstract shape that is refused
(`neg-obligation-abstract`), and an abstract outcome requirement that stays valid
(`pos-outcome-abstract`) (§11.3.2, P-71). `schemas/check_evidence_contract_examples.py` runs it. The witness Receipt
check of §6.2.2 keeps its set, `vectors/anchor-witness-v1/`. The `evidence-interop/1` sets in
`vectors/interop-profile-v1/` and `vectors/interop-profile-v1-requirement-facts/` are frozen with
that revision. The pins, fixture formats and readings of v1 §11.5 hold unchanged.

## 13. Open points

P-1 to P-68 are carried over from `evidence-interop/1` as written, except P-52 as P-71 amends it.
`evidence-interop/2` is the second change to take a new identifier under P-1.

- **P-69** The refusal's `policy_digest` (§6.3). ER leaves the refusal's signature format to the
  deployment [ER §4.2 item 4], and ERV A7 fixes three signed members, so a responder that wants
  to say which of its declared policies a refusal applies has nowhere signed to say it: a
  `policy_digest` beside the A7 members binds nothing once the refusal is passed on. This profile
  adds:
  - `policy_digest`, OPTIONAL, a digest (§5.2): the SHA-256 of the policy document the responder
    declares, as it publishes it;
  - the signing input of `evidence-interop/2`: the three ERV A7 members and `policy_digest` when
    present, so a refusal without one keeps the A7 bytes;
  - the signing input chosen by the identifier the request asks for, as the reasons are (P-65):
    under `evidence-interop/0` and `evidence-interop/1` a `policy_digest` stays outside the
    signature and binds nothing, and under an identifier the verifier does not implement the
    signature passes over the signing input of any identifier it implements whose rules the
    refusal meets;
  - a `policy_digest` binds the responder only when the signing input that verified includes it,
    under every identifier, so one beside a signature over the A7 members is never reported as
    the responder's;
  - a `policy_digest` not of the digest form makes `refusal_signature` `FAIL`.

  It takes a new identifier because it changes a signing input (P-1). A new identifier, not a
  rule that signs `policy_digest` whenever present, keeps every deployed `evidence-interop/1`
  verifier working: it asks for `evidence-interop/1`, so it is never sent a refusal signed over
  four members, and a refusal it already holds that carries an unsigned `policy_digest` still
  verifies. Left open: a policy format, where a relying party obtains the policy, and a property
  that compares the digest with the policy or with a commitment that names it; candidates for a
  later revision, or for the deployment that publishes the policy.
- **P-70** The HTTP location of the manifest (§11.4.2). ER's HTTP binding says a responder SHOULD
  publish a manifest and names no location, so a requester knowing only an origin had nothing to
  fetch. This profile fixes `/.well-known/evidence-manifest`, with a JCS body served as
  `application/json`, and makes the form of that response part of `manifest_form` (§11.4.7), with a
  path that belongs to an origin, not to a responder. It adds no manifest member and no outcome word
  and changes no signing input, so it fills a placeholder of v1 §11.4.9 (P-1). The new MUST and
  the stricter `manifest_form` apply only to the HTTP copy of the manifest, so `evidence-interop/1`
  and `evidence-interop/0` responders and verifiers are unaffected until they re-pin to
  `evidence-interop/2` (§3.1). Left open: registering `evidence-manifest` in the IANA "Well-Known
  URIs" registry [RFC 8615]. It is not registered; until it is the name is this profile's own, and
  a later draft revision that adopts the path would carry the registration request. Also left
  open: a requester has no fixed path for a responder that shares its origin with another
  responder, since the path belongs to the origin. This revision adds RFC 8615 and RFC 9110 to the
  references of v1.
- **P-71** One obligation shape (§11.3.2). The pinned schema of `evidence-interop/1` accepts an
  obligation requirement in two shapes, the native, pack-declared one and an abstract one, and
  states that the two have not been reconciled; P-52 left that open. The native shape was ruled the
  one obligation shape on 2026-10-05. This revision:
  - re-pins EC to `schemas/evidence-contract-v0.json` in this repository, which is the
    capsule-engine copy with its `$id` changed and `requirementObligationGeneric` dropped from the
    schema's `$defs` and from `$defs/requirement`, so `requirements` entries match one of eight
    shapes;
  - so refuses an obligation requirement that carries `clause_ref` without `evidence_rule` and
    `clause`, which `evidence-interop/1` accepts;
  - leaves the outcome profile's two shapes as they are. P-52 stays open for them, and for what an
    absent `tier`, `mode` or `measurability` means.

  The change narrows what a valid contract is and changes no signing input, canonical byte rule,
  member name, status word or §8 mapping. `evidence-interop/2` is not yet published, so EC is
  re-pinned under the exception of §3.2 and takes no new identifier (P-1). No corpus contract in
  this repository's vectors uses the abstract obligation shape, and no implementation here
  validates contracts against the schema, so no verifier result under `evidence-interop/2`
  changes; only the refused case of `vectors/evidence-contract-obligation/` is written in it.
  `evidence-interop/0` and `evidence-interop/1` keep v1's EC pin and both obligation shapes.
