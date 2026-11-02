# Minimum Evidence Interoperability Profile — v2

**Status.** Informational profile, pre-Internet-Draft, kept in this repository. It is not part of
any Internet-Draft revision and changes no posted draft. Like v1, it **pins** existing documents
and states as its own, under [Open points](#13-open-points), every requirement that no pinned
document says.

This is revision v2, identified as `evidence-interop/2` (§3.1). It is `evidence-interop/1`
(`spec/interop-profile-v1.md`, frozen) with one change: a refusal MAY carry `policy_digest`, the
digest of the policy its responder declares, and the refusal's signature covers it when present
(§6.3). P-69 lists the change. `evidence-interop/1` and `evidence-interop/0` keep their meaning: a
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
   same number below. In the **Refusal** paragraph of §7.3, "Rebuild `{issued_at, reason,
   request_digest}` with JCS" reads "Rebuild the §6.3 signing input of the identifier the request
   asks for", and the `refusal_signature` row of §7.2 checks that signing input.
3. **Added open point.** §13 gains P-69. P-1 to P-68 are carried over as written.
4. **Unchanged.** Everything else: the Dependency boundary table and its pins (ER -02 included),
   naming, canonical bytes, the envelope and its material, the absence record, coverage
   declarations, the properties and statuses of §7, the mapping of §8, the ten §9.1 tokens, the
   acceptance record, lifecycle links, the Evidence Contract prose, carriage and discovery, and the
   security considerations. ER -02's unavailable-window statements stay deferred (P-66); adopting
   them would take another identifier.

The host profiles that cite `evidence-interop/0` or `evidence-interop/1` stay on the identifier
they cite until they re-pin.

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

`evidence-interop/2` pins the revisions in v1's Dependency boundary table. A new revision of any
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
  signature: it binds nothing, and a verifier MUST NOT report it as the responder's statement
  [P-69]. A refusal signed with the `evidence-interop/2` signing input answering such a request
  has `refusal_signature` `FAIL`.
- When the request asks for an identifier the verifier does not implement, `refusal_signature` is
  `PASS` when `sig` verifies over the signing input of any identifier the verifier implements.

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
| `refusal-under-v1-policy-digest-signed`, `refusal-policy-digest-checked-by-v1-verifier` | the v2 signing input answering a request for `evidence-interop/1`, and a signed `policy_digest` checked by a verifier implementing only `evidence-interop/1`; `refusal_signature` `FAIL` | §3.3, §6.3, P-69 |

A second set, `vectors/interop-profile-v2-requirement-facts/`, is the v2 regeneration of the v1
requirement-facts set, from the same generator with `--set requirement-facts`. The witness Receipt
check of §6.2.2 keeps its set, `vectors/anchor-witness-v1/`. The `evidence-interop/1` sets in
`vectors/interop-profile-v1/` and `vectors/interop-profile-v1-requirement-facts/` are frozen with
that revision. The pins, fixture formats and readings of v1 §11.5 hold unchanged.

## 13. Open points

P-1 to P-68 are carried over from `evidence-interop/1` as written. `evidence-interop/2` is the
second change to take a new identifier under P-1.

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
    signature passes over the signing input of any identifier it implements;
  - a `policy_digest` not of the digest form makes `refusal_signature` `FAIL`.

  It takes a new identifier because it changes a signing input (P-1). A new identifier, not a
  rule that signs `policy_digest` whenever present, keeps every deployed `evidence-interop/1`
  verifier working: it asks for `evidence-interop/1`, so it is never sent a refusal signed over
  four members, and a refusal it already holds that carries an unsigned `policy_digest` still
  verifies. Left open: a policy format, where a relying party obtains the policy, and a property
  that compares the digest with the policy or with a commitment that names it; candidates for a
  later revision, or for the deployment that publishes the policy.
