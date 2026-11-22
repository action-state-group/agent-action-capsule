# Person Signature — v0

**Status.** Informational, pre-Internet-Draft, kept in this repository. It changes no
Internet-Draft and no record format. It defines one object, the **person signature**: a person's
signature, made with the person's own key, over the digest of one record that some other party
signed. The object travels beside that record, never inside it. This document also defines the
member that carries it, how a verifier checks it offline, and what the verifier reports. Where it
needs a rule that no other document states, it lists the rule under
[Open points](#10-open-points) (PS-1, PS-2, and so on).

A record in an agent's log is signed by the agent's key, or by the key of the store that keeps the
log. When that record says a person approved something, the signature shows only that the agent
says so. A person signature adds the person's own signature over the same record. It certifies
what the record already says, no more.

## Dependency boundary

**Owns:** the person signature object and its members (§3); the key types and how each signs
(§3.2, §4); exactly what is signed (§4.1); the carrier member, `person_signatures` (§5); the
verifier's inputs, steps and statuses (§6); and what a verifier reports (§7).

**Uses unchanged:**

| Tag | Document | What this document takes from it |
|---|---|---|
| IP | `spec/interop-profile-v0.md` (`evidence-interop/0`) | the value conventions (§5.2) and the per-property status vocabulary (§7.1) |
| WebAuthn | W3C, "Web Authentication: An API for accessing Public Key Credentials", Level 3 | the assertion: authenticator data, client data and their serialization, the assertion signature, and the verification of an assertion (§7.2), for the `webauthn` key type |
| COSE | RFC 9053 | the algorithm identifiers -7 (ES256) and -8 (EdDSA) |
| RFC 5280 | RFC 5280, RFC 5480 and RFC 8410 | SubjectPublicKeyInfo for P-256 and Ed25519 public keys |
| RFC 4648 | RFC 4648 §5 | base64url, without padding |
| RFC 8259 | RFC 8259 | JSON, for the client data |
| RFC 8949 | RFC 8949 | a well-formed CBOR map, for authenticator data extensions |

**Does not define:** which key belongs to which person (enrolment); any identity, account or naming
scheme; any relying party; how a record digest is computed (the using profile defines it); which
records need a person signature before something may rely on them; or the user interface that asks
the person to sign.

## 1. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

This document uses these terms:

- **Signed record:** the record a person signature names. Some party other than the person signed
  it, for example an agent's record key or a store's key.
- **Record digest:** the digest of the signed record. The using profile defines it. It is 32
  octets, written as 64 lowercase hexadecimal characters (IP §5.2).
- **Using profile:** the document that carries signed records and says which of them a person
  signature is for. It supplies the verifier inputs of §6.1.
- **Person key:** a public key that the using profile, by its own enrolment rule, accepts as the
  person's.
- **Enrolment:** how the using profile comes to accept a key as the person's. This document does
  not define it (§8.1).

Binary values are base64url without padding (RFC 4648 §5). A verifier rejects a binary value that
holds a character outside the base64url alphabet, padding, or non-zero trailing bits.

## 2. What a person signature is for

An agent acts for a person, and its log records what the person said: an approval, a confirmation,
an instruction. Every record in the log is signed by a key the agent's runtime can use. A record
signed by that key is the agent's claim about the person, however honest the agent is. A
counterparty that relies on the record relies on the agent's word.

A person signature is the person's own statement over the same record. The person signs the record
digest with a key that the agent's runtime cannot use without the person present. A verifier that
holds the record, the person signature and the person key checks it offline. A record with no
person signature stays valid. It reads as *not signed by the person*, never as signed, and never as
an error.

## 3. The person signature object

### 3.1 Members

A person signature is a JSON object with exactly these members:

| Member | Value |
|---|---|
| `person_signature_version` | the text string `person-signature/0` |
| `record_digest` | the record digest of the signed record: 64 lowercase hexadecimal characters |
| `key_type` | a key type token (§3.2) |
| `key` | the signing key, in the form its key type defines (§4) |
| `proof` | the signature, in the form its key type defines (§4) |

A person signature with a duplicate member name, a missing member, any other member, or a value
outside its form is malformed. For a `key_type` this revision defines, `key` and `proof` take the
form of §4, and any other form is malformed. For a `key_type` it does not define, `key` and `proof`
can be any JSON value.

`key` names the key that made the signature. A verifier uses it to find the person key it was
given (§6.2, step 3). `key` never makes a key a person key by itself.

### 3.2 Key types

A key type says what kind of key signed, the form of `key` and `proof`, and how a verifier checks
them.

| Token | Key | Signs by |
|---|---|---|
| `webauthn` | a WebAuthn public key credential's public key | a WebAuthn assertion whose challenge is the signed octets (§4.1, §4.2) |

A person signature whose `key_type` is not in this table is well formed. A verifier reports it
`NOT_CHECKED` (§6.3), and it never reads as signed by the person.

**Registration policy.** A key type is added only by a revision of this document, and only for a
key that the person holds and that the agent's runtime cannot use without the person present. The
provisional registry of record is `spec/REGISTRY.md`. A key type is a statement about the kind of
key, not about who holds it. Who holds a key is shown only by enrolment (§8.1).

## 4. What is signed, and how each key type signs

### 4.1 The signed octets

The **signed octets** of a person signature are the UTF-8 octets of the text

    person-signature/0:<record_digest>

where `<record_digest>` is the object's `record_digest`, as 64 lowercase hexadecimal characters.
They are 83 octets. Every key type signs these octets, as it defines.

The prefix names the object, so a signature made for some other purpose never reads as a person
signature. A WebAuthn sign-in uses a challenge that the relying party draws at random, and that
challenge does not equal these octets. The record digest binds the signature to exactly one signed
record and, through the record, to whatever the record names: for example the request the person
answered and the text they were shown, when the using profile's record names them.

### 4.2 `webauthn`

`key` is an object with exactly these members:

| Member | Value |
|---|---|
| `alg` | an integer: the COSE algorithm of the credential, as `getPublicKeyAlgorithm()` returns it |
| `spki` | binary: the credential public key as a DER SubjectPublicKeyInfo, as `getPublicKey()` returns it |

This revision defines two algorithms:

| `alg` | Algorithm | `spki` | Signature |
|---|---|---|---|
| -7 | ES256: ECDSA on P-256 with SHA-256 | an `id-ecPublicKey` key on `secp256r1`, with the point uncompressed (RFC 5480) | ASN.1 DER `ECDSA-Sig-Value` |
| -8 | EdDSA with Ed25519 | an `id-Ed25519` key (RFC 8410) | the 64-octet Ed25519 signature |

A verifier that implements `webauthn` implements both. A `key` whose `spki` does not match its
`alg`, for example a P-256 key under -8, is malformed. A `key` with any other `alg` is well formed,
and a verifier reports it `NOT_CHECKED`. The algorithm is read from `key`, never from the proof.

Two keys are **the same key** when they have the same `alg` and the same public key: for -7 the
same point, and for -8 the same 32 octets. A raw Ed25519 key identifier is the same key as a -8 key
with the same 32 octets. A verifier compares keys this way, never by comparing the octets of
`spki`, and a key under an algorithm this revision does not define is the same key as no other.

`proof` is an object with exactly these members, each binary:

| Member | Value |
|---|---|
| `authenticator_data` | the assertion's authenticator data, as the authenticator returned it |
| `client_data_json` | the assertion's client data, as the client returned it: the exact octets the authenticator's signature covers |
| `signature` | the assertion signature |

The signer runs a WebAuthn authentication ceremony (`navigator.credentials.get()`) whose
`challenge` is the signed octets (§4.1). The credential id and the user handle are not carried,
because the verifier needs neither (§8.3).

The assertion signature is over `authenticator_data || SHA-256(client_data_json)`, as WebAuthn
defines it. It is not over the record digest itself. The record digest is inside
`client_data_json`, as the challenge.

## 5. Carriage

A person signature travels **beside** the signed record, never inside it. A signature over a
record's digest cannot sit inside that record, and carrying it beside the record changes no record
format.

A using profile that carries a signed record in a JSON object carries the record's person
signatures in that object's member `person_signatures`, beside the record. Its value is an array of
person signature objects. Each one names, in `record_digest`, the record it signs. The array MAY
hold person signatures for several records, and several for one record. A verifier selects the
ones whose `record_digest` equals the target record digest (§6.1) and ignores the rest. A using
profile that carries records some other way names its own carrier and keeps the object of §3
unchanged.

A holder that passes a signed record on SHOULD pass the record's person signatures with it. A copy
of a record without them reads `NOT_PRESENT`: not signed by the person (§6.3). Leaving them out
changes no other result for the record. A holder MAY leave them out, for example to avoid
disclosing the person key (§8.3).

## 6. Verification

### 6.1 Verifier inputs

The using profile supplies these inputs. A verifier never takes them from the person signature:

| Input | Value |
|---|---|
| target record digest | the record digest of the signed record, which the verifier computes or obtains by the using profile's rule |
| person keys | one or more keys, in the form of §4.2 `key`, that the using profile's enrolment accepts as the person's |
| excluded keys | the keys that signed the signed record or its envelope, each in the form of §4.2 `key` or as a raw Ed25519 key identifier (IP §5.2) |
| relying party id | for `webauthn`: the RP ID the person's credential is scoped to |
| allowed origins | for `webauthn`: the origins at which the signing ceremony may run |
| allowed top-level origins | for `webauthn`: the top-level origins under which a ceremony in a cross-origin frame counts. When the using profile names none, no cross-origin ceremony counts |
| user verification required | for `webauthn`: true or false. When the using profile says nothing, false |

The relying party id and the allowed origins belong with the person key: the using profile fixes them
when it enrols the key, and a verifier obtains them from the same place as the person key, never
from whoever presents a copy.

### 6.2 Checking one person signature

A verifier checks each person signature whose `record_digest` equals the target record digest, in
this order. The first step that does not succeed gives its status, and the verifier stops.

1. **Form.** The object is well formed (§3.1). Otherwise `FAIL`, reason `malformed`.
2. **Key type and algorithm.** The verifier implements `key_type` and, for `webauthn`, `key.alg`.
   Otherwise `NOT_CHECKED`, reason `unsupported key type` or `unsupported algorithm`.
3. **Person key.** When the using profile supplied no person key, `NOT_CHECKED`, reason
   `no person key`. Otherwise `key` is the same key (§4.2) as one of the person keys, or `FAIL`,
   reason `not a person key`.
4. **Not a record key.** `key` is not the same key as any excluded key. Otherwise `FAIL`, reason
   `record signer key`. This step only rejects a using profile that enrolled a record key by
   mistake. It is not why an agent's key fails; step 3 is (§8.1).
5. **Client data** (`webauthn`). `client_data_json` is UTF-8 JSON text whose value is an object.
   The verifier decodes the exact octets as UTF-8, which removes a leading byte order mark, and
   parses the text as JSON (RFC 8259). Text that is not UTF-8, is not JSON (for example `NaN`),
   is not an object, or holds a duplicate member name is `FAIL`, reason `malformed`. The verifier
   never serializes the client data again. Then:
   - `type` is `webauthn.get`. Otherwise `FAIL`, reason `wrong type`.
   - `challenge` is a base64url text whose decoded octets equal the signed octets (§4.1) of this
     person signature. Otherwise `FAIL`, reason `wrong challenge`. A challenge that holds the record
     digest in hexadecimal, or the signed octets with padding or in standard base64, is a wrong
     challenge.
   - `origin` is one of the allowed origins. Otherwise `FAIL`, reason `origin not allowed`.
   - When `crossOrigin` is true or `topOrigin` is present, `topOrigin` is present and is one of the
     allowed top-level origins. Otherwise `FAIL`, reason `cross-origin`. A cross-origin ceremony that
     names no `topOrigin` therefore never counts.

   Other members of the client data are ignored, whatever their order.
6. **Authenticator data** (`webauthn`). `authenticator_data` is an assertion's authenticator data
   (WebAuthn §6.1): at least 37 octets; the AT flag (bit 6 of octet 32) clear, since an assertion
   carries no attested credential data; when the ED flag (bit 7) is clear, exactly 37 octets; when
   it is set, the octets after the first 37 are exactly one well-formed CBOR map (RFC 8949), which
   the verifier does not otherwise read; and the BS flag (bit 4) clear when the BE flag (bit 3) is
   clear. Otherwise `FAIL`, reason `malformed`. Then:
   - its first 32 octets equal SHA-256 of the UTF-8 relying party id. Otherwise `FAIL`, reason
     `wrong relying party`.
   - the UP flag (bit 0 of octet 32) is set. Otherwise `FAIL`, reason `user not present`.
   - when user verification is required, the UV flag (bit 2) is set. Otherwise `FAIL`, reason
     `user not verified`.

   The signature counter (octets 33 to 36) is reported and never checked (§8.2).
7. **Signature.** `signature` verifies under `key`, by `key.alg`, over
   `authenticator_data || SHA-256(client_data_json)`. For -7 it is DER: a BER encoding of the same
   values, such as a long-form length, does not verify. Otherwise `FAIL`,
   reason `bad signature`.

A person signature that passes every step is `PASS`.

Checking a person signature changes no state. A verifier that checks the same person signature
twice, or checks two in either order, gets the same results.

### 6.3 The result for a record

A verifier reports one property for the signed record, `person_signature`, with the IP §7.1
statuses:

| Status | When |
|---|---|
| `PASS` | at least one person signature for the record is `PASS` |
| `FAIL` | none is `PASS`, and at least one is `FAIL` |
| `NOT_CHECKED` | none is `PASS` or `FAIL`, and at least one is `NOT_CHECKED` |
| `NOT_PRESENT` | no person signature names the record's digest, including when `person_signatures` is absent |

Only `PASS` means the record is signed by the person. `FAIL`, `NOT_CHECKED` and `NOT_PRESENT`
each read as *not signed by the person*. None of them makes the signed record invalid, and none
changes any other property the verifier reports for it. A using profile that needs a person's
signature before something may rely on the record requires `PASS`.

The `method` of the report names the key type and algorithm of a `PASS`, for example
`webauthn ES256 over person-signature/0`.

## 7. What a verifier reports

1. `person_signature` with its status (§6.3).
2. For each person signature it checked: its status, its reason when it is not `PASS`, its key
   type and algorithm, and, for a `webauthn` one that reached step 7, the UP, UV, BE and BS flags
   and the signature counter as found. These are the authenticator's own statements (§8.1).
3. **What a `PASS` proves.** Whoever could use the person key made an assertion over the signed
   octets, at an allowed origin, for the relying party id, with the user-present flag set. With the
   UV flag set, the authenticator also states it verified the user. The verifier reports the
   person key, and that the using profile accepts it as the person's.
4. **What a `PASS` never proves.** A verifier MUST NOT present a person signature as establishing:
   - that the person, rather than whoever controls the key, made it (§8.1);
   - that the person saw or read the signed record. The authenticator does not show the challenge;
   - consent in the person's own words, beyond what the signed record says;
   - when the person signed. Nothing in the object carries a time the verifier can check.

## 8. Security and privacy considerations

### 8.1 Enrolment is the guarantee

A WebAuthn assertion shows that whoever could use the credential made a gesture during a ceremony
with this challenge. It does not show who that was. An authenticator implemented in software, run
by the agent's runtime, produces assertions that verify, with any flags it chooses. Synced
credentials usually carry no attestation, so nothing in an assertion tells a person's credential
from one an agent created.

So the assurance that the person, and not the agent, signed rests entirely on enrolment: on how the
using profile came to accept the key as the person's, for example at a moment the person was
present and the agent could not create the key. Step 3 of §6.2 applies that decision, and is the
step that rejects an agent's key. A verifier MUST NOT treat a `webauthn` key type, or a set UV
flag, as evidence of who holds the key.

### 8.2 Replay and the signature counter

The challenge holds the record digest (§4.1), so a person signature for one record never verifies
for another. Presenting the same person signature again with the same record shows the same
signature again, which is the purpose of carrying it. Whether one approval may authorize more than
one act is the using profile's rule.

WebAuthn relying parties compare an assertion's signature counter with a stored value to detect a
cloned authenticator. A verifier of a person signature has no stored value, and many synced
credentials always report 0. The counter is reported (§7) and never checked. A using profile that
keeps counters for its own risk checks does so outside this verification, which stays stateless
(§6.2).

### 8.3 What a person signature discloses

- **The relying party and origin.** `authenticator_data` holds SHA-256 of the relying party id, and
  `client_data_json` holds the origin in the clear. Every copy that carries a person signature
  shows where the person's credential is scoped and where the ceremony ran. A verifier needs both
  (§6.2), so they cannot be removed. This document names no relying party.
- **The person key.** Every person signature carries the person's public key. Two copies signed
  with the same credential can be linked to one key holder by anyone who holds both, for example two
  counterparties, or an adjudicator who sees both. A person who uses a separate credential for each
  counterparty avoids that link. Which credential a person uses with which counterparty is
  enrolment, which the using profile defines (§8.1, PS-2).
- **Not carried.** The credential id and the user handle are not carried (§4.2).

A holder can withhold person signatures from a copy (§5). The copy then reads `NOT_PRESENT`.

### 8.4 Malleability

An ECDSA signature can be changed into a second valid signature over the same octets. A person
signature is never named or deduplicated by the octets of its `proof`. Its record digest and its
key identify what it states.

## 9. Vectors

`vectors/person-signature-v0/` holds the conformance vectors. Each case gives one signed record's
digest, the verifier inputs of §6.1, a `person_signatures` array or none, and the expected result:
the status and reason of each person signature, and the record's `person_signature` status. The
policy negatives carry assertions that are correctly signed over what they hold, so a verifier that
checks only the signature fails them. `python/scripts/generate_person_signature_v0_vectors.py`
writes the corpus from test keys derived from public seeds, and
`python/tests/test_person_signature_v0_vectors.py` checks it with an evaluator written from §3 to
§6.

## 10. Open points

| Id | Point |
|---|---|
| PS-1 | Further key types. This revision registers only `webauthn`. A later key type, for example a wallet key, is added by a revision of this document, under the registration policy of §3.2. |
| PS-2 | Credential scope. Whether a person uses one credential with every counterparty or a separate credential for each is enrolment, which the using profile decides (§8.3). |
| PS-3 | Attestation. A using profile may require an attestation at enrolment to learn more about the authenticator. This document does not carry or check one. |
