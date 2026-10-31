# Controller Binding — v0

**Status.** Informational, pre-Internet-Draft, kept in this repository. It changes no
Internet-Draft. It defines one signed object, the **binding record**, by which the holders of two
signing keys jointly state how the two keys are related, and the properties a verifier reports for
it. The Minimum Evidence Interoperability Profile (`spec/interop-profile-v0.md`, cited here as IP)
uses it in issuer independence (IP §6.7.4). It is proposed as a `composed/v1` join basis for a
later revision of the Evidence Bundle draft (§8). Where this document needs a rule that no other
document states, it lists it under [Open points](#11-open-points) (CB-1, CB-2, …).

A binding record shows that whoever held each of the two private keys signed it. That is all its
signatures show. It does not show who controls either key, and it never establishes an identity.

## Dependency boundary

**Owns:** the binding record, its member names and signing input (§3, §4), the claim types and
their verification methods (§3.2), the key types and how each signs (§3.3, §4.1), the revocation
statement (§5), the declaration of a complete revocation list (§5.1), the binding properties (§6),
what a verifier reports (§7), and the proposed `controller_binding` join basis (§8).

**Uses unchanged:**

| Tag | Document | What this document takes from it |
|---|---|---|
| IP | `spec/interop-profile-v0.md` (`evidence-interop/0`) | the value conventions (§5.2), the as-transmitted rule for foreign objects (§5.1), the per-property status vocabulary (§7.1), issuer independence (§6.7.4) |
| EB | `draft-mih-zhang-agent-disclosure-bundle` -01 working revision (`spec/draft-mih-zhang-agent-disclosure-bundle-01.md`) | the `composed/v1` block, its joins and its redundancy rule ("The composed/v1 Extension") |
| BIP-340 | Bitcoin Improvement Proposal 340, "Schnorr Signatures for secp256k1" | x-only public keys and signature verification, for the `bip340` key type (§3.3, §4.1) |
| NIP-01 | Nostr Implementation Possibilities 01, "Basic protocol flow description" | the event, its serialization and its id, for the `bip340` key type (§4.1) |

**Interop profile revision.** This profile stays on `evidence-interop/0`: IP is
`spec/interop-profile-v0.md` as of commit `1456285979bd759b7828fd3ccc4a24296074e552`, which is
frozen, not `spec/interop-profile-v1.md` (`evidence-interop/1`). The IP sections it cites (§5.1,
§5.2, §6.7.4, §7.1) are the same in `evidence-interop/1`, which changes only the ER pin, the refusal
reasons and their mapping (IP v1 P-65). Re-pinning to `evidence-interop/1` is a revision of this
profile.

**Does not define:** any identity, account or naming scheme; any identity provider; any registry of
keys, controllers or organizations; any trust policy; how two key holders meet to sign; or what a
relying party should conclude from a binding.

## 1. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

Terms from IP §1 are used unchanged. This document adds:

- **Bound keys:** the two keys a binding record names in `keys`.
- **Key holder:** whoever can sign with a bound key. This document says nothing about who that is.
- **Ceremony:** the signing of one binding record by both key holders. The two signatures need not
  be made at one moment, and nothing in the record shows when either was made. `issued_at` is the
  time the signers state (CB-2).
- **In effect at T:** a binding is in effect at time T when `not_before` ≤ T < `not_after` and no
  revocation statement that applies (§5) has `revoked_at` ≤ T.

All values follow IP §5.2: digests and key identifiers are 64 lowercase hexadecimal characters, a
key identifier is a raw Ed25519 public key, signatures are Ed25519, and times are RFC 3339 UTC with
`Z` and seconds precision. The one exception is a bound key whose key type (§3.3) is not
`ed25519`: its key identifier and its signatures follow that key type (§4.1).

## 2. What a binding is for

Two keys can sign records that agree with each other: for example a node key that runs a service
and a holder key that a personal agent signs with. A relying party that sees the two signatures
cannot tell whether two parties stated the same thing, or one party stated it twice (IP §6.7.4).
A binding record is how the key holders themselves say which it is. It is used in two ways:

1. **Issuer independence** (IP §6.7.4). A binding that applies to two members presented as
   corroborating makes the pair *redundant, not corroborating*. It never makes them corroborating,
   and a binding that does not apply leaves the pair where it would be without one.
2. **Joining two families of records** (§8). Records signed under the two bound keys can be joined
   as records about the activity of keys whose holders bound them, for example a service History and a personal
   History, without either key holder revealing who they are.

## 3. The binding record

### 3.1 Members

A binding record is a JSON object with exactly these members, plus the ones its claim type adds
(§3.2):

| Member | Value |
|---|---|
| `binding_version` | the text string `controller-binding/0` |
| `claim` | one claim type of §3.2 |
| `method` | a verification method token: one of §3.2 for that claim type, or one this revision does not define |
| `keys` | an array of exactly two distinct key identifiers, in ascending order |
| `key_types` | OPTIONAL: an array of exactly two key type tokens (§3.3), one per entry of `keys` and in its order. When it is absent, both keys are `ed25519` |
| `issued_at` | a time: the ceremony, as the signers state it |
| `not_before` | a time, not later than `issued_at`. An earlier `not_before` is the signers' statement about records signed before the ceremony, and nothing checks it |
| `not_after` | a time, later than `issued_at` |
| `revocation` | the revocation method; this revision defines one, `revocation_statement/0` (§5) |
| `nonce` | a text string chosen for this ceremony, so that two ceremonies over the same keys and times give two records. When `key_types` names a `bip340` key, at least 32 lowercase hexadecimal characters (§9.3) |
| `sigs` | an array of exactly two objects `{key_id, sig}`, one per bound key, in the order of `keys` (§4) |

A binding record with a duplicate member name, a missing member other than `key_types`, a member
this section or §3.2 does not list for its claim type, or a value outside its form is malformed. So is a record whose
`method` is defined in §3.2 for another claim type, and a record whose two `keys` are the same key:
a key bound to itself is redundant, and binding it states nothing.

### 3.2 Claim types and their verification methods

| `claim` | Added members | `method` | The two key holders state |
|---|---|---|---|
| `same_controller_asserted` | none | `dual_signature/0` | that one controller holds both keys |
| `delegated_by` | `delegator`: one of `keys` | `dual_signature/0` | that the holder of `delegator` delegated to the holder of the other key, who accepted |
| `same_organization_credentialed` | `credential`: `{issuer, method, digest}` | `dual_signature_credential/0` | that both keys are held within one organization, as the credential states |

- **`dual_signature/0`:** both bound keys sign the signing input of §4. Both signatures verifying
  is the whole method.
- **`dual_signature_credential/0`:** `dual_signature/0`, plus a credential: a signed object from a
  third key, `credential.issuer`, stating that both bound keys belong to one organization.
  `credential.digest` is the SHA-256 of the credential's octets as transmitted (IP §5.1), and
  `credential.method` names the credential's native verification method. The credential is
  delivered beside the binding record, and how is the using profile's choice. This revision
  registers no credential format (CB-3). The organization is whatever the credential names. A
  verifier compares it with nothing and never presents it as an identity.

A verifier that does not implement a record's `method`, including a method this revision does not
define, reports `controller_binding_signatures` as `NOT_CHECKED` (IP §7.1). The record is then not
used (§6.2), because its signatures were not verified.

`delegated_by` states a relation, not a scope. It does not say what was delegated, and a verifier
reads no authority from it (CB-4).

### 3.3 Key types

A key type says what a key identifier is and how that key signs (§4.1). An Ed25519 public key and a
BIP-340 public key are both 32 octets, so a verifier cannot tell them apart from the key
identifier. The record states the type of each key in `key_types`, and both keys sign it, so
neither key holder can change the other key's type without that key's signature.

| Token | Key identifier | Signs by |
|---|---|---|
| `ed25519` | a raw Ed25519 public key (RFC 8032) | Ed25519 over the signed octets |
| `bip340` | a BIP-340 x-only secp256k1 public key, the key a Nostr identity (NIP-01) is | a Nostr event over the signed octets' digest (§4.1) |

A record whose `key_types` holds a token this table does not list is well formed. A verifier
reports its `controller_binding_signatures` as `NOT_CHECKED`, as for a method it does not
implement (§3.2), and the record is then not used (§6.2). A verifier that implements this revision
implements both tokens.

A key type is a statement about the key, not about who holds it. A `bip340` key is often a Nostr
identity, and binding it links that identity to the other key wherever the record is shown (§9.3).

## 4. Signature coverage

The **signing input** is the UTF-8 octets of the JCS (RFC 8785) serialization of the binding record
with `sigs` removed. Every other member is covered, including `claim`, `method`, both `keys`, the
claim type's added members, the three times, `revocation` and `nonce`.

**Both bound keys sign the same signing input.** `sigs[0].key_id` is `keys[0]` and `sigs[1].key_id`
is `keys[1]`, and each `sig` is that key's signature over the signing input, made as its key type
says (§4.1). A record that
lacks either signature, carries a signature that does not verify, or carries a third entry is not a
binding: `controller_binding_signatures` is `FAIL`. One key cannot bind another key to itself.
Because each key signs the other key's identifier, neither key holder can add or replace the other
key without that key's signature.

The **binding digest** is the SHA-256 of the signing input. It does not cover `sigs`, so a binding
keeps its digest if either key signs it again. A revocation statement (§5) and a join (§8) name a
binding by its digest. A revocation therefore reaches every copy of the record, whatever signatures
it carries. Two ceremonies over the same keys differ in `nonce` and so have two digests.

### 4.1 How each key type signs

A signature names what it signs: the signed object's version (`controller-binding/0` for a binding
record, `controller-binding-revocation/0` for a revocation statement, §5) and its **signed octets**
(the signing input of a binding record, or a revocation statement's octets of §5).

- **`ed25519`:** `sig` is 128 lowercase hexadecimal characters: the Ed25519 signature over the
  signed octets.
- **`bip340`:** `sig` is an object with exactly two members:

  | Member | Value |
  |---|---|
  | `created_at` | a non-negative integer, at most 2^53 − 1: the event's `created_at` |
  | `sig` | 128 lowercase hexadecimal characters: the event's BIP-340 signature |

  The **signing event** is the Nostr event (NIP-01) with `pubkey` the key identifier, `created_at`
  as above, `kind` 3374, `tags` an empty array, and `content` the text string `<version>:<digest>`,
  where `<version>` is the signed object's version and `<digest>` is the SHA-256 of the signed
  octets, in lowercase hexadecimal. A verifier rebuilds the event id as NIP-01 defines it, the
  SHA-256 of the UTF-8 octets of `[0,"<pubkey>",<created_at>,3374,[],"<content>"]` with no
  whitespace, and verifies `sig` over that id under BIP-340.

The `bip340` form exists so that a key holder signs with the tools that already hold a Nostr
key, which sign events and not arbitrary octets. The event is never published (§9.3), and
`created_at` is the signer's clock, which nothing checks; the binding's times are its own (CB-2).
The kind is provisional (CB-8).

## 5. Revocation

Either key holder can withdraw a binding. A **revocation statement** is a JSON object with exactly
these members:

| Member | Value |
|---|---|
| `revocation_version` | the text string `controller-binding-revocation/0` |
| `binding` | the binding digest (§4) |
| `key_id` | one of the binding's two `keys` |
| `revoked_at` | a time |
| `sig` | by `key_id`, as the binding's `key_types` gives that key's type (§4.1), over UTF-8 of JCS of the other four members |

A revocation statement **applies** to a binding when its form is valid, `binding` equals the
binding's digest, `key_id` is one of its `keys`, and `sig` verifies. From `revoked_at` on, the
binding is not in effect. A binding revoked after T was in effect at T. `revoked_at` is the revoking
key holder's statement, and nothing stops it from being dated earlier than the statement was made.
A key holder who backdates a revocation removes the binding's effect on the pairs it covered. Those
pairs then go back to where they would be with no binding (§6.2), never above.

Revocation statements are delivered beside the binding, and how is the using profile's choice. This
revision registers no place to fetch them from (CB-1). A verifier therefore knows only of the
statements it received, unless a using profile declares a list of them complete (§5.1).

### 5.1 A list declared complete

A using profile MAY name, for a binding, one **revocation list**, and the party that asserts it is
complete: that every revocation statement for the binding made by the list's `as_of` is in it. For
the profile, that party is the one that pins the list's octets, for example the run that publishes
them. The **revocation list** is a JSON array of revocation statements (§5), as transmitted.

The **declaration** is what the using profile gives the verifier beside the list: a JSON object
with exactly these members.

| Member | Value |
|---|---|
| `profile` | a text string: the using profile that names the list |
| `asserted_by` | a text string: the party the profile names as asserting that the list is complete |
| `binding` | the binding digest (§4) of the binding the list is for |
| `list_digest` | the SHA-256 of the list's octets as transmitted (IP §5.1) |
| `as_of` | a time: the list is asserted complete up to it |
| `max_age` | an integer from 0 to 2^53 − 1: the profile's freshness bound, in seconds |

The declaration **counts** for a binding at the times T and an evaluation time E when all of these
hold, and otherwise it does not:

- it has exactly the members above, each in its form;
- `binding` is the binding's digest. A list for another binding says nothing about this one;
- `list_digest` is the SHA-256 of the list's octets as received, and they are a JSON array;
- `as_of` is not earlier than any T, so the list covers every statement dated at or before T that
  was made by `as_of`;
- `as_of` is not later than E, and E is at most `max_age` seconds after `as_of`.

Each entry of the list is a received statement (§5): one that applies is a revocation whether or
not the declaration counts, and one that does not apply is ignored, as any received statement is.
When the list's octets are not a JSON array, it has no entries, and the declaration does not count.

A declaration that counts is the asserting party's statement, not the verifier's finding. It shows
that no statement in the list applies at T, and nothing more. A statement made after `as_of`, even
one whose `revoked_at` is earlier than T, can still withdraw the binding (§5), and the list does
not exclude it. A declaration is not signed in this revision: the using profile is what makes it
the asserting party's, as it makes the list's octets theirs by pinning them.

## 6. Binding properties

### 6.1 The properties

A verifier reports each property in the IP §7.1 vocabulary, with its method. T is the time or times
the binding is asked about: for a pair under IP §6.7.4, each member's `issued_at`.

| Property | Check |
|---|---|
| `controller_binding_form` | the record is well formed (§3.1, §3.2) |
| `controller_binding_signatures` | both entries of `sigs` are present, name `keys` in order, and verify over the signing input by each key's type (§4, §4.1), with no third entry; `NOT_CHECKED` when the verifier does not implement `method` or a key type in `key_types` |
| `controller_binding_window` | the binding is in its window at every T: `not_before` ≤ T < `not_after`. The window is the signers' statement; the check is against it, not against when the keys were in fact held |
| `controller_binding_revocation` | `FAIL` when a received revocation statement applies with `revoked_at` ≤ some T, from a declared list (§5.1) or delivered otherwise; otherwise `PASS` when a declaration counts (§5.1); otherwise `NOT_CHECKED`, because a statement the verifier did not receive cannot be excluded (CB-1) |
| `controller_binding_credential` | `same_organization_credentialed` only: the credential is present, hashes to `credential.digest`, verifies by `credential.method` under `credential.issuer`, `credential.issuer` is accepted by the relying party's trust policy, and the credential names both bound keys. `FAIL` when any of these fails, as `responder_trust` does for an unaccepted key (IP §7.2). `NOT_PRESENT` when it was not delivered, `NOT_CHECKED` when the verifier does not implement `credential.method`, `INCONCLUSIVE` when the trust policy cannot decide |

When `controller_binding_form` is `FAIL`, no other binding property is reported. A property that
does not apply to the claim type is not reported. `controller_binding_revocation` is `PASS` only
under a declaration that counts (§5.1). Its method is then the declaration: a verifier reports the
`profile`, `asserted_by`, the list's digest and `as_of`, and presents the `PASS` as `asserted_by`'s
statement that the list was complete as of `as_of`, under that profile. With no declaration, or one
that does not count, a verifier reports what it would report with no list, and the list's entries
are still received statements.

### 6.2 When a binding applies to a pair

A binding **binds a pair** when its two `keys` are exactly the keys the pair's two members are
signed under, in either order.

A binding **applies** to a pair when it binds the pair, `controller_binding_form`,
`controller_binding_signatures` and `controller_binding_window` are `PASS`, and
`controller_binding_revocation` is not `FAIL`. A binding that is expired, revoked, signed by one
key, under a method the verifier does not implement, or malformed does not apply. Such a pair is
treated as if it had no binding.

`controller_binding_credential` does not decide whether a binding applies, whatever its status.
Both key holders signed the claim, and that alone states that their keys are not independent
issuers (§7). The credential only adds what a trusted issuer states (§7 item 2). A credential that
fails is reported, and its failure is a conformance failure of the credential, not of the two
signatures.

**No binding raises a result.** A binding that applies gives `FAIL` (§7 item 4). A binding that does
not apply gives what the pair would get with no binding. Neither ever gives `PASS`, and so no path
through a binding produces corroboration. A revocation statement, the window and a failed
signature can each stop a binding from applying, and so take the pair back to that baseline, never
above it. A verifier uses every binding it received for the pair (§9.1).

## 7. What a verifier reports

1. The claim type, the two bound keys, `delegator` where present, the window, and every property
   of §6 that applies.
2. **What the binding proves.** When `controller_binding_form` and `controller_binding_signatures`
   are both `PASS`, whatever the window and revocation, a verifier reports that the binding proves
   *control of each key when it signed the record*: whoever held each private key signed these
   bytes. It reports the claim as *stated by both key holders*. For
   `same_organization_credentialed` with `controller_binding_credential` `PASS`, it adds that a
   trusted issuer key stated the same. When either of those two properties is not `PASS`, the
   binding proves nothing, and the verifier says so. Whether the binding applies to a pair is
   reported separately (item 4).
3. **What it never proves.** A verifier MUST NOT present a binding as establishing:
   - who controls either key;
   - a person, name, account, organization identity or legal relationship;
   - that the keys were under one control at any time. The window, and the claim within it, are
     what both key holders stated, and the verifier reports them as that;
   - that two keys with no binding between them have distinct controllers;
   - that no revocation statement exists, when `controller_binding_revocation` is `PASS`. The
     `PASS` is the asserting party's statement about one list as of `as_of` (§5.1).

   A binding never raises a result (§6.2): it can make a pair redundant, never corroborating. The
   ceremony time is the signers' own statement (CB-2).
4. For a pair under IP §6.7.4, whether the binding binds the pair and whether it applies (§6.2),
   and the `issuer_independence` it gives:

   | The pair | `issuer_independence` | Shown as |
   |---|---|---|
   | both members signed by one key | `FAIL` | "redundant, not corroborating": same key |
   | two keys, and at least one binding received that applies to the pair | `FAIL` | "redundant, not corroborating": the binding's claim type and digest |
   | two keys, and no binding that applies | `NOT_CHECKED` | "not corroborating" |

**Why a binding gives `FAIL`, never `PASS`.** Each claim type is a statement by both key holders
that the two keys are not independent issuers: they have one controller, one acts for the other,
or they sit in one organization. Corroboration needs distinct controllers, and a binding is
evidence of the opposite. If a binding could give `PASS`, the holder of two keys could sign one
binding and turn two of their own signatures into corroboration. This is the rule the Evidence
Bundle applies to same-custody members ("redundant, not corroborating"), applied to keys. Evidence
that two keys have *distinct* controllers is still open (IP P-60).

## 8. The `controller_binding` join basis

### 8.1 Proposed derivation

EB's `composed/v1` joins name a linkage basis from a closed list ("Joins"). This document proposes
one more basis, `controller_binding`, for the next revision of EB:

- `identifier_digest` is the binding digest (§4). `pointer` selects a key identifier in each
  member's root record, for example its `key_id`. The two selected values differ: they are the two
  keys.
- The binding record is delivered beside the block, as a population object is beside a History
  (IP §6.7.1). It is not a member of the block, so the composed digest binds the binding through
  `identifier_digest` alone.
- The two members are *linked* when all of these hold:
  - the delivered record's binding digest equals `identifier_digest`;
  - the two values `pointer` selects are the record's two `keys`, one in each root record;
  - the record applies (§6.2) to those two keys, with T the time each root record was issued.
- Once the members are linked, `compare` gives `agree` or `mismatch` exactly as EB says. EB's join
  says two records are about the same thing. Under this basis, that thing is the activity of the
  keys' holders, as both of them stated it.
- A verifier that does not have the binding record, or does not implement this basis, reports the
  join as `not_derivable`, as EB requires for any basis it cannot derive.
- A `controller_binding` join that derives `agree` is `redundant`: it is added to the cases in
  EB's "Observers and Redundancy". The linked members' keys are not independent issuers (§7), so
  their agreement is not corroboration.

This is how a composite joins two families of records: service records under a node key with a
personal agent's records under a holder key. The join shows the two records are under keys whose
holders bound them. It says nothing about who those holders are.

### 8.2 How it is registered in this revision

EB `-01` is an unposted working revision, and its `join-basis` is a closed list. This document does
not edit it. Until an EB revision adds `controller_binding` to `join-basis`, an EB `-01` verifier
reads a `composed/v1` block carrying it as malformed. So:

1. `controller_binding` is listed in `REGISTRY.md` under "Provisional: composed/v1 join basis
   values", **held for ratification and not yet registered**, alongside EB's four values for
   reference.
2. A producer MUST NOT put a `controller_binding` join in a `composed/v1` block until a posted EB
   revision lists it.
3. Until then, the binding is used only beside the composition, under IP §6.7.4. A verifier
   compares two members presented as corroborating, and the binding makes them redundant.

Adding the basis to EB is a change to a co-authored draft and needs its authors' agreement (CB-5).

### 8.3 Declared and derived join states

The producer declares the join state it derived. A verifier that received a revocation statement
the producer did not have derives a different state: the binding does not apply, and the join is
`unjoined`. EB reports a declared state that does not match the derived one as
`join_state_mismatch`, which fails the block. That is EB's rule, and this document does not change
it (CB-7). A producer and a verifier that read one list a using profile declared complete (§5.1)
have the same statements from it, though either may also have others.

## 9. Security considerations

### 9.1 Who delivers a binding

Any party can deliver a binding record to a verifier. That includes the presenter of the pair, a
relying party, or a third party. A verifier uses every binding it received that binds the pair.

- **A presenter that leaves out a binding** gets the pair's no-binding result. That result is
  `NOT_CHECKED`, "not corroborating", so leaving out a binding gains the presenter no corroboration.
- **A third party that delivers an old binding** can make a pair redundant, but only with a record
  that both keys signed and that is in its window. If a key has changed hands since then, the
  binding still shows the old holder's statement. The old holder revokes it, or the window ends it.
  Until then, the pair is reported as redundant. This is the conservative direction: a pair that
  really is independent loses corroboration it could not have shown anyway (IP P-60).

### 9.2 Signed objects

The binding record, the revocation statement and the IP objects (the envelope, the refusal, the
absence record and the producer record of IP §11.5) are each signed over UTF-8 of JCS of a JSON
object. They are told apart by their member sets. The binding record and the revocation statement
also carry a version member that names them, `binding_version` and `revocation_version`, which no
other object has. A key holder SHOULD sign a binding record only when it has read the whole record,
and in particular the other key and the claim. A signature over JCS of an object someone else
composed is a signature over whatever that object says.

### 9.3 A `bip340` key and its Nostr identity

A `bip340` key is usually a Nostr identity that its holder uses elsewhere. A binding record names
it in the clear, so anyone shown the record can link the other key to everything that identity has
signed. A key holder SHOULD show the record only to the parties that need to verify it. Where the
record is listed publicly, the binding digest alone (§4) can name it. The digest does not cover
`sigs`, and every other member but `nonce` can be guessed: the keys from a list of candidates, the
times to the second. So `nonce` alone keeps a listed digest from being matched to a guessed pair
of keys. A binding record whose `key_types` names a `bip340` key MUST carry a `nonce` of at least
32 lowercase hexadecimal characters, and its key holders MUST draw it from at least 128 bits of a
cryptographically secure random source. A verifier checks the form (§3.1) and cannot check the
randomness. Which of these a using profile chooses is outside this document (CB-9).

The signing event of §4.1 is a valid Nostr event. A key holder SHOULD NOT publish it to a relay,
which would publish the link. Its kind and its `content` (a version and a digest) keep it from
being read as any other event: it is a signature over one binding record and nothing else.

### 9.4 A list declared complete

A declaration (§5.1) is only as good as the party the using profile names, and the verifier cannot
check that the list is in fact complete. A false declaration changes no result a binding gives:
`controller_binding_revocation` `PASS` and `NOT_CHECKED` both leave the binding applying (§6.2), so
the pair is redundant either way. What it changes is what the verifier reports: that the asserting
party stated no statement in the list applies. A declaration that does not count, or a list that
cannot be read, gives `NOT_CHECKED`, never `FAIL`. Only a statement that applies gives `FAIL`, so a
party that can corrupt a list's delivery cannot use it to stop a binding from applying.

## 10. Vectors

The vectors are in `vectors/controller-binding-v0/`.
`python/scripts/generate_controller_binding_v0_vectors.py` generates them, and
`python/tests/test_controller_binding_v0_vectors.py` checks them. Each case is a pair of agreeing
halves (the producer record of IP §11.5) plus a binding record, and some cases add revocation
statements, a declared revocation list (§5.1) or a credential. They pin trust, verification policy,
contract and evaluation time as IP §11.5 does. The evaluation time is E for a declaration (§5.1).

These formats are fixed for the vectors only and are not registered:

- the credential: `issued_at`, `issuer`, `keys` (the two bound keys, ascending), `organization`
  (an opaque label digest) and `sig`, where `sig` is Ed25519 by `issuer` over UTF-8 of JCS of the
  other members;
- its method, `Ed25519 over UTF-8 of JCS of the credential's other members (controller-binding-v0 §10, vectors only)`.

| Case | What it shows |
|---|---|
| `valid-same-controller` | a `same_controller_asserted` binding that applies: `issuer_independence` `FAIL`, redundant |
| `valid-delegated-by` | a `delegated_by` binding that applies: `FAIL`, redundant |
| `valid-same-organization-credentialed` | credential `PASS`, binding applies: `FAIL`, redundant |
| `credential-method-unimplemented` | credential `NOT_CHECKED`, binding still applies: `FAIL`, redundant |
| `revoked-after-the-pair` | a revocation dated after both halves: revocation `NOT_CHECKED`, binding applies |
| `expired` | window `FAIL`: the binding does not apply, `NOT_CHECKED` |
| `revoked` | a revocation by one bound key before the halves: revocation `FAIL`, `NOT_CHECKED` |
| `one-key-signed` | only one bound key signed: signatures `FAIL`, the record is not a binding, `NOT_CHECKED` |
| `same-key-halves` | both halves and both `keys` are one key: form `FAIL` (a key bound to itself is redundant), and `issuer_independence` `FAIL` by the same-key rule |
| `other-keys` | a valid binding of one half's key to a third key: it does not bind the pair, `NOT_CHECKED` |
| `credential-forged` | a credential naming the issuer and signed by another key: credential `FAIL`, and the binding still applies on the two keys' signatures: `FAIL`, redundant |
| `unknown-method` | a method this revision does not define, over two valid signatures: signatures `NOT_CHECKED`, the binding does not apply, `NOT_CHECKED` |
| `delegator-not-bound` | `delegated_by` whose `delegator` is neither bound key: form `FAIL`, `NOT_CHECKED` |
| `revocation-by-other-key` | a revocation before the halves, signed by a key the binding does not bind: it does not apply, so revocation is `NOT_CHECKED` and the binding applies |
| `valid-nostr-key` | a `same_controller_asserted` binding of a half's Ed25519 key to a `bip340` key, signed by the Nostr event of §4.1: form, signatures and window `PASS`. It does not bind the pair, whose other half is under another key: `NOT_CHECKED` |
| `nostr-key-read-as-ed25519` | the same keys and signatures with no `key_types`, so both keys are `ed25519`: the `bip340` key's object `sig` is not an Ed25519 signature, signatures `FAIL` |
| `nostr-wrong-digest` | the Nostr event's `content` names the digest of another record (another `nonce`): signatures `FAIL` |
| `nostr-other-kind` | the Nostr event is of kind 1 (a text note) over the right `content`: signatures `FAIL` |
| `nostr-revoked` | a revocation by the `bip340` key, signed by the Nostr event, before the halves: revocation `FAIL`, the binding does not apply |
| `nostr-nonce-short` | a binding with a `bip340` key whose `nonce` is `ceremony-1`: form `FAIL` (§3.1, §9.3) |
| `nostr-sig-malformed` | the `bip340` key's `sig` object carries a third member beside a valid signature: signatures `FAIL` |
| `nostr-created-at-negative` | the Nostr event is validly signed over a `created_at` of −1, which §4.1 does not allow: signatures `FAIL` |
| `nostr-created-at-text` | the same over a `created_at` written as text: signatures `FAIL` |
| `key-types-malformed` | `key_types` names one type for two keys: form `FAIL` |
| `key-types-unknown` | `key_types` names a token §3.3 does not list: signatures `NOT_CHECKED`, the binding does not apply; a revocation by that key signed with Ed25519 does not apply either, so revocation is `NOT_CHECKED` |
| `no-half-key-bound` | a valid binding of a third key to the `bip340` key, naming neither half's key: form, signatures and window `PASS`, it does not bind the pair, `NOT_CHECKED` |
| `complete-list` | a revocation list declared complete (§5.1) as of a time after both halves, with no statement in it: the declaration counts, revocation `PASS`, the binding applies: `FAIL`, redundant |
| `complete-list-statement-by-other-key` | the same with a statement before the halves by a key the binding does not bind: it does not apply and is ignored, revocation `PASS` |
| `complete-list-revoked` | the same with a statement by a bound key before the halves: revocation `FAIL`, the binding does not apply, `NOT_CHECKED` |
| `complete-list-stale` | `as_of` is the first half's time, earlier than the second's: the declaration does not count, revocation `NOT_CHECKED`, the binding applies |
| `complete-list-past-max-age` | `as_of` after the halves, but the evaluation time is more than `max_age` after it: does not count, `NOT_CHECKED` |
| `complete-list-as-of-future` | `as_of` after the evaluation time: does not count, `NOT_CHECKED` |
| `complete-list-other-binding` | the declaration names another binding of the same keys: does not count, `NOT_CHECKED` |
| `complete-list-digest-mismatch` | `list_digest` is not the digest of the list delivered: does not count, `NOT_CHECKED` |
| `complete-list-not-an-array` | the list's octets are a JSON object: it has no entries and does not count, `NOT_CHECKED`, never `FAIL` (§9.4) |

No case reaches `issuer_independence` `PASS`. Nothing in this revision gives it (IP P-60).

## 11. Open points

| Id | Point |
|---|---|
| CB-1 | Revocation distribution. No place to fetch revocation statements is registered. A using profile may declare its own list complete (§5.1), and under a declaration that counts `controller_binding_revocation` is `PASS`, as the asserting party's statement. With no such declaration it is `FAIL` or `NOT_CHECKED`, never `PASS`, and a binding still applies under `NOT_CHECKED`, because it only lowers a result. Still open: a registered source that every verifier can query, and a declaration signed by the asserting party. |
| CB-2 | The ceremony time is the signers' statement. Nothing anchors `issued_at`. A binding whose record is counter-signed by a time source or included in a log would show when the ceremony happened, and no such form is registered. |
| CB-3 | Credential format. `same_organization_credentialed` names its credential by digest and native method. No credential format is registered. The vectors fix one for themselves only (§10). |
| CB-4 | Delegation scope. `delegated_by` has no scope member. A scope would be a claim about authority, which this document does not make. |
| CB-5 | Registration of `controller_binding` as an EB join basis (§8). It needs a posted EB revision that adds it to `join-basis` and to the redundancy cases, with its co-authors' agreement. Until then it is provisional in `REGISTRY.md`. |
| CB-6 | More than two keys. A record binds exactly two keys. Three keys under one controller take three records, one per pair. |
| CB-7 | A revocation the producer of a `composed/v1` block did not have makes a declared `agree` a `join_state_mismatch` (§8.3). A later EB revision may report that join as `not_derivable`, or as a finding on the join alone, rather than failing the block. |
| CB-8 | The Nostr event kind of §4.1, 3374, is chosen from the kinds no NIP lists. It is provisional in `REGISTRY.md` and not registered with the NIPs. |
| CB-9 | Showing a `bip340` key. Whether a using profile lists a binding record, or only its digest, where anyone can read it is the using profile's choice (§9.3). A binding verifies the same either way. |

## 12. Changes

Changes to this revision are additive: a record, statement or verifier input that does not use
them gives every result it gave before.

| Change | What it adds |
|---|---|
| agent-action-capsule#458 | the `bip340` key type and how it signs (§3.3, §4.1, §9.3), the optional `key_types` member, and CB-8 and CB-9 |
| agent-action-capsule#482 | a revocation list a using profile declares complete (§5.1, §9.4), under which `controller_binding_revocation` can be `PASS` (§6.1); CB-1 narrowed |
