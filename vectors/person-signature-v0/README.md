# Person signature v0: conformance vectors

These vectors exercise `spec/person-signature-v0.md` (cited as PS): a person's signature, made with
the person's own key, over the digest of a record that another party signed, carried beside that
record in `person_signatures`. They cover:

- the object's form and its `webauthn` key and proof (PS §3, §4.2);
- the signed octets, `person-signature/0:<record_digest>`, as the WebAuthn challenge (PS §4.1);
- the seven verification steps, in order, with the verifier inputs the using profile supplies
  (PS §6.1, §6.2);
- the record's `person_signature` status when it has no, one or several person signatures (PS §5,
  §6.3).

Every case cites the sections its expected values come from.

## Derivation

`python/scripts/generate_person_signature_v0_vectors.py` writes every file except this README. It
uses no repository implementation, and it states every expected status and reason by hand from
PS §6. The record digests are stand-ins, since the using profile defines the real one (PS §1).

The policy negatives (a wrong type, challenge, origin, cross-origin ceremony, relying party, a
clear UP or required UV flag, a key that is not a person key, a record signer key) and the
malformed authenticator data and client data carry assertions that are correctly signed over the
authenticator data and client data they hold. A verifier that checks only the signature
therefore fails each of them.

`python/tests/test_person_signature_v0_vectors.py` checks the corpus from the case inputs alone,
with an evaluator written from PS §3 to §6:

- It compares the evaluator's result with each case's `expected` block.
- It checks that every policy negative's signature verifies.
- It runs defective evaluators, each of which leaves out one check and must disagree with at least
  one case.
- It regenerates the directory twice and requires both runs to be byte-identical to the committed
  files.

## Test keys

`test_keys` lists each key with its public seed label. An Ed25519 private key is the 32-byte seed
SHA-256(seed_label). A P-256 private scalar is int(SHA-256(seed_label)) mod (n − 1) + 1. ES256
signatures use deterministic ECDSA (RFC 6979), so the corpus is reproducible. The relying party
`rp.example` and the origins are example names. Never use a key or name here for anything else.

## Case format

Each case has `id`, `title`, `cites`, `inputs` (PS §6.1: `target_record_digest`, `person_keys`,
`excluded_keys`, `relying_party_id`, `allowed_origins`, `allowed_top_origins` and
`user_verification_required`), `person_signatures` when the record has any, and `expected`. Three
cases, `malformed-duplicate-member`, `malformed-duplicate-key-member` and
`malformed-duplicate-proof-member`, give the array instead as JSON text in
`person_signatures_json`, because a JSON object in `vectors.json` cannot hold a duplicate member.
`expected` holds:

- `signatures`: one entry per person signature whose `record_digest` equals the target, with its
  `index` in `person_signatures`, `status` and `reason` (PS §6.2). An entry that reached step 7 also
  has `flags` (UP, UV, BE, BS) and `sign_count`, and a `PASS` has `method` (PS §7);
- `person_signature`: the record's status (PS §6.3);
- `fails`: the check a negative is there to fail (`form`, `type`, `challenge`, `origin`,
  `cross_origin`, `client_data`, `authenticator_data`, `rp_id`, `up`, `uv`, `person_key`,
  `excluded_key` or `signature`), or `null`.
