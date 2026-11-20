# Card statements beside a Standard History card: conformance vectors

These vectors exercise `spec/standard-history-v0.md` §13: a card statement (a SCITT Transparent
Statement under the holder key over the SHA-256 of the card octets, with RFC 9942 Receipts in its
`receipts` header) and the check `card_registered` over the statements beside one card.

## Derivation

`python/scripts/generate_card_registration_v0_vectors.py` builds every statement and Receipt and
writes every per-statement result by hand from §13; the card-level status, service and time
are derived from those results by §13.3's aggregation rule. It reuses the CBOR encoder, RFC 9162 tree and P-256
signer of `generate_anchor_witness_v1_vectors.py` and imports no implementation. The card is
`person-3-months` of `vectors/standard-history-v0/vectors.json`, as JCS octets. Keys are test keys
derived from public labels, so the directory regenerates byte for byte.

## The corpus

`vectors.json` holds `policies` (the shared transparency policy, `default`, in the form of
`spec/interop-profile-v1.md` §6.2.2's witness policy) and `cases`. Each case gives:

| Member | What it is |
|---|---|
| `card` | the card octets, as hex |
| `holder` | the holder key identifier (the envelope's `responder`): a raw Ed25519 key, 64 lowercase hex characters |
| `anchor` | the envelope's `anchor.digest`, 64 lowercase hex characters |
| `statements` | the card statements beside the card, in the order received, each as hex of its octets |
| `policy` | `"default"`, or an inline policy: `{"witnesses": [{"name", "keys": [<hex DER SubjectPublicKeyInfo>]}]}` |
| `expected` | the report: `status`, one `{status, service, registration_time}` per statement, and the card's `service` and `registration_time` |

Times are NumericDates. A consumer compares the whole `expected` object.

## The cases

Positive: one statement with an EdDSA Receipt with and without a registration time, with an ES256
Receipt, a failing Receipt before a passing one, two passing Receipts (the earlier time with its
service), a `kid`, a content type and another CWT claim, a private-use label, a protected header over 64 KiB (a
65,536-octet private-use value), a passing statement beside a failing one (one of them a large
statement whose signature fails), and two passing statements.

`NOT_PRESENT` and `NOT_CHECKED`: no statement, an empty policy, and an ES256 Receipt under a policy
with Ed25519 keys only. Aggregation: a statement not checked beside a passing one (`PASS`) and
beside a failing one (`FAIL`), and one statement with a Receipt not checked and one failing (`FAIL`).

Negative (MUST reject, `FAIL`): a statement over another card, the card octets changed, a statement
signed by another key, an `iss` of another key, a `sub` of another anchor, a tampered statement
signature, a Receipt over the card digest instead of the statement entry, a Receipt by an unlisted
service, a tampered Receipt, and departures from the one form: an untagged COSE_Sign1, an outer tag 17, a 63-octet signature, a text
`kid`, an integer content type, CWT_Claims that is not a map, a byte-string `iss` or `sub`, a
`receipts` element that is not a byte string, `alg` ES256,
a `crit`, `payload_hash_alg` (258), no CWT_Claims, no `iss`, no `sub`, a 31-octet payload, a
detached payload, an unprotected label besides `receipts`, an empty `receipts`, no `receipts`, 17
Receipts, trailing octets and octets that are not CBOR.

A report may add `method` and `detail`; the vectors leave them out.

## Gates

- `python/tests/test_card_registration_v0_vectors.py` runs every case through
  `agent_action_capsule.witness.check_card_registered` and regenerates the directory,
  byte-identical.
- `go/witness` (`TestCardRegistrationVectors`), `ts/test/card-registration-vectors.test.ts` and
  `rust/agent-action-capsule/tests/card_registration_vectors.rs` run every case.

This README is the only hand-written file in the directory.
