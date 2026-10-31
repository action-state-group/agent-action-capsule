# Witness Receipts over an anchor: conformance vectors

These vectors exercise `spec/interop-profile-v1.md` §6.2.2: the kind `cll-witness-receipt`, an
RFC 9942 COSE Receipt (RFC9162_SHA256) whose leaf entry is the 32 octets of an anchor digest, and
the check `anchor_witnessed` over the Receipts beside one answer.

## Derivation

`python/scripts/generate_anchor_witness_v1_vectors.py` builds every Receipt with its own RFC 9162
tree, CBOR encoder and P-256 signer, and writes every expected report by hand from §6.2.2. It
imports no implementation. Keys are test keys derived from public labels, and the anchor digests
are label digests (SHA-256 of a text string), for these vectors only. ES256 nonces are derived
from a label, so the directory regenerates byte for byte.

## The corpus

`vectors.json` holds `policies` (the shared witness policy, `default`) and `cases`. Each case gives:

| Member | What it is |
|---|---|
| `anchor` | the anchor digest, 64 lowercase hex characters |
| `receipts` | the Receipts beside the answer, in the order received, each as hex of its octets |
| `policy` | `"default"`, or an inline witness policy: `{"witnesses": [{"name", "keys": [<hex DER SubjectPublicKeyInfo>]}]}` |
| `expected` | the report: `status`, one `{status, witness, registration_time}` per Receipt, and the anchor's `witness` and `witnessed_time` |

Times are NumericDates (seconds since 1970-01-01T00:00:00Z). A consumer compares the whole
`expected` object.

## The cases

Positive: an EdDSA Receipt with and without a protected `iat`, an ES256 Receipt, a tree of one
leaf, a rotated key, a second inclusion proof that verifies after one that does not, the earliest
time with the witness that signed it, a timed Receipt after an untimed one, a tie on time, no time
at all, a passing Receipt beside a failing one, `iat` values that give no registration time
(negative, over 2^53 - 1, text, `true`), a protected `kid`, a private-use label, other CWT claims,
and nesting 16 levels deep.

`NOT_PRESENT` and `NOT_CHECKED`: no Receipt, an empty policy, an ES256 Receipt under a policy with
Ed25519 keys only, and that beside a failing Receipt (`FAIL`).

Negative (MUST reject, `FAIL`): another anchor, an unlisted witness, a tampered signature, S not
below the group order, a small-order key, a listed P-256 key off the curve, and every departure
from the one form, checked before the policy: an attached payload, an untagged COSE_Sign1, `vds`
2, another `alg`, no `alg`, any `crit`, a protected label outside the closed set, a text `kid`,
CWT_Claims that is not a map, an `iat` bignum or float, an unprotected label besides `vdp`, a `vdp`
key besides -1, a repeated protected label, a byte-string or array map key, nesting 17 levels deep,
a longer argument (outer head, `alg`, `tree_size`), a 63-octet signature, no `vdp`, no proofs, 17
proofs, a malformed proof beside a valid one, a short path, `leaf_index` equal to `tree_size`, a
31-octet node, trailing octets, and octets that are not CBOR. The 10,485,760-octet limit is tested
in `python/tests/test_anchor_witness_v1_vectors.py` with signed Receipts at and one octet over it,
too large for this file.

A report may add `method` and `detail` (§6.2.2); the vectors leave them out.

## Gates

- `python/tests/test_anchor_witness_v1_vectors.py` runs every case through
  `agent_action_capsule.witness.check_anchor_witnessed` and regenerates the directory,
  byte-identical.
- `go/witness` (`TestAnchorWitnessVectors`), `ts/test/anchor-witness-vectors.test.ts` and
  `rust/agent-action-capsule/tests/anchor_witness_vectors.rs` run every case.

This README is the only hand-written file in the directory.
