# Strict Evidence Bundle vectors

These vectors pin `verify_bundle` in strict mode: the checks a verifier needs
before it tells a person that an Evidence Bundle
(`draft-mih-zhang-agent-disclosure-bundle-01`) is VALID. Strict mode keeps
every result of the plain verifier and adds:

- each record's producer signature;
- the checkpoint, read only from its signed COSE form;
- producer-selected Bundles;
- the `disclosures` overlay as one claim;
- the witness receipts in `checkpoint.witnesses`, checked under a witness
  directory the caller supplies;
- a verdict: `VALID`, `INCOMPLETE` or `INVALID`.

Two inputs here are **not defined by the Bundle draft**:
`completeness.selection: "producer-selected"` and `checkpoint.witnesses`. A
witness entry is a CLL `WitnessRecord`
(`draft-mih-scitt-checkpointed-local-log`). Strict mode reads both as verifier
extensions. A Bundle without them is judged by the draft's rules alone, and
only a witness receipt that fails changes the verdict.

## Files

| File | What it pins |
|---|---|
| `vectors.json` | `cases`: Bundles with their options and expected strict results. `record_signatures`: single records and their producer-signature verdict. `witness_directory`: the directory the witness cases use. `keys`: the public test keys. |
| `manifest.json` | SHA-256 of `vectors.json`, and the case counts. |
| `SHA256SUMS` | SHA-256 of every file in this directory except itself. |

`python/scripts/generate_bundle_strict_vectors.py` regenerates every file
except this README, byte for byte. Each expected result is written by hand in
the generator; the generator runs no verifier. Every key is a fixed test seed
and every signature is deterministic: Ed25519, and RFC 6979 ECDSA P-256 for
the Rekor key. None of these keys is a production key.

## The rules

**Kind.** A Bundle that is not a JSON object, or whose `bundle_kind` is not `evidence-bundle/v2`, or whose
`bundle_version` is not `"2"`, is refused before any other strict check. Its
only claim is `records`, which fails with `not_an_evidence_bundle_v2`, and
`witnesses` is absent (`null`).

**Claims, in this order:** `records`, `signatures`, `graph_closure`,
`checkpoint`, `interval_coverage`, `per_record_membership`, then
`disclosures` when the Bundle carries a `disclosures` member. Each claim is
`pass`, `withheld` or `fail`, with findings in the order given below. The
verdict is `INVALID` when any claim fails or the witnesses fail, `VALID` when
every claim passes, and `INCOMPLETE` otherwise. `witnesses` is reported
beside the claims and is never one of them.

**`records`.** One entry per object in `records`, in order. `identity_ok`
holds when the plain verifier verified that record (Class 1, recomputed
Capsule ID) under its carried `capsule_id`. The claim passes when there is at
least one record and every record's identity holds. Otherwise it fails with
`record_identity_invalid:<capsule_id>` per failing record, or `no_records`.
`seq` is the record's `log_coordinates.seq` from its membership, or `null`.

**`signatures`.** A record's producer signature is its local-only `signature`
(the hex Producer Envelope) and `key_id` (hex raw Ed25519 key):

- `unclaimed`: neither member is present.
- `invalid`: only one of them is present, either is not a string of hex digit
  pairs (upper or lower case, no whitespace), or the envelope does not verify
  under `key_id` over the Capsule ID recomputed from the record's own content.
- `authored`: otherwise.

The Capsule ID is recomputed as the record's `canonicalization_id` declares.
Under `jcs`, every member except `capsule_id`, `signature` and `key_id` is
committed. Under `jcs-n`, declared or implied by an absent or `null` member
(the vintage reading), `chain` is also removed, then null, empty-array and
empty-object members are removed bottom-up before JCS. Any other value is
`invalid`. The carried `capsule_id` is not read.

The claim's findings are `producer_signature_invalid:<id>` for each invalid
record, then `producer_signature_unclaimed:<id>` for each unclaimed one. The
claim fails when a record is invalid, when there are no records, or when a
record is unclaimed and the caller passed `require_signature`. It is
`withheld` when a record is unclaimed, and `pass` otherwise.

**`checkpoint`.**

- With no `checkpoint.cose`, the claim is `withheld`
  (`checkpoint_signature_absent`).
- When `cose` is not unpadded canonical base64url, the claim fails
  (`checkpoint_signature_malformed`).
- When the bytes are not a CLL COSE checkpoint that verifies under its own key,
  the claim fails (`checkpoint_signature_invalid`).
- Otherwise, the JSON copy is held to the signed statement. Each of `log_id`,
  `mmr_size`, `root`, `key_id`, `timestamp`, `prev_size` and `prev_root` that
  the copy carries must equal the signed value, with JSON types kept apart, or
  the claim gets `checkpoint_field_mismatch:<name>`. The signed values, as CLL
  decodes them, are strings for `log_id`, `root` (lowercase hex), `key_id`
  (lowercase hex), `timestamp` (the statement's `issued_at` text as signed)
  and `prev_root` (`""` for a first checkpoint, never `null`), and integers
  for `mmr_size` and `prev_size` (`1.0` and `true` are not `1`). Each of `log_id`,
  `mmr_size` and `root` that the copy lacks gets
  `checkpoint_field_missing:<name>`. Any such finding fails the claim.
- Otherwise the claim passes, and the checkpoint is authenticated.

**`interval_coverage`, `per_record_membership`.** These are the plain
verifier's claims, with two changes:

- **Producer-selected Bundles.** When `completeness.selection` is
  `producer-selected`, interval coverage is `withheld`
  (`selection_not_checkable`). Membership is checked record by record against
  the signed checkpoint:
  - `completeness_certificate_invalid` when `memberships` is not an object or
    `range_root` is not the signed `root`;
  - for each record, in order: `membership_record_unbound:<id>` when it has no
    `log_coordinates`; `membership_coordinates_invalid:<id>` when its `log_id`
    is not the signed one, `seq` or `leaf_index` is not a safe integer, `seq`
    is below 1, `leaf_index` is not `seq - 1`, or the `seq` repeats;
    `membership_proof_invalid:<id>` when the inclusion proof is malformed, its
    `size` is not the signed `mmr_size`, or it does not verify;
  - then `membership_record_unknown:<id>` for each membership whose record is
    not in the Bundle.
- **Unanchored proofs.** When the checkpoint is not authenticated, a claim
  that did not fail becomes `withheld`, with `checkpoint_unverified` appended
  to its findings (once).

**`disclosures`.** When the Bundle carries `disclosures`, the claim lists
`<status>:<capsule_id>:<member>` for each disclosure result whose status is
neither `disclosure_match` nor `withheld`, in the plain verifier's order. Any
such finding fails the claim; otherwise it passes.

**`signer_matches_checkpoint`.** When the checkpoint is authenticated and
there is a record, this states whether every record's `key_id` is the signed
checkpoint's `key_id`. It is reported and never gates. Otherwise it is
`null`.

**`witnesses`.**

- With no `checkpoint.witnesses` (absent, not a list, or empty), the result is
  `withheld` (`witness_receipt_absent`).
- When the checkpoint is not authenticated, it is `withheld`
  (`checkpoint_unverified`).
- Otherwise, an entry that is not an object with a string `ts_url` and all of
  `entry_hash`, `receipt_b64`, `leaf_index` and `tree_size` is malformed. Its
  finding, `witness_receipt_malformed:<index>`, is listed before every other
  finding.

Each other entry gets one result `{ts_url, binding, status, grade}`, worked
out in this order:

1. A receipt with `is_stub` set to JSON `true` is `withheld`.
2. Its directory row is the row whose `binding` (default `cll`) is the
   receipt's binding and whose `endpoint`, with every trailing `/` removed,
   is the receipt's endpoint. The binding is `rekor` for a `rekor+` URL
   scheme, `scrapi` for a `scrapi+` scheme (the scheme compared without
   case), and otherwise `cll`. The endpoint is the URL with any `rekor+` or
   `scrapi+` prefix removed and every trailing `/` removed. No
   row means `withheld`.
3. The row's keys, in `key_ids` order: a `key_id` that names a `public_keys`
   entry (base64 DER SubjectPublicKeyInfo) by the SHA-256 of its DER, or an
   Ed25519 entry by its raw key, is that key. Any other `key_id` is read as a
   raw Ed25519 key, except in a `rekor` row, where it makes the row unusable
   (`withheld`). A row with no keys is `withheld`.
4. The receipt is `pass` under the first key it verifies under. If none
   verifies, it is `fail`.

A verifier that cannot run a receipt check at all (for example, no COSE
library) reports the receipt `withheld`, never `fail`.

A `withheld` receipt adds `witness_unverified:<ts_url>`; a `fail` adds
`witness_receipt_invalid:<ts_url>`. Overall, `witnesses` fails when an entry
is malformed or a receipt fails, passes when a receipt passes, and is
`withheld` otherwise.

The three bindings check a receipt as follows.

- **`cll`.**
  - The checkpoint digest is the SHA-256 of
    `{"v":1,"kind":"mmr_checkpoint",log_id,mmr_size,root,prev_size,prev_root,key_id,timestamp}`
    as JSON with sorted keys and no whitespace, non-ASCII escaped as
    `\uXXXX`, taking each value from the signed statement. The receipt's
    `entry_hash` must equal the SHA-256 of that digest's 32 bytes.
  - `receipt_b64` (strict standard base64) must be a COSE Receipt over the
    leaf `entry_hash`, signed under the key (see "COSE Receipts" below).
  - `grade` is the receipt's protected-header label -65537:
    `observed-only`, `mmr-verified`, or `countersigned-observed` read as
    `observed-only`. Any other value or no label is `null`.
- **`scrapi`.**
  - `receipt_b64` (standard base64) must be a COSE Receipt over the leaf
    SHA-256 of the checkpoint's COSE bytes, signed under the key.
  - `grade` is label -65537 as above. With no label, or an unknown one, it is
    `observed-only`.
- **`rekor`.** `receipt_b64` is base64 of a Rekor log entry, and four checks
  must all hold:
  1. Its `logID` is the SHA-256 of the key's DER SubjectPublicKeyInfo.
  2. `integratedTime` and `logIndex` are JSON integers (not strings or
     booleans), `body` is a string, and
     `verification.signedEntryTimestamp` (base64 DER ECDSA P-256 SHA-256)
     verifies over `{"body","integratedTime","logID","logIndex"}` as JSON with
     sorted keys and no whitespace.
  3. `body` decodes (base64 JSON) to a `dsse` entry whose
     `spec.payloadHash.value` is the SHA-256 of the checkpoint's COSE bytes.
  4. The verifier keys of `spec.signatures` (base64 PEM, compared without
     `\r` and surrounding whitespace) are exactly the signed checkpoint's
     `key_id`, as an Ed25519 SubjectPublicKeyInfo PEM.

  `grade` is `observed-only`.

**COSE Receipts** (`cll` and `scrapi`; draft-ietf-cose-merkle-tree-proofs).
A receipt verifies over a leaf when all of these hold:

- it is a CBOR tag-18 COSE_Sign1 whose payload is detached (`nil`), so the
  signature covers the rebuilt Merkle root. An attached payload is refused
  even when its signature verifies: it binds nothing
  (`neg-witness-cll-attached-payload`);
- its protected header has `vds` (395) equal to the integer 1
  (RFC9162_SHA256) and an `alg` (1) of the integer -8 (EdDSA) or -7 (ES256).
  No other `vds` or `alg` is accepted, nor `true` or a float;
- its unprotected `vdp` (396) map carries a non-empty array of inclusion
  proofs under -1, each a byte string holding CBOR
  `[tree_size, leaf_index, [audit_path...]]`. Every entry must decode;
- for some proof, the RFC 9162 root rebuilt from the leaf and that proof
  verifies the signature under the key.

Decoding follows the scitt-cose verifiers (Python `scitt_cose.verify_receipt`,
the Rust crate `scitt-cose-receipt`), including their `crit` handling.

Every base64 field a receipt check reads (`receipt_b64`, the Rekor `body`,
`signedEntryTimestamp` and `verifier`) is strict standard base64 with padding:
a character outside the alphabet, or missing padding, makes the receipt fail.
A directory `public_keys` entry that is not strict base64 DER is skipped. A row
whose `key_ids` or `public_keys` is not a list, or with a key id that is not 64
lowercase hex characters, is unusable (`withheld`).

The `reason` text a verifier reports for a receipt is not part of these
vectors. A record or settlement leg whose `capsule_id` is not a string is
reported with `""` in strict `records` and with `null` in settlement
`failures`. `membership_record_unknown` findings come in sorted Capsule ID
order.

## Cases (`cases`)

The base Bundle is a whole log of three signed records under one key, whose
checkpoint is signed by another, the log key.

| id | What it shows | verdict |
|---|---|---|
| `pos-signed-whole-log` | everything checks; no receipts | VALID |
| `pos-records-signed-by-the-log-key` | the records' key is the checkpoint's key | VALID, `signer_matches_checkpoint` |
| `incomplete-no-signed-checkpoint` | no `checkpoint.cose`: checkpoint, interval and membership not shown | INCOMPLETE |
| `neg-checkpoint-field-differs-from-signed` | JSON `timestamp` differs from the signed one | INVALID |
| `neg-checkpoint-field-differs-in-type` | JSON `prev_size` is `false` where the signed value is `0` | INVALID |
| `neg-checkpoint-field-missing` | JSON copy lacks `log_id` | INVALID |
| `neg-checkpoint-signature-invalid` | one bit of the COSE signature flipped | INVALID |
| `neg-checkpoint-cose-malformed` | `cose` is not base64url | INVALID |
| `incomplete-unsigned-record` | one record has no producer signature | INCOMPLETE |
| `neg-unsigned-record-signature-required` | the same with `require_signature` | INVALID |
| `neg-record-signature-wrong-key` | an envelope signed by another key than `key_id` | INVALID |
| `neg-record-edited` | a record edited after signing | INVALID |
| `incomplete-producer-selected` | records 1 and 3 of 3, producer-selected | INCOMPLETE |
| `neg-producer-selected-proof-invalid` | the same with one inclusion proof edited | INVALID |
| `neg-producer-selected-coordinates-log-and-seq` | producer-selected: one membership names another log, another has `seq` 0 | INVALID |
| `neg-producer-selected-leaf-index` | producer-selected: `leaf_index` is not `seq - 1` | INVALID |
| `neg-producer-selected-repeated-seq` | producer-selected: two memberships claim `seq` 1 | INVALID |
| `neg-producer-selected-unbound` | producer-selected: a membership without `log_coordinates` | INVALID |
| `pos-checkpoint-with-prior` | a checkpoint with `prev_size > 0` and its consistency proof | VALID |
| `neg-checkpoint-prev-root-null` | the JSON copy says `prev_root: null` for a first checkpoint | INVALID |
| `pos-disclosure-matches` | a disclosed member that matches its committed digest | VALID |
| `neg-disclosure-mismatch` | a disclosed member that does not | INVALID |
| `neg-not-an-evidence-bundle-v2` | `bundle_kind` is `evidence-bundle/v1` | INVALID |
| `pos-witness-cll` | a `cll` receipt under the directory's key, grade `mmr-verified` | VALID, witnesses pass |
| `pos-witness-cll-no-directory` | the same with no directory | VALID, witnesses withheld |
| `pos-witness-cll-legacy-grade` | grade label `countersigned-observed` | VALID, grade `observed-only` |
| `pos-witness-cll-no-grade` | no grade label | VALID, grade `null` |
| `pos-witness-unlisted` | a witness with no directory row | VALID, witnesses withheld |
| `pos-witness-row-without-keys` | a row with no keys | VALID, witnesses withheld |
| `pos-witness-stub` | `is_stub: true` | VALID, witnesses withheld |
| `neg-witness-cll-other-checkpoint` | a genuine receipt for another checkpoint | INVALID |
| `neg-witness-cll-wrong-key` | a receipt signed by a key the row does not list | INVALID |
| `neg-witness-cll-attached-payload` | a receipt with an attached payload signed by the listed key | INVALID |
| `neg-witness-malformed` | an entry without `tree_size`, beside a good receipt | INVALID |
| `pos-witness-scrapi` | a `scrapi` receipt, no grade label | VALID, grade `observed-only` |
| `pos-witness-scrapi-unknown-grade` | an unknown grade label | VALID, grade `observed-only` |
| `neg-witness-scrapi-other-statement` | a `scrapi` receipt over other bytes | INVALID |
| `pos-witness-rekor` | a Rekor `dsse` entry under the checkpoint's key | VALID |
| `neg-witness-rekor-other-payload` | `payloadHash` of other bytes | INVALID |
| `neg-witness-rekor-other-signer` | logged under another key | INVALID |
| `neg-witness-rekor-string-integer` | `integratedTime` is the signed value as a JSON string | INVALID |
| `pos-witness-rekor-row-without-key` | a `rekor` row with a log ID and no public key | VALID, witnesses withheld |
| `pos-witness-three-bindings` | one receipt of each binding | VALID |
| `incomplete-witness-on-unsigned-checkpoint` | a receipt on a checkpoint with no `cose` | INCOMPLETE, witnesses withheld |

## Record signatures (`record_signatures`)

| id | expect |
|---|---|
| `authored-jcs` | `authored` |
| `authored-jcs-n` | `authored`: no `canonicalization_id`, so `chain` and null or empty members are dropped |
| `authored-jcs-n-declared` | `authored`: `canonicalization_id` is `jcs-n` |
| `unclaimed` | `unclaimed` |
| `invalid-half-claim` | `invalid`: `key_id` without `signature` |
| `invalid-other-key` | `invalid` |
| `invalid-not-hex` | `invalid` |
| `invalid-unknown-canonicalization` | `invalid`: `as-transmitted` cannot be recomputed |

## How to consume them

For each case, run strict `verify_bundle` on `bundle`. Pass
`require_signature` as given in `options`, and pass the file's
`witness_directory` when `options.witness_directory` is `true` (otherwise no
directory). Then compare:

- `verdict`;
- `kind_ok` (expected `true` unless stated);
- `claims` (`name`, `status`, `findings`, in order);
- `witnesses` (`status`, `findings`, and `receipts` with `ts_url`, `binding`,
  `status` and `grade`);
- `records` (`capsule_id`, `identity_ok`, `signature`, `key_id`, `seq`);
- `checkpoint_authenticated` (the `checkpoint` claim passed);
- `signer_matches_checkpoint`.

For each `record_signatures` entry, the record's verdict must equal `expect`.

## Regenerating

From the repository root, with `agent-action-capsule[bundle,envelope]`
installed:

```sh
python3 python/scripts/generate_bundle_strict_vectors.py
```
