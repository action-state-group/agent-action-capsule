# parent-log-witness/v1 vectors

These vectors pin strict `verify_bundle` on the `parent-log-witness/v1`
extension (`draft-mih-zhang-agent-disclosure-bundle-03`, "The
parent-log-witness/v1 Extension"). The extension carries a chain from the
Bundle's checkpoint, or from an earlier checkpoint of the same log, through a
salted leaf of a Merkle tree, to an entry of a parent log signed by the same
key, and the witness receipts over the parent log's checkpoint. The verifier
checks every link and computes how much of the log was witnessed itself.

## Files

| File | What it pins |
|---|---|
| `vectors.json` | `cases`: Bundles and their expected strict results. `witness_directory`: the directory the cases use. `keys`: the public test keys. |
| `manifest.json` | SHA-256 of `vectors.json`, and the case count. |
| `SHA256SUMS` | SHA-256 of every file in this directory except itself. |

`python/scripts/generate_bundle_parent_witness_vectors.py` regenerates every
file except this README, byte for byte. Each expected result is written by
hand in the generator; the generator runs no verifier. It builds on the strict
vectors' generator (`../strict/`): the same fixed test keys, the same three
signed records and their whole-log checkpoint, and `cll` witness receipts.
None of these keys is a production key.

## The Bundles

The Bundle is the strict vectors' base shape: three signed records, a whole-log
certificate and a checkpoint (MMR size 4, three entries) signed by the log
key. The earlier checkpoint is the same log after two entries (MMR size 3).
The tree has 16 leaves (a path of four hashes); the covered checkpoint's leaf
is at position 5 and the other leaves are fillers. The parent log
(`log:parent-vectors`) has two entries, another tree's root and this tree's
root, and its checkpoint is signed by the log key. The receipt is a `cll`
receipt over that checkpoint by the directory's CLL witness, with a protected
`iat` 60 seconds after the checkpoints' timestamp.

## The rules

The draft states them; in short:

- The chain is checked only when the Bundle's checkpoint is authenticated
  (the strict `checkpoint` claim passed). Otherwise the result is `withheld`
  with `checkpoint_unverified`.
- Otherwise the links are checked in the draft's order, and the first that
  fails is the result, `fail` with that one finding:
  `parent_witness_malformed`, then (when `earlier` is present)
  `parent_witness_earlier_checkpoint_malformed`, `_signature_invalid`,
  `_not_this_log` and `_not_a_prefix`, then
  `parent_witness_leaf_does_not_name_this_checkpoint`,
  `parent_witness_path_malformed`, `parent_witness_leaf_malformed`,
  `parent_witness_parent_checkpoint_malformed`,
  `parent_witness_parent_checkpoint_signature_invalid`,
  `parent_witness_parent_signer_differs`,
  `parent_witness_parent_log_id_mismatch` and
  `parent_witness_entry_not_included`.
- `cose` members are unpadded canonical base64url, as for `checkpoint.cose`
  (`../strict/`). Hashes are 64 lowercase hexadecimal characters. Integers are
  JSON integers (`true` and `4.0` are not integers).
- When every link holds, the status and findings are those of the strict
  witness check (`../strict/README.md`, "`witnesses`") run on
  `parent.witnesses` over the parent checkpoint, under the case's directory.
- `extent` is `{"entries", "of"}`, the leaf counts of the covered checkpoint
  and of the Bundle's checkpoint, when the status is `pass`, and `null`
  otherwise. Members the draft does not define, such as a stated `extent`,
  are ignored.
- A `fail` makes the verdict `INVALID`. `pass` and `withheld` change no claim.
- The extension's entry in the plain `extensions` results carries the
  `parent_witness` status in strict mode, and stays `uninterpreted` in plain
  mode.

## Cases

| id | What it shows | verdict, `parent_witness` |
|---|---|---|
| `pos-unwitnessed` | no block | VALID, `null` |
| `pos-witnessed-whole` | the Bundle's checkpoint is the leaf | VALID, pass, 3 of 3 |
| `pos-witnessed-part` | the earlier checkpoint is the leaf, with a consistency proof | VALID, pass, 2 of 3 |
| `pos-stated-extent-ignored` | the part chain with `extent: "whole"` and step counts stated | VALID, pass, 2 of 3 |
| `pos-path-empty` | a path of no hashes: the leaf is the root | VALID, pass, 3 of 3 |
| `pos-no-directory` | every link holds, no directory | VALID, withheld (`witness_unverified`) |
| `pos-no-receipts` | every link holds, `parent.witnesses` empty | VALID, withheld (`witness_receipt_absent`) |
| `incomplete-bundle-checkpoint-unsigned` | the Bundle's checkpoint has no `cose` | INCOMPLETE, withheld (`checkpoint_unverified`) |
| `neg-malformed` | the block is an array | INVALID, `parent_witness_malformed` |
| `neg-earlier-checkpoint-malformed` | `earlier.checkpoint.cose` is not base64url | INVALID, `parent_witness_earlier_checkpoint_malformed` |
| `neg-earlier-not-an-object` | `earlier` is `null` | INVALID, `parent_witness_earlier_checkpoint_malformed` |
| `neg-earlier-checkpoint-signature-invalid` | one signature bit flipped | INVALID, `parent_witness_earlier_checkpoint_signature_invalid` |
| `neg-earlier-checkpoint-other-key` | the earlier checkpoint is signed by another key | INVALID, `parent_witness_earlier_checkpoint_not_this_log` |
| `neg-earlier-checkpoint-not-earlier` | `earlier` carries the Bundle's own checkpoint | INVALID, `parent_witness_earlier_checkpoint_not_this_log` |
| `neg-earlier-not-a-prefix` | a consistency-proof peak edited | INVALID, `parent_witness_earlier_checkpoint_not_a_prefix` |
| `neg-earlier-proof-sizes` | the consistency proof states another `old_size` | INVALID, `parent_witness_earlier_checkpoint_not_a_prefix` |
| `neg-leaf-size` | `size` is the earlier checkpoint's, with no `earlier` | INVALID, `parent_witness_leaf_does_not_name_this_checkpoint` |
| `neg-leaf-size-float` | `size` is `4.0` | INVALID, `parent_witness_leaf_does_not_name_this_checkpoint` |
| `neg-leaf-log-id` | `log_id` names another log | INVALID, `parent_witness_leaf_does_not_name_this_checkpoint` |
| `neg-path-uppercase` | a path hash in uppercase | INVALID, `parent_witness_path_malformed` |
| `neg-path-too-long` | a path of 33 hashes | INVALID, `parent_witness_path_malformed` |
| `neg-leaf-salt-empty` | `salt` is `""` | INVALID, `parent_witness_leaf_malformed` |
| `neg-leaf-index-out-of-range` | `index` is 16 with a path of four | INVALID, `parent_witness_leaf_malformed` |
| `neg-leaf-index-boolean` | `index` is `true` | INVALID, `parent_witness_leaf_malformed` |
| `neg-parent-checkpoint-malformed` | `parent.checkpoint.cose` is padded | INVALID, `parent_witness_parent_checkpoint_malformed` |
| `neg-parent-missing` | no `parent` | INVALID, `parent_witness_parent_checkpoint_malformed` |
| `neg-parent-checkpoint-signature-invalid` | one signature bit flipped | INVALID, `parent_witness_parent_checkpoint_signature_invalid` |
| `neg-parent-signer-differs` | the parent log is signed by another key | INVALID, `parent_witness_parent_signer_differs` |
| `neg-parent-log-id-mismatch` | `parent.log_id` is not the signed one | INVALID, `parent_witness_parent_log_id_mismatch` |
| `neg-leaf-salt-other` | another salt, so another root | INVALID, `parent_witness_entry_not_included` |
| `neg-path-edited` | a path hash edited | INVALID, `parent_witness_entry_not_included` |
| `neg-entry-other` | `entry_index` names the other entry | INVALID, `parent_witness_entry_not_included` |
| `neg-entry-index-string` | `entry_index` is `"1"` | INVALID, `parent_witness_entry_not_included` |
| `neg-entry-proof-malformed` | the inclusion proof has no `kind` | INVALID, `parent_witness_entry_not_included` |
| `neg-receipt-other-checkpoint` | every link holds; the receipt is over the Bundle's checkpoint | INVALID, fail (`witness_receipt_invalid`) |
| `neg-parent-receipt-on-bundle-checkpoint` | the parent's receipt carried in `checkpoint.witnesses`, with no block | INVALID, `null`; `witnesses` fail |

## How to consume them

For each case, run strict `verify_bundle` on `bundle`, passing the file's
`witness_directory` when `options.witness_directory` is `true` (otherwise no
directory). Compare `verdict`; `parent_witness` (`status`, `findings`,
`extent`, and `receipts` with the strict vectors' receipt fields), or its
absence; the extension's status (`extension_status`) when given; and
`witnesses` (`status`, `findings`) when given.

## Regenerating

From the repository root, with `agent-action-capsule[bundle,envelope]` and
`scitt-cose` 0.3.0 or later installed:

```sh
python3 python/scripts/generate_bundle_parent_witness_vectors.py
```
