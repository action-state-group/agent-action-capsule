# checkpoint-consistency vectors

These vectors pin `verifyRetainedHead` (TypeScript, `ts/src/retained-head.ts`): whether a
log's current head extends a head the reader kept from an earlier look (verification
ladder rung 6). The kept head is the reader's own state, so it is a verifier input and no
Bundle member, and a page never fetches it.

## Files

| File | What it pins |
|---|---|
| `vectors.json` | `cases`: a retained head, a current head, an optional proof and the expected result. |
| `manifest.json` | SHA-256 of `vectors.json`, and the case count. |
| `SHA256SUMS` | SHA-256 of every file in this directory except itself. |

`python/scripts/generate_checkpoint_consistency_vectors.py` regenerates every file except
this README, byte for byte. Each expected result is written by hand in the generator; the
generator runs no verifier. The logs and proofs are the `cll` reference's (MMR). No key
or signature is involved: the current head comes from a checkpoint the caller has already
authenticated.

## A case

- `retained`, `current`: a head, `{size, root}`: the MMR size (the checkpoint's `mmr_size`,
  a positive JSON integer) and the root (64 lowercase hex). `retained` may be absent or
  `null`.
- `proof`: the consistency proof from `retained.size` to `current.size`, in the wire shape of
  `parent-log-witness/v1`'s `earlier.consistency_proof` (`v` 1, `kind` `consistency`,
  `old_size`, `new_size`, `old_peaks`, `witness`, `new_peaks`). Absent or `null` when none.
- `expect`: `status` (`pass`, `fail` or `not_present`) and `finding` (`null` on `pass`).

## The rules

Checked in this order; the first that applies is the result.

1. No retained head: `not_present`, `retained_head_absent`.
2. A malformed retained head: `fail`, `retained_head_malformed`; a malformed current head:
   `fail`, `current_head_malformed`.
3. The retained size above the current size: `fail`, `retained_head_ahead_of_current`.
4. Equal sizes: `pass` when the roots are equal, else `fail`, `retained_head_root_differs`.
   No proof is consulted.
5. No proof: `not_present`, `consistency_proof_absent`. A result is never guessed.
6. A malformed proof: `fail`, `consistency_proof_malformed`; a proof whose `old_size` or
   `new_size` is not the two heads' sizes: `fail`, `consistency_proof_sizes_differ`.
7. Otherwise `pass` when the proof verifies the retained root against the current root
   (the `cll` MMR consistency check), else `fail`, `retained_head_not_a_prefix`.
