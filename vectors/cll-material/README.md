# CLL material encoding vectors

Profile `evidence-interop/0` §6.2.1 carries a Checkpointed Local Log's proofs as
deterministic CBOR. These cases give a responder's inputs and the exact octets
an encoder must produce, so every implementation's encoder can be checked
against one corpus:

| Kind | Inputs | Octets |
|---|---|---|
| `cll-inclusion-proof` | `leaf` (zero-based leaf number), `path` (the siblings from the leaf to its peak) | `[2·leaf − popcount(leaf), path]` |
| `cll-consistency-proof` | `old_size`, `new_size` (MMR node counts), `old_peaks`, `paths` (one per old peak, into the new MMR), `new_peaks` | `[old_size, new_size, paths, right-peaks]` |

`right-peaks` are the new peaks after the roots the old peaks' paths reach,
with adjacent repeats merged (MMR -02 §7.1). An encoder that takes the
right peaks directly (Go's `EncodeCLLConsistencyProof`) computes them from
`old_peaks` and `paths` first.

Nodes are 32-octet byte strings, given as lowercase hex. Each case's
`context` gives what a checker needs to verify the octets as well (the logged
entry E, whose leaf is SHA-256(0x00 || E), and the peaks of the tree it was proved under); encoders do not read it.

## Cases

- `worked-example-inclusion` and `worked-example-consistency`: the proofs of
  the profile's §10.1 worked example. Their SHA-256 values are the ones the
  profile states.
- `inclusion-n<N>-leaf<L>`: every leaf of a log of `N` entries, `N` from 1 to
  13, where entry `k` is SHA-256 of the single octet `k`.
- `consistency-n<A>-n<B>`: the same log, from `A` entries to `B` entries, for
  every `1 ≤ A ≤ B ≤ 13`.

## Derivation

`python/scripts/generate_cll_material_vectors.py` writes every file except this
README. It builds the log from MMR -02 with the standard library and runs no
repository implementation.

## Consumers

- Python: `python/tests/test_cll_material_vectors.py` (`encode_cll_inclusion_proof`,
  `encode_cll_consistency_proof`).
- Go: `go/evidencerequest/cll_material_vectors_test.go` (`EncodeCLLInclusionProof`,
  `EncodeCLLConsistencyProof`).
- Rust: `rust/evidence-request/tests/cll_material_vectors.rs` (`encode_inclusion_proof`,
  `encode_consistency_proof`).
