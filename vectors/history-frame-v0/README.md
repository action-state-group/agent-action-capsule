# History frame v0: conformance vectors

These vectors exercise `spec/history-frame-v0.md` (cited as HF): the counting table and the
wording pack each instance of the frame pins (HF §5), the digests HF §6 lists for them, and the
three document properties of HF §6.2.

## Derivation

`python/scripts/generate_history_frame_v0_vectors.py` reads the eight documents in
`spec/history-frame/` and states every expected property by hand. Each case gives:

| Input | What it is |
|---|---|
| `instance` | the instance identifier (HF §6) |
| `listed` | the table and pack digests HF §6 lists for it |
| `table` | a counting table, as a JSON value |
| `pack` | a wording pack, as a JSON value |

`expected` gives `table_binding`, `pack_binding` and `pack_form`, whether the documents are
accepted (all three `PASS`), and the properties that `FAIL`. A digest is SHA-256 of UTF-8 of JCS of
the document. `instances` at the top of `vectors.json` repeats HF §6's list.

## The cases

Positive: each of the four instances' documents as pinned: `standard-history-as-pinned`,
`personal-history-basic-as-pinned`, `personal-history-outcome-as-pinned` and
`inference-service-history-as-pinned`.

Negative, each failing the properties its `expected.fails` lists:

- `pack-digest-mismatch`: a pack label made stronger than its evidence ("one-sided" shown as
  "peer-confirmed"), so its digest is not the listed one;
- `pack-translated-in-place`: a translation offered as the pinned pack (HF §5.3);
- `table-digest-mismatch`: a table with a member added;
- `pack-carries-checked-string`: a pack string that its table carries and a property checks;
- `pack-for-another-instance`: a pack naming another instance.

## Gates

- `python/tests/test_history_frame_v0_vectors.py` evaluates every case with an evaluator of its
  own, checks that the documents in `spec/history-frame/` and the digests in HF §6 agree with
  `instances`, and regenerates the directory twice, byte-identical.
- The generators of `standard-history-v0/`, `personal-history-basic-v0/`,
  `personal-history-outcome-v0/` and `inference-service-history-v0/` (both sets) load the same
  documents and assert that they match what each set emits (HF §6.3).

This README is the only hand-written file in the directory.
