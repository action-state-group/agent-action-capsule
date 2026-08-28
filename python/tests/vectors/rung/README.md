# Rung-transition vectors

Frozen vectors for `agent_action_capsule.history`'s anchoring-evidence rung
(`docs/ledger-grade.md` §4 — "Anchored by default" is a **rung report**, not
a completeness gate). Each case supplies a set of capsules plus optional
`inclusion_proofs` / `countersignatures` and pins the exact `rung` that
evidence justifies — no synonyms, no higher.

Run via `python/tests/test_history.py::test_rung_vectors`, which loads
`vectors.json` and asserts `verify_chain_completeness(...).rung` against each
case's `expected_rung`.

## Evidence shape

- `countersignatures`: `[{"capsule_id": "<64-hex>", ...}]` — presence of a
  matching entry earns `countersigned`.
- `inclusion_proofs`: `[{"capsule_id": "<64-hex>", "visibility": "local" |
  "counterparty" | "public", ...}]` — `visibility` maps to `local-anchored` /
  `counterparty-visible` / `publicly-anchored` respectively. A proof with no
  (or an unrecognised) `visibility` is credited only `local-anchored`, the
  floor anchored tier — evidence of *some* registration is not evidence of
  *public* registration (see `neg-inclusion-proof-no-visibility-does-not-default-to-public`).

## Two guard cases, named `neg-*`

- `neg-inclusion-proof-no-visibility-does-not-default-to-public` — an
  under-specified proof must not be read as the strongest claim.
- `neg-overclaim-misdirected-evidence-does-not-inflate-bundle` — a bundle's
  rung is the MINIMUM across its capsules; one capsule's strong evidence must
  never inflate a sibling capsule's (or the whole bundle's) claim. This is the
  vector used for the mutant-flip drill: removing the `capsule_id` match in
  the inclusion-proof loop (or taking `max()` instead of `min()` across
  capsules in `_compute_rung`) makes this case wrongly report
  `publicly-anchored`.

## Regenerating SHA256SUMS

```bash
shasum -a 256 vectors.json > SHA256SUMS
```
