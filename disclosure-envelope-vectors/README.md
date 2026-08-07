# Disclosure Envelope conformance vectors

Frozen conformance vectors for the Disclosure Envelope companion profile
(`../spec/draft-mih-scitt-agent-action-capsule-disclosure-envelope-00.md`).
Each case is a Disclosure Envelope (`{"envelope": {"capsule": {...}, "disclosures": {...}}}`)
plus the expected verifier result, version-pinned and hand-checkable.

## Why this lives outside `../test-vectors/`

`../test-vectors/` is the Class-1 conformance corpus for the base Agent
Action Capsule profile, and it is **cross-language-shared**: the Go
reference implementation's `vector_runner` (`../go/cmd/vector_runner/`)
reads `../test-vectors/vectors.json` directly and asserts every listed case
as a bare Capsule (or `{"ledger": [...]}`). A Disclosure Envelope
(`{"envelope": {...}}`) is neither shape, and this profile currently has no
Go implementation — mixing the shapes into `../test-vectors/` would break
that Go conformance run rather than extend it. This directory follows the
same frozen-vector discipline and file layout in a corpus of its own.

## These are DERIVED and FROZEN (not hand-authored)

Every `expected.json` is **derived** by running
`agent_action_capsule.verify_disclosure_envelope()` over a hand-built
`input.json`, then **frozen**. A change to the result of any case is either
a spec/format revision (regenerate and review the diff) or a regression.
They regenerate via:

```bash
cd python && PYTHONPATH=. python3 scripts/generate_vectors.py
```

(this also regenerates `../test-vectors/`; see that directory's own
regeneration caveats before running it against a checkout with local vector
edits).

The expected values are **spec-anchored** — see
`draft-mih-scitt-agent-action-capsule-disclosure-envelope-00.md`, "Verifier
Checks":

- `ok` — the overall envelope result: the wrapped `capsule`'s own Class 1
  `ok` AND every provided disclosure matches its committed digest.
- `capsule` — the wrapped Capsule's own Class 1 result, in the same shape
  as `../test-vectors/*/expected.json` (`ok`, `derived`,
  `capsule_id_recomputed`, `findings`). This is unaffected by disclosure
  outcomes — a bad disclosure never flips `capsule.ok`.
- `disclosures_checked` / `disclosures_matched` — counts over the
  `disclosures` object provided in the envelope.
- `disclosure_findings` — one `{member, code}` entry per provided
  disclosure; `code` is `disclosure_match`, `disclosure_mismatch`,
  `disclosure_ineligible_field`, or `disclosure_no_committed_digest` (DE-1
  through DE-3 of the companion profile).

## Layout

```
disclosure-envelope-vectors/
  README.md
  vectors.json              — manifest: every case with kind + one-line description
  SHA256SUMS                — pins every input.json / expected.json byte
  <case>/input.json         — {"envelope": {"capsule": {...}, "disclosures": {...}}}
  <case>/expected.json      — { ok, capsule: {...}, disclosures_checked, disclosures_matched, disclosure_findings }
```

## Cases

- **`pos-disclosure-envelope-match`**: the `agent_input` disclosure
  recomputes to the digest committed in
  `capsule.model_attestation.compute_attestation.agent_input_digest`.
  `disclosure_match`; overall `ok: true`.
- **`neg-disclosure-envelope-mismatch`**: same `capsule` as the match case
  (same committed digest), but the disclosed `agent_input` value has been
  tampered with. `disclosure_mismatch`; overall `ok: false` — while
  `capsule.ok` stays `true` and `capsule.capsule_id_recomputed` is
  byte-identical to the match case's, demonstrating that a bad disclosure
  never gates the wrapped Capsule's own verification or its `capsule_id`.

## Running

`python/tests/test_disclosure_envelope_vectors.py` runs every case in this
directory through `verify_disclosure_envelope()` and asserts each
`expected.json`. To check an independent implementation, run it over each
`input.json` and compare `ok`, `capsule.ok`, `capsule.capsule_id_recomputed`,
and the per-member `disclosure_findings`.
