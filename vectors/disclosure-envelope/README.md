# Disclosure Envelope conformance vectors

Frozen conformance vectors for the Disclosure Envelope companion profile
(`../../spec/draft-mih-scitt-agent-action-capsule-disclosure-envelope-00.md`).
Each case is a Disclosure Envelope (`{"envelope": {"capsule": {...}, "disclosures": {...}}}`)
plus the expected verifier result, version-pinned and hand-checkable.

## Why this is a separate corpus from `../capsule/`

`../capsule/` is the Class-1 corpus for bare Capsules (or
`{"ledger": [...]}`). A Disclosure Envelope has a distinct wrapper shape, so
it remains a sibling corpus with its own manifest. Python, Go, and TypeScript
all consume both corpora.

## These are DERIVED and FROZEN (not hand-authored)

Every `expected.json` is **derived** by running
`agent_action_capsule.verify_disclosure_envelope()` over a hand-built
`input.json`, then **frozen**. A change to the result of any case is either
a spec/format revision (regenerate and review the diff) or a regression.
They regenerate via:

```bash
python/.venv-review/bin/python python/scripts/generate_all_vectors.py
```

(this also regenerates `../capsule/`; see that directory's own
regeneration caveats before running it against a checkout with local vector
edits).

The expected values are **spec-anchored** — see
`draft-mih-scitt-agent-action-capsule-disclosure-envelope-00.md`, "Verifier
Checks":

- `ok` — the overall envelope result: the wrapped `capsule`'s own Class 1
  `ok` AND every provided disclosure matches its committed digest.
- `capsule` — the wrapped Capsule's own Class 1 result, in the same shape
  as `../capsule/*/expected.json` (`ok`, `derived`,
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
vectors/disclosure-envelope/
  README.md
  vectors.json              — manifest: every case with kind + one-line description
  SHA256SUMS                — pins every input.json / expected.json byte
  <case>/input.json         — {"envelope": {"capsule": {...}, "disclosures": {...}}}
  <case>/expected.json      — { ok, capsule: {...}, disclosures_checked, disclosures_matched, disclosure_findings }
```

## Cases

The corpus covers each disclosure result code: match, mismatch, ineligible
member, and missing committed digest. It also covers both eligible fields in a
single envelope, deterministic result ordering, and an uncanonicalizable value
that DE-3 must report as a mismatch. Disclosure findings never alter the
embedded Capsule's own Class-1 result or `capsule_id`.

## Running

`python/tests/test_disclosure_envelope_vectors.py` runs every case in this
directory through `verify_disclosure_envelope()` and asserts each
`expected.json`. To check an independent implementation, run it over each
`input.json` and compare `ok`, `capsule.ok`, `capsule.capsule_id_recomputed`,
and the per-member `disclosure_findings`.
