# Disclosure Envelope conformance vectors

These frozen vectors cover the Disclosure Envelope companion profile in
`../../spec/draft-mih-scitt-agent-action-capsule-disclosure-envelope-00.md`.
Each input wraps one format-4 Capsule and a `disclosures` object.

This corpus is separate from `../capsule/` because the envelope is a distinct
wrapper and result shape. Python, Go, and TypeScript consume both corpora.

## Expected-result provenance

Reference-derived cases are frozen outputs from the reference verifier.
Spec-derived cases are hand-derived from the companion profile and RFC 8785
and MUST NOT be regenerated from an implementation. Newly derived hashes carry
their exact strings in `canonical_preimages`.

## Expected result

- `ok`: the wrapped Capsule is valid and every provided disclosure matches.
- `capsule`: the wrapped Capsule's independent Class-1 result.
- `disclosures_checked` and `disclosures_matched`: deterministic counts.
- `disclosure_findings`: one DE-1 through DE-3 result per supplied disclosure.

The corpus covers matches for nested input and output values, objects inside
arrays, a one-leaf nested mismatch, an ineligible member, a missing committed
digest, both eligible fields with deterministic ordering, and an
uncanonicalizable disclosure. A bad disclosure never changes the wrapped
Capsule's own Class-1 result or Capsule ID.

## Layout

```text
vectors/disclosure-envelope/
  README.md
  vectors.json
  SHA256SUMS
  <case>/input.json
  <case>/expected.json
```
