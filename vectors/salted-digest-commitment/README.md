# Salted JSON-DIGEST commitment vectors

**Informative.** These vectors exercise the construction described in
`docs/salted-digest-commitment.md` (identifier `sha256-jcs-nonce256`). It
registers nothing and places no requirement on producers.

A producer commits to a text `T` with a 256-bit nonce `N`, written as 64
lowercase hex characters:

    commitment = JSON-DIGEST({"nonce": N, "text": T})

JSON-DIGEST is the base profile's rule: lowercase-hex SHA-256 of
`UTF8(JCS(value))` (RFC 8785). The commitment is opened by disclosing the
object `{"nonce": N, "text": T}`. A verifier checks the opening exactly as
Disclosure Envelope DE-3 checks a disclosed value: it recomputes JSON-DIGEST
of the opening and compares it with the commitment.

## Derivation

`python/scripts/generate_salted_digest_commitment_vectors.py` writes every file
except this README. It uses only the standard library and runs no repository
implementation. The nonces are fixed test values, not secrets.
`python/tests/test_salted_digest_commitment_vectors.py` regenerates the
directory byte for byte and checks every case with the reference library's
`json_digest`. `go/canonical/salted_digest_commitment_vectors_test.go` and
`ts/test/salted-digest-commitment-vectors.test.ts` check the same cases with
the Go and TypeScript JSON-DIGEST.

Each case carries `opening_jcs`, the literal RFC 8785 string of the opening,
so a reader can recompute a commitment with any SHA-256 tool.

## Cases

| Case | What it shows | Expected |
|---|---|---|
| `pos-ascii` | ASCII text | match |
| `pos-non-ascii-newline` | U+20AC and a newline (`\n` in JCS) | match |
| `pos-non-ascii-punctuation` | U+2014 and an apostrophe, unescaped in JCS | match |
| `neg-text-edited` | last character of the text changed | mismatch |
| `neg-nonce-other` | right text, another well-formed nonce | mismatch |
| `neg-nonce-uppercase` | right nonce in upper case; JCS does not case-fold | mismatch |
| `neg-nonce-empty` | right text, empty nonce | mismatch |
| `neg-trailing-space` | one trailing space added to the text | mismatch |
| `equality-same-nonce-same-text` | the same nonce and text give the same commitment | equal |

Each negative names the positive whose commitment it fails to open
(`against`) and records what its own opening recomputes to (`recomputed`).
