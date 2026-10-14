# Producer Envelope conformance vectors

Shared binary vectors for the AAC Producer Envelope profile in the current
draft. Python, Go, TypeScript, and Rust read this exact corpus.

Each case contains:

- `capsule_id.txt`: the expected 64-character lowercase hexadecimal Capsule ID;
- `envelope.cose`: a tagged COSE_Sign1 object;
- `expected.json`: the expected verdict, finding codes, and authenticated key.

The valid envelope has an attached raw 32-byte Capsule-ID payload, an empty
unprotected map, and a protected map containing exactly `alg=-8`, content type
`application/agent-action-capsule-id`, and a raw 32-byte Ed25519 public key as
`kid`. Negative cases cover signature and payload tampering, a wrong algorithm,
a wrong content type, nonempty unprotected data, extra protected data, and an
invalid key.

The encoding cases pin the Producer Envelope CBOR encoding rule: definite
lengths, the shortest form of every argument and float (outside and inside the
protected-header byte string), no tag but the outermost tag 18, a map as the
unprotected header, and byte strings as payload and signature. The Python
reference already enforced it; its normative draft text is held for -06
(agent-action-capsule#258). Each violation
is `envelope_malformed`. `protected-label-order` is positive: map-key order is
not constrained, and two maps with the same entries in different orders are
the same key. Python's cbor2 also treats the nested keys `1`, `1.0` and `true`
as equal, which the CBOR data model does not; such a key can only sit inside
an envelope that is already invalid, so the finding code for it is not pinned.
Verifiers may also bound nesting depth and container sizes;
no conforming envelope approaches such a bound, and the finding code for input
beyond one is implementation-defined, so no vector pins it.

Regenerate deterministically from the repository root:

```bash
python/.venv-review/bin/python python/scripts/generate_all_vectors.py
```

`generate_producer_envelope_vectors.py` rewrites the original cases only. The
later cases are appended by `generate_parity_hardening_vectors.py` and
`generate_envelope_encoding_vectors.py`, which leave existing cases untouched
and refresh `SHA256SUMS`. `generate_all_vectors.py` runs all three in that
order.

Vector generation uses a fixed test seed. The seed is public test material and
must never be used as a production signing key.
