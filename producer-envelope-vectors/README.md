# Producer Envelope conformance vectors

Shared binary vectors for the AAC Producer Envelope profile in the current
draft. Both the Python and Go runtimes read this exact corpus.

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

Regenerate deterministically from the repository root:

```bash
cd python
uv run --no-project --with cbor2 --with cryptography --with scitt-cose \
  -- python scripts/generate_producer_envelope_vectors.py
```

Vector generation uses a fixed test seed. The seed is public test material and
must never be used as a production signing key.
