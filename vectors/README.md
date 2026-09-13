# Authoritative conformance vectors

This directory is the language-agnostic, releaseable conformance surface for
the Agent Action Capsule repository. Python is the reference producer; Python,
Go, and TypeScript consume these same-commit files in CI.

- `capsule/`: format-4 JCS, Capsule ID, Class-1, store, `references[]`, and
  unsupported-format rejection cases.
- `producer-envelope/`: binary COSE Producer Envelope cases.
- `disclosure-envelope/`: Disclosure Envelope DE-1 through DE-3 cases.
- `cross-language/`: format-4 input used by the all-producer/all-consumer
  interlock.
- `interop/`: established composition and run-under interoperability suites.

Regenerate the reference-produced corpora and every checksum from the repo
root:

```bash
python3 python/scripts/generate_all_vectors.py
```

The `vectors/vX.Y.Z` release workflow archives this directory directly. The
release asset is a deterministic snapshot at the selected commit; consumers
must pin the printed SHA-256 digest.
