# Authoritative conformance vectors

This directory is the language-agnostic, releasable conformance surface for
the Agent Action Capsule repository. Python, Go, and TypeScript consume these
same-commit files in CI.

- `capsule/`: format-4 JCS, Capsule ID, Class-1, store, `references[]`, and
  deliberate unsupported-format rejection cases. Most cases carry
  `spec_version` `-04` and stay frozen: they show `-04` Capsules still verify.
  The `pos-v05-*` cases carry `-05` and exercise the `-05` registrations;
  `python/scripts/generate_v05_vectors.py` regenerates them.
- `producer-envelope/`: binary COSE Producer Envelope cases.
- `disclosure-envelope/`: Disclosure Envelope DE-1 through DE-3 cases.
- `cross-language/`: format-4 input used by the all-producer/all-consumer
  interlock.
- `interop/`: established composition and run-under interoperability suites.

Reference-derived corpora and checksum manifests can be regenerated with:

```bash
python3 python/scripts/generate_all_vectors.py
```

Do not overwrite `spec-derived` cases with generator output. Their recorded
preimages and expected results are the implementation-independent authority.

The `vectors/vX.Y.Z` release workflow archives this directory directly. The
release asset is a deterministic snapshot at the selected commit; consumers
must pin the printed SHA-256 digest.

## Provenance

Each case may carry a `provenance` field in both its `vectors.json` entry and
its `expected.json`. `reference-derived` identifies an expected result frozen
from the reference verifier. `spec-derived` identifies a value derived from the
draft and RFC 8785 without running any repository implementation. A
`spec-derived` expected result records each literal RFC 8785 canonical string
used for a SHA-256 golden value in `canonical_preimages`.
