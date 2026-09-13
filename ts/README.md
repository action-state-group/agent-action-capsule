# Agent Action Capsule TypeScript reference

This package is the record-format reference conforming to the Python authority
in this repository. It implements strict JSON/JCS, format-4 Capsule IDs, the
typed record model, Class-1 and `references[]` verification, registries,
Producer Envelopes, and Disclosure Envelopes through DE-3. It intentionally
does not contain producer verbs, CLL storage, policy, adapters, or permalink
transport.

Requires Node.js 22 or newer.

```bash
npm ci
npm run check
```

The tests consume the same-commit corpora under `../vectors/`.
