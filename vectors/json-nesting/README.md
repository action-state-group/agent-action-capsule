# JSON nesting limit

Every strict reader and canonicalizer that more than one implementation
shares reads objects and arrays nested up to 128 levels deep (`[]` is one
level, `[[]]` two) and refuses anything deeper, so one document never reads
differently across Go, Python, TypeScript and Rust (#498). The
evidence-interop/1 profile states the limit (`spec/interop-profile-v1.md`
§5.2); the capsule draft does not yet, and 128 is the limit the four share. Go's
`evidenceresult` and `evidenceplan` text readers, which no other
implementation has, keep `encoding/json`'s limit; a value they digest still
meets the 128 limit of `canonical`.

- A reader refuses deeper JSON text as it refuses other malformed input: an
  error from the strict decoders, `None` from the interop profile's
  `parse_json`, a malformed request from the Evidence Request reader.
- A canonicalizer (RFC 8785 JCS) refuses a deeper value with an error.
- A verifier refuses a deeper value before any check: Class 1 verification
  reports only `verifier_internal_error`, Bundle verification
  `bundle_malformed` on every claim.

`cases.json` holds the cases. Each has its JSON text (`json`), its nesting
`depth` and whether it is read (`accept`). An accepted case's text is its own
RFC 8785 form and `jcs_sha256` is its SHA-256. A refused case names in
`wraps` the accepted case whose text it wraps in one more array or object.
`python/scripts/generate_json_nesting_vectors.py` regenerates `cases.json`
and `SHA256SUMS`; this file is hand-written.

| Case | Depth | Read |
|---|---|---|
| `pos-arrays-at-limit` | 128 | yes |
| `neg-arrays-past-limit` | 129 | no |
| `pos-objects-at-limit` | 128 | yes |
| `neg-objects-past-limit` | 129 | no |
| `pos-mixed-at-limit` | 128 | yes |
| `neg-mixed-past-limit` | 129 | no |
| `pos-brackets-in-string` | 1 | yes |
| `pos-after-escaped-backslash` | 128 | yes |
| `neg-after-escaped-backslash` | 129 | no |

Run by Go (`./canonical`, `./evidencerequest`, and the Bundle fragment tests
in `./bundle`), Python (`test_json_nesting_vectors.py`, `test_bundle_vectors.py`),
TypeScript (`json-nesting.test.ts`, `fragment-vectors.test.ts`) and Rust
(`agent-action-capsule:json_nesting`, `agent-action-capsule:bundle_vectors`,
`evidence-request:json_nesting`, and the `evidence-request` unit tests).
