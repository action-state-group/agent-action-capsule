# Presentation resolution vectors

Shared vectors for the presentation registry of
`spec/presentation-contract-v0.md`: the presentation ABI refusal (section
3.2), the descriptor a verified bundle yields (section 4.2), the match and
the two tiers (sections 4.3 and 4.4), and the static ambiguity test at
registration (section 4.5).

They are normative for every implementation of the registry. Today that is
the TypeScript registry (`ts/src/presentation-registry.ts`) and the Go
package `go/presentation`; both run every case in CI, and a result that
differs from a case is a bug in the implementation. The TypeScript registry
is the reference that generates them:

```bash
cd ts && AAC_WRITE_VECTORS=1 npx vitest run test/presentation-resolution-vectors.test.ts
```

(`python3 python/scripts/generate_all_vectors.py` runs the same command when
`ts/node_modules` is present.) Without `AAC_WRITE_VECTORS` the same test
checks that the committed files are exactly what the generator writes.

## Shared encodings

- A **descriptor** is `{verified, bundle_kind, profiles, extensions}`, with
  `bundle_kind` `null` when the bundle has none and the two sets as sorted
  arrays.
- A **runtime** is `{presentation_apis, runtime_version}`.
- A **resolution** is `{kind: "refusal"}`, `{kind: "no-presentation",
  refused}`, `{kind: "module", module, refused}` or an error: `{kind:
  "ambiguity", ids, message}`. `refused` lists each refusal recorded on the
  way, as `{id, presentation_api, runtime_min, reason, extensions,
  runtime_version}` plus its exact section 3.2 wording: `row_covered` and
  `row_uncovered` (the semantics cell of an extension row, with and without
  bundle-digest coverage) and `line` (the line for a module that requires no
  extension).
- `declines` lists the module ids whose `canRender` is false; every other
  module renders. An implementation with no module code (the Go package)
  takes this as its `canRender` answer.
- A registration error is `{kind: "ambiguity", ids, message}` or `{kind:
  "registration", message}`; messages are compared exactly.

## Files

| File | Cases | What |
|---|---|---|
| `table.json` | 1,536 | Appendix A.3's table, in full: verified or not; four `spec_version` states; a Result carrier or not; every subset of `outcome-report/v1`, `eu-ai-act-compliance/v1` and `composed/v1`; the graph renders or declines; two audiences; three formats; resolved over the six built-in page manifests under the reference runtime. |
| `registration.json` | 53 | Small registries: the built-ins, the built-in section registry, appendix B's examples, every refusal reason and their precedence, numeric `runtime_min` comparison, a runtime implementing several or no APIs, refused modules counting for ambiguity, the ambiguous pair (registered, and resolved without the registration test), each appendix A forbid removed in turn (both ways), duplicate ids, disjoint audiences and formats, and each malformed or dead manifest rule the registry enforces. |
| `descriptors.json` | 377 | Section 4.2 over real bundles: the small test fixtures (unsealed, and sealed into verified bundles), a Result fixture with its root input withheld and with a tampered disclosure, and the bundles of `bundle/producer-key/`, `bundle/report-single-record.json` and `bundle/composed/`; each verified one also with every combination of the `outcome-report/v1` and `eu-ai-act-compliance/v1` blocks (absent, engaged, declined) and `composed/v1` (absent, present). Each case records the descriptor and the module the built-in page and section registries select for it (audience `*`, format `html`, every module rendering). This is the parity test of the Go verifier and descriptor against the TypeScript ones. |

`manifest.json` carries the built-in page and section manifests exactly as
the TypeScript package defines them, the reference runtime, and the SHA-256
and case count of each file.

## Left out

- The two largest fixtures (`outcome-report-bundle.json`, `week-bundle.json`,
  several megabytes each). The overlays on the small Result fixture engage
  the same extension readers.
- The sealed forms of `report-mixed-tz-bundle.json` and
  `report-rows-uncheckpointed-bundle.json`: one of their records carries a
  non-object `provenance_mode`, which the Python and Go record verifiers
  reject (`block_not_object`) and the TypeScript one does not yet check, so
  the two disagree on "verified". Their unsealed forms are carried.
- The schema-only negative `neg-hint-wording-source.json`: the registry does
  not read the declarative block, so only the JSON Schema rejects it.
