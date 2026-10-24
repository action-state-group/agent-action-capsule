# Viewer core text vectors

The core's own fixed text, which every page draws and no module, wording
pack or bundle supplies (`spec/presentation-contract-v0.md` sections 6.1,
6.2 and 8):

- the banner's line for each verification state of section 6.2, with its
  `data-verify` and `data-verdict` values and whether the checks let the
  records be shown (a presentation refusal can still withhold them, and never
  changes the banner);
- the refusal line of invariant I1, and the lines of the unable-to-verify
  state;
- the verification page's check-list headings, each check's line in plain
  words with the technical name drawn under it, and the lines around the
  lists;
- the semantics cell of an extension row.

A viewer's words MUST equal these. The TypeScript core text
(`ts/src/verification-page.ts`) is the reference that generates them;
capsule-viewer (`action-state-group/capsule-viewer`,
`ts/src/evidence-graph-view.ts` there) draws the page from it:

```bash
cd ts && AAC_WRITE_VECTORS=1 npx vitest run test/verification-states.test.ts
```

(`python3 python/scripts/generate_all_vectors.py` runs the same command when
`ts/node_modules` is present.) Without `AAC_WRITE_VECTORS` the same test
checks that the committed files are exactly what the generator writes, and
reads each final banner state from the verification model against
`core-text.json`. capsule-viewer renders one page per banner state against the
same file: a held digest shows `checking` alone, then the final state.

The details line under an incomplete or failed banner
(`data-banner-detail`) names the verifier's findings, with counts, so it is
not fixed text and is not in this corpus; `ts/test/bundle-verdict.test.ts`
pins it.

| File | Cases | What |
|---|---|---|
| `core-text.json` | 21 | Seven banner states and fourteen check-list lines, with the refusal, unable, heading, extension-row and surrounding lines. |

`manifest.json` names the contract and the generator, and carries the
SHA-256 and case count of `core-text.json`.
