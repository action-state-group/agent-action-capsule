# Task 6 report

Implemented the browser IIFE build path without committing generated `dist` output.

- Added `esbuild` as a development dependency.
- Added `emitter:iife`, bundling `src/browser.ts` to `dist/evidence-graph.iife.js` and exposing `globalThis.renderEvidenceGraph`.
- Wired the IIFE build into `npm run build`.
- Verified the existing `src/index.ts` barrel exports `emitEvidenceGraphHtml` through `emitter.ts`.
- Added a deterministic Vitest that invokes the build and checks the generated artifact for `renderEvidenceGraph` and a non-trivial size.
- Documented the Go `EmitEvidenceGraphHTML` browser-IIFE relationship.

Validation: `cd ts && npm run check` passed: 10 test files and 152 tests.
