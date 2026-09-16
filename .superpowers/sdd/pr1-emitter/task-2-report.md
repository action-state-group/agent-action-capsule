# Task 2 report

## Delivered

- Added `renderEvidenceGraph(bundle, root)` to the browser entry point.
- Rendered aggregate metrics, optional human-check data, date-sorted report tiles,
  report outcome/case drill-down, per-axis judgments, disclosed act transcripts,
  and capsule/log provenance.
- Rendered a verification banner from `verifyBundle`; the verified state requires
  passing graph, interval, membership, and capsule checks.
- Kept case payloads out of the view. The renderer consumes only the Task 1
  evidence-graph model and uses DOM `textContent` for displayed values.
- Added the jsdom DOM test environment and a drill-down/verification test using
  `week-bundle.json`.

## Verification

`cd ts && npm run check` passed: Prettier, TypeScript typecheck, 146 Vitest
tests, and the TypeScript build all completed successfully.

## Scope

Only `ts/` implementation, test, and package metadata were changed. No Go
files were modified.
