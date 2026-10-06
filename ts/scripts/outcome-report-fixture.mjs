// Regenerates test/testdata/outcome-report-bundle.json, the unsealed bundle
// source the outcome-report tests seal at test time
// (test/helpers/sealed-bundle.ts).
//
// The source is the output of a judge pipeline run -- evidencebook-skills'
// daily judge with its deterministic mock backend over the public tau2-bench
// airline tasks (scripts/run_daily.py, then scripts/rollup_day.py for the
// day's Result v0 document, then the pipeline's fixture builder, which
// fetches every cited record from the book with `capsulectl get` into the
// unsealed bundle source shape). This script takes that file and writes the
// fixture: the same records and disclosures, with the card's opt-in block
// set to exactly `{ "enabled": true, "percentages": false }` and every other
// extension dropped, so the fixture carries no setting the card does not
// read. Deterministic: the same input always writes the same bytes.
//
//   node scripts/outcome-report-fixture.mjs [SOURCE.json]
//
// With no argument it re-normalizes the committed fixture in place.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const target = resolve(
  here,
  "..",
  "test",
  "testdata",
  "outcome-report-bundle.json",
);
const source =
  process.argv[2] === undefined ? target : resolve(process.argv[2]);
const bundle = JSON.parse(readFileSync(source, "utf8"));
if (typeof bundle.root !== "string" || !Array.isArray(bundle.records))
  throw new Error(`${source}: not an unsealed bundle source (root, records)`);
const out = {
  root: bundle.root,
  extensions: { "outcome-report/v1": { enabled: true, percentages: false } },
  ...Object.fromEntries(
    Object.entries(bundle).filter(([k]) => k !== "root" && k !== "extensions"),
  ),
};
writeFileSync(target, `${JSON.stringify(out, null, 2)}\n`);
console.log(`wrote ${target}`);
