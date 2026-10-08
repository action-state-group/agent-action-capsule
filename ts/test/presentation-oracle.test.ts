// @vitest-environment jsdom
// The registry against the old control flow, on real bundles: every fixture
// page the render-diff covers, plus each verified one re-dressed with every
// combination of the extension blocks the old dispatch read (and composed/v1,
// which it ignored). For each, resolve() must pick the module the old
// if-chain picked; where the old chain threw before drawing, the selected
// module's buildModel must throw the same error.
import { readFileSync, readdirSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import { expect, it } from "vitest";
import {
  buildVerifiedBundleContext,
  type VerifiedBundleContext,
} from "../src/bundle.js";
import {
  buildEvidenceGraph,
  EvidenceGraphError,
} from "../src/evidence-graph.js";
import { createPresentationRegistry } from "../src/evidence-graph-view.js";
import {
  bundleVerified,
  describeContext,
  PRESENTATION_FORMATS,
} from "../src/presentation-registry.js";
import {
  derivedFixture,
  type DerivedFixtureName,
} from "./helpers/derived-fixtures.js";
import {
  ID_COMPLIANCE,
  ID_GRAPH,
  ID_NO_AGGREGATE,
  ID_OUTCOME,
  ID_RESULT,
  ID_ROWS,
  legacyBundleVerified,
  legacyDispatch,
  legacyOverDescriptor,
  REFUSAL,
} from "./helpers/legacy-dispatch.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

type Obj = Record<string, unknown>;
const testdata = resolvePath(process.cwd(), "test", "testdata");
const vectors = resolvePath(process.cwd(), "..", "vectors", "bundle");
const json = (path: string): Obj =>
  JSON.parse(readFileSync(path, "utf8")) as Obj;

async function fixtureBundles(): Promise<Array<[string, unknown]>> {
  const out: Array<[string, unknown]> = [];
  const skip = new Set([
    "bundle-vectors.json",
    "countersign-v1-anchor-golden.json",
    "countersigners.json",
    "witnesses-with-placeholder.json",
  ]);
  for (const file of readdirSync(testdata)
    .filter((f) => f.endsWith(".json") && !skip.has(f))
    .sort()) {
    const bundle = json(resolvePath(testdata, file));
    out.push([`testdata/${file}`, bundle]);
    try {
      out.push([
        `testdata/${file}#sealed`,
        (await sealEvidenceBundle(bundle)).bundle,
      ]);
    } catch {
      /* not sealable: the raw form above still counts */
    }
  }
  for (const name of [
    "week-bundle-empty-countersignatures.json",
    "week-bundle-producer-countersigned.json",
    "week-bundle-directory-countersigned.json",
    "week-bundle-unresolved-countersigned.json",
    "week-bundle-presentation.json",
  ] as DerivedFixtureName[])
    out.push([`derived/${name}`, await derivedFixture(name)]);
  // A verified bundle whose root names itself a Result v0 but is malformed:
  // the old chain threw before drawing anything.
  const malformed = json(resolvePath(testdata, "result-root-bundle.json"));
  (
    (((malformed.disclosures as Obj).result as Obj).agent_input as Obj)
      .claims as Obj[]
  )[2]!.verdict = "met";
  out.push([
    "malformed-result-root#sealed",
    (await sealEvidenceBundle(malformed)).bundle,
  ]);
  for (const c of json(resolvePath(vectors, "producer-key", "vectors.json"))
    .cases as Obj[])
    out.push([`vectors/bundle/producer-key/${String(c.id)}`, c.bundle]);
  for (const c of json(resolvePath(vectors, "report-single-record.json"))
    .cases as Obj[])
    out.push([
      `vectors/bundle/report-single-record/${String(c.name)}`,
      c.bundle,
    ]);
  for (const c of json(resolvePath(vectors, "composed", "vectors.json"))
    .cases as Obj[])
    out.push([`vectors/bundle/composed/${String(c.id)}`, c.container]);
  return out;
}

const complianceBlock = (
  json(resolvePath(testdata, "compliance-bundle.json")).extensions as Obj
)["eu-ai-act-compliance/v1"];
// [label, block] per extension; undefined removes the kind.
const OUTCOME_CHOICES: Array<[string, unknown]> = [
  ["outcome:absent", undefined],
  ["outcome:enabled", { enabled: true }],
  ["outcome:declined", { enabled: false }],
];
const COMPLIANCE_CHOICES: Array<[string, unknown]> = [
  ["compliance:absent", undefined],
  ["compliance:enabled", complianceBlock],
  ["compliance:declined", { enabled: true, obligations: [] }],
];
const COMPOSED_CHOICES: Array<[string, unknown]> = [
  ["composed:absent", undefined],
  ["composed:present", { kind: "composed/v1" }],
];

function withExtensions(bundle: unknown, blocks: Obj): unknown {
  const copy = structuredClone(bundle) as Obj;
  const extensions = { ...((copy.extensions as Obj | undefined) ?? {}) };
  for (const [kind, block] of Object.entries(blocks))
    if (block === undefined) delete extensions[kind];
    else extensions[kind] = block;
  copy.extensions = extensions;
  return copy;
}

async function graphBuilds(context: VerifiedBundleContext): Promise<boolean> {
  try {
    await buildEvidenceGraph(context);
    return true;
  } catch (err) {
    if (err instanceof EvidenceGraphError) return false;
    throw err;
  }
}

it("resolve() picks the old control flow's module for every fixture and every extension combination", async () => {
  const registry = createPresentationRegistry();
  const cases: Array<[string, unknown]> = [];
  for (const [name, bundle] of await fixtureBundles()) {
    cases.push([name, bundle]);
    const context = await buildVerifiedBundleContext(bundle);
    if (!bundleVerified(context.verification)) continue;
    for (const [o, outcome] of OUTCOME_CHOICES)
      for (const [c, compliance] of COMPLIANCE_CHOICES)
        for (const [m, composed] of COMPOSED_CHOICES)
          cases.push([
            `${name} {${o} ${c} ${m}}`,
            withExtensions(bundle, {
              "outcome-report/v1": outcome,
              "eu-ai-act-compliance/v1": compliance,
              "composed/v1": composed,
            }),
          ]);
  }

  const seen = new Map<string, number>();
  let resolutions = 0;
  for (const [name, bundle] of cases) {
    const context = await buildVerifiedBundleContext(bundle);
    expect(bundleVerified(context.verification), name).toBe(
      legacyBundleVerified(context.verification),
    );
    let want: string;
    let legacyError: unknown;
    try {
      want = await legacyDispatch(context);
    } catch (err) {
      want = "<threw>";
      legacyError = err;
    }
    seen.set(want, (seen.get(want) ?? 0) + 1);
    for (const audience of ["*", "owner", "counterparty"])
      for (const format of PRESENTATION_FORMATS) {
        resolutions += 1;
        const got = await registry.resolve(context, audience, format);
        if (legacyError !== undefined) {
          // The old chain threw before drawing: the same module family is
          // selected and its buildModel throws the same error.
          expect(got.kind, name).toBe("module");
          if (got.kind !== "module") continue;
          await expect(
            Promise.resolve().then(() => got.module.buildModel(context)),
            name,
          ).rejects.toThrow(String((legacyError as Error).message));
          continue;
        }
        const id =
          got.kind === "module"
            ? got.module.manifest.id
            : got.kind === "refusal"
              ? REFUSAL
              : "<no-presentation>";
        expect(id, `${name} ${audience}/${format}`).toBe(want);
      }
    // The descriptor transcription the 1,536-case table uses agrees with the
    // real old code on this real bundle.
    if (legacyError === undefined)
      expect(
        legacyOverDescriptor(
          describeContext(context),
          await graphBuilds(context),
        ),
        name,
      ).toBe(want);
  }
  // Every page shape, the floor, the refusal and the pre-draw throw occur.
  for (const id of [
    ID_ROWS,
    ID_OUTCOME,
    ID_COMPLIANCE,
    ID_RESULT,
    ID_GRAPH,
    ID_NO_AGGREGATE,
    REFUSAL,
    "<threw>",
  ])
    expect(seen.get(id) ?? 0, `cases selecting ${id}`).toBeGreaterThan(0);
  console.info(
    `presentation oracle: ${cases.length} bundles, ${resolutions} resolutions; by old branch: ${JSON.stringify(Object.fromEntries(seen))}`,
  );
}, 600_000);
