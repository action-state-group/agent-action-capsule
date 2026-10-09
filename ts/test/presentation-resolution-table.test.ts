// The contract checker's resolution table (spec/presentation-contract-v0.md
// appendix A.3), run against this registry: 1,536 (descriptor, audience,
// format) cases -- verified or not; four spec_version states; a Result
// carrier or not; every subset of outcome-report/v1, eu-ai-act-compliance/v1
// and composed/v1; the graph model builds or not; two audiences; three
// formats. Each must resolve to the module the old if-chain picked
// (legacyOverDescriptor, which presentation-oracle.test.ts ties to the real
// old code). Then each load-bearing forbid is removed in turn and the
// registry must refuse the set, and the table must meet an ambiguity.
import { expect, it } from "vitest";
import { BUILTIN_MANIFESTS } from "../src/builtin-manifests.js";
import {
  PRESENTATION_FORMATS,
  PresentationAmbiguityError,
  PresentationRegistry,
  resolveModules,
  type PresentationDescriptor,
  type PresentationManifest,
  type PresentationModule,
} from "../src/presentation-registry.js";
import {
  ID_COMPLIANCE,
  ID_GRAPH,
  ID_OUTCOME,
  ID_RESULT,
  legacyOverDescriptor,
  REFUSAL,
} from "./helpers/legacy-dispatch.js";

const SPEC_TOKENS = [
  undefined,
  "report/v1",
  "evaluation-summary/v1",
  "org.example.other/v1",
];
const READ_EXTENSIONS = [
  "outcome-report/v1",
  "eu-ai-act-compliance/v1",
  "composed/v1",
];

function* universe(): Generator<[PresentationDescriptor, boolean]> {
  for (const verified of [true, false])
    for (const spec of SPEC_TOKENS)
      for (const result of [false, true])
        for (let mask = 0; mask < 1 << READ_EXTENSIONS.length; mask += 1)
          for (const graphBuilds of [true, false]) {
            const profiles = new Set<string>();
            if (spec !== undefined) profiles.add(`spec_version:${spec}`);
            if (result) profiles.add("result_version:evidence-result-v0");
            yield [
              {
                verified,
                bundle_kind: "evidence-bundle/v2",
                profiles,
                extensions: new Set(
                  READ_EXTENSIONS.filter((_, i) => mask & (1 << i)),
                ),
              },
              graphBuilds,
            ];
          }
}

// Stand-ins carrying the real manifests: resolution reads manifests and
// canRender only. Only the graph can decline, exactly when its model fails.
const stub = (manifest: PresentationManifest): PresentationModule => ({
  manifest,
  canRender: () => true,
  buildModel: () => null,
  render: () => undefined,
});

async function table(
  manifests: readonly PresentationManifest[],
): Promise<{ cases: number; mismatches: string[]; ambiguities: number }> {
  const modules = manifests.map(stub);
  let cases = 0;
  let ambiguities = 0;
  const mismatches: string[] = [];
  for (const [descriptor, graphBuilds] of universe()) {
    const want = legacyOverDescriptor(descriptor, graphBuilds);
    for (const audience of ["owner", "counterparty"])
      for (const format of PRESENTATION_FORMATS) {
        cases += 1;
        try {
          const got = await resolveModules(
            modules,
            descriptor,
            audience,
            format,
            (m) => (m.manifest.id === ID_GRAPH ? graphBuilds : true),
          );
          const id =
            got.kind === "module"
              ? got.module.manifest.id
              : got.kind === "refusal"
                ? REFUSAL
                : "<no-presentation>";
          if (id !== want)
            mismatches.push(
              `${[...descriptor.profiles].join(",")} ${[...descriptor.extensions].join(",")} graph=${graphBuilds}: old ${want}, resolved ${id}`,
            );
        } catch (err) {
          if (!(err instanceof PresentationAmbiguityError)) throw err;
          ambiguities += 1;
        }
      }
  }
  return { cases, mismatches, ambiguities };
}

it("the 1,536-case table resolves exactly as the old control flow dispatched", async () => {
  const registry = new PresentationRegistry();
  for (const manifest of BUILTIN_MANIFESTS) registry.register(stub(manifest));
  const { cases, mismatches, ambiguities } = await table(BUILTIN_MANIFESTS);
  expect(cases).toBe(1536);
  expect(ambiguities).toBe(0);
  expect(mismatches).toEqual([]);
});

function dropForbid(
  id: string,
  field: "profiles" | "extensions",
  token: string,
): PresentationManifest[] {
  return BUILTIN_MANIFESTS.map((manifest) => {
    if (manifest.id !== id) return manifest;
    const forbids = { ...manifest.forbids };
    const kept = (forbids[field] ?? []).filter((t) => t !== token);
    if (kept.length === 0) delete forbids[field];
    else forbids[field] = kept;
    const copy: Record<string, unknown> = { ...manifest, forbids };
    if (Object.keys(forbids).length === 0) delete copy.forbids;
    return copy as unknown as PresentationManifest;
  });
}

it.each([
  [ID_COMPLIANCE, "extensions", "outcome-report/v1"],
  [ID_RESULT, "extensions", "eu-ai-act-compliance/v1"],
  [ID_RESULT, "extensions", "outcome-report/v1"],
  [ID_GRAPH, "profiles", "result_version:evidence-result-v0"],
  [ID_OUTCOME, "profiles", "spec_version:report/v1"],
] as const)(
  "MUTANT: without %s forbidding %s %s, registration refuses the set and the table meets an ambiguity",
  async (id, field, token) => {
    const mutated = dropForbid(id, field, token);
    const registry = new PresentationRegistry();
    expect(() => {
      for (const manifest of mutated) registry.register(stub(manifest));
    }).toThrow(PresentationAmbiguityError);
    const { ambiguities } = await table(mutated);
    expect(ambiguities).toBeGreaterThan(0);
  },
);
