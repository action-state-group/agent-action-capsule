// @vitest-environment jsdom
import { readFileSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import { describe, expect, it } from "vitest";
import {
  buildVerifiedBundleContext,
  type VerifiedBundleContext,
} from "../src/bundle.js";
import {
  BUILTIN_PRESENTATIONS,
  createPresentationRegistry,
} from "../src/evidence-graph-view.js";
import {
  describeContext,
  PresentationAmbiguityError,
  type PresentationFormat,
  type PresentationManifest,
  type PresentationModule,
  resolveModules,
} from "../src/presentation-registry.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

/**
 * Two deal pages, shipped by two tools, against one unilateral x-deal-v0
 * bundle: capsulectl.deal-view/v0 (capsule-cli) and
 * capsuleviewer.receipt.unilateral/v0 (capsule-viewer). Both are specific,
 * both require only x-deal-v0, both serve html to keep, counterparty and
 * adjudicator. A real deal bundle's root carries no spec_version, so its
 * descriptor has no profile either manifest could split on (section 4.2).
 *
 * resolution.json is what the registry does today, pinned: one named error,
 * PresentationAmbiguityError with both ids, at registration (section 4.5)
 * and, for a resolver that skipped that test, at resolution (section 4.3).
 */

type Obj = Record<string, unknown>;
const dir = resolvePath(
  process.cwd(),
  "test",
  "testdata",
  "deal-presentation-ambiguity",
);
const json = (name: string): Obj =>
  JSON.parse(readFileSync(resolvePath(dir, name), "utf8")) as Obj;

const DEAL_VIEW = json(
  "capsulectl.deal-view.manifest.json",
) as unknown as PresentationManifest;
const UNILATERAL = json(
  "capsuleviewer.receipt.unilateral.manifest.json",
) as unknown as PresentationManifest;
const GOLDEN = json("resolution.json");
const FORMAT: PresentationFormat = "html";

function stub(manifest: PresentationManifest, calls: string[]) {
  return {
    manifest,
    canRender: () => {
      calls.push(manifest.id);
      return true;
    },
    buildModel: () => ({}),
    render: () => {},
  } satisfies PresentationModule;
}

function outcome(run: () => unknown): Obj {
  try {
    run();
  } catch (error) {
    if (error instanceof PresentationAmbiguityError)
      return { error: error.name, ids: [...error.ids], message: error.message };
    throw error;
  }
  return { registered: true };
}

async function resolved(
  modules: readonly PresentationModule[],
  context: VerifiedBundleContext,
  audience: string,
  calls: string[],
): Promise<Obj> {
  try {
    const resolution = await resolveModules(
      modules,
      describeContext(context),
      audience,
      FORMAT,
      (module) => module.canRender(context),
    );
    return resolution.kind === "module"
      ? { winner: resolution.module.manifest.id }
      : { kind: resolution.kind };
  } catch (error) {
    if (error instanceof PresentationAmbiguityError)
      return { error: error.name, ids: [...error.ids], canRender: [...calls] };
    throw error;
  }
}

async function unilateralDealContext(): Promise<VerifiedBundleContext> {
  const { bundle } = await sealEvidenceBundle(
    json("unilateral-deal-bundle.json"),
  );
  return buildVerifiedBundleContext(bundle);
}

async function observed(context: VerifiedBundleContext): Promise<Obj> {
  const descriptor = describeContext(context);
  const calls: string[] = [];
  const dealView = stub(DEAL_VIEW, calls);
  const unilateral = stub(UNILATERAL, calls);
  const modules = [...BUILTIN_PRESENTATIONS, dealView, unilateral];
  const resolve: Obj = {};
  for (const audience of ["keep", "counterparty", "adjudicator", "*"]) {
    calls.length = 0;
    resolve[audience] = await resolved(modules, context, audience, calls);
  }
  return {
    descriptor: {
      verified: descriptor.verified,
      bundle_kind: descriptor.bundle_kind,
      profiles: [...descriptor.profiles].sort(),
      extensions: [...descriptor.extensions].sort(),
    },
    register: {
      "deal-view then unilateral": outcome(() => {
        const registry = createPresentationRegistry();
        registry.register(dealView);
        registry.register(unilateral);
      }),
      "unilateral then deal-view": outcome(() => {
        const registry = createPresentationRegistry();
        registry.register(unilateral);
        registry.register(dealView);
      }),
      // The candidate "deal-view becomes the generic page for x-deal-v0":
      // the fallback tier already holds aac.builtin.no-aggregate/v0.
      "deal-view as a fallback": outcome(() => {
        const { priority: _priority, ...rest } = DEAL_VIEW;
        createPresentationRegistry().register(
          stub({ ...rest, fallback: true }, calls),
        );
      }),
    },
    resolve,
  };
}

describe("capsulectl.deal-view/v0 and capsuleviewer.receipt.unilateral/v0 on one unilateral x-deal-v0 bundle", () => {
  it("is one named error, PresentationAmbiguityError, at registration and at resolution: never first-wins", async () => {
    const context = await unilateralDealContext();
    expect(await observed(context)).toEqual(GOLDEN);
  });

  it("each manifest alone is selected for the bundle: the error is the pair, not either manifest", async () => {
    const context = await unilateralDealContext();
    for (const manifest of [DEAL_VIEW, UNILATERAL]) {
      const registry = createPresentationRegistry();
      registry.register(stub(manifest, []));
      const resolution = await registry.resolve(context, "keep", FORMAT);
      expect(
        resolution.kind === "module" && resolution.module.manifest.id,
      ).toBe(manifest.id);
    }
  });

  it("without x-deal-v0 neither matches and the built-in fallback renders", async () => {
    const source = json("unilateral-deal-bundle.json");
    delete source.extensions;
    const { bundle } = await sealEvidenceBundle(source);
    const context = await buildVerifiedBundleContext(bundle);
    const resolution = await resolveModules(
      [...BUILTIN_PRESENTATIONS, stub(DEAL_VIEW, []), stub(UNILATERAL, [])],
      describeContext(context),
      "keep",
      FORMAT,
      (module) => module.canRender(context),
    );
    expect(resolution.kind === "module" && resolution.module.manifest.id).toBe(
      "aac.builtin.no-aggregate/v0",
    );
  });
});
