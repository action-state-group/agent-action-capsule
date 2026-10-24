// The presentation registry (spec/presentation-contract-v0.md sections 3.2
// and 4): registration, resolution over a verified context, and the ABI
// refusals. The built-in modules stand in by their manifests
// (BUILTIN_MANIFESTS); the modules themselves, and the page that draws what
// resolve() selects, are capsule-viewer's (action-state-group/capsule-viewer).
import { readFileSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import { describe, expect, it } from "vitest";
import {
  buildVerifiedBundleContext,
  type VerifiedBundleContext,
} from "../src/bundle.js";
import {
  BUILTIN_MANIFEST_NO_AGGREGATE,
  BUILTIN_MANIFESTS,
} from "../src/builtin-manifests.js";
import {
  describeContext,
  presentationRefusalLine,
  presentationRefusalRow,
  PresentationAmbiguityError,
  PresentationRegistrationError,
  PresentationRegistry,
  resolveModules,
  type PresentationManifest,
  type PresentationModule,
  type PresentationResolution,
  type PresentationResolver,
  REFERENCE_PRESENTATION_RUNTIME,
} from "../src/presentation-registry.js";
import type { VerificationBanner } from "../src/verification-page.js";
import { pageModel } from "./helpers/page-model.js";
import { stub } from "./helpers/presentation-resolution-vectors.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

type Obj = Record<string, unknown>;
const json = (path: string): Obj =>
  JSON.parse(readFileSync(path, "utf8")) as Obj;
const testdata = resolvePath(process.cwd(), "test", "testdata");

// A verified bundle no built-in specific module matches: its root carries no
// profile token, and it carries the producer-key/v1 extension.
const producerKeyBundle = (): unknown =>
  (
    json(
      resolvePath(
        process.cwd(),
        "..",
        "vectors",
        "bundle",
        "producer-key",
        "vectors.json",
      ),
    ).cases as Obj[]
  )[0]!.bundle;

const BUILTIN_PROFILES = [
  "spec_version:report/v1",
  "spec_version:evaluation-summary/v1",
  "result_version:evidence-result-v0",
];

function manifest(overrides: Partial<Obj> = {}): PresentationManifest {
  return {
    spec_version: "aac.presentation-manifest/v0",
    id: "org.example.view/v0",
    presentation_api: "aac.presentation-api/v0",
    runtime_min: "0.1.0",
    trust_class: "trusted-executable",
    requires: {
      bundle_kind: "evidence-bundle/v2",
      extensions: { required: ["producer-key/v1"] },
    },
    forbids: { profiles: BUILTIN_PROFILES },
    audiences: ["*"],
    formats: ["html", "fragment", "embedded"],
    fallback: false,
    priority: 1,
    executable: { carrier: "module-slot", script_sha256: "0".repeat(64) },
    ...overrides,
  } as PresentationManifest;
}

// The built-in modules by their manifests, each able to render.
const BUILTIN_PRESENTATIONS: readonly PresentationModule[] =
  BUILTIN_MANIFESTS.map(stub);

/** A fresh registry holding the seven built-in manifests. */
function createPresentationRegistry(): PresentationRegistry {
  const registry = new PresentationRegistry();
  for (const module of BUILTIN_PRESENTATIONS) registry.register(module);
  return registry;
}

const defaultRegistry = createPresentationRegistry();
const registerPresentation = (module: PresentationModule) =>
  defaultRegistry.register(module);

interface Spy {
  readonly module: PresentationModule;
  readonly calls: string[];
}

function spyModule(
  m: PresentationManifest,
  behaviour: { canRender?: boolean } = {},
): Spy {
  const calls: string[] = [];
  return {
    calls,
    module: {
      manifest: m,
      canRender: () => {
        calls.push("canRender");
        return behaviour.canRender ?? true;
      },
      buildModel: () => {
        calls.push("buildModel");
        return { id: m.id };
      },
      render: () => {
        calls.push("render");
      },
    },
  };
}

interface Resolved {
  readonly banner: VerificationBanner;
  readonly resolution: PresentationResolution;
  /** The selected module's id, if one was selected. */
  readonly selected: string | undefined;
  /** The refused modules that matched, as the page names them. */
  readonly refused: string;
}

// Verify the bundle and resolve its page over `registry`, as a viewer does.
async function render(
  bundle: unknown,
  registry: PresentationResolver,
  options: { audience?: string } = {},
): Promise<Resolved> {
  const { context, banner } = await pageModel(bundle);
  const resolution = await registry.resolve(
    context,
    options.audience ?? "*",
    "html",
  );
  return {
    banner,
    resolution,
    selected:
      resolution.kind === "module" ? resolution.module.manifest.id : undefined,
    refused:
      resolution.kind === "refusal"
        ? ""
        : resolution.refused.map((r) => r.id).join(" "),
  };
}

describe("registration (spec section 4.5)", () => {
  it("registers the seven built-ins without a co-matchable pair", () => {
    const registry = createPresentationRegistry();
    expect(registry.list().map((m) => m.manifest.id)).toEqual(
      BUILTIN_MANIFESTS.map((m) => m.id),
    );
    expect(BUILTIN_PRESENTATIONS.map((m) => m.manifest)).toEqual(
      BUILTIN_MANIFESTS,
    );
  });

  it("refuses two specific modules that both match one fixture, naming both ids, whatever their priorities", async () => {
    const a = spyModule(manifest({ id: "org.example.a/v0", priority: 1 }));
    const b = spyModule(manifest({ id: "org.example.b/v0", priority: 9 }));
    const registry = new PresentationRegistry();
    registry.register(a.module);
    let error: unknown;
    try {
      registry.register(b.module);
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(PresentationAmbiguityError);
    expect((error as PresentationAmbiguityError).ids).toEqual([
      "org.example.a/v0",
      "org.example.b/v0",
    ]);
    expect(String(error)).toContain("org.example.a/v0");
    expect(String(error)).toContain("org.example.b/v0");
    expect(registry.list()).toHaveLength(1);

    // The same pair at resolution, on the real fixture both match: a hard
    // error naming both, decided before any canRender is called.
    const context = await buildVerifiedBundleContext(producerKeyBundle());
    await expect(
      resolveModules(
        [a.module, b.module],
        describeContext(context),
        "*",
        "html",
        (m) => m.canRender(context),
      ),
    ).rejects.toThrow(/org\.example\.a\/v0, org\.example\.b\/v0/u);
    expect(a.calls).toEqual([]);
    expect(b.calls).toEqual([]);
  });

  it("refuses a second fallback beside the built-in one", () => {
    const fallback = spyModule(
      manifest({
        id: "org.example.generic-view/v0",
        requires: { bundle_kind: "evidence-bundle/v2" },
        forbids: undefined,
        fallback: true,
        priority: undefined,
      }),
    );
    expect(() => registerPresentation(fallback.module)).toThrow(
      PresentationAmbiguityError,
    );
    expect(() => registerPresentation(fallback.module)).toThrow(
      BUILTIN_MANIFEST_NO_AGGREGATE.id,
    );
  });

  it("accepts a specific module whose forbids exclude every built-in specific", () => {
    const registry = createPresentationRegistry();
    registry.register(spyModule(manifest()).module);
    expect(registry.list()).toHaveLength(8);
  });

  it("does not call disjoint audiences or formats ambiguous", () => {
    const registry = new PresentationRegistry();
    const add = (id: string, audiences: string[], formats: string[]): void => {
      registry.register(spyModule(manifest({ id, audiences, formats })).module);
    };
    add("org.example.a/v0", ["owner"], ["html"]);
    add("org.example.b/v0", ["counterparty"], ["html"]);
    add("org.example.c/v0", ["*"], ["embedded"]);
    expect(() =>
      add("org.example.d/v0", ["owner"], ["html", "embedded"]),
    ).toThrow(PresentationAmbiguityError);
    expect(registry.list()).toHaveLength(3);
  });

  it.each([
    ["an unknown member", { title: "Words belong in a wording pack" }],
    ["a fallback with a priority", { fallback: true }],
    ["a specific module with no priority", { priority: undefined }],
    ["the presentation/v1 namespace", { spec_version: "presentation/v1" }],
    ["no id", { id: undefined }],
    ["no presentation_api", { presentation_api: undefined }],
    ["a malformed presentation_api", { presentation_api: "v0" }],
    ["no runtime_min", { runtime_min: undefined }],
    ["a malformed runtime_min", { runtime_min: "1.0" }],
    ["a malformed id", { id: "Example View" }],
    ["no formats", { formats: [] }],
    [
      "a dead manifest (requires and forbids share a profile)",
      {
        requires: {
          bundle_kind: "evidence-bundle/v2",
          profiles: ["spec_version:report/v1"],
        },
        forbids: { profiles: ["spec_version:report/v1"] },
      },
    ],
    [
      "two tokens of one profile key",
      {
        requires: {
          bundle_kind: "evidence-bundle/v2",
          profiles: ["spec_version:a/v1", "spec_version:b/v1"],
        },
      },
    ],
    [
      "a declarative module carrying executable",
      { trust_class: "declarative" },
    ],
  ] as Array<[string, Obj]>)("refuses %s", (_label, overrides) => {
    const m = manifest(overrides);
    for (const [key, value] of Object.entries(overrides))
      if (value === undefined) delete (m as unknown as Obj)[key];
    expect(() =>
      new PresentationRegistry().register(spyModule(m).module),
    ).toThrow(PresentationRegistrationError);
  });

  it("refuses a duplicate id", () => {
    const registry = new PresentationRegistry();
    registry.register(spyModule(manifest()).module);
    expect(() =>
      registry.register(
        spyModule(manifest({ audiences: ["nobody-else"] })).module,
      ),
    ).toThrow(/already registered/u);
  });
});

describe("resolution (spec section 4.3)", () => {
  it("chooses the specific module over a declared fallback; the fallback renders when the specific declines", async () => {
    const generic = manifest({
      id: "org.example.generic-view/v0",
      requires: { bundle_kind: "evidence-bundle/v2" },
      fallback: true,
      priority: undefined,
    });
    delete (generic as unknown as Obj).priority;
    delete (generic as unknown as Obj).forbids;

    const specific = spyModule(manifest());
    const fallback = spyModule(generic);
    const registry = new PresentationRegistry();
    registry.register(fallback.module); // order decides nothing
    registry.register(specific.module);
    const page = await render(producerKeyBundle(), registry);
    expect(page.selected).toBe("org.example.view/v0");
    expect(fallback.calls).toEqual([]);

    const declining = spyModule(manifest(), { canRender: false });
    const fallback2 = spyModule(generic);
    const registry2 = new PresentationRegistry();
    registry2.register(declining.module);
    registry2.register(fallback2.module);
    const page2 = await render(producerKeyBundle(), registry2);
    expect(page2.selected).toBe("org.example.generic-view/v0");
    expect(declining.calls).toEqual(["canRender"]);
  });

  it("a specific module registered beside the built-ins replaces the no-aggregate page for the bundles it matches", async () => {
    const registry = createPresentationRegistry();
    registry.register(spyModule(manifest()).module);
    const page = await render(producerKeyBundle(), registry);
    expect(page.selected).toBe("org.example.view/v0");
    const plain = await render(
      producerKeyBundle(),
      createPresentationRegistry(),
    );
    expect(plain.selected).toBe(BUILTIN_MANIFEST_NO_AGGREGATE.id);
  });

  it("a failing bundle states the refusal and selects no module; no module method is called", async () => {
    const everything = spyModule(
      manifest({
        id: "org.example.everything/v0",
        requires: { bundle_kind: "evidence-bundle/v2" },
        fallback: true,
      }),
    );
    delete (everything.module.manifest as unknown as Obj).priority;
    delete (everything.module.manifest as unknown as Obj).forbids;
    const registry = new PresentationRegistry();
    registry.register(everything.module);
    // Unsealed: alias ids, so the bundle does not verify.
    const unverified = json(resolvePath(testdata, "report-rows-bundle.json"));
    const page = await render(unverified, registry);
    expect(page.banner.state).toBe("failed");
    expect(page.banner.refusal).toBeDefined();
    expect(page.resolution.kind).toBe("refusal");
    expect(everything.calls).toEqual([]);

    const builtIn = await render(unverified, createPresentationRegistry());
    expect(builtIn.resolution.kind).toBe("refusal");
  });

  it("an ambiguity met at resolution is a named error, and no module is consulted", async () => {
    const a = spyModule(manifest({ id: "org.example.a/v0" }));
    const b = spyModule(manifest({ id: "org.example.b/v0" }));
    // A resolver that skipped the registration test.
    const unchecked: PresentationResolver = {
      resolve: (context: VerifiedBundleContext, audience, format) =>
        resolveModules(
          [a.module, b.module],
          describeContext(context),
          audience,
          format,
          (m) => m.canRender(context),
        ),
    };
    await expect(render(producerKeyBundle(), unchecked)).rejects.toThrow(
      PresentationAmbiguityError,
    );
    expect(a.calls).toEqual([]);
    expect(b.calls).toEqual([]);
  });

  it("resolves to no presentation when nothing matches", async () => {
    const registry = new PresentationRegistry();
    registry.register(
      spyModule(manifest({ audiences: ["counterparty"] })).module,
    );
    const page = await render(producerKeyBundle(), registry);
    expect(page.resolution.kind).toBe("no-presentation");
    const forThem = await render(producerKeyBundle(), registry, {
      audience: "counterparty",
    });
    expect(forThem.selected).toBe("org.example.view/v0");
  });

  it("derives the descriptor from the context: profile tokens and engaged extensions only", async () => {
    const source = json(resolvePath(testdata, "outcome-report-bundle.json"));
    const { bundle } = await sealEvidenceBundle(source);
    const descriptor = describeContext(
      await buildVerifiedBundleContext(bundle),
    );
    expect(descriptor.verified).toBe(true);
    expect(descriptor.bundle_kind).toBe("evidence-bundle/v2");
    expect([...descriptor.profiles]).toEqual([
      "result_version:evidence-result-v0",
    ]);
    expect([...descriptor.extensions]).toEqual(["outcome-report/v1"]);

    // A present block its reader declines counts as absent.
    const declined = structuredClone(bundle) as Obj;
    (declined.extensions as Obj)["outcome-report/v1"] = { enabled: false };
    (declined.extensions as Obj)["x-example-unknown/v1"] = {};
    const d2 = describeContext(await buildVerifiedBundleContext(declined));
    expect([...d2.extensions]).toEqual(["x-example-unknown/v1"]);
  });

  it("an unverified context is described without reading its payloads or extensions", async () => {
    const unverified = json(
      resolvePath(testdata, "outcome-report-bundle.json"),
    );
    const context = await buildVerifiedBundleContext(unverified);
    const descriptor = describeContext(context);
    expect(descriptor.verified).toBe(false);
    expect(descriptor.profiles.size).toBe(0);
    expect(descriptor.extensions.size).toBe(0);
  });
});

describe("the presentation ABI (spec section 3.2)", () => {
  const UNSUPPORTED = "aac.presentation-api/v99";

  it("the reference runtime implements exactly aac.presentation-api/v0 at 0.1.0, and every built-in declares it", () => {
    expect(REFERENCE_PRESENTATION_RUNTIME).toEqual({
      presentationApis: ["aac.presentation-api/v0"],
      runtimeVersion: "0.1.0",
    });
    for (const m of BUILTIN_MANIFESTS) {
      expect(m.presentation_api).toBe("aac.presentation-api/v0");
      expect(m.runtime_min).toBe("0.1.0");
    }
    expect(createPresentationRegistry().refused()).toEqual([]);
  });

  it("refuses a module whose presentation_api the runtime does not implement, and says so", async () => {
    const future = spyModule(
      manifest({ id: "org.example.future/v1", presentation_api: UNSUPPORTED }),
    );
    const registry = createPresentationRegistry();
    const registration = registry.register(future.module);
    const refusal = {
      id: "org.example.future/v1",
      presentation_api: UNSUPPORTED,
      runtime_min: "0.1.0",
      reason: "presentation_api_unsupported",
      extensions: ["producer-key/v1"],
      runtimeVersion: "0.1.0",
    };
    expect(registration).toEqual({ status: "refused", refusal });
    expect(registry.list().map((m) => m.manifest.id)).not.toContain(
      "org.example.future/v1",
    );
    expect(registry.refused()).toEqual([refusal]);

    // Resolution: not selected, never called, and not silent -- the
    // fallback renders WITH the refusal in the result.
    const context = await buildVerifiedBundleContext(producerKeyBundle());
    const resolution = await registry.resolve(context, "*", "html");
    expect(resolution.kind).toBe("module");
    if (resolution.kind !== "module") throw new Error("unreachable");
    expect(resolution.module.manifest.id).toBe(
      BUILTIN_MANIFEST_NO_AGGREGATE.id,
    );
    expect(resolution.refused).toEqual([refusal]);
    expect(future.calls).toEqual([]);

    // The page names it.
    const root = await render(producerKeyBundle(), registry);
    expect(root.refused).toBe("org.example.future/v1");
    expect(future.calls).toEqual([]);

    // The words of the contract, exactly.
    expect(presentationRefusalRow(resolution.refused[0]!, true)).toBe(
      "Integrity verified; meaning not interpreted: presentation module org.example.future/v1 needs presentation API aac.presentation-api/v99, which this viewer does not implement",
    );
    expect(presentationRefusalRow(resolution.refused[0]!, false)).toBe(
      "Integrity not verified; meaning not interpreted: presentation module org.example.future/v1 needs presentation API aac.presentation-api/v99, which this viewer does not implement",
    );
    expect(presentationRefusalLine(resolution.refused[0]!)).toBe(
      "Presentation module org.example.future/v1 was not used: it needs presentation API aac.presentation-api/v99, which this viewer does not implement",
    );
  });

  it("the same module on a supported API is selected: the refusal is the API's doing", async () => {
    const current = spyModule(manifest({ id: "org.example.future/v1" }));
    const registry = createPresentationRegistry();
    expect(registry.register(current.module)).toEqual({ status: "registered" });
    const root = await render(producerKeyBundle(), registry);
    expect(root.selected).toBe("org.example.future/v1");
    expect(root.refused).toBe("");
  });

  it("refuses a module whose runtime_min the runtime does not meet", async () => {
    const newer = spyModule(
      manifest({ id: "org.example.newer/v0", runtime_min: "0.2.0" }),
    );
    const registry = createPresentationRegistry();
    const registration = registry.register(newer.module);
    expect(registration).toMatchObject({
      status: "refused",
      refusal: { reason: "runtime_too_old", runtime_min: "0.2.0" },
    });
    if (registration.status !== "refused") throw new Error("unreachable");
    expect(presentationRefusalLine(registration.refusal)).toBe(
      "Presentation module org.example.newer/v0 was not used: it needs runtime 0.2.0 or later; this viewer is 0.1.0",
    );
    const root = await render(producerKeyBundle(), registry);
    expect(root.refused).toBe("org.example.newer/v0");
    expect(newer.calls).toEqual([]);

    // A runtime at 0.2.0 implementing the same API accepts it.
    const later = new PresentationRegistry({
      presentationApis: ["aac.presentation-api/v0"],
      runtimeVersion: "0.2.0",
    });
    expect(later.register(newer.module)).toEqual({ status: "registered" });
  });

  it("a refused module still counts for ambiguity, so nothing silently takes its place", () => {
    const registry = new PresentationRegistry();
    registry.register(
      spyModule(
        manifest({
          id: "org.example.future/v1",
          presentation_api: UNSUPPORTED,
        }),
      ).module,
    );
    expect(() =>
      registry.register(
        spyModule(manifest({ id: "org.example.stand-in/v0" })).module,
      ),
    ).toThrow(PresentationAmbiguityError);
  });

  it("a runtime that implements none of the built-ins' API refuses all seven and selects no module", async () => {
    const registry = new PresentationRegistry({
      presentationApis: ["aac.presentation-api/v1"],
      runtimeVersion: "1.0.0",
    });
    for (const module of BUILTIN_PRESENTATIONS)
      expect(registry.register(module).status).toBe("refused");
    expect(registry.list()).toEqual([]);
    const context = await buildVerifiedBundleContext(producerKeyBundle());
    const resolution = await registry.resolve(context, "*", "html");
    expect(resolution).toMatchObject({ kind: "no-presentation" });
    if (resolution.kind !== "no-presentation") throw new Error("unreachable");
    expect(resolution.refused.map((r) => r.id)).toEqual([
      BUILTIN_MANIFEST_NO_AGGREGATE.id,
    ]);
    const root = await render(producerKeyBundle(), registry);
    expect(root.refused).toBe(BUILTIN_MANIFEST_NO_AGGREGATE.id);
    expect(root.resolution.kind).toBe("no-presentation");
  });
});
