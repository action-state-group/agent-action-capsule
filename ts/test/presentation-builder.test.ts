import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { build } from "esbuild";
import { JSDOM } from "jsdom";
import { beforeAll, describe, expect, it } from "vitest";
import { emitEvidenceGraphHtml } from "../src/emitter.js";
import {
  BUILTIN_PRESENTATIONS,
  createPresentationRegistry,
} from "../src/evidence-graph-view.js";
import {
  availablePackagings,
  buildFragmentViewerHtml,
  buildPresentation,
  offlineHtmlFromFragment,
  PACKAGING_TARGETS,
  PackagingUnavailableError,
  PresentationBuildError,
  PresentationModuleRefusedError,
  PresentationStylePinsError,
  STATIC_BUILD_TIME_STATEMENT,
  STATIC_NOT_SELF_VERIFYING,
  type BuildPresentationOptions,
  type BuiltPresentation,
  type PackagingAvailability,
  type PackagingTarget,
  type PresentationModuleScript,
} from "../src/presentation-builder.js";
import {
  decodePresentationFragment,
  FRAGMENT_TOKEN_DEFAULT_BUDGET,
  FRAGMENT_TOKEN_MAX_LENGTH,
  FragmentTooLargeError,
  type DisclosureScope,
  type WordingPackInput,
} from "../src/presentation-fragment.js";
import {
  PresentationRegistry,
  REFERENCE_PRESENTATION_RUNTIME,
  resolveModules,
  type PresentationManifest,
  type PresentationModule,
  type PresentationResolver,
} from "../src/presentation-registry.js";
import { monthlyComplianceFixture } from "./helpers/monthly-fixtures.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

// The builder runs in node (the emitter reads its shell with node:fs), so
// this file keeps the node environment and gives the embedded packaging a
// jsdom document of its own, as result-root-emitter.test.ts does.
const host = new JSDOM();
globalThis.document = host.window.document;
globalThis.HTMLElement = host.window.HTMLElement;

type Obj = Record<string, unknown>;
const testdata = (name: string): string =>
  resolve(process.cwd(), "test", "testdata", name);
const fixture = (name: string): Obj =>
  JSON.parse(readFileSync(testdata(name), "utf8")) as Obj;
const hex = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex");

let runtime: string;
beforeAll(async () => {
  const result = await build({
    entryPoints: [resolve(process.cwd(), "src", "browser.ts")],
    bundle: true,
    format: "iife",
    globalName: "EvidenceGraph",
    footer: {
      js: "globalThis.renderEvidenceGraph = EvidenceGraph.renderEvidenceGraph;",
    },
    write: false,
  });
  runtime = result.outputFiles[0]!.text;
});

// ---------------------------------------------------------------------------
// Rendering each packaging and reading what it shows
// ---------------------------------------------------------------------------

interface Snapshot {
  readonly verify: (string | null)[];
  readonly pages: (string | null)[];
  readonly notices: (string | null)[];
  readonly refusals: (string | null)[];
  readonly evidence_ids: string[];
  readonly text: string;
  readonly html: string;
}

// The markup as HTML parsing reads it. A page drawn by script can hold a
// table row directly in its table; the same markup, parsed, gets the implied
// tbody. Comparing the parsed form compares what the markup means, so the
// static page (parsed) and the pages drawn in the reader's browser compare.
const parsed = (html: string): string => {
  const holder = host.window.document.createElement("div");
  holder.innerHTML = html;
  return holder.innerHTML;
};

function snapshot(root: Element): Snapshot {
  const values = (name: string): (string | null)[] =>
    [...root.querySelectorAll(`[${name}]`)].map((e) => e.getAttribute(name));
  return {
    verify: values("data-verify"),
    pages: values("data-page"),
    notices: values("data-notice"),
    refusals: values("data-refusal"),
    evidence_ids: [
      ...new Set(root.innerHTML.match(/[0-9a-f]{64}/gu) ?? []),
    ].sort(),
    text: (root.textContent ?? "").replace(/\s+/gu, " ").trim(),
    html: parsed(root.innerHTML),
  };
}

const done = (root: Element): boolean =>
  root.querySelector('[data-page="verification"]') !== null ||
  root.querySelector('[data-refusal="fragment-unreadable"]') !== null;

// Wait until the page has drawn its verification section and stopped changing.
async function settled(root: Element): Promise<Snapshot> {
  const deadline = Date.now() + 60_000;
  let last = "";
  let stable = 0;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 15));
    const now = root.innerHTML;
    stable = done(root) && now === last ? stable + 1 : 0;
    last = now;
    if (stable >= 3) return snapshot(root);
  }
  throw new Error("page did not settle");
}

/** Open a page in jsdom with its scripts running, as a browser would. */
async function openPage(html: string, url: string): Promise<Snapshot> {
  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    url,
    beforeParse(window) {
      Object.defineProperty(window, "crypto", { value: globalThis.crypto });
      Object.assign(window, { TextEncoder, TextDecoder });
    },
  });
  try {
    return await settled(dom.window.document.getElementById("app")!);
  } finally {
    dom.window.close();
  }
}

/**
 * Open a static page as a browser would, with scripting off (it has no
 * script to run; its CSP allows none). Returns what #app shows and the
 * page itself for the static checks.
 */
function openStatic(html: string): { snapshot: Snapshot; page: Document } {
  const dom = new JSDOM(html);
  return {
    snapshot: snapshot(dom.window.document.getElementById("app")!),
    page: dom.window.document,
  };
}

/** What every static page must say and carry, for one verification state. */
function expectStaticPage(html: string, verify: string): void {
  const { page } = openStatic(html);
  expect(page.querySelectorAll("script")).toHaveLength(0);
  expect(
    [...page.querySelectorAll("*")].flatMap((e) =>
      [...e.attributes].filter((a) => a.name.startsWith("on")),
    ),
  ).toEqual([]);
  const csp = page
    .querySelector('meta[http-equiv="Content-Security-Policy"]')!
    .getAttribute("content")!;
  expect(csp).toMatch(/^default-src 'none'; script-src 'none'; style-src /u);
  expect(csp).toContain("connect-src 'none'");
  const notice = page.querySelector(
    '[data-static-notice="not-self-verifying"]',
  )!;
  expect(notice.getAttribute("data-built-verification")).toBe(verify);
  const text = (notice.textContent ?? "").replace(/\s+/gu, " ");
  expect(text).toContain(STATIC_NOT_SELF_VERIFYING);
  expect(text).toContain(STATIC_BUILD_TIME_STATEMENT);
  expect(text).toContain(
    `when this page was built: ${verify === "verified" ? "verified" : "did not verify"}.`,
  );
}

type Outcome =
  | {
      readonly kind: "shown";
      readonly built: BuiltPresentation;
      readonly snapshot: Snapshot;
    }
  | { readonly kind: "refused"; readonly error: string };

async function showAll(
  bundle: unknown,
  options: Omit<BuildPresentationOptions, "format" | "runtime">,
): Promise<Record<PackagingTarget, Outcome>> {
  const out = {} as Record<PackagingTarget, Outcome>;
  for (const format of PACKAGING_TARGETS) {
    let built: BuiltPresentation;
    try {
      built = await buildPresentation(bundle, {
        ...options,
        format,
        runtime: { code: runtime },
      });
    } catch (err) {
      out[format] = {
        kind: "refused",
        error: `${(err as Error).name}: ${(err as Error).message}`,
      };
      continue;
    }
    let shown: Snapshot;
    if (built.format === "html")
      shown = await openPage(built.html, "file:///offline.html");
    else if (built.format === "fragment")
      shown = await openPage(
        buildFragmentViewerHtml({ code: runtime }),
        `file:///viewer.html#${built.fragment}`,
      );
    else if (built.format === "static") shown = openStatic(built.html).snapshot;
    else {
      const element = document.createElement("main");
      await built.mount(element);
      shown = snapshot(element);
    }
    out[format] = { kind: "shown", built, snapshot: shown };
  }
  return out;
}

// ---------------------------------------------------------------------------
// The (bundle, audience) table
// ---------------------------------------------------------------------------

// The fixtures: one per built-in page shape, plus a bundle that does not verify.
const FIXTURES: readonly [string, string, boolean][] = [
  ["report rows", "report-rows-bundle.json", true],
  ["result + outcome report", "outcome-report-bundle.json", true],
  ["result + compliance", "compliance-bundle.json", true],
  ["result", "result-root-bundle.json", true],
  ["result (book form)", "result-root-book-bundle.json", true],
  ["evaluation summary graph", "report-date-only-bundle.json", true],
  ["does not verify", "report-rows-bundle.json", false],
];

const rootOnly = (bundle: unknown): DisclosureScope => {
  const root = (bundle as Obj).root as string;
  return { [root]: ["agent_input", "agent_output"] };
};

// Audiences: the record holder sees the bundle as it is; a counterparty is
// shown the root's disclosures only; the public is shown no payload at all.
// Scoping is the builder's, before encoding.
const AUDIENCES: readonly [
  string,
  (bundle: unknown) => DisclosureScope | undefined,
][] = [
  ["*", () => undefined],
  ["counterparty", rootOnly],
  ["public", () => ({})],
];

// What availablePackagings reported, in one line for the table.
const availabilityLine = (report: readonly PackagingAvailability[]): string =>
  report
    .map((a) =>
      a.available
        ? `${a.target} available`
        : `${a.target} unavailable (${a.reason.code}${a.reason.code === "fragment-too-large" ? ` ${a.reason.length} > ${a.reason.limit}` : ""})`,
    )
    .join(", ");

describe("one builder, four packagings: acceptance over (bundle, audience) pairs", () => {
  const sealed = new Map<string, unknown>();
  beforeAll(async () => {
    for (const [, file, verifies] of FIXTURES)
      sealed.set(
        `${file}:${verifies}`,
        verifies
          ? (await sealEvidenceBundle(fixture(file))).bundle
          : fixture(file),
      );
  }, 120_000);

  const table: string[] = [];

  for (const [label, file, verifies] of FIXTURES)
    for (const [audience, scope] of AUDIENCES)
      it(`${label} × ${audience}: every supported packaging shows the same verified content and identifiers`, async () => {
        const bundle = sealed.get(`${file}:${verifies}`);
        const disclose = scope(bundle);
        const settings = {
          presentation: "auto",
          audience,
          ...(disclose === undefined ? {} : { disclose }),
        };
        const outcome = await showAll(bundle, settings);
        const shown = Object.entries(outcome).filter(
          (e): e is [string, Extract<Outcome, { kind: "shown" }>] =>
            e[1].kind === "shown",
        );
        const refused = Object.entries(outcome).filter(
          (e): e is [string, Extract<Outcome, { kind: "refused" }>] =>
            e[1].kind === "refused",
        );

        if (!verifies && disclose !== undefined) {
          // Scoping a failing bundle is refused in every format alike.
          expect(shown).toEqual([]);
          for (const [, r] of refused)
            expect(r.error).toMatch(
              /refusing to scope a bundle that did not verify/u,
            );
          // Not a packaging question: availablePackagings throws the same.
          await expect(
            availablePackagings(bundle, {
              ...settings,
              runtime: { code: runtime },
            }),
          ).rejects.toThrow(/refusing to scope a bundle that did not verify/u);
          table.push(
            `${label} | ${audience} | refused in all four: cannot scope a failing bundle`,
          );
          return;
        }
        // The availability report agrees with what was built, target by target.
        const report = await availablePackagings(bundle, {
          ...settings,
          runtime: { code: runtime },
        });
        expect(report.map((a) => a.target)).toEqual([...PACKAGING_TARGETS]);
        for (const a of report) {
          expect(a.available, a.target).toBe(
            outcome[a.target].kind === "shown",
          );
          if (!a.available) {
            expect(a.reason.code).toBe("fragment-too-large");
            if (a.reason.code === "fragment-too-large")
              expect(a.reason.length).toBeGreaterThan(a.reason.limit);
          }
        }
        // Only a fragment too large for a URL may be refused, and only for size.
        for (const [format, r] of refused) {
          expect(format).toBe("fragment");
          expect(r.error).toMatch(/^FragmentTooLargeError/u);
        }
        expect(shown.length).toBeGreaterThanOrEqual(3);
        const [first, ...rest] = shown;
        for (const [, s] of rest) {
          expect(s.built.module).toBe(first![1].built.module);
          expect(s.snapshot).toEqual(first![1].snapshot);
        }
        const snap = first![1].snapshot;
        expect(snap.verify).toEqual([verifies ? "verified" : "failed"]);
        if (verifies) expect(snap.evidence_ids.length).toBeGreaterThan(0);

        // The static page: no script, the statement, the build-time state.
        const statik = outcome.static;
        expect(statik.kind).toBe("shown");
        if (statik.kind === "shown" && statik.built.format === "static") {
          expect(statik.built.verification).toBe(snap.verify[0]);
          expectStaticPage(statik.built.html, snap.verify[0]!);
        }

        // The hand-back: the fragment rebuilds the exact offline file.
        const html = outcome.html;
        const fragment = outcome.fragment;
        if (html.kind === "shown" && fragment.kind === "shown") {
          expect(html.built.format).toBe("html");
          expect(fragment.built.format).toBe("fragment");
          if (
            html.built.format === "html" &&
            fragment.built.format === "fragment"
          )
            expect(
              await offlineHtmlFromFragment(fragment.built.fragment, {
                code: runtime,
              }),
            ).toBe(html.built.html);
        }
        table.push(
          `${label} | ${audience} | module ${first![1].built.module ?? first![1].built.resolution} | verify ${snap.verify.join(",")} | ids ${snap.evidence_ids.length} | identical across ${shown.map(([f]) => f).join("+")} | ${availabilityLine(report)}`,
        );
      }, 180_000);

  it("prints the table", () => {
    // Visible with --reporter=verbose; also a guard that the table ran.
    expect(table.length).toBe(FIXTURES.length * AUDIENCES.length);
    process.stdout.write(`\n${table.join("\n")}\n`);
  });
});

// ---------------------------------------------------------------------------
// Presentation settings never change evidence (contract I3)
// ---------------------------------------------------------------------------

async function pack(entries: Obj, locale: string): Promise<WordingPackInput> {
  const text = JSON.stringify({
    entries,
    id: "org.example.view.wording/v0",
    locale,
    wording_pack_version: "aac.wording-pack/v0",
  });
  return { pack: text, sha256: hex(text) };
}

describe("theme, wording, locale and depth", () => {
  it("leave every evidence identifier and the verified content unchanged", async () => {
    const { bundle } = await sealEvidenceBundle(
      fixture("compliance-bundle.json"),
    );
    const base = await buildPresentation(bundle, {
      presentation: "auto",
      audience: "adjudicator",
      format: "html",
      runtime: { code: runtime },
    });
    if (base.format !== "html") throw new Error("html expected");
    const baseline = await openPage(base.html, "file:///a.html");
    const variants: [string, Partial<BuildPresentationOptions>][] = [
      ["theme", { themeCss: ":root{--aac-accent:#7a1f5c}" }],
      ["wording", { wording: await pack({ "page.title": "Findings" }, "en") }],
      ["locale", { wording: await pack({ "page.title": "Constats" }, "fr") }],
      ["depth L0", { depth: "L0" }],
      ["depth L1", { depth: "L1" }],
      ["title", { title: "Another title" }],
    ];
    for (const [name, change] of variants) {
      const built = await buildPresentation(bundle, {
        presentation: "auto",
        audience: "adjudicator",
        format: "html",
        runtime: { code: runtime },
        ...change,
      });
      if (built.format !== "html") throw new Error("html expected");
      expect(built.html, name).not.toBe(base.html);
      const shown = await openPage(built.html, "file:///b.html");
      expect(shown.evidence_ids, name).toEqual(baseline.evidence_ids);
      expect(shown, name).toEqual(baseline);
    }
  }, 120_000);

  it("a wording pack titles the page, and its digest is checked", async () => {
    const { bundle } = await sealEvidenceBundle(
      fixture("report-rows-bundle.json"),
    );
    const words = await pack({ "page.title": "What was checked" }, "en");
    const built = await buildPresentation(bundle, {
      presentation: "auto",
      audience: "*",
      format: "html",
      runtime: { code: "/*IIFE_MARKER*/" },
      wording: words,
    });
    if (built.format !== "html") throw new Error("html expected");
    expect(built.html).toContain("<title>What was checked</title>");
    await expect(
      buildPresentation(bundle, {
        presentation: "auto",
        audience: "*",
        format: "html",
        runtime: { code: "/*IIFE_MARKER*/" },
        wording: { pack: words.pack, sha256: "0".repeat(64) },
      }),
    ).rejects.toThrow(/do not hash to its wording_sha256/u);
    await expect(
      buildPresentation(bundle, {
        presentation: "auto",
        audience: "*",
        format: "html",
        runtime: { code: "/*IIFE_MARKER*/" },
        wording: await pack({ "Bad Key": "x" }, "en"),
      }),
    ).rejects.toThrow(/aac.wording-pack\/v0/u);
  });
});

// ---------------------------------------------------------------------------
// The default path, the hand-back, scoping and refusals
// ---------------------------------------------------------------------------

describe("buildPresentation", () => {
  it("with the default settings writes exactly the page the emitter writes", async () => {
    for (const name of ["result-root-bundle.sealed.json", "week-bundle.json"]) {
      const bundle = fixture(name);
      const built = await buildPresentation(bundle, {
        presentation: "auto",
        audience: "*",
        format: "html",
        runtime: { code: "/*IIFE_MARKER*/" },
      });
      if (built.format !== "html") throw new Error("html expected");
      expect(built.html).toBe(emitEvidenceGraphHtml(bundle, "/*IIFE_MARKER*/"));
    }
  }, 120_000);

  it("refuses a fragment over the limit with a clear error, never a cut-down link", async () => {
    const bundle = fixture("week-bundle.json");
    await expect(
      buildPresentation(bundle, {
        presentation: "auto",
        audience: "*",
        format: "fragment",
        runtime: { code: "/*IIFE_MARKER*/" },
      }),
    ).rejects.toThrow(FragmentTooLargeError);
    const small = (await sealEvidenceBundle(fixture("report-rows-bundle.json")))
      .bundle;
    await expect(
      buildPresentation(small, {
        presentation: "auto",
        audience: "*",
        format: "fragment",
        runtime: { code: "/*IIFE_MARKER*/" },
        maxFragmentLength: 100,
      }),
    ).rejects.toThrow(/over the 100-character maximum/u);
  }, 120_000);

  it("scopes before encoding: withheld payloads are not in the fragment at all", async () => {
    const { bundle } = await sealEvidenceBundle(
      fixture("report-date-only-bundle.json"),
    );
    const full = await buildPresentation(bundle, {
      presentation: "auto",
      audience: "*",
      format: "fragment",
      runtime: { code: runtime },
    });
    const scoped = await buildPresentation(bundle, {
      presentation: "auto",
      audience: "counterparty",
      format: "fragment",
      runtime: { code: runtime },
      disclose: rootOnly(bundle),
    });
    if (full.format !== "fragment" || scoped.format !== "fragment")
      throw new Error("fragment expected");
    const kept = decodePresentationFragment(scoped.fragment).bundle as Obj;
    expect(Object.keys(kept.disclosures as Obj)).toEqual([
      (bundle as Obj).root,
    ]);
    expect(
      Object.keys((full.payload.bundle as Obj).disclosures as Obj).length,
    ).toBeGreaterThan(1);
    expect(scoped.fragment.length).toBeLessThan(full.fragment.length);
  });

  it("the hand-back refuses a different runtime or module set", async () => {
    const { bundle } = await sealEvidenceBundle(
      fixture("report-rows-bundle.json"),
    );
    const module = { code: "/*module*/", sha256: hex("/*module*/") };
    const built = await buildPresentation(bundle, {
      presentation: "auto",
      audience: "*",
      format: "fragment",
      runtime: { code: "/*IIFE_MARKER*/" },
      modules: [module],
    });
    if (built.format !== "fragment") throw new Error("fragment expected");
    await expect(
      offlineHtmlFromFragment(built.fragment, { code: "/*other*/" }, [module]),
    ).rejects.toThrow(/not the one the fragment was built with/u);
    await expect(
      offlineHtmlFromFragment(built.fragment, { code: "/*IIFE_MARKER*/" }),
    ).rejects.toThrow(/not the ones the fragment was built with/u);
    const direct = await buildPresentation(bundle, {
      presentation: "auto",
      audience: "*",
      format: "html",
      runtime: { code: "/*IIFE_MARKER*/" },
      modules: [module],
    });
    if (direct.format !== "html") throw new Error("html expected");
    expect(
      await offlineHtmlFromFragment(
        built.fragment,
        { code: "/*IIFE_MARKER*/" },
        [module],
      ),
    ).toBe(direct.html);
  });

  it("refuses a requested presentation the registry does not select, and an ambiguous registry", async () => {
    const { bundle } = await sealEvidenceBundle(
      fixture("report-rows-bundle.json"),
    );
    await expect(
      buildPresentation(bundle, {
        presentation: "aac.builtin.result/v0",
        audience: "*",
        format: "html",
        runtime: { code: "/*IIFE_MARKER*/" },
      }),
    ).rejects.toThrow(/registry selected aac.builtin.report-rows\/v0/u);
    const ok = await buildPresentation(bundle, {
      presentation: "aac.builtin.report-rows/v0",
      audience: "*",
      format: "html",
      runtime: { code: "/*IIFE_MARKER*/" },
    });
    expect(ok.module).toBe("aac.builtin.report-rows/v0");

    const twin = (id: string): PresentationModule => ({
      manifest: {
        spec_version: "aac.presentation-manifest/v0",
        id,
        presentation_api: "aac.presentation-api/v0",
        runtime_min: "0.1.0",
        trust_class: "trusted-executable",
        requires: { bundle_kind: "evidence-bundle/v2" },
        audiences: ["*"],
        formats: ["html"],
        fallback: false,
        priority: 1,
        executable: { carrier: "core-runtime" },
      },
      canRender: () => true,
      buildModel: () => null,
      render: () => undefined,
    });
    const modules = [twin("org.example.a/v0"), twin("org.example.b/v0")];
    // A resolver that skipped the registration test meets the tie at resolution.
    const ambiguous: PresentationResolver = {
      resolve: (_context, audience, format) =>
        resolveModules(
          modules,
          {
            verified: true,
            bundle_kind: "evidence-bundle/v2",
            profiles: new Set(),
            extensions: new Set(),
          },
          audience,
          format,
          () => true,
        ),
    };
    await expect(
      buildPresentation(bundle, {
        presentation: "auto",
        audience: "*",
        format: "html",
        runtime: { code: "/*IIFE_MARKER*/" },
        registry: ambiguous,
      }),
    ).rejects.toThrow(PresentationBuildError);
  });

  it("refuses to inline a module the page's runtime would refuse, naming both sides (contract 3.2)", async () => {
    const { bundle } = await sealEvidenceBundle(
      fixture("report-rows-bundle.json"),
    );
    const code = "/*future module*/";
    const manifest = (
      overrides: Partial<PresentationManifest>,
    ): PresentationManifest => ({
      spec_version: "aac.presentation-manifest/v0",
      id: "org.example.future/v1",
      presentation_api: "aac.presentation-api/v0",
      runtime_min: "0.1.0",
      trust_class: "trusted-executable",
      requires: { bundle_kind: "evidence-bundle/v2" },
      audiences: ["*"],
      formats: ["html"],
      fallback: false,
      priority: 1,
      executable: { carrier: "module-slot", script_sha256: hex(code) },
      ...overrides,
    });
    const build = (
      m: PresentationManifest,
      format: PackagingTarget = "html",
    ): Promise<BuiltPresentation> =>
      buildPresentation(bundle, {
        presentation: "auto",
        audience: "*",
        format,
        runtime: { code: "/*IIFE_MARKER*/" },
        modules: [{ code, sha256: hex(code), manifest: m }],
      });

    // presentation_api the runtime does not implement: every packaging fails.
    const unsupported = manifest({
      presentation_api: "aac.presentation-api/v1",
    });
    for (const format of PACKAGING_TARGETS) {
      const err = await build(unsupported, format).then(
        () => undefined,
        (e: unknown) => e,
      );
      expect(err).toBeInstanceOf(PresentationModuleRefusedError);
      expect(err).toBeInstanceOf(PresentationBuildError);
      const refused = err as PresentationModuleRefusedError;
      expect(refused.module).toEqual({
        id: "org.example.future/v1",
        presentation_api: "aac.presentation-api/v1",
        runtime_min: "0.1.0",
      });
      expect(refused.reason).toBe("presentation_api_unsupported");
      expect(refused.runtime).toEqual(REFERENCE_PRESENTATION_RUNTIME);
      expect(refused.message).toBe(
        "presentation module org.example.future/v1 (presentation_api aac.presentation-api/v1, runtime_min 0.1.0) would be refused by the page's runtime (implements aac.presentation-api/v0; runtime version 0.1.0): presentation_api_unsupported; no page is written",
      );
    }
    // availablePackagings treats it as an error of the request, not a target.
    await expect(
      availablePackagings(bundle, {
        presentation: "auto",
        audience: "*",
        runtime: { code: "/*IIFE_MARKER*/" },
        modules: [{ code, sha256: hex(code), manifest: unsupported }],
      }),
    ).rejects.toThrow(PresentationModuleRefusedError);

    // runtime_min newer than the runtime.
    await expect(build(manifest({ runtime_min: "0.2.0" }))).rejects.toThrow(
      "presentation module org.example.future/v1 (presentation_api aac.presentation-api/v0, runtime_min 0.2.0) would be refused by the page's runtime (implements aac.presentation-api/v0; runtime version 0.1.0): runtime_too_old; no page is written",
    );

    // A manifest that does not pin this script, or is malformed, is an error too.
    await expect(
      build(
        manifest({
          executable: { carrier: "module-slot", script_sha256: hex("other") },
        }),
      ),
    ).rejects.toThrow(/does not pin this module-slot script/u);
    await expect(
      build(manifest({ runtime_min: undefined as unknown as string })),
    ).rejects.toThrow(/runtime_min is not MAJOR.MINOR.PATCH/u);

    // The same module on the runtime's API is inlined, byte for byte as without a manifest.
    const accepted = await build(manifest({}));
    const plain = await buildPresentation(bundle, {
      presentation: "auto",
      audience: "*",
      format: "html",
      runtime: { code: "/*IIFE_MARKER*/" },
      modules: [{ code, sha256: hex(code) }],
    });
    if (accepted.format !== "html" || plain.format !== "html")
      throw new Error("html expected");
    expect(accepted.html).toBe(plain.html);
    expect(accepted.html).toContain(code);
  });

  describe("module stylesheet pins (contract 5.1)", () => {
    const code = "/*styled module*/";
    const first = hex(".m{color:red}");
    const second = hex(".n{color:blue}");
    const b64 = (pin: string): string =>
      `'sha256-${Buffer.from(pin, "hex").toString("base64")}'`;
    const styleSrc = (html: string): string =>
      /style-src ([^;"]*)/u.exec(html)![1]!;
    const manifest = (style?: readonly string[]): PresentationManifest => ({
      spec_version: "aac.presentation-manifest/v0",
      id: "org.example.styled/v0",
      presentation_api: "aac.presentation-api/v0",
      runtime_min: "0.1.0",
      trust_class: "trusted-executable",
      requires: { bundle_kind: "evidence-bundle/v2" },
      audiences: ["*"],
      formats: ["html"],
      fallback: false,
      priority: 1,
      executable: {
        carrier: "module-slot",
        script_sha256: hex(code),
        ...(style === undefined ? {} : { style_sha256: style }),
      },
    });
    const build = async (
      module: PresentationModuleScript,
      format: PackagingTarget = "html",
    ): Promise<BuiltPresentation> =>
      buildPresentation(
        (await sealEvidenceBundle(fixture("report-rows-bundle.json"))).bundle,
        {
          presentation: "auto",
          audience: "*",
          format,
          runtime: { code: "/*IIFE_MARKER*/" },
          modules: [module],
        },
      );
    const html = async (module: PresentationModuleScript): Promise<string> => {
      const built = await build(module);
      if (built.format !== "html") throw new Error("html expected");
      return built.html;
    };

    it("passes each module's style pins to the emitter, with or without a manifest", async () => {
      const { bundle } = await sealEvidenceBundle(
        fixture("report-rows-bundle.json"),
      );
      const emitted = emitEvidenceGraphHtml(bundle, "/*IIFE_MARKER*/", {
        modules: [{ code, sha256: hex(code), styleSha256: [first, second] }],
      });
      for (const module of [
        { code, sha256: hex(code), styleSha256: [first, second] },
        {
          code,
          sha256: hex(code),
          styleSha256: [first, second],
          manifest: manifest([first, second]),
        },
      ]) {
        const page = await html(module);
        expect(page).toBe(emitted);
        expect(styleSrc(page)).toContain(b64(first));
        expect(styleSrc(page)).toContain(b64(second));
      }
      // Without pins the page is the one it always was.
      const unpinned = await html({ code, sha256: hex(code) });
      expect(unpinned).toBe(
        emitEvidenceGraphHtml(bundle, "/*IIFE_MARKER*/", {
          modules: [{ code, sha256: hex(code) }],
        }),
      );
      expect(styleSrc(unpinned)).not.toContain(b64(first));
    });

    it("compares the manifest's style_sha256 with the module's pins as a set", async () => {
      const inOrder = await html({
        code,
        sha256: hex(code),
        styleSha256: [first, second],
        manifest: manifest([first, second]),
      });
      const reordered = await html({
        code,
        sha256: hex(code),
        styleSha256: [second, first, second],
        manifest: manifest([first, second]),
      });
      expect(styleSrc(reordered)).toContain(b64(first));
      expect(styleSrc(reordered)).toContain(b64(second));
      expect(inOrder).toContain(code);
      // No stylesheet on either side is equal too.
      await expect(
        html({ code, sha256: hex(code), manifest: manifest() }),
      ).resolves.toContain(code);
    });

    it("writes no page when they differ, in any packaging, and names both lists", async () => {
      const cases: [readonly string[] | undefined, readonly string[]][] = [
        [[first, second], [first]],
        [[first], [first, second]],
        [[second], [first]],
        [undefined, [first]],
        [[first], []],
      ];
      for (const [declared, carried] of cases) {
        const module = {
          code,
          sha256: hex(code),
          ...(carried.length === 0 ? {} : { styleSha256: carried }),
          manifest: manifest(declared),
        };
        for (const format of PACKAGING_TARGETS) {
          const err = await build(module, format).then(
            () => undefined,
            (e: unknown) => e,
          );
          expect(err, format).toBeInstanceOf(PresentationStylePinsError);
          expect(err).toBeInstanceOf(PresentationBuildError);
          const mismatch = err as PresentationStylePinsError;
          expect(mismatch.module).toBe("org.example.styled/v0");
          expect(mismatch.manifestStyleSha256).toEqual(declared ?? []);
          expect(mismatch.moduleStyleSha256).toEqual(carried);
          expect(mismatch.message).toBe(
            `module manifest org.example.styled/v0 style_sha256 [${(declared ?? []).join(", ")}] does not equal the module's style pins [${carried.join(", ")}] as a set; no page is written`,
          );
        }
      }
    });

    it("applies the same check when the offline file is rebuilt from a fragment", async () => {
      const module = {
        code,
        sha256: hex(code),
        styleSha256: [first],
        manifest: manifest([first]),
      };
      const built = await build(module, "fragment");
      const offline = await html(module);
      if (built.format !== "fragment") throw new Error("fragment expected");
      await expect(
        offlineHtmlFromFragment(built.fragment, { code: "/*IIFE_MARKER*/" }, [
          module,
        ]),
      ).resolves.toBe(offline);
      await expect(
        offlineHtmlFromFragment(built.fragment, { code: "/*IIFE_MARKER*/" }, [
          { ...module, styleSha256: [second] },
        ]),
      ).rejects.toThrow(PresentationStylePinsError);
    });
  });

  it("refuses a requested presentation the registry holds as refused, naming both sides", async () => {
    const { bundle } = await sealEvidenceBundle(
      fixture("report-rows-bundle.json"),
    );
    // The fallback alone, so the refused module is ambiguous with nothing.
    const registry = new PresentationRegistry();
    registry.register(BUILTIN_PRESENTATIONS.at(-1)!);
    const registration = registry.register({
      manifest: {
        spec_version: "aac.presentation-manifest/v0",
        id: "org.example.newer/v0",
        presentation_api: "aac.presentation-api/v0",
        runtime_min: "0.3.0",
        trust_class: "trusted-executable",
        requires: {
          bundle_kind: "evidence-bundle/v2",
          extensions: { required: ["org.example.unused/v0"] },
        },
        audiences: ["*"],
        formats: ["html"],
        fallback: false,
        priority: 1,
        executable: { carrier: "core-runtime" },
      },
      canRender: () => {
        throw new Error("a refused module was called");
      },
      buildModel: () => {
        throw new Error("a refused module was called");
      },
      render: () => {
        throw new Error("a refused module was called");
      },
    });
    expect(registration.status).toBe("refused");
    const err = await buildPresentation(bundle, {
      presentation: "org.example.newer/v0",
      audience: "*",
      format: "html",
      runtime: { code: "/*IIFE_MARKER*/" },
      registry,
    }).then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(PresentationModuleRefusedError);
    expect((err as PresentationModuleRefusedError).reason).toBe(
      "runtime_too_old",
    );
    expect((err as Error).message).toBe(
      "presentation module org.example.newer/v0 (presentation_api aac.presentation-api/v0, runtime_min 0.3.0) would be refused by the page's runtime (implements aac.presentation-api/v0; runtime version 0.1.0): runtime_too_old; no page is written",
    );
    // "auto" is not a request for that module: the page renders as before.
    const auto = await buildPresentation(bundle, {
      presentation: "auto",
      audience: "*",
      format: "html",
      runtime: { code: "/*IIFE_MARKER*/" },
      registry,
    });
    expect(auto.module).toBe("aac.builtin.no-aggregate/v0");
  });

  it("needs the runtime for html and fragment, and an audience", async () => {
    const bundle = fixture("result-root-bundle.sealed.json");
    for (const format of ["html", "fragment"] as const)
      await expect(
        buildPresentation(bundle, {
          presentation: "auto",
          audience: "*",
          format,
        }),
      ).rejects.toThrow(/needs the core runtime/u);
    await expect(
      buildPresentation(bundle, {
        presentation: "auto",
        audience: "",
        format: "embedded",
      }),
    ).rejects.toThrow(/audience is required/u);
    const embedded = await buildPresentation(bundle, {
      presentation: "auto",
      audience: "*",
      format: "embedded",
      registry: createPresentationRegistry(),
    });
    expect(embedded.format).toBe("embedded");
  });

  it("the offline output carries the per-page CSP and no outbound reference", async () => {
    const { bundle } = await sealEvidenceBundle(
      fixture("report-rows-bundle.json"),
    );
    for (const [audience, extra] of [
      ["*", {}],
      [
        "counterparty",
        {
          depth: "L1" as const,
          wording: await pack({ "page.title": "x" }, "en"),
        },
      ],
    ] as const) {
      const built = await buildPresentation(bundle, {
        presentation: "auto",
        audience,
        format: "html",
        runtime: { code: runtime },
        ...extra,
      });
      if (built.format !== "html") throw new Error("html expected");
      expect(built.html).toMatch(
        /<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src [^"]+; connect-src 'none'; base-uri 'none'; form-action 'none'" \/>/u,
      );
      expect(built.html).not.toMatch(
        /<(?:script|link|img|iframe)[^>]+(?:src|href)=/iu,
      );
    }
    const viewer = buildFragmentViewerHtml({ code: runtime });
    expect(viewer).toContain("connect-src 'none'");
    expect(viewer).not.toMatch(
      /<(?:script|link|img|iframe)[^>]+(?:src|href)=/iu,
    );
  });

  it("an unreadable fragment shows a fixed statement and nothing else", async () => {
    const shown = await openPage(
      buildFragmentViewerHtml({ code: runtime }),
      "file:///viewer.html#not*base64",
    );
    expect(shown.refusals).toEqual(["fragment-unreadable"]);
    expect(shown.verify).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Packaging availability, monthly-scale bundles, and the static page
// ---------------------------------------------------------------------------

describe("packaging availability", () => {
  // A month of the compliance report, derived deterministically from the
  // committed two-session fixture: 40 sessions (about 490 KB of JCS) and 80
  // sessions (about 1 MB).
  const monthly = new Map<number, unknown>();
  beforeAll(async () => {
    for (const sessions of [40, 80])
      monthly.set(
        sessions,
        (await sealEvidenceBundle(monthlyComplianceFixture(sessions))).bundle,
      );
  }, 120_000);

  it("the monthly fixtures are deterministic and monthly-report scale", async () => {
    const again = (await sealEvidenceBundle(monthlyComplianceFixture(40)))
      .bundle;
    expect(JSON.stringify(again)).toBe(JSON.stringify(monthly.get(40)));
    const size = (n: number): number => JSON.stringify(monthly.get(n)).length;
    expect(size(40)).toBeGreaterThan(300_000);
    expect(size(40)).toBeLessThan(1_000_000);
    expect(size(80)).toBeGreaterThan(size(40));
  });

  for (const [sessions, raise] of [
    [40, false],
    [80, false],
    [80, true],
  ] as const)
    it(`a ${sessions}-session monthly report: the fragment is reported unavailable${raise ? " even at the maximum budget" : ""}, never a link`, async () => {
      const bundle = monthly.get(sessions);
      const settings = {
        presentation: "auto",
        audience: "*",
        runtime: { code: runtime },
        ...(raise ? { maxFragmentLength: FRAGMENT_TOKEN_MAX_LENGTH } : {}),
      };
      const report = await availablePackagings(bundle, settings);
      const limit = raise
        ? FRAGMENT_TOKEN_MAX_LENGTH
        : FRAGMENT_TOKEN_DEFAULT_BUDGET;
      expect(report.map((a) => [a.target, a.available])).toEqual([
        ["html", true],
        ["fragment", false],
        ["embedded", true],
        ["static", true],
      ]);
      const fragment = report[1]!;
      if (fragment.available) throw new Error("fragment reported available");
      expect(fragment.reason).toMatchObject({
        code: "fragment-too-large",
        subject: "fragment token",
        limit,
      });
      if (fragment.reason.code !== "fragment-too-large")
        throw new Error("unexpected reason");
      expect(fragment.reason.length).toBeGreaterThan(limit);
      expect(fragment.reason.message).toContain(
        `${fragment.reason.length} characters, over the ${limit}-character maximum`,
      );
      // A direct call keeps its error: no link is ever returned.
      await expect(
        buildPresentation(bundle, { ...settings, format: "fragment" }),
      ).rejects.toThrow(FragmentTooLargeError);

      // The supported packagings show the same thing.
      const html = await buildPresentation(bundle, {
        ...settings,
        format: "html",
      });
      const statik = await buildPresentation(bundle, {
        ...settings,
        format: "static",
      });
      const embedded = await buildPresentation(bundle, {
        ...settings,
        format: "embedded",
      });
      if (
        html.format !== "html" ||
        statik.format !== "static" ||
        embedded.format !== "embedded"
      )
        throw new Error("unexpected format");
      const element = document.createElement("main");
      await embedded.mount(element);
      const fromEmbedded = snapshot(element);
      const fromStatic = openStatic(statik.html).snapshot;
      expect(fromStatic).toEqual(fromEmbedded);
      expect(await openPage(html.html, "file:///monthly.html")).toEqual(
        fromStatic,
      );
      expect(fromStatic.verify).toEqual(["verified"]);
      expect(fromStatic.pages).toContain("verification");
      expectStaticPage(statik.html, "verified");
    }, 180_000);

  it("reports a missing runtime for html and fragment, and a missing DOM for static", async () => {
    const { bundle } = await sealEvidenceBundle(
      fixture("report-rows-bundle.json"),
    );
    const report = await availablePackagings(bundle, {
      presentation: "auto",
      audience: "*",
    });
    expect(
      report.map((a) => [a.target, a.available ? "ok" : a.reason.code]),
    ).toEqual([
      ["html", "runtime-missing"],
      ["fragment", "runtime-missing"],
      ["embedded", "ok"],
      ["static", "ok"],
    ]);
    const saved = globalThis.document;
    try {
      Reflect.deleteProperty(globalThis, "document");
      const noDom = await availablePackagings(bundle, {
        presentation: "auto",
        audience: "*",
        runtime: { code: "/*IIFE_MARKER*/" },
      });
      expect(noDom[3]).toMatchObject({
        target: "static",
        available: false,
        reason: { code: "no-document" },
      });
      await expect(
        buildPresentation(bundle, {
          presentation: "auto",
          audience: "*",
          format: "static",
        }),
      ).rejects.toThrow(PackagingUnavailableError);
    } finally {
      globalThis.document = saved;
    }
  });

  it("a static page is refused, and reported, when a module writes a script", async () => {
    const { bundle } = await sealEvidenceBundle(
      fixture("report-rows-bundle.json"),
    );
    const scripted: PresentationModule = {
      manifest: {
        spec_version: "aac.presentation-manifest/v0",
        id: "org.example.scripted/v0",
        presentation_api: "aac.presentation-api/v0",
        runtime_min: "0.1.0",
        trust_class: "trusted-executable",
        requires: { bundle_kind: "evidence-bundle/v2" },
        audiences: ["*"],
        formats: ["html"],
        fallback: false,
        priority: 1,
        executable: { carrier: "core-runtime" },
      },
      canRender: () => true,
      buildModel: () => null,
      render: (_model, host) => {
        const button = document.createElement("button");
        button.setAttribute("onclick", "alert(1)");
        host.L1.append(button);
      },
    };
    const registry: PresentationResolver = {
      resolve: (_context, audience, format) =>
        resolveModules(
          [scripted],
          {
            verified: true,
            bundle_kind: "evidence-bundle/v2",
            profiles: new Set(),
            extensions: new Set(),
          },
          audience,
          format,
          () => true,
        ),
    };
    const report = await availablePackagings(bundle, {
      presentation: "auto",
      audience: "*",
      registry,
    });
    expect(report[3]).toMatchObject({
      target: "static",
      available: false,
      reason: { code: "static-carries-script" },
    });
  });
});

describe("the static page", () => {
  it("carries the html page's theme and title, and no bundle or code", async () => {
    const { bundle } = await sealEvidenceBundle(
      fixture("compliance-bundle.json"),
    );
    const words = await pack({ "page.title": "Findings" }, "en");
    const settings = {
      presentation: "auto",
      audience: "*",
      themeCss: ":root{--aac-accent:#7a1f5c}",
      wording: words,
      depth: "L1" as const,
    };
    const statik = await buildPresentation(bundle, {
      ...settings,
      format: "static",
    });
    const html = await buildPresentation(bundle, {
      ...settings,
      format: "html",
      runtime: { code: runtime },
    });
    if (statik.format !== "static" || html.format !== "html")
      throw new Error("unexpected format");
    expect(statik.html).toContain("<title>Findings</title>");
    expect(statik.html).toContain("<style>:root{--aac-accent:#7a1f5c}</style>");
    expect(statik.html).not.toContain("__BUNDLE__");
    expect(statik.html).not.toMatch(/<script/iu);
    expect(openStatic(statik.html).snapshot).toEqual(
      await openPage(html.html, "file:///themed.html"),
    );
    expectStaticPage(statik.html, "verified");
  });

  it("every style it carries is in its CSP, by hash", async () => {
    const { bundle } = await sealEvidenceBundle(
      fixture("outcome-report-bundle.json"),
    );
    const built = await buildPresentation(bundle, {
      presentation: "auto",
      audience: "*",
      format: "static",
    });
    if (built.format !== "static") throw new Error("static expected");
    const { page } = openStatic(built.html);
    const csp = page
      .querySelector('meta[http-equiv="Content-Security-Policy"]')!
      .getAttribute("content")!;
    const source = (text: string): string =>
      `'sha256-${createHash("sha256").update(text, "utf8").digest("base64")}'`;
    for (const style of page.querySelectorAll("style"))
      expect(csp).toContain(source(style.textContent ?? ""));
    const attributes = [...page.querySelectorAll("[style]")].map(
      (e) => e.getAttribute("style")!,
    );
    // The outcome report's bars carry their widths as style attributes.
    expect(attributes.length).toBeGreaterThan(0);
    expect(csp).toContain("'unsafe-hashes'");
    for (const value of attributes) expect(csp).toContain(source(value));
  }, 120_000);

  it("states a failed verification as computed at build time", async () => {
    const built = await buildPresentation(fixture("report-rows-bundle.json"), {
      presentation: "auto",
      audience: "*",
      format: "static",
    });
    if (built.format !== "static") throw new Error("static expected");
    expect(built.verification).toBe("failed");
    expect(built.resolution).toBe("refusal");
    expectStaticPage(built.html, "failed");
  });
});

// ---------------------------------------------------------------------------
// Go parity: go/emitter reads the same two files
// ---------------------------------------------------------------------------

/**
 * The Go twin (go/emitter/presentation.go) is pinned to these two files:
 * TestBuildOfflineHTMLMatchesTypeScript and
 * TestOfflineHTMLFromFragmentMatchesTypeScript. To regenerate after an
 * intentional change, run this file with UPDATE_PRESENTATION_GOLDENS=1.
 */
describe("the Go twin's goldens", () => {
  const goTestdata = (name: string): string =>
    resolve(process.cwd(), "..", "go", "emitter", "testdata", name);

  it("the offline file and the fragment that rebuilds it", async () => {
    const bundle = fixture("result-root-bundle.sealed.json");
    const words = await pack(
      { "page.title": "Résumé </script> & co" },
      "fr-CA",
    );
    const options = {
      presentation: "auto",
      audience: "counterparty",
      runtime: { code: "/*IIFE_MARKER*/" },
      depth: "L1" as const,
      themeCss: ":root{--aac-accent:#7a1f5c}",
      wording: words,
      disclose: rootOnly(bundle),
    };
    const html = await buildPresentation(bundle, {
      ...options,
      format: "html",
    });
    const fragment = await buildPresentation(bundle, {
      ...options,
      format: "fragment",
    });
    if (html.format !== "html" || fragment.format !== "fragment")
      throw new Error("unexpected format");
    expect(
      await offlineHtmlFromFragment(fragment.fragment, {
        code: "/*IIFE_MARKER*/",
      }),
    ).toBe(html.html);
    if (process.env.UPDATE_PRESENTATION_GOLDENS === "1") {
      const { writeFileSync } = await import("node:fs");
      writeFileSync(goTestdata("expected-offline.html"), html.html);
      writeFileSync(
        goTestdata("offline-fragment.txt"),
        `${fragment.fragment}\n`,
      );
    }
    expect(html.html).toBe(
      readFileSync(goTestdata("expected-offline.html"), "utf8"),
    );
    expect(`${fragment.fragment}\n`).toBe(
      readFileSync(goTestdata("offline-fragment.txt"), "utf8"),
    );
  });
});
