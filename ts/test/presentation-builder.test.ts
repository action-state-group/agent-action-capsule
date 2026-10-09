import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { build } from "esbuild";
import { JSDOM } from "jsdom";
import { beforeAll, describe, expect, it } from "vitest";
import { emitEvidenceGraphHtml } from "../src/emitter.js";
import { createPresentationRegistry } from "../src/evidence-graph-view.js";
import {
  buildFragmentViewerHtml,
  buildPresentation,
  offlineHtmlFromFragment,
  PresentationBuildError,
  type BuildPresentationOptions,
  type BuiltPresentation,
} from "../src/presentation-builder.js";
import {
  decodePresentationFragment,
  FragmentTooLargeError,
  type DisclosureScope,
  type WordingPackInput,
} from "../src/presentation-fragment.js";
import {
  resolveModules,
  type PresentationModule,
  type PresentationResolver,
} from "../src/presentation-registry.js";
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
    html: root.innerHTML,
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
): Promise<Record<"html" | "fragment" | "embedded", Outcome>> {
  const out = {} as Record<"html" | "fragment" | "embedded", Outcome>;
  for (const format of ["html", "fragment", "embedded"] as const) {
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

describe("one builder, three packagings: acceptance over (bundle, audience) pairs", () => {
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
      it(`${label} × ${audience}: every format shows the same verified content and identifiers`, async () => {
        const bundle = sealed.get(`${file}:${verifies}`);
        const disclose = scope(bundle);
        const outcome = await showAll(bundle, {
          presentation: "auto",
          audience,
          ...(disclose === undefined ? {} : { disclose }),
        });
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
          table.push(
            `${label} | ${audience} | refused in all three: cannot scope a failing bundle`,
          );
          return;
        }
        // Only a fragment too large for a URL may be refused, and only for size.
        for (const [format, r] of refused) {
          expect(format).toBe("fragment");
          expect(r.error).toMatch(/^FragmentTooLargeError/u);
        }
        expect(shown.length).toBeGreaterThanOrEqual(2);
        const [first, ...rest] = shown;
        for (const [, s] of rest) {
          expect(s.built.module).toBe(first![1].built.module);
          expect(s.snapshot).toEqual(first![1].snapshot);
        }
        const snap = first![1].snapshot;
        expect(snap.verify).toEqual([verifies ? "verified" : "failed"]);
        if (verifies) expect(snap.evidence_ids.length).toBeGreaterThan(0);

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
          `${label} | ${audience} | module ${first![1].built.module ?? first![1].built.resolution} | verify ${snap.verify.join(",")} | ids ${snap.evidence_ids.length} | formats shown ${shown.map(([f]) => f).join("+")}${refused.length > 0 ? ` | fragment refused: too large` : ""}`,
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
