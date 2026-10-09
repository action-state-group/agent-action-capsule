import { createHash } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { build } from "esbuild";
import { chromium, type Browser, type Page } from "playwright-core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { emitEvidenceGraphHtml } from "../src/emitter.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

// These tests need a real CSP-enforcing browser. They use AAC_CHROMIUM_PATH,
// then Playwright's own Chromium, then a system Chrome/Chromium (present on
// GitHub-hosted Ubuntu runners), and skip when none is installed.
function browserPath(): string | undefined {
  const candidates = [
    process.env.AAC_CHROMIUM_PATH,
    chromium.executablePath(),
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  ];
  return candidates.find(
    (candidate) =>
      candidate !== undefined && candidate !== "" && existsSync(candidate),
  );
}

const executablePath = browserPath();
const hex = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex");
type Obj = Record<string, unknown>;
const fixture = (name: string): Obj =>
  JSON.parse(
    readFileSync(resolve(import.meta.dirname, "testdata", name), "utf8"),
  ) as Obj;

interface Loaded {
  readonly page: Page;
  readonly violations: string[];
}

describe.skipIf(executablePath === undefined)(
  "emitted page under a CSP-enforcing browser",
  () => {
    let browser: Browser;
    let directory: string;
    let pageCount = 0;

    beforeAll(async () => {
      browser = await chromium.launch({ executablePath: executablePath! });
      directory = mkdtempSync(join(tmpdir(), "aac-csp-"));
    });

    afterAll(async () => {
      await browser?.close();
      rmSync(directory, { recursive: true, force: true });
    });

    async function load(html: string, width = 1280): Promise<Loaded> {
      const file = join(directory, `page-${pageCount++}.html`);
      writeFileSync(file, html);
      const context = await browser.newContext({
        viewport: { width, height: 900 },
      });
      const page = await context.newPage();
      await page.addInitScript(() => {
        const seen: string[] = [];
        (globalThis as unknown as { __violations: string[] }).__violations =
          seen;
        document.addEventListener("securitypolicyviolation", (event) =>
          seen.push(event.effectiveDirective),
        );
      });
      await page.goto(`file://${file}`);
      await page.waitForFunction(() => document.readyState === "complete");
      await page.waitForTimeout(300);
      const violations = await page.evaluate(
        () =>
          (globalThis as unknown as { __violations: string[] }).__violations,
      );
      return { page, violations };
    }

    const flag = (page: Page, name: string): Promise<unknown> =>
      page.evaluate(
        (key) => (globalThis as unknown as Record<string, unknown>)[key],
        name,
      );

    const core = "window.coreRan = true;";
    const module = "window.moduleRan = true;";
    const bootstrap =
      'window.booted = window.__BUNDLE__ !== undefined; fetch("https://example.invalid/").then(() => { window.fetched = true; }, () => { window.fetchRefused = true; });';
    const page = (): string =>
      emitEvidenceGraphHtml({ note: "csp" }, core, {
        coreRuntimeSha256: hex(core),
        modules: [{ code: module, sha256: hex(module) }],
        bootstrap,
      });

    it("runs every hashed inline script and refuses the network", async () => {
      const { page: loaded, violations } = await load(page());
      expect(await flag(loaded, "coreRan")).toBe(true);
      expect(await flag(loaded, "moduleRan")).toBe(true);
      expect(await flag(loaded, "booted")).toBe(true);
      await loaded.waitForFunction(() => "fetchRefused" in globalThis);
      expect(await flag(loaded, "fetched")).toBeUndefined();
      expect(violations.filter((v) => v !== "connect-src")).toEqual([]);
    });

    it("refuses a script whose hash the page does not list", async () => {
      const html = page().replace(
        "</body>",
        "<script>window.injected = true;</script></body>",
      );
      const { page: loaded, violations } = await load(html);
      expect(await flag(loaded, "injected")).toBeUndefined();
      expect(violations).toContain("script-src-elem");
      expect(await flag(loaded, "coreRan")).toBe(true);
    });

    it("refuses the core runtime once its bytes are edited", async () => {
      const html = page().replace(core, "window.coreRan = 1;");
      const { page: loaded, violations } = await load(html);
      expect(await flag(loaded, "coreRan")).toBeUndefined();
      expect(violations).toContain("script-src-elem");
    });

    describe("a module that inserts a stylesheet at render time", () => {
      const pinned = "#probe{color:rgb(1, 2, 3)}";
      const unlisted = "#probe{color:rgb(4, 5, 6)}";
      const inserting = (css: string): string =>
        `const style = document.createElement("style"); style.textContent = ${JSON.stringify(css)}; document.head.appendChild(style); const probe = document.createElement("div"); probe.id = "probe"; document.body.appendChild(probe); window.moduleRan = true;`;
      const color = (loaded: Page): Promise<string> =>
        loaded.evaluate(
          () => getComputedStyle(document.getElementById("probe")!).color,
        );

      it("applies a stylesheet the module pinned, with no CSP violation", async () => {
        const code = inserting(pinned);
        const { page: loaded, violations } = await load(
          emitEvidenceGraphHtml({ note: "csp" }, core, {
            coreRuntimeSha256: hex(core),
            modules: [{ code, sha256: hex(code), styleSha256: [hex(pinned)] }],
            bootstrap: "window.booted = true;",
          }),
        );
        expect(await flag(loaded, "moduleRan")).toBe(true);
        expect(violations).toEqual([]);
        expect(await color(loaded)).toBe("rgb(1, 2, 3)");
      });

      it("blocks a stylesheet the module did not pin", async () => {
        const code = inserting(unlisted);
        const { page: loaded, violations } = await load(
          emitEvidenceGraphHtml({ note: "csp" }, core, {
            coreRuntimeSha256: hex(core),
            modules: [{ code, sha256: hex(code), styleSha256: [hex(pinned)] }],
            bootstrap: "window.booted = true;",
          }),
        );
        expect(await flag(loaded, "moduleRan")).toBe(true);
        expect(violations).toContain("style-src-elem");
        expect(await color(loaded)).not.toBe("rgb(4, 5, 6)");
      });
    });

    describe("with the reference core runtime", () => {
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

      for (const [name, selector] of [
        ["outcome-report-bundle.json", ".oi"],
        ["compliance-bundle.json", ".cc"],
      ] as const) {
        it(`${name} renders with no CSP violation and no overflow at 390px`, async () => {
          const { bundle } = await sealEvidenceBundle(fixture(name));
          const html = emitEvidenceGraphHtml(bundle, runtime, {
            title: "Supplied title",
          });
          const { page: loaded, violations } = await load(html, 390);
          await loaded.waitForSelector(selector);
          expect(violations).toEqual([]);
          expect(await loaded.title()).toBe("Supplied title");
          const width = await loaded.evaluate(
            () => document.documentElement.scrollWidth,
          );
          expect(width).toBeLessThanOrEqual(390);
        });
      }
    });
  },
  60_000,
);
