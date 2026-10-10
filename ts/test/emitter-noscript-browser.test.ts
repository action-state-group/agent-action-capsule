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
import {
  DEFAULT_EVIDENCE_GRAPH_NOSCRIPT_TEXT,
  emitEvidenceGraphHtml,
} from "../src/emitter.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

// The no-script slot in a real browser, with scripting off and on. Same
// browser lookup as emitter-csp-browser.test.ts; skipped when none exists.
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
type Obj = Record<string, unknown>;
const fixture = (name: string): Obj =>
  JSON.parse(
    readFileSync(resolve(import.meta.dirname, "testdata", name), "utf8"),
  ) as Obj;

// Real pages: each bundle renders a different built-in presentation (a
// Result root, a compliance card, an outcome report) with its verification
// page and lists when scripting is on.
const fixtures = [
  "result-root-bundle.json",
  "compliance-bundle.json",
  "outcome-report-bundle.json",
] as const;

const hostText =
  'To check this file without JavaScript, run: example-verify --bundle "<this file>" & read its report.';

interface Shown {
  /** The text a reader sees: the body's rendered text. */
  readonly text: string;
  /** Elements under #app. */
  readonly appElements: number;
  /** List and table elements anywhere in the body. */
  readonly lists: number;
}

const shown = (page: Page): Promise<Shown> =>
  page.evaluate(() => ({
    text: document.body.innerText.trim(),
    appElements: document.querySelectorAll("#app *").length,
    lists: document.querySelectorAll("body ul, body ol, body li, body table")
      .length,
  }));

describe.skipIf(executablePath === undefined)(
  "the no-script slot in a browser",
  () => {
    let browser: Browser;
    let directory: string;
    let runtime: string;
    let pageCount = 0;

    beforeAll(async () => {
      browser = await chromium.launch({ executablePath: executablePath! });
      directory = mkdtempSync(join(tmpdir(), "aac-noscript-"));
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

    afterAll(async () => {
      await browser?.close();
      rmSync(directory, { recursive: true, force: true });
    });

    async function open(html: string, javaScriptEnabled: boolean) {
      const file = join(directory, `page-${pageCount++}.html`);
      writeFileSync(file, html);
      const context = await browser.newContext({ javaScriptEnabled });
      const page = await context.newPage();
      await page.goto(`file://${file}`);
      await page.waitForFunction(() => document.readyState === "complete");
      return { page, context };
    }

    for (const name of fixtures) {
      for (const [label, noscriptText, expected] of [
        ["the default text", undefined, DEFAULT_EVIDENCE_GRAPH_NOSCRIPT_TEXT],
        ["the host's text", hostText, hostText],
      ] as const) {
        it(`${name}, scripting off: shows ${label} and nothing else`, async () => {
          const { bundle } = await sealEvidenceBundle(fixture(name));
          const html = emitEvidenceGraphHtml(bundle, runtime, {
            ...(noscriptText === undefined ? {} : { noscriptText }),
          });
          const { page, context } = await open(html, false);
          expect(await shown(page)).toEqual({
            text: expected,
            appElements: 0,
            lists: 0,
          });
          await context.close();
        });
      }

      it(`${name}, scripting on: the page renders and the slot text is not shown`, async () => {
        const { bundle } = await sealEvidenceBundle(fixture(name));
        const html = emitEvidenceGraphHtml(bundle, runtime, {
          noscriptText: hostText,
        });
        const { page, context } = await open(html, true);
        await page.waitForSelector("[data-verify]");
        const on = await shown(page);
        expect(on.appElements).toBeGreaterThan(0);
        expect(on.text).not.toContain("without JavaScript");
        expect(
          await page.evaluate(
            () => document.querySelector("noscript")!.getClientRects().length,
          ),
        ).toBe(0);
        await context.close();
      });
    }
  },
  60_000,
);
