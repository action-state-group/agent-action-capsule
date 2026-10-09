import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { build } from "esbuild";
import { chromium, type Browser } from "playwright-core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  buildFragmentViewerHtml,
  buildPresentation,
} from "../src/presentation-builder.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

// A real CSP-enforcing browser, found as emitter-csp-browser.test.ts finds
// one; skipped when none is installed.
function browserPath(): string | undefined {
  return [
    process.env.AAC_CHROMIUM_PATH,
    chromium.executablePath(),
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  ].find((c) => c !== undefined && c !== "" && existsSync(c));
}
const executablePath = browserPath();

interface Opened {
  /** Every request the page made, the document load included. */
  readonly requests: string[];
  readonly document: string;
  readonly violations: string[];
  readonly verify: string | null;
  readonly page: string;
  readonly text: string;
}

describe.skipIf(executablePath === undefined)(
  "offline file and fragment permalink in a CSP-enforcing browser",
  () => {
    let browser: Browser;
    let directory: string;
    let runtime: string;

    beforeAll(async () => {
      browser = await chromium.launch({ executablePath: executablePath! });
      directory = mkdtempSync(join(tmpdir(), "aac-builder-"));
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

    async function open(
      file: string,
      html: string,
      hash = "",
    ): Promise<Opened> {
      const path = join(directory, file);
      writeFileSync(path, html);
      const context = await browser.newContext();
      const page = await context.newPage();
      const requests: string[] = [];
      page.on("request", (request) => requests.push(request.url()));
      await page.addInitScript(() => {
        const seen: string[] = [];
        (globalThis as unknown as { __violations: string[] }).__violations =
          seen;
        document.addEventListener("securitypolicyviolation", (event) =>
          seen.push(event.effectiveDirective),
        );
      });
      const url = `${pathToFileURL(path).href}${hash}`;
      await page.goto(url);
      await page.waitForSelector('[data-page="verification"]');
      await page.waitForTimeout(200);
      const shown = await page.evaluate(() => {
        const app = document.getElementById("app")!;
        return {
          verify:
            app.querySelector("[data-verify]")?.getAttribute("data-verify") ??
            null,
          page: app.innerHTML,
          text: app.textContent ?? "",
          violations: (globalThis as unknown as { __violations: string[] })
            .__violations,
        };
      });
      await context.close();
      return {
        requests,
        document: pathToFileURL(path).href,
        violations: shown.violations,
        verify: shown.verify,
        page: shown.page,
        text: shown.text,
      };
    }

    for (const name of ["report-rows-bundle.json", "result-root-bundle.json"])
      it(`${name}: the fragment URL opens with no request beyond its own document and shows what the offline file shows`, async () => {
        const { bundle } = await sealEvidenceBundle(
          JSON.parse(
            readFileSync(
              resolve(import.meta.dirname, "testdata", name),
              "utf8",
            ),
          ),
        );
        const offline = await buildPresentation(bundle, {
          presentation: "auto",
          audience: "counterparty",
          format: "html",
          runtime: { code: runtime },
        });
        const fragment = await buildPresentation(bundle, {
          presentation: "auto",
          audience: "counterparty",
          format: "fragment",
          runtime: { code: runtime },
        });
        if (offline.format !== "html" || fragment.format !== "fragment")
          throw new Error("unexpected format");
        const a = await open("offline.html", offline.html);
        const b = await open(
          "viewer.html",
          buildFragmentViewerHtml({ code: runtime }),
          `#${fragment.fragment}`,
        );
        for (const opened of [a, b]) {
          // The document load is the only request, and it carries no
          // fragment: the browser kept the permalink's data to itself.
          expect(opened.requests).toEqual([opened.document]);
          expect(opened.violations).toEqual([]);
          expect(opened.verify).toBe("verified");
        }
        expect(b.page).toBe(a.page);
      }, 60_000);
  },
  120_000,
);
