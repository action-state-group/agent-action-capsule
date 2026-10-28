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
  VERIFICATION_BANNER_LINES,
  verificationCheckWords,
} from "../src/verification-page.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

// A real browser, skipped when none is installed: the browser build checks
// the checkpoint signature with CLL's browser entry (#435), as Node does.
// The page holds only the bundle, the verification model built for the
// browser (test/helpers/page-model.ts, which reads only modules src/browser.ts
// exports) and a bootstrap that reads it; capsule-viewer draws the full page
// from the same model.
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

type Obj = Record<string, unknown>;
const json = (...path: string[]): Obj =>
  JSON.parse(readFileSync(resolve(process.cwd(), ...path), "utf8")) as Obj;

interface Lists {
  readonly page: string[];
  readonly failed: string[];
  readonly notChecked: string[];
  readonly checkpointLine: string | null;
  readonly verify: string;
  readonly verdict: string;
  readonly checkpoint: string;
  readonly detail: string;
  readonly banner: string;
}

describe.skipIf(executablePath === undefined)(
  "the verification page's check lists in a browser",
  () => {
    let browser: Browser;
    let directory: string;
    let runtime: string;
    let count = 0;

    beforeAll(async () => {
      directory = mkdtempSync(join(tmpdir(), "aac-checks-"));
      const result = await build({
        entryPoints: [
          resolve(process.cwd(), "test", "helpers", "page-model.ts"),
        ],
        bundle: true,
        format: "iife",
        platform: "browser",
        globalName: "PageModel",
        write: false,
      });
      runtime = result.outputFiles[0]!.text;
      browser = await chromium.launch({ executablePath: executablePath! });
    }, 60_000);

    afterAll(async () => {
      await browser?.close();
      if (directory !== undefined)
        rmSync(directory, { recursive: true, force: true });
    }, 60_000);

    async function open(
      bundle: unknown,
      options: { citedSigners?: boolean } = {},
    ): Promise<Lists> {
      const file = join(directory, `page-${count++}.html`);
      // "<" escaped so no value can close the script element.
      const embedded = JSON.stringify(bundle).replace(/</gu, "\\u003c");
      writeFileSync(
        file,
        `<!doctype html><meta charset="utf-8">` +
          `<script>window.__BUNDLE__ = ${embedded};</script>` +
          `<script>${runtime.replace(/<\/script/giu, "<\\/script")}</script>`,
      );
      const context = await browser.newContext();
      const page = await context.newPage();
      await page.goto(pathToFileURL(file).href);
      const shown = await page.evaluate(async (options) => {
        const { banner, page } = await (
          window as unknown as {
            PageModel: typeof import("./helpers/page-model.js");
          }
        ).PageModel.pageModel(
          (window as unknown as { __BUNDLE__: unknown }).__BUNDLE__,
          options,
        );
        return { banner, lists: page.checkLists };
      }, options);
      await context.close();
      const { banner, lists } = shown;
      return {
        page: [...lists.page],
        failed: [...lists.failed],
        notChecked: [...lists.notChecked],
        checkpointLine: lists.notChecked.includes("checkpoint-signature")
          ? verificationCheckWords("checkpoint-signature", "notChecked", lists)
          : null,
        verify: banner.state,
        verdict: banner.verdict,
        checkpoint: banner.checkpoint,
        banner: banner.line,
        detail: banner.detail,
      };
    }

    it("a signed checkpoint: the browser checks its signature and refuses what the library refuses", async () => {
      const bundle = json(
        "..",
        "vectors",
        "minimum-necessary",
        "bundle-internal-audit",
        "input.json",
      ).bundle;
      const shown = await open(bundle);
      // The signed checkpoint covers a log_id the stated one omits: the
      // signature was checked, so the page refuses it rather than say less.
      expect(shown.verify).toBe("failed");
      expect(shown.verdict).toBe("invalid");
      expect(shown.checkpoint).toBe("invalid");
      expect(shown.banner).toBe(VERIFICATION_BANNER_LINES.failed);
      expect(shown.detail).toBe(
        "What failed: the checkpoint is missing fields its signature covers (checkpoint_field_missing).",
      );
      expect(shown.notChecked).not.toContain("checkpoint-signature");
      expect(shown.checkpointLine).toBeNull();
    });

    it("a valid signed checkpoint reads verified", async () => {
      const vectors = json("..", "vectors", "bundle", "strict", "vectors.json")
        .cases as { id: string; bundle: Obj }[];
      const shown = await open(
        vectors.find((c) => c.id === "pos-signed-whole-log")!.bundle,
      );
      expect(shown.verify).toBe("verified");
      expect(shown.checkpoint).toBe("verified");
      expect(shown.notChecked).toEqual([]);
    });

    it("a page module that checked the signers it cites: they are on the page list, every record's signature is not", async () => {
      const { bundle } = await sealEvidenceBundle(
        json("test", "testdata", "result-root-close-bundle.json"),
      );
      const shown = await open(bundle, { citedSigners: true });
      expect(shown.page).toContain("cited-signers");
      expect(shown.notChecked).toEqual(["producer-signatures"]);
    });
  },
  60_000,
);
