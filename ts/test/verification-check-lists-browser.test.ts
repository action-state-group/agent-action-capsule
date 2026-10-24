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
  CHECKPOINT_NOT_CHECKED_NOTE,
  VERIFICATION_BANNER_LINES,
  VERIFICATION_CHECK_WORDS,
  verificationCheckWords,
} from "../src/verification-page.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

// The browser build has no checkpoint authenticator, so a signed checkpoint
// is recorded as checkpoint_unverified there: this is the runtime in which
// the not-checked list matters most. A real browser, skipped when none is
// installed. The page holds only the bundle, the verification model built
// for the browser (test/helpers/page-model.ts, which reads only modules
// src/browser.ts exports) and a bootstrap that reads it; capsule-viewer
// draws the full page from the same model.
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

    it("a signed checkpoint: the rows render, the verdict is incomplete, and the checkpoint signature is listed as not checked", async () => {
      const bundle = json(
        "..",
        "vectors",
        "minimum-necessary",
        "bundle-internal-audit",
        "input.json",
      ).bundle;
      const shown = await open(bundle);
      expect(shown.verify).toBe("incomplete");
      // The checkpoint could not be authenticated here (#196): never "passed".
      expect(shown.verdict).toBe("incomplete");
      expect(shown.checkpoint).toBe("unverified");
      expect(shown.banner).toBe(VERIFICATION_BANNER_LINES.incomplete);
      expect(shown.detail).toContain(
        "checkpoint_unverified: relative to a producer-asserted checkpoint this page could not authenticate.",
      );
      expect(shown.page).toEqual([
        "record-digests",
        "record-rules",
        "closure",
        "range",
        "membership",
        "disclosures",
      ]);
      expect(shown.failed).toEqual([]);
      expect(shown.notChecked).toEqual(["checkpoint-signature"]);
      expect(shown.checkpointLine).toBe(
        `${VERIFICATION_CHECK_WORDS["checkpoint-signature"]} ${CHECKPOINT_NOT_CHECKED_NOTE}`,
      );
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
