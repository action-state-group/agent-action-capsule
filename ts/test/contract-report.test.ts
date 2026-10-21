// @vitest-environment jsdom
// contract-report/v1 (spec/contract-report-v1.md): the block reader, the
// descriptor it feeds, and the built-in manifest that draws the generic
// Result page for a Result root that opts in.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { buildVerifiedBundleContext } from "../src/bundle.js";
import {
  CONTRACT_REPORT_KIND,
  readContractReport,
} from "../src/contract-report.js";
import { renderEvidenceGraph } from "../src/browser.js";
import { describeContext } from "../src/presentation-registry.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

type Obj = Record<string, unknown>;

const fixture = (name: string): Obj =>
  JSON.parse(
    readFileSync(resolve(process.cwd(), "test", "testdata", name), "utf8"),
  ) as Obj;

const withExtensions = (bundle: Obj, extensions: Obj): Obj => ({
  ...bundle,
  extensions: {
    ...((bundle.extensions as Obj | undefined) ?? {}),
    ...extensions,
  },
});

describe("readContractReport", () => {
  it("engages a closed empty object", () => {
    expect(
      readContractReport({ extensions: { [CONTRACT_REPORT_KIND]: {} } }),
    ).toBe(true);
  });

  it.each([
    ["a member", { wording_sha256: "0".repeat(64) }],
    ["an enabled flag", { enabled: true }],
    ["an x- member", { "x-note": "text" }],
    ["an array", []],
    ["null", null],
    ["a string", "contract-report"],
    ["a number", 1],
    ["true", true],
  ])("declines a block that is %s", (_, block) => {
    expect(
      readContractReport({ extensions: { [CONTRACT_REPORT_KIND]: block } }),
    ).toBe(false);
  });

  it.each([
    ["no extensions", {}],
    ["extensions that are not an object", { extensions: [] }],
    ["no contract-report member", { extensions: { "composed/v1": {} } }],
    ["a bundle that is not an object", "bundle"],
  ])("declines %s", (_, bundle) => {
    expect(readContractReport(bundle)).toBe(false);
  });

  it("reads the member only as an own property", () => {
    const extensions = Object.create({ [CONTRACT_REPORT_KIND]: {} }) as Obj;
    expect(readContractReport({ extensions })).toBe(false);
  });
});

async function render(bundle: unknown): Promise<HTMLElement> {
  const root = document.createElement("main");
  await renderEvidenceGraph(bundle, root);
  return root;
}

/**
 * The Result page and the verification page's two check lists (which include
 * the cited-signer check). The rest of the verification page differs by
 * design: the bundle digest covers the block, and the extension table
 * lists it.
 */
function resultAndChecks(root: HTMLElement): string[] {
  return [
    '[data-page="result"]',
    'ul[data-checks="page"]',
    'ul[data-checks="not-checked"]',
  ].map((selector) => root.querySelector(selector)?.outerHTML ?? "");
}

function extensionRow(root: HTMLElement, kind: string): HTMLElement | null {
  return root.querySelector<HTMLElement>(
    `table[data-extensions] tr[data-extension-id="${kind}"]`,
  );
}

describe("a Result root that opts into contract-report/v1", () => {
  it.each(["result-root-bundle.json", "result-root-close-bundle.json"])(
    "%s: the engaged block resolves to aac.builtin.result-contract-report/v0, which draws the generic Result page unchanged",
    async (name) => {
      const { bundle } = await sealEvidenceBundle(fixture(name));
      const opted = withExtensions(bundle as Obj, {
        [CONTRACT_REPORT_KIND]: {},
      });

      const descriptor = describeContext(
        await buildVerifiedBundleContext(opted),
      );
      expect(descriptor.verified).toBe(true);
      expect(descriptor.extensions.has(CONTRACT_REPORT_KIND)).toBe(true);

      const plain = await render(bundle);
      const report = await render(opted);
      expect(report.querySelector('[data-page="result"]')).not.toBeNull();
      // Same page, same check lists (the cited-signer check included).
      expect(resultAndChecks(report)).toEqual(resultAndChecks(plain));
      // AAC applies no report view, so the block is listed as present and
      // not interpreted.
      expect(
        extensionRow(report, CONTRACT_REPORT_KIND)?.dataset.semantics,
      ).toBe("uninterpreted");
    },
  );

  it("takes precedence over a deprecated alias: the outcome card is not drawn", async () => {
    const { bundle } = await sealEvidenceBundle(
      fixture("result-root-bundle.json"),
    );
    const plain = await render(bundle);
    const both = await render(
      withExtensions(bundle as Obj, {
        [CONTRACT_REPORT_KIND]: {},
        "outcome-report/v1": { enabled: true },
      }),
    );
    const alias = await render(
      withExtensions(bundle as Obj, { "outcome-report/v1": { enabled: true } }),
    );
    expect(both.querySelector('[data-page="result"]')?.outerHTML).toBe(
      plain.querySelector('[data-page="result"]')?.outerHTML,
    );
    // Without the new kind, the deprecated alias still draws its card.
    expect(alias.querySelector('[data-page="result"]')).toBeNull();
  });

  it("a declined block is not engaged: the generic Result page draws, and the block is listed as present", async () => {
    const { bundle } = await sealEvidenceBundle(
      fixture("result-root-bundle.json"),
    );
    const declined = withExtensions(bundle as Obj, {
      [CONTRACT_REPORT_KIND]: { enabled: true },
    });
    const descriptor = describeContext(
      await buildVerifiedBundleContext(declined),
    );
    expect(descriptor.extensions.has(CONTRACT_REPORT_KIND)).toBe(false);
    const root = await render(declined);
    expect(root.querySelector('[data-page="result"]')).not.toBeNull();
    expect(extensionRow(root, CONTRACT_REPORT_KIND)).not.toBeNull();
  });
});
