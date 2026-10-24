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
import { describeContext } from "../src/presentation-registry.js";
import { builtinPage } from "./helpers/builtin-resolution.js";
import { pageModel } from "./helpers/page-model.js";
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

// What a Result page states about the bundle: the page it resolves to, its
// check lists (the Result page checks the signers it cites) and its
// extension rows, with the interpreters the generic Result page runs.
async function render(bundle: unknown) {
  const { context } = await pageModel(bundle);
  const { page } = await pageModel(context, {
    citedSigners: true,
    applied: new Set([
      "presentation-header",
      "countersignature-stamp",
      "result-root",
    ]),
  });
  return { selected: await builtinPage(context), page };
}

describe("a Result root that opts into contract-report/v1", () => {
  it.each(["result-root-bundle.json", "result-root-close-bundle.json"])(
    "%s: the engaged block resolves to aac.builtin.result-contract-report/v0, the generic Result page, with the same checks",
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
      expect(plain.selected).toBe("aac.builtin.result/v0");
      expect(report.selected).toBe("aac.builtin.result-contract-report/v0");
      // The same check lists (the cited-signer check included).
      expect(report.page.checkLists).toEqual(plain.page.checkLists);
      // AAC applies no report view, so the block is listed as present and
      // not interpreted.
      const row = report.page.extensions.find(
        (r) => r.id === CONTRACT_REPORT_KIND,
      );
      expect(row).toBeDefined();
      expect(row?.interpreter).toBeUndefined();
    },
  );

  it("takes precedence over a deprecated alias: the outcome card is not selected", async () => {
    const { bundle } = await sealEvidenceBundle(
      fixture("result-root-bundle.json"),
    );
    const both = await render(
      withExtensions(bundle as Obj, {
        [CONTRACT_REPORT_KIND]: {},
        "outcome-report/v1": { enabled: true },
      }),
    );
    const alias = await render(
      withExtensions(bundle as Obj, { "outcome-report/v1": { enabled: true } }),
    );
    expect(both.selected).toBe("aac.builtin.result-contract-report/v0");
    // Without the new kind, the deprecated alias still selects its card.
    expect(alias.selected).toBe("aac.builtin.result-outcome-report/v0");
  });

  it("a declined block is not engaged: the generic Result page is selected, and the block is listed as present", async () => {
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
    const { selected, page } = await render(declined);
    expect(selected).toBe("aac.builtin.result/v0");
    expect(page.extensions.map((row) => row.id)).toContain(
      CONTRACT_REPORT_KIND,
    );
  });
});
