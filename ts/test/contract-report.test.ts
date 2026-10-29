// contract-report/v1 (spec/contract-report-v1.md section 1): the block
// reader, and what AAC's verification page states about the block. Which
// page a Result root that opts in resolves to is capsule-viewer's registry.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  CONTRACT_REPORT_KIND,
  readContractReport,
} from "../src/contract-report.js";
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

// What AAC's verification page states about the block on a Result root: the
// verifier interprets an engaged block with the contract-report reader, and a
// page that applied no contract-report module lists it as present and not
// interpreted, with the same check lists as the root without it.
describe("a Result root that carries contract-report/v1", () => {
  const page = async (bundle: unknown) =>
    (
      await pageModel(bundle, {
        citedSigners: true,
        applied: new Set([
          "presentation-header",
          "countersignature-stamp",
          "result-root",
        ]),
      })
    ).page;

  it.each(["result-root-bundle.json", "result-root-close-bundle.json"])(
    "%s: the engaged block is interpreted by contract-report, and the core page lists it not interpreted",
    async (name) => {
      const { bundle } = await sealEvidenceBundle(fixture(name));
      const opted = withExtensions(bundle as Obj, {
        [CONTRACT_REPORT_KIND]: {},
      });
      const { context } = await pageModel(opted);
      expect(
        context.verification.extensions.find(
          (e) => e.kind === CONTRACT_REPORT_KIND,
        ),
      ).toMatchObject({
        status: "interpreted",
        interpreter: "contract-report",
      });

      const plain = await page(bundle);
      const report = await page(opted);
      expect(report.checkLists).toEqual(plain.checkLists);
      const row = report.extensions.find((r) => r.id === CONTRACT_REPORT_KIND);
      expect(row).toBeDefined();
      expect(row?.interpreter).toBeUndefined();
    },
  );

  it("a declined block is not interpreted, and is listed as present", async () => {
    const { bundle } = await sealEvidenceBundle(
      fixture("result-root-bundle.json"),
    );
    const declined = withExtensions(bundle as Obj, {
      [CONTRACT_REPORT_KIND]: { enabled: true },
    });
    const { context } = await pageModel(declined);
    expect(
      context.verification.extensions.find(
        (e) => e.kind === CONTRACT_REPORT_KIND,
      )?.status,
    ).not.toBe("interpreted");
    expect((await page(declined)).extensions.map((row) => row.id)).toContain(
      CONTRACT_REPORT_KIND,
    );
  });
});
