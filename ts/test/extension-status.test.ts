// @vitest-environment jsdom

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  EXTENSION_NOT_INTERPRETED,
  EXTENSION_NOT_INTERPRETED_NOT_COVERED,
  extensionRows,
  renderEvidenceGraph,
  verifyBundle,
  type BundleVerificationResult,
} from "../src/browser.js";
import { derivedFixture } from "./helpers/derived-fixtures.js";

type Obj = Record<string, unknown>;

const json = (...path: string[]): Obj =>
  JSON.parse(readFileSync(resolve(process.cwd(), ...path), "utf8")) as Obj;
const weekBundle = (): Obj => json("test", "testdata", "week-bundle.json");
const composedAgree = (): Obj =>
  (
    json("..", "vectors", "bundle", "composed", "vectors.json").cases as {
      id: string;
      container: Obj;
    }[]
  ).find((c) => c.id === "agree")!.container;

const withExtensions = (bundle: Obj, extensions: Obj): Obj => ({
  ...bundle,
  extensions: {
    ...((bundle.extensions as Obj | undefined) ?? {}),
    ...extensions,
  },
});

interface Row {
  id: string | undefined;
  integrity: string | undefined;
  semantics: string | undefined;
  cells: string[];
}

async function render(
  bundle: unknown,
): Promise<{ root: HTMLElement; rows: Row[] }> {
  const root = document.createElement("main");
  await renderEvidenceGraph(bundle, root);
  const page = root.querySelector<HTMLElement>('[data-page="verification"]')!;
  const rows = Array.from(
    page.querySelectorAll<HTMLElement>("table[data-extensions] tbody tr"),
  ).map((tr) => ({
    id: tr.dataset.extensionId,
    integrity: tr.dataset.integrity,
    semantics: tr.dataset.semantics,
    cells: Array.from(tr.querySelectorAll("td"), (td) => td.textContent ?? ""),
  }));
  return { root, rows };
}

const verdicts = (result: BundleVerificationResult) => ({
  graphClosure: result.graphClosure,
  intervalCoverage: result.intervalCoverage,
  perRecordMembership: result.perRecordMembership,
  disclosures: result.disclosures,
  capsules: Object.fromEntries(
    Object.entries(result.capsuleResults).map(([id, r]) => [id, r.ok]),
  ),
});

describe("extension interpretation status", () => {
  it("the user-facing wording is exact", () => {
    expect(EXTENSION_NOT_INTERPRETED).toBe(
      "Integrity verified; meaning not interpreted by this viewer",
    );
  });

  it("an interpreted extension names its interpreter, with integrity in its own cell", async () => {
    const bundle = await derivedFixture("week-bundle-presentation.json");
    const verified = await verifyBundle(bundle);
    expect(verified.extensions).toEqual([
      {
        kind: "presentation/v1",
        status: "interpreted",
        interpreter: "presentation-header",
        integrityCovered: true,
      },
    ]);
    const { rows } = await render(bundle);
    expect(rows).toEqual([
      {
        id: "presentation/v1",
        integrity: "covered",
        semantics: "interpreted",
        cells: [
          "presentation/v1",
          "covered",
          "interpreted by presentation-header",
        ],
      },
    ]);
  });

  it("an unknown x- extension is covered but uninterpreted, in exactly those words, and changes no verdict", async () => {
    const plain = weekBundle();
    const bundle = withExtensions(plain, {
      "x-acme-risk-score/v1": { score: 99, verdict: "approved" },
    });
    const verified = await verifyBundle(bundle);
    expect(verified.extensions).toEqual([
      {
        kind: "x-acme-risk-score/v1",
        status: "uninterpreted",
        integrityCovered: true,
      },
    ]);
    expect(verdicts(verified)).toEqual(verdicts(await verifyBundle(plain)));
    const { root, rows } = await render(bundle);
    expect(rows).toEqual([
      {
        id: "x-acme-risk-score/v1",
        integrity: "covered",
        semantics: "uninterpreted",
        cells: [
          "x-acme-risk-score/v1",
          "covered",
          "Integrity verified; meaning not interpreted by this viewer",
        ],
      },
    ]);
    // The block's own words never reach the page.
    expect(root.textContent).not.toContain("approved");
    // Nothing else on the page moves: the extension table is the only
    // addition, apart from the bundle digest the new block changes.
    const before = await render(plain);
    root
      .querySelector("table[data-extensions]")
      ?.previousElementSibling?.remove();
    root.querySelector("table[data-extensions]")?.remove();
    expect(
      root.innerHTML.replaceAll(
        verified.bundleDigest!,
        (await verifyBundle(plain)).bundleDigest!,
      ),
    ).toBe(before.root.innerHTML);
  });

  it("composed/v1 and an unknown kind render two rows, both covered; on a refused bundle composed/v1 is not interpreted (its section did not render)", async () => {
    const bundle = withExtensions(composedAgree(), { "x-unknown/v1": {} });
    const { rows } = await render(bundle);
    expect(rows.map((row) => row.cells)).toEqual([
      ["composed/v1", "covered", EXTENSION_NOT_INTERPRETED],
      ["x-unknown/v1", "covered", EXTENSION_NOT_INTERPRETED],
    ]);
  });

  it("a block the bundle digest cannot cover is reported not covered, and never as integrity verified", async () => {
    // A non-integer number has no canonical form under the integer-only JCS
    // profile, so the bundle digest is uncomputable and covers nothing.
    const bundle = withExtensions(weekBundle(), { "x-float/v1": { n: 1.5 } });
    const verified = await verifyBundle(bundle);
    expect(verified.bundleDigest).toBeUndefined();
    expect(verified.extensions).toEqual([
      { kind: "x-float/v1", status: "uninterpreted", integrityCovered: false },
    ]);
    const { root, rows } = await render(bundle);
    expect(rows.map((row) => row.cells)).toEqual([
      ["x-float/v1", "not covered", EXTENSION_NOT_INTERPRETED_NOT_COVERED],
    ]);
    expect(
      root.querySelector("table[data-extensions]")?.textContent,
    ).not.toContain("Integrity verified");
  });

  it("an interpretable block whose module did not render is shown as not interpreted", async () => {
    // outcome-report/v1 is a card over a Result root; on an evaluation-summary
    // root the card never renders, so its meaning was not applied here.
    const bundle = withExtensions(weekBundle(), {
      "outcome-report/v1": { enabled: true },
    });
    const verified = await verifyBundle(bundle);
    expect(verified.extensions).toEqual([
      {
        kind: "outcome-report/v1",
        status: "interpreted",
        interpreter: "outcome-report-card",
        integrityCovered: true,
      },
    ]);
    const { rows } = await render(bundle);
    expect(rows.map((row) => row.cells)).toEqual([
      ["outcome-report/v1", "covered", EXTENSION_NOT_INTERPRETED],
    ]);
  });

  it("a block its interpreter's reader ignores is uninterpreted", async () => {
    const verified = await verifyBundle(
      withExtensions(weekBundle(), {
        "outcome-report/v1": { enabled: false },
        "presentation/v1": { badge: "VERIFIED" },
        "producer-key/v1": { public_key: "ABC" },
      }),
    );
    expect(verified.extensions.map((e) => [e.kind, e.status])).toEqual([
      ["outcome-report/v1", "uninterpreted"],
      ["presentation/v1", "uninterpreted"],
      ["producer-key/v1", "uninterpreted"],
    ]);
  });

  it("extensionRows: without an applied set the verifier's status stands", () => {
    expect(
      extensionRows([
        {
          kind: "evidencebook/payloads",
          status: "interpreted",
          interpreter: "result-root",
          integrityCovered: true,
        },
        { kind: "x-a", status: "uninterpreted", integrityCovered: true },
      ]),
    ).toEqual([
      {
        id: "evidencebook/payloads",
        integrity: "covered",
        interpreter: "result-root",
        semantics: "interpreted by result-root",
      },
      { id: "x-a", integrity: "covered", semantics: EXTENSION_NOT_INTERPRETED },
    ]);
  });

  it("a bundle with no extensions draws no extension table", async () => {
    const { root } = await render(weekBundle());
    expect(root.querySelector("table[data-extensions]")).toBeNull();
  });
});
