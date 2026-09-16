// @vitest-environment jsdom

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { expect, it } from "vitest";
import { buildEvidenceGraph } from "../src/evidence-graph.js";
import { renderEvidenceGraph } from "../src/browser.js";

async function fixture(name: string): Promise<unknown> {
  return JSON.parse(
    await readFile(resolve(process.cwd(), "test", "testdata", name), "utf8"),
  );
}

it("renders the dated drill-down view and verifies the bundle", async () => {
  const bundle = await fixture("week-bundle.json");
  const graph = buildEvidenceGraph(bundle);
  const root = document.createElement("main");

  await renderEvidenceGraph(bundle, root);

  const tiles = root.querySelectorAll<HTMLElement>("[data-report-date]");
  expect(tiles).toHaveLength(graph.reports.length);
  expect(tiles[0]?.dataset.reportDate).toBe(
    [...graph.reports].sort((a, b) => a.date.localeCompare(b.date))[0]?.date,
  );

  tiles[0]?.click();
  const caseNode = root.querySelector<HTMLElement>("[data-case-id]");
  expect(caseNode).not.toBeNull();

  caseNode?.click();
  expect(root.querySelector('[data-verify="verified"]')).not.toBeNull();
});
