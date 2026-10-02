// @vitest-environment jsdom

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { expect, it } from "vitest";
import { renderEvidenceGraph } from "../src/browser.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

type Obj = Record<string, unknown>;

function fixture(name: string): Obj {
  return JSON.parse(
    readFileSync(resolve(process.cwd(), "test", "testdata", name), "utf8"),
  ) as Obj;
}

async function render(bundle: unknown): Promise<HTMLElement> {
  const root = document.createElement("main");
  await renderEvidenceGraph(bundle, root);
  return root;
}

async function sealedComplianceBundle(
  mutate?: (source: Obj) => void,
): Promise<{ bundle: Obj; ids: Record<string, string> }> {
  const source = fixture("compliance-bundle.json");
  mutate?.(source);
  return sealEvidenceBundle(source);
}

// ---------------------------------------------------------------------------
// (a) card selection, after outcome-report/v1
// ---------------------------------------------------------------------------

it("renders the compliance card, not the generic Result page, when eu-ai-act-compliance/v1 opts in", async () => {
  const { bundle } = await sealedComplianceBundle();
  const root = await render(bundle);
  expect(root.querySelector('[data-verify="verified"]')).not.toBeNull();
  const page = root.querySelector<HTMLElement>('[data-page="compliance"]')!;
  expect(page).not.toBeNull();
  expect(page.classList.contains("cc")).toBe(true);
  expect(root.querySelector('[data-page="result"]')).toBeNull();
  expect(root.lastElementChild).toBe(
    root.querySelector('[data-page="verification"]'),
  );
});

it("eu-ai-act-compliance/v1 present but not enabled falls back to the generic Result page", async () => {
  const { bundle } = await sealedComplianceBundle((source) => {
    ((source.extensions as Obj)["eu-ai-act-compliance/v1"] as Obj).enabled =
      false;
  });
  const root = await render(bundle);
  expect(root.querySelector('[data-page="result"]')).not.toBeNull();
  expect(root.querySelector('[data-page="compliance"]')).toBeNull();
});

it("outcome-report/v1 takes precedence over eu-ai-act-compliance/v1 when a bundle carries both", async () => {
  const { bundle } = await sealedComplianceBundle((source) => {
    (source.extensions as Obj)["outcome-report/v1"] = {
      enabled: true,
      percentages: false,
    };
  });
  const root = await render(bundle);
  expect(root.querySelector('[data-page="outcome-report"]')).not.toBeNull();
  expect(root.querySelector('[data-page="compliance"]')).toBeNull();
});

// ---------------------------------------------------------------------------
// (b) scoped stylesheet, no external reference anywhere
// ---------------------------------------------------------------------------

it("the card's styles are scoped under .cc and the page carries no external reference", async () => {
  const { bundle } = await sealedComplianceBundle();
  const root = await render(bundle);
  const style = root.querySelector('[data-page="compliance"] style')!;
  expect(style.textContent).toContain(".cc ");
  expect(style.textContent).not.toMatch(/(^|[^.\w-])body\s*\{/);
  expect(root.innerHTML).not.toMatch(/https?:\/\//);
  expect(root.querySelectorAll("img, script, link, iframe")).toHaveLength(0);
});

// ---------------------------------------------------------------------------
// (c) section content
// ---------------------------------------------------------------------------

it("the summary table shows one row per obligation with its article and status", async () => {
  const { bundle } = await sealedComplianceBundle();
  const root = await render(bundle);
  const rows = root.querySelectorAll<HTMLElement>(
    '[data-rows="summary"] tbody tr',
  );
  expect(rows).toHaveLength(3);
  const art26row = root.querySelector<HTMLElement>(
    'tr[data-obligation="art26"]',
  )!;
  expect(art26row.textContent).toContain("Applies 2 Aug 2027");
});

it("the test-results table carries all five tests with population, exceptions and not-evaluable counts", async () => {
  const { bundle } = await sealedComplianceBundle();
  const root = await render(bundle);
  const art50f = root.querySelector<HTMLElement>(
    'tr[data-criterion="art50.disclosure_before_first_turn"]',
  )!;
  expect(art50f.textContent).toContain("Not evaluable");
  const cells = art50f.querySelectorAll("td");
  expect(cells[3]!.textContent).toBe("2"); // population
  expect(cells[4]!.textContent).toBe("0"); // exceptions
  expect(cells[5]!.textContent).toBe("2"); // not evaluable
});

it("a session's drill-down shows a check-it block per test with its sealed tier", async () => {
  const { bundle } = await sealedComplianceBundle();
  const root = await render(bundle);
  const session = root.querySelector<HTMLElement>(
    'details[data-session="tau2:airline:task-0:trial-0"]',
  )!;
  expect(session).not.toBeNull();
  const blocks = session.querySelectorAll("[data-crit]");
  expect(blocks).toHaveLength(5);
  const judgedBlock = session.querySelector<HTMLElement>(
    '[data-crit="art5.no_manipulation_or_deception"]',
  )!;
  expect(
    judgedBlock.querySelector("[data-tier]")!.getAttribute("data-tier"),
  ).toBe("judged");
  const recomputedBlock = session.querySelector<HTMLElement>(
    '[data-crit="art50.disclosure_before_first_turn"]',
  )!;
  expect(recomputedBlock.textContent).toContain("recomputed");
});

it("findings render for a not-met row with a finding template, never for disclosure_before_first_turn", async () => {
  const { bundle } = await sealedComplianceBundle();
  const root = await render(bundle);
  expect(root.querySelector('[data-finding="F-01"]')).not.toBeNull();
  expect(root.querySelector('[data-finding="F-02"]')).not.toBeNull();
  expect(root.querySelectorAll("[data-finding]")).toHaveLength(2); // F-03/F-04 rows have zero not-met sessions here
});

it("the header states where the terms come from, and the regulatory mapping is labelled the producer's", async () => {
  const { bundle } = await sealedComplianceBundle();
  const root = await render(bundle);
  const basis = root.querySelector<HTMLElement>('[data-basis="terms"]')!;
  expect(basis.textContent).toContain("sealed claims and reports");
  expect(basis.textContent).toContain("producer's mapping");
  expect(root.querySelector(".hd .sub")!.textContent).toContain(
    "Pack eu-ai-act-obligations v0.1.0",
  );
});

it("a session without a transcript in the bundle says so, and names the case record", async () => {
  const { bundle } = await sealedComplianceBundle();
  const root = await render(bundle);
  const tx = root.querySelector<HTMLElement>('[data-transcript="absent"]')!;
  expect(tx.textContent).toContain("not in this bundle");
});

it("population counts only the sessions a test has a sealed result for", async () => {
  const { bundle } = await sealedComplianceBundle();
  const root = await render(bundle);
  const row = root.querySelector<HTMLElement>(
    'tr[data-criterion="art26.allowed_action_rules"]',
  )!;
  expect(row.querySelectorAll("td")[3]!.textContent).toBe("1");
});
