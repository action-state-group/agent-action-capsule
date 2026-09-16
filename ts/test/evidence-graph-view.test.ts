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
  const selectedCase = graph.reports[0]!.cases[0]!;
  const drawer = Array.from(root.querySelectorAll("h3")).find(
    (heading) => heading.textContent === `Case ${selectedCase.caseId}`,
  )?.parentElement;
  expect(drawer).toBeDefined();
  const rationale = selectedCase.judgments[0]!.rationale;
  expect(rationale.length).toBeGreaterThan(0);
  expect(
    Array.from(drawer!.querySelectorAll("p")).some((paragraph) =>
      paragraph.textContent?.includes(rationale),
    ),
  ).toBe(true);
  const act = selectedCase.acts[0]!;
  expect(act.agentInput).toBeDefined();
  expect(act.agentOutput).toBeDefined();
  const transcript = Array.from(drawer!.querySelectorAll("pre")).map(
    (region) => region.textContent,
  );
  expect(transcript).toContain(JSON.stringify(act.agentInput));
  expect(transcript).toContain(JSON.stringify(act.agentOutput));
  expect(root.querySelector('[data-verify="verified"]')).not.toBeNull();
});

it("renders disclosed calibration agreement and confusion data", async () => {
  const root = document.createElement("main");
  await renderEvidenceGraph(
    await fixture("week-bundle-calibration.json"),
    root,
  );
  expect(root.textContent).toContain("confusion matrix");
  expect(root.textContent).toContain('"pass_pass":2');
  expect(root.textContent).toContain("agreement");
  expect(root.textContent).toContain("0.75");
});

it("renders only digests for undisclosed case acts without leaking transcripts", async () => {
  const bundle = (await fixture("week-bundle.json")) as {
    disclosures: Record<string, unknown>;
    records: Array<{
      capsule_id: string;
      model_attestation: {
        compute_attestation: {
          agent_input_digest: string;
          agent_output_digest: string;
        };
      };
    }>;
  };
  const selectedCase = buildEvidenceGraph(bundle).reports[0]!.cases[0]!;
  expect(selectedCase.acts.length).toBeGreaterThan(0);
  const closed = { ...bundle, disclosures: { ...bundle.disclosures } };
  for (const act of selectedCase.acts) {
    const record = bundle.records.find(
      (record) => record.capsule_id === act.capsuleId,
    )!;
    const digests = record.model_attestation.compute_attestation;
    delete closed.disclosures[act.capsuleId];
    delete closed.disclosures[digests.agent_input_digest];
    delete closed.disclosures[digests.agent_output_digest];
  }
  const closedCase = buildEvidenceGraph(closed).reports[0]!.cases.find(
    (candidate) =>
      candidate.taskId === selectedCase.taskId &&
      candidate.trial === selectedCase.trial,
  )!;
  const root = document.createElement("main");
  await expect(renderEvidenceGraph(closed, root)).resolves.toBeUndefined();
  root.querySelector<HTMLElement>("[data-report-date]")!.click();
  const button = Array.from(
    root.querySelectorAll<HTMLElement>("[data-case-id]"),
  ).find((candidate) => candidate.dataset.caseId === closedCase.caseId);
  expect(button).toBeDefined();
  button!.click();
  const drawer = Array.from(root.querySelectorAll("h3")).find(
    (heading) => heading.textContent === `Case ${closedCase.caseId}`,
  )?.parentElement;
  expect(drawer).toBeDefined();
  expect(drawer!.querySelectorAll("pre")).toHaveLength(0);
  for (const act of selectedCase.acts) {
    expect(act.agentInput).toBeDefined();
    expect(act.agentOutput).toBeDefined();
    expect(root.textContent).not.toContain(JSON.stringify(act.agentInput));
    expect(root.textContent).not.toContain(JSON.stringify(act.agentOutput));
  }
  for (const act of selectedCase.acts) {
    expect(root.textContent).toContain(act.capsuleId);
    const record = bundle.records.find(
      (record) => record.capsule_id === act.capsuleId,
    )!;
    const digests = record.model_attestation.compute_attestation;
    expect(root.textContent).toContain(digests.agent_input_digest);
    expect(root.textContent).toContain(digests.agent_output_digest);
  }
});

it("fails the banner on a disclosure mismatch and accepts a withheld disclosure", async () => {
  const bundle = (await fixture("week-bundle.json")) as {
    disclosures: Record<string, unknown>;
    records: Array<{
      model_attestation: {
        compute_attestation: { agent_output_digest: string };
      };
    }>;
  };
  const digest =
    bundle.records[0]!.model_attestation.compute_attestation
      .agent_output_digest;
  const tampered = {
    ...bundle,
    disclosures: {
      ...bundle.disclosures,
      [digest]: { agent_output: "tampered" },
    },
  };
  const root = document.createElement("main");
  await renderEvidenceGraph(tampered, root);
  expect(root.querySelector('[data-verify="failed"]')).not.toBeNull();

  const withheld = { ...bundle, disclosures: { ...bundle.disclosures } };
  delete withheld.disclosures[digest];
  const withheldRoot = document.createElement("main");
  await renderEvidenceGraph(withheld, withheldRoot);
  expect(withheldRoot.querySelector('[data-verify="verified"]')).not.toBeNull();
});

it("renders the verification page as the last page with the ten checks and the verify-independently line", async () => {
  const bundle = await fixture("week-bundle.json");
  const root = document.createElement("main");
  await renderEvidenceGraph(bundle, root);

  const page = root.querySelector<HTMLElement>('[data-page="verification"]');
  expect(page).not.toBeNull();
  expect(root.lastElementChild).toBe(page);
  expect(page!.textContent?.toLowerCase()).not.toContain("certificate");
  expect(page!.textContent?.toLowerCase()).not.toContain("proves");
  expect(page!.textContent).toContain(
    "verify independently at verify.agentactioncapsule.org or with the CLI",
  );
  const checks = page!.querySelectorAll("[data-check-status]");
  expect(checks).toHaveLength(10);
  expect(page!.querySelector('[data-stamp-kind="hollow"]')?.textContent).toBe(
    "Countersigned: none",
  );
});

it("renders the hollow countersignature stamp when countersignatures[] is an empty array", async () => {
  const bundle = await fixture("week-bundle-empty-countersignatures.json");
  const root = document.createElement("main");
  await renderEvidenceGraph(bundle, root);
  const stamp = root.querySelector("[data-stamp-kind]");
  expect(stamp?.getAttribute("data-stamp-kind")).toBe("hollow");
  expect(stamp?.textContent).toBe("Countersigned: none");
});

it("renders the producer-key stamp as not independent", async () => {
  const bundle = await fixture("week-bundle-producer-countersigned.json");
  const root = document.createElement("main");
  await renderEvidenceGraph(bundle, root);
  const stamp = root.querySelector('[data-stamp-kind="producer"]');
  expect(stamp?.textContent).toBe(
    "countersigned by the producer — not independent",
  );
});

it("renders the directory-resolved stamp with the directory's name, logo, and recompute count", async () => {
  const bundle = await fixture("week-bundle-directory-countersigned.json");
  const directory = (await fixture("countersigner-directory.json")) as Array<{
    publicKey: string;
    name: string;
    logoDataUrl: string;
    checksRecomputed: number;
  }>;
  const root = document.createElement("main");
  await renderEvidenceGraph(bundle, root, directory);
  const stamp = root.querySelector<HTMLElement>(
    '[data-stamp-kind="directory"]',
  );
  expect(stamp?.textContent).toContain(
    "Countersigned by Example Countersigners Ltd",
  );
  expect(stamp?.textContent).toContain("7 of 10 checks recomputed");
  expect(stamp?.querySelector("img")?.src).toBe(directory[0]!.logoDataUrl);
});

it("chrome rule: a presentation/v1 VERIFIED badge renders in the header only, never near the checks", async () => {
  const bundle = await fixture("week-bundle-presentation.json");
  const root = document.createElement("main");
  await renderEvidenceGraph(bundle, root);

  const header = root.querySelector<HTMLElement>(
    '[data-presentation="header"]',
  );
  expect(header).not.toBeNull();
  expect(root.firstElementChild).toBe(header);
  expect(header!.textContent).toContain("VERIFIED");
  const badgeSrc = header!.querySelector("img")!.src;
  expect(badgeSrc).toContain("data:image/png;base64,");

  const page = root.querySelector<HTMLElement>('[data-page="verification"]')!;
  expect(page.textContent).not.toContain("VERIFIED");
  expect(page.innerHTML).not.toContain(badgeSrc);
  const checksList = page.querySelector("ol")!;
  expect(checksList.textContent).not.toContain("VERIFIED");
  expect(checksList.querySelector("img")).toBeNull();
});

it("renders a report/v1 bundle as generic rows, never the evaluation-graph view", async () => {
  const bundle = await fixture("report-rows-bundle.json");
  const root = document.createElement("main");
  await renderEvidenceGraph(bundle, root);

  const page = root.querySelector<HTMLElement>('[data-page="report-rows"]');
  expect(page).not.toBeNull();
  expect(root.querySelector("[data-report-date]")).toBeNull();

  const rowButtons = page!.querySelectorAll<HTMLElement>("[data-row-id]");
  expect(rowButtons).toHaveLength(3);
  const statusCells = page!.querySelectorAll<HTMLElement>("[data-row-status]");
  expect(Array.from(statusCells).map((cell) => cell.dataset.rowStatus)).toEqual(
    ["established", "not_checked", "not_present"],
  );

  // click through the established row to its cited, disclosed evidence
  const establishedButton = Array.from(rowButtons).find(
    (button) => button.dataset.rowId === "art-50",
  )!;
  establishedButton.click();
  expect(page!.textContent).toContain("act-established");
  expect(page!.textContent).toContain("disclosed evidence for art-50");

  // click through the not_checked row: its citation is undisclosed, so the
  // capsule ID appears but never a fabricated payload -- only "withheld"
  const notCheckedButton = Array.from(rowButtons).find(
    (button) => button.dataset.rowId === "art-14",
  )!;
  notCheckedButton.click();
  expect(page!.textContent).toContain(
    "pack runtime did not evaluate this clause in the demo window",
  );
  expect(page!.textContent).toContain("act-not-checked");
  expect(page!.textContent).toContain("withheld");

  // the not_present row cites nothing -- the honest shape, not hidden
  const notPresentButton = Array.from(rowButtons).find(
    (button) => button.dataset.rowId === "art-26-6",
  )!;
  notPresentButton.click();
  expect(page!.textContent).toContain("no citation");

  const verificationPage = root.querySelector('[data-page="verification"]');
  expect(verificationPage).not.toBeNull();
  expect(root.lastElementChild).toBe(verificationPage);
});

it("renders referenced non-tau2 withheld acts by their committed digests", async () => {
  const bundle = (await fixture("week-bundle.json")) as {
    disclosures: Record<string, unknown>;
    records: Array<{
      capsule_id: string;
      action_id?: string;
      model_attestation: {
        compute_attestation: {
          agent_input_digest: string;
          agent_output_digest: string;
        };
      };
    }>;
  };
  const selected = buildEvidenceGraph(bundle).reports[0]!.cases[0]!.acts[0]!;
  const record = bundle.records.find(
    (candidate) => candidate.capsule_id === selected.capsuleId,
  )!;
  record.action_id = "producer:action:42";
  const digests = record.model_attestation.compute_attestation;
  const closed = { ...bundle, disclosures: { ...bundle.disclosures } };
  delete closed.disclosures[record.capsule_id];
  delete closed.disclosures[digests.agent_input_digest];
  delete closed.disclosures[digests.agent_output_digest];
  const root = document.createElement("main");
  await renderEvidenceGraph(closed, root);
  root.querySelector<HTMLElement>("[data-report-date]")!.click();
  root.querySelector<HTMLElement>("[data-case-id]")!.click();
  expect(root.textContent).toContain(digests.agent_input_digest);
  expect(root.textContent).toContain(digests.agent_output_digest);
});
