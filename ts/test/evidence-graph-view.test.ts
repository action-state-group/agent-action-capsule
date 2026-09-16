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
    expect(drawer!.textContent).toContain(act.capsuleId);
    const record = bundle.records.find(
      (record) => record.capsule_id === act.capsuleId,
    )!;
    const digests = record.model_attestation.compute_attestation;
    expect(drawer!.textContent).toContain(digests.agent_input_digest);
    expect(drawer!.textContent).toContain(digests.agent_output_digest);
  }
});
