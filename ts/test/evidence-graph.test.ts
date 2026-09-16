import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  buildEvidenceGraph,
  EvidenceGraphError,
} from "../src/evidence-graph.js";

const fixture = async (name: string): Promise<unknown> =>
  JSON.parse(
    await readFile(
      fileURLToPath(new URL(`./testdata/${name}`, import.meta.url)),
      "utf8",
    ),
  ) as unknown;

describe("buildEvidenceGraph", () => {
  it("builds ordered aggregate, report, case, and act nodes", async () => {
    const graph = buildEvidenceGraph(await fixture("week-bundle.json"));

    expect(graph.aggregate.crossCaseAggregation).toBe("rate");
    expect(graph.reports).toHaveLength(3);
    expect(graph.reports.map((report) => report.date)).toEqual([
      "2026-09-14",
      "2026-09-15",
      "2026-09-16",
    ]);
    expect(graph.reports[0]?.outcomes[0]).toMatchObject({
      role: "required",
    });
    for (const report of graph.reports) {
      for (const caseNode of report.cases) {
        expect(caseNode.acts.map((act) => act.turnIdx)).toEqual(
          [...caseNode.acts.map((act) => act.turnIdx)].sort((a, b) => a - b),
        );
      }
    }
  });

  it("reverse-indexes human ratings by report", async () => {
    const graph = buildEvidenceGraph(
      await fixture("week-bundle-with-rating.json"),
    );

    expect(graph.reports[0]?.ratings).toEqual([
      expect.objectContaining({
        reportId: graph.reports[0]?.capsuleId,
        verdict: "pass",
      }),
    ]);
  });

  it("rejects an undisclosed aggregate payload", async () => {
    const bundle = (await fixture("week-bundle.json")) as {
      disclosures: Record<string, unknown>;
      records: Array<{
        capsule_id: string;
        model_attestation: {
          compute_attestation: { agent_input_digest: string };
        };
      }>;
      root: string;
    };
    const root = bundle.records.find(
      (record) => record.capsule_id === bundle.root,
    );
    expect(root).toBeDefined();
    if (root === undefined) throw new Error("root fixture record is missing");
    delete bundle.disclosures[root.capsule_id];

    expect(() => buildEvidenceGraph(bundle)).toThrow(EvidenceGraphError);
  });

  it("uses only reports and acts reached through acted_on references", async () => {
    const bundle = (await fixture("week-bundle.json")) as {
      root: string;
      records: Array<Record<string, unknown>>;
    };
    const root = bundle.records.find(
      (record) => record.capsule_id === bundle.root,
    )!;
    const referenced = (root.references as Array<{ digest: string }>)[0]!
      .digest;
    const firstReport = bundle.records.find(
      (record) => record.capsule_id === referenced,
    )!;
    const unrelated = { ...firstReport, capsule_id: "unrelated-report" };
    const restrictedRoot = {
      ...root,
      references: (root.references as unknown[]).slice(0, 1),
    };
    const graph = buildEvidenceGraph({
      ...bundle,
      records: [
        ...bundle.records.filter((record) => record !== root),
        restrictedRoot,
        unrelated,
      ],
    });

    expect(graph.reports.map((report) => report.capsuleId)).toEqual([
      referenced,
    ]);
    expect(
      graph.reports[0]!.cases.flatMap((caseNode) => caseNode.acts).every(
        (act) =>
          (firstReport.references as Array<{ digest: string }>).some(
            (reference) => reference.digest === act.capsuleId,
          ),
      ),
    ).toBe(true);
    expect(
      buildEvidenceGraph({
        ...bundle,
        records: bundle.records.map((record) =>
          record === root ? { ...root, references: [] } : record,
        ),
      }).reports,
    ).toEqual([]);
  });

  it("maps disclosed calibration fields without confusing agreement and period window", async () => {
    const graph = buildEvidenceGraph(
      await fixture("week-bundle-calibration.json"),
    );
    expect(graph.calibration).toMatchObject({
      confusion: { pass_pass: 2, fail_fail: 1 },
      agreement: 0.75,
      correctedRate: 0.8,
      correctedRateCi: [0.7, 0.9],
      periodWindow: { start: "2026-09-14", end: "2026-09-20" },
    });
  });
});
