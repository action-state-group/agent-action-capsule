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
});
