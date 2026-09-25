import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  buildEvidenceGraph,
  EvidenceGraphError,
  resolveDisclosure,
} from "../src/evidence-graph.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

const fixture = async (name: string): Promise<unknown> =>
  JSON.parse(
    await readFile(
      fileURLToPath(new URL(`./testdata/${name}`, import.meta.url)),
      "utf8",
    ),
  ) as unknown;

type SealedRecord = {
  capsule_id: string;
  model_attestation: {
    compute_attestation: {
      agent_input_digest: string;
      agent_output_digest?: string;
    };
  };
};
type WeekBundle = {
  root: string;
  records: SealedRecord[];
  disclosures: Record<string, Record<string, unknown>>;
};

describe("buildEvidenceGraph", () => {
  it("builds ordered aggregate, report, case, and act nodes", async () => {
    const graph = await buildEvidenceGraph(await fixture("week-bundle.json"));

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
    // A rating record chained to the first report, disclosed under its own
    // capsule_id and sealed so the verdict hashes to its committed digest.
    const week = (await fixture("week-bundle.json")) as WeekBundle;
    const firstReport = (await buildEvidenceGraph(week)).reports[0]!.capsuleId;
    const { bundle, ids } = await sealEvidenceBundle({
      ...week,
      records: [
        ...week.records,
        {
          capsule_id: "rating",
          action_id: "tau2-airline-human-rating",
          chain: {
            parent_capsule_id: firstReport,
            relation: "io.evaluation.human_rates",
          },
        },
      ],
      disclosures: {
        ...week.disclosures,
        rating: { agent_input: { verdict: "pass" } },
      },
    });
    const graph = await buildEvidenceGraph(bundle);

    expect(graph.reports[0]?.ratings).toEqual([
      {
        capsuleId: ids.rating,
        reportId: firstReport,
        verdict: "pass",
      },
    ]);
  });

  it("rejects an undisclosed aggregate payload", async () => {
    const bundle = (await fixture("week-bundle.json")) as WeekBundle;
    const root = bundle.records.find(
      (record) => record.capsule_id === bundle.root,
    );
    expect(root).toBeDefined();
    if (root === undefined) throw new Error("root fixture record is missing");
    delete bundle.disclosures[root.capsule_id];

    await expect(buildEvidenceGraph(bundle)).rejects.toThrow(
      EvidenceGraphError,
    );
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
    const graph = await buildEvidenceGraph({
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
      (
        await buildEvidenceGraph({
          ...bundle,
          records: bundle.records.map((record) =>
            record === root ? { ...root, references: [] } : record,
          ),
        })
      ).reports,
    ).toEqual([]);
  });

  it("maps disclosed calibration fields without confusing agreement and period window", async () => {
    const { bundle } = await sealEvidenceBundle(
      (await fixture("week-bundle-calibration.json")) as Record<
        string,
        unknown
      >,
    );
    const graph = await buildEvidenceGraph(bundle);
    expect(graph.calibration).toMatchObject({
      confusion: { pass_pass: 2, fail_fail: 1 },
      agreement: "0.75",
      correctedRate: "0.8",
      correctedRateCi: ["0.7", "0.9"],
      periodWindow: { start: "2026-09-14", end: "2026-09-20" },
    });
  });
});

describe("disclosure resolution (H1: a forged disclosure never becomes a payload)", () => {
  const firstAct = async (): Promise<{
    bundle: WeekBundle;
    record: SealedRecord;
    genuine: unknown;
  }> => {
    const bundle = (await fixture("week-bundle.json")) as WeekBundle;
    const act = (await buildEvidenceGraph(bundle)).reports[0]!.cases[0]!
      .acts[0]!;
    const record = bundle.records.find(
      (candidate) => candidate.capsule_id === act.capsuleId,
    )!;
    return { bundle, record, genuine: act.agentOutput };
  };

  it("accepts a genuine disclosure and reports withheld when none is supplied", async () => {
    const { bundle, record, genuine } = await firstAct();
    expect(genuine).toBeDefined();
    await expect(
      resolveDisclosure(record, bundle.disclosures, "agent_output"),
    ).resolves.toEqual({ state: "disclosed", payload: genuine });

    const closed = { ...bundle.disclosures };
    delete closed[record.capsule_id];
    await expect(
      resolveDisclosure(record, closed, "agent_output"),
    ).resolves.toEqual({ state: "withheld" });
  });

  it("ignores an entry keyed by the payload digest: the overlay is keyed by capsule_id", async () => {
    const { bundle, record } = await firstAct();
    const digest =
      record.model_attestation.compute_attestation.agent_output_digest!;
    // keep the genuine agent_input so the act still resolves to its case
    const { agent_output: _omitted, ...withoutOutput } =
      bundle.disclosures[record.capsule_id]!;
    const forged = {
      ...bundle.disclosures,
      [record.capsule_id]: withoutOutput,
      [digest]: { agent_output: "forged" },
    };

    await expect(
      resolveDisclosure(record, forged, "agent_output"),
    ).resolves.toEqual({ state: "withheld" });

    const graph = await buildEvidenceGraph({ ...bundle, disclosures: forged });
    const act = graph.reports[0]!.cases[0]!.acts[0]!;
    expect(act.agentOutput).toBeUndefined();
    expect(act.agentOutputDisclosure).toBe("withheld");
    expect(act.agentOutputDigest).toBe(digest);
    expect(JSON.stringify(graph)).not.toContain("forged");
  });

  it("marks a capsule_id-keyed value that does not hash to the committed digest as disclosure_mismatch", async () => {
    const { bundle, record } = await firstAct();
    const forged = {
      ...bundle.disclosures,
      [record.capsule_id]: {
        ...bundle.disclosures[record.capsule_id],
        agent_output: "forged",
      },
    };

    await expect(
      resolveDisclosure(record, forged, "agent_output"),
    ).resolves.toEqual({ state: "disclosure_mismatch" });

    const graph = await buildEvidenceGraph({ ...bundle, disclosures: forged });
    const act = graph.reports[0]!.cases[0]!.acts[0]!;
    expect(act.agentOutput).toBeUndefined();
    expect(act.agentOutputDisclosure).toBe("disclosure_mismatch");
    expect(act.agentInputDisclosure).toBe("disclosed");
    expect(act.agentOutputDigest).toBe(
      record.model_attestation.compute_attestation.agent_output_digest,
    );
    expect(graph.reports[0]!.withheldActs).toContainEqual(
      expect.objectContaining({ capsuleId: record.capsule_id }),
    );
    expect(JSON.stringify(graph)).not.toContain("forged");
  });

  it("treats a value the integer-only JCS profile cannot digest as a mismatch", async () => {
    const { bundle, record } = await firstAct();
    const forged = {
      ...bundle.disclosures,
      [record.capsule_id]: {
        ...bundle.disclosures[record.capsule_id],
        agent_output: { amount: 0.5 },
      },
    };
    await expect(
      resolveDisclosure(record, forged, "agent_output"),
    ).resolves.toEqual({ state: "disclosure_mismatch" });
  });

  it("does not accept a value for a member the record never committed to", async () => {
    const { bundle, record } = await firstAct();
    const uncommitted: SealedRecord = {
      ...record,
      model_attestation: { compute_attestation: { agent_input_digest: "" } },
    };
    await expect(
      resolveDisclosure(uncommitted, bundle.disclosures, "agent_output"),
    ).resolves.toEqual({ state: "disclosure_mismatch" });
  });

  it("refuses a forged root summary the same way", async () => {
    const bundle = (await fixture("week-bundle.json")) as WeekBundle;
    const forged = {
      ...bundle,
      disclosures: {
        ...bundle.disclosures,
        [bundle.root]: {
          agent_input: {
            spec_version: "evaluation-summary/v1",
            cross_case_aggregation: "forged",
          },
        },
      },
    };
    await expect(buildEvidenceGraph(forged)).rejects.toThrow(
      EvidenceGraphError,
    );
  });
});
