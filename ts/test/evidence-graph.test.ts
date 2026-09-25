import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  buildEvidenceGraph,
  calibrationCount,
  EvidenceGraphError,
  recordTimes,
  resolveDisclosure,
  zoneStatement,
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
    expect(graph.calibration).toEqual({
      capsuleId: expect.any(String),
      confusion: { pass_pass: 2, fail_fail: 1, pass_fail: 1 },
      agreement: { k: 3, n: 4 },
      correctedRate: { k: 4, n: 5 },
      periodWindow: { start: "2026-09-14", end: "2026-09-20" },
    });
    // no rate, no float, no decimal string anywhere in the calibration node
    expect(JSON.stringify(graph.calibration)).not.toMatch(/0\.\d/u);
  });

  it("keeps a calibration figure stated only as a rate, as given, without k and n", async () => {
    const source = (await fixture("week-bundle-calibration.json")) as {
      disclosures: Record<string, { agent_input: Record<string, unknown> }>;
    };
    // a producer that states a rate (as a string -- the JCS profile could
    // not have sealed a float) and a k/n object with a non-integer member
    source.disclosures.calibration!.agent_input.agreement = "0.75";
    source.disclosures.calibration!.agent_input.corrected_rate = {
      k: "4",
      n: 5,
    };
    const { bundle } = await sealEvidenceBundle(
      source as unknown as Record<string, unknown>,
    );
    const graph = await buildEvidenceGraph(bundle);
    expect(graph.calibration?.agreement).toEqual({ rate: "0.75" });
    expect(graph.calibration?.correctedRate).toEqual({
      rate: { k: "4", n: 5 },
    });
    expect(calibrationCount({ k: 5, n: 4 })).toEqual({ rate: { k: 5, n: 4 } });
    expect(calibrationCount({ k: 0, n: 0 })).toEqual({ k: 0, n: 0 });
    expect(calibrationCount(undefined)).toBeUndefined();
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

describe("report day (tiles come from date)", () => {
  const withoutDay = (bundle: WeekBundle): WeekBundle => ({
    ...bundle,
    disclosures: Object.fromEntries(
      Object.entries(bundle.disclosures).map(([id, entry]) => {
        const input = entry.agent_input;
        if (
          typeof input !== "object" ||
          input === null ||
          (input as { spec_version?: unknown }).spec_version !==
            "evaluation-report/v1"
        )
          return [id, entry];
        const { day: _day, ...dateOnly } = input as { day?: unknown };
        return [id, { ...entry, agent_input: dateOnly }];
      }),
    ),
  });

  it("keeps a stated day", async () => {
    const graph = await buildEvidenceGraph(await fixture("week-bundle.json"));
    expect(graph.reports.map((report) => report.day)).toEqual([1, 2, 3]);
  });

  it("derives day from date when the producer emits only date (the assemble_week shape)", async () => {
    const week = (await fixture("week-bundle.json")) as WeekBundle;
    const stated = await buildEvidenceGraph(week);
    const dateOnly = withoutDay(week);
    for (const entry of Object.values(dateOnly.disclosures))
      expect(entry.agent_input).not.toHaveProperty("day");
    const { bundle } = await sealEvidenceBundle(dateOnly);
    const graph = await buildEvidenceGraph(bundle);

    expect(graph.reports).toHaveLength(3);
    expect(graph.reports.map((report) => report.date)).toEqual(
      stated.reports.map((report) => report.date),
    );
    expect(graph.reports.map((report) => report.day)).toEqual([1, 2, 3]);
    expect(graph.reports.map((report) => report.cases.length)).toEqual(
      stated.reports.map((report) => report.cases.length),
    );
  });

  it("counts calendar days, not report positions, when dates have gaps", async () => {
    const week = (await fixture("week-bundle.json")) as WeekBundle;
    const shifted: WeekBundle = {
      ...week,
      disclosures: Object.fromEntries(
        Object.entries(withoutDay(week).disclosures).map(([id, entry]) => {
          const input = entry.agent_input as { date?: string };
          return input.date === "2026-09-16"
            ? [id, { ...entry, agent_input: { ...input, date: "2026-09-20" } }]
            : [id, entry];
        }),
      ),
    };
    const { bundle } = await sealEvidenceBundle(shifted);
    const graph = await buildEvidenceGraph(bundle);
    expect(graph.reports.map((report) => [report.date, report.day])).toEqual([
      ["2026-09-14", 1],
      ["2026-09-15", 2],
      ["2026-09-20", 7],
    ]);
  });

  it("builds a report tile from the date-only fixture", async () => {
    const { bundle, ids } = await sealEvidenceBundle(
      (await fixture("report-date-only-bundle.json")) as Record<
        string,
        unknown
      >,
    );
    const graph = await buildEvidenceGraph(bundle);
    expect(graph.reports).toHaveLength(1);
    expect(graph.reports[0]).toMatchObject({
      capsuleId: ids.report,
      date: "2026-09-14",
      day: 1,
    });
    expect(graph.reports[0]!.cases[0]!.acts[0]!.agentOutput).toEqual({
      role: "assistant",
      content: "date-only report act",
    });
  });

  it("keeps a dated report whose date is not a calendar date, without a day", async () => {
    const source = (await fixture("report-date-only-bundle.json")) as {
      disclosures: Record<string, { agent_input: Record<string, unknown> }>;
    };
    source.disclosures.report!.agent_input.date = "week-1";
    const { bundle } = await sealEvidenceBundle(
      source as unknown as Record<string, unknown>,
    );
    const graph = await buildEvidenceGraph(bundle);
    expect(graph.reports).toHaveLength(1);
    expect(graph.reports[0]!.date).toBe("week-1");
    expect(graph.reports[0]!.day).toBeUndefined();
  });
});

describe("report day is the UTC calendar day, wherever the graph is built", () => {
  // The real corpus mixes naive timestamps (no designator) with `Z` ones.
  // Both reports here fall on 2026-08-26 UTC. A reader in America/Los_Angeles
  // that let `new Date(string)` read the naive one in local time, or that took
  // local calendar fields from the `Z` one, would put them on different days.
  const NAIVE = "2026-08-26T20:15:00.123456";
  const ZULU = "2026-08-26T03:00:00Z";

  const mixed = async () =>
    sealEvidenceBundle(
      (await fixture("report-mixed-tz-bundle.json")) as Record<string, unknown>,
    );

  const daysByRun = async (bundle: Record<string, unknown>) => {
    const graph = await buildEvidenceGraph(bundle);
    return Object.fromEntries(
      graph.reports.map((report) => [report.date, report.day]),
    );
  };

  const withTimezone = async <T>(zone: string, run: () => Promise<T>) => {
    const previous = process.env.TZ;
    process.env.TZ = zone;
    try {
      return await run();
    } finally {
      if (previous === undefined) delete process.env.TZ;
      else process.env.TZ = previous;
    }
  };

  it("the fixture would split across days under a local-time reading", async () => {
    await withTimezone("America/Los_Angeles", async () => {
      // Local-time reading of the naive string (the hazard, kept out of src).
      const naiveLocal = new Date(NAIVE);
      const zuluLocal = new Date(ZULU);
      expect(new Date(NAIVE + "Z").getTimezoneOffset()).not.toBe(0);
      expect(naiveLocal.getUTCDate()).toBe(27);
      expect(zuluLocal.getDate()).toBe(25);
    });
  });

  it("tiles a naive and a Z timestamp from the same UTC day on one day", async () => {
    const { bundle, ids } = await mixed();
    const graph = await buildEvidenceGraph(bundle);
    expect(graph.reports).toHaveLength(2);
    expect(graph.reports.map((report) => report.date)).toEqual([ZULU, NAIVE]);
    expect(graph.reports.map((report) => report.day)).toEqual([1, 1]);
    expect(graph.reports.map((report) => report.capsuleId)).toEqual([
      ids["report-zulu"],
      ids["report-naive"],
    ]);
  });

  it("derives the same day under TZ=America/Los_Angeles and TZ=UTC", async () => {
    const { bundle } = await mixed();
    const losAngeles = await withTimezone("America/Los_Angeles", () =>
      daysByRun(bundle),
    );
    const utc = await withTimezone("UTC", () => daysByRun(bundle));
    expect(losAngeles).toEqual({ [ZULU]: 1, [NAIVE]: 1 });
    expect(utc).toEqual(losAngeles);
  });

  it("folds an offset timestamp to UTC and reads a naive one as UTC", async () => {
    const source = (await fixture("report-mixed-tz-bundle.json")) as {
      disclosures: Record<string, { agent_input: Record<string, unknown> }>;
    };
    // 2026-08-26T23:30-05:00 is 2026-08-27T04:30Z: the day after the naive one.
    source.disclosures["report-zulu"]!.agent_input.date =
      "2026-08-26T23:30:00-05:00";
    const { bundle } = await sealEvidenceBundle(
      source as unknown as Record<string, unknown>,
    );
    const graph = await buildEvidenceGraph(bundle);
    expect(graph.reports.map((report) => [report.date, report.day])).toEqual([
      [NAIVE, 1],
      ["2026-08-26T23:30:00-05:00", 2],
    ]);
  });

  it("keeps a bare calendar date as written and on its own day", async () => {
    const source = (await fixture("report-mixed-tz-bundle.json")) as {
      disclosures: Record<string, { agent_input: Record<string, unknown> }>;
    };
    source.disclosures["report-zulu"]!.agent_input.date = "2026-08-25";
    const { bundle } = await sealEvidenceBundle(
      source as unknown as Record<string, unknown>,
    );
    const graph = await buildEvidenceGraph(bundle);
    expect(graph.reports.map((report) => [report.date, report.day])).toEqual([
      ["2026-08-25", 1],
      [NAIVE, 2],
    ]);
  });
});

describe("times as given (backfill rule: nothing gets a zone assigned)", () => {
  it("states whether a written time carries a zone, without parsing it into one", () => {
    expect(zoneStatement("2026-08-26T03:00:00Z")).toBe("stated");
    expect(zoneStatement("2026-08-26T23:30:00-05:00")).toBe("stated");
    expect(zoneStatement("2026-08-26T20:15:00.123456")).toBe("not-stated");
    expect(zoneStatement("2026-08-26T20:15")).toBe("not-stated");
    expect(zoneStatement("2026-08-26")).toBe("date-only");
    expect(zoneStatement("week-1")).toBe("not-stated");
  });

  it("carries a record's seal time, action time and provenance mode verbatim", async () => {
    const { bundle, ids } = await sealEvidenceBundle(
      (await fixture("report-mixed-tz-bundle.json")) as Record<string, unknown>,
    );
    const graph = await buildEvidenceGraph(bundle);
    const acts = Object.fromEntries(
      graph.reports.flatMap((report) =>
        report.cases.flatMap((caseNode) =>
          caseNode.acts.map((act) => [act.capsuleId, act]),
        ),
      ),
    );
    // the backfilled act keeps its source's own (naive) time as the action
    // time; its seal time is the capsule timestamp, a different instant
    expect(acts[ids["act-naive"]!]).toMatchObject({
      provenanceMode: "backfilled",
      actionTime: "2026-08-26T20:14:58.000001",
      sealTime: "2026-09-14T00:00:00Z",
    });
    // the live act states no action time; the seal time is not copied into it
    expect(acts[ids["act-zulu"]!]).toMatchObject({
      sealTime: "2026-09-14T00:00:00Z",
    });
    expect(acts[ids["act-zulu"]!]).not.toHaveProperty("actionTime");
    expect(acts[ids["act-zulu"]!]).not.toHaveProperty("provenanceMode");
    // the report's date is kept exactly as the producer wrote it
    expect(graph.reports.map((report) => report.date)).toEqual([
      "2026-08-26T03:00:00Z",
      "2026-08-26T20:15:00.123456",
    ]);
    expect(
      recordTimes({ capsule_id: "x", timestamp: 5, occurred_at: "as-written" }),
    ).toEqual({ actionTime: "as-written" });
  });
});
