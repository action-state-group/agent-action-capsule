import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { jsonDigest } from "../src/json.js";
import {
  buildOutcomeReportModel,
  NOT_STATED,
  parseJudgeProbabilities,
  readOutcomeReportTerms,
  RESOLUTION_RULE,
  verifyJudgePin,
} from "../src/outcome-report.js";
import {
  buildResultRoot,
  type CitedRecord,
  type ResultRoot,
} from "../src/result-root.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

type Obj = Record<string, unknown>;

function fixture(name: string): Obj {
  return JSON.parse(
    readFileSync(resolve(process.cwd(), "test", "testdata", name), "utf8"),
  ) as Obj;
}

/** Result-root's own shape check requires aggregate.buckets to partition every
 * claim exactly once -- any test that mutates a claim's verdict or adds/removes
 * a claim has to rebuild buckets from the claims it ends with, same as a real
 * producer would, rather than leaving the old partition stale. */
function rebuildBuckets(claims: Obj[]): Obj {
  const buckets: Record<string, string[]> = {
    met: [],
    not_met: [],
    not_evaluable: [],
  };
  for (const claim of claims)
    buckets[claim.verdict as string]!.push(claim.id as string);
  return buckets;
}

// test/testdata/outcome-report-bundle.json is not hand-shaped: it is the
// output of evidencebook-skills' judge pipeline (mock judge backend, 50
// trial-0 tau2-bench airline tasks, nine rubric criteria judged), sealed here
// by the test-only sealEvidenceBundle helper; scripts/outcome-report-fixture.mjs
// says how it is regenerated. Every verdict, rationale, case id and
// judge_pin_digest below is read back from that run, not invented.

/** The nine criteria the fixture's claims name, in claim order. */
const FIXTURE_CHECKS = [
  {
    id: "policy_compliance",
    criteria: [
      { id: "confirmed_before_acting" },
      { id: "within_fare_rules" },
      { id: "no_unrequested_actions" },
    ],
  },
  {
    id: "task_resolution",
    criteria: [
      { id: "right_reservation" },
      { id: "right_change" },
      { id: "done_in_full" },
    ],
  },
  {
    id: "grounded_communication",
    criteria: [
      { id: "prices_from_system" },
      { id: "refunds_match_payment_records" },
      { id: "no_invented_policy" },
    ],
  },
];

it("recomputes the AND-of-nine-criteria rollup per conversation, never from a stated verdict", async () => {
  const { bundle } = await sealEvidenceBundle(
    fixture("outcome-report-bundle.json"),
  );
  const result = await buildResultRoot(bundle);
  const model = buildOutcomeReportModel(result, {
    percentages: false,
  });
  expect(model.totalCount).toBe(50);
  // The mock run's own expectation: each of the nine criteria judges roughly uniformly at
  // random under the mock backend, so the chance any one of 50 cases lands
  // "met" on all nine is on the order of (1/3)^9 -- essentially zero. This
  // is not a bug in the rollup; test_rollup.py and test_result_v0.py (the
  // judge side) exercise the resolved/not-resolved paths directly and
  // unconditionally, so correctness here does not depend on this run
  // happening to produce a resolved case.
  expect(model.resolvedCount).toBe(0);
  expect(model.missedCount).toBe(50);
  // every conversation's own verdict is the AND of its 9 criteria claims
  for (const conversation of model.conversations) {
    const verdicts = conversation.criteria.map((c) => c.verdict);
    const expected = verdicts.some((v) => v === "not_met")
      ? "not_met"
      : verdicts.some((v) => v === "not_evaluable")
        ? "not_evaluable"
        : "met";
    expect(conversation.verdict).toBe(expected);
    expect(conversation.criteria).toHaveLength(9);
  }
});

it("a criterion with no claim at all reads as not_applicable, counts as passing, and is never silently dropped", async () => {
  // Evidence Result v0 has no verdict value for not_applicable (agent-action-
  // capsule's own spec/evidence-result-v0.md): evidencebook-skills'
  // result_v0.py excludes such a criterion from claims[] entirely rather than
  // emit an invalid verdict. Simulated here on one conversation: force its
  // other eight claims to met (so resolution depends only on the ninth),
  // then remove the ninth claim entirely -- its real counterpart, before
  // this fix, would have made that criterion silently vanish from
  // conversation.criteria with no trace at all.
  const source = fixture("outcome-report-bundle.json");
  const resultDoc = ((source.disclosures as Obj).result as Obj)
    .agent_input as Obj;
  const claims = resultDoc.claims as Obj[];
  const target = claims.find(
    (claim) => claim.verdict === "met" && (claim.id as string).includes("::"),
  )!;
  const [conversationId, requirementRef] = (target.id as string).split("::");
  const sameConversation = claims.filter((claim) =>
    (claim.id as string).startsWith(`${conversationId}::`),
  );
  expect(sameConversation).toHaveLength(9);
  for (const claim of sameConversation) {
    claim.verdict = "met";
    claim.sufficiency = "SATISFIED";
  }
  resultDoc.claims = claims.filter((claim) => claim !== target);
  (resultDoc.aggregate as Obj).buckets = rebuildBuckets(
    resultDoc.claims as Obj[],
  );
  const coverage = (resultDoc.aggregate as Obj).coverage as Obj;
  coverage.evaluated_population = (coverage.evaluated_population as number) - 1;
  coverage.excluded_not_applicable =
    (coverage.excluded_not_applicable as number) + 1;

  const { bundle } = await sealEvidenceBundle(source);
  const result = await buildResultRoot(bundle);
  const model = buildOutcomeReportModel(result, { percentages: false });
  const conversation = model.conversations.find(
    (c) => c.conversationId === conversationId,
  )!;
  // the criterion is still there, identified, just with no claim and its own state
  expect(conversation.criteria).toHaveLength(9);
  const criterion = conversation.criteria.find(
    (c) => `${c.checkId}.${c.criterionId}` === requirementRef,
  )!;
  expect(criterion.verdict).toBe("not_applicable");
  expect(criterion.claim).toBeUndefined();
  expect(criterion.rationale).toBeUndefined();
  // not_applicable never blocks resolution: the other eight are met, so the
  // conversation resolves met, never not_evaluable or not_met on its account
  expect(conversation.verdict).toBe("met");
  // counted at the bundle level, never silently absorbed into any other count
  expect(model.notApplicableCount).toBeGreaterThanOrEqual(1);
});

it("a criterion with no claim that excluded_not_applicable does not account for is a gap: never passing, never not_applicable", async () => {
  // Result v0 section 3: a missing claim reads as not_applicable only when
  // the exclusions account for it. The same removal as the test above, with
  // the exclusion count left as it was: nothing accounts for the gap.
  const source = fixture("outcome-report-bundle.json");
  const resultDoc = ((source.disclosures as Obj).result as Obj)
    .agent_input as Obj;
  const claims = resultDoc.claims as Obj[];
  const target = claims.find(
    (claim) => claim.verdict === "met" && (claim.id as string).includes("::"),
  )!;
  const [conversationId, requirementRef] = (target.id as string).split("::");
  for (const claim of claims)
    if ((claim.id as string).startsWith(`${conversationId}::`)) {
      claim.verdict = "met";
      claim.sufficiency = "SATISFIED";
    }
  resultDoc.claims = claims.filter((claim) => claim !== target);
  (resultDoc.aggregate as Obj).buckets = rebuildBuckets(
    resultDoc.claims as Obj[],
  );
  const coverage = (resultDoc.aggregate as Obj).coverage as Obj;
  coverage.evaluated_population = (coverage.evaluated_population as number) - 1;

  const { bundle } = await sealEvidenceBundle(source);
  const result = await buildResultRoot(bundle);
  const model = buildOutcomeReportModel(result, { percentages: false });
  const conversation = model.conversations.find(
    (c) => c.conversationId === conversationId,
  )!;
  const criterion = conversation.criteria.find(
    (c) => `${c.checkId}.${c.criterionId}` === requirementRef,
  )!;
  expect(criterion.verdict).toBe("no_claim");
  expect(criterion.claim).toBeUndefined();
  // the other eight are met, and still the conversation does not resolve
  expect(conversation.verdict).toBe("not_evaluable");
  expect(conversation.checkVerdicts.get(requirementRef!.split(".")[0]!)).toBe(
    "not_evaluable",
  );
  expect(model.noClaimCount).toBe(1);
  expect(model.notApplicableCount).toBe(0);
});

it("reads requirements_covered: a covered requirement no claim cites is a criterion, a contract requirement outside the list is not run", async () => {
  const source = fixture("outcome-report-bundle.json");
  const resultDoc = ((source.disclosures as Obj).result as Obj)
    .agent_input as Obj;
  const claims = resultDoc.claims as Obj[];
  const contractRef = claims[0]!.contract_ref as string;
  const conversations = new Set(
    claims.map((claim) => (claim.id as string).split("::")[0]),
  );
  const claimed = [
    ...new Set(claims.map((claim) => claim.requirement_ref as string)),
  ];
  const coverage = (resultDoc.aggregate as Obj).coverage as Obj;
  // One more covered requirement, excluded as not applicable everywhere.
  coverage.excluded_not_applicable =
    (coverage.excluded_not_applicable as number) + conversations.size;
  coverage.requirements_covered = [
    ...claimed,
    "task_resolution.no_follow_up_needed",
  ].map((requirement_ref) => ({
    contract_ref: contractRef,
    requirement_ref,
  }));

  const { bundle } = await sealEvidenceBundle(source);
  const result = await buildResultRoot(bundle);
  expect(result.requirementsCovered).toHaveLength(claimed.length + 1);
  const terms = readOutcomeReportTerms(result);
  expect(
    terms.checks.find((c) => c.id === "task_resolution")!.criteria.at(-1)!.id,
  ).toBe("no_follow_up_needed");

  const at = contractRef.lastIndexOf("@");
  const records = new Map(result.records);
  records.set("contract-rec", {
    capsuleId: "contract-rec",
    agentInput: {
      state: "disclosed",
      payload: {
        id: contractRef.slice(0, at),
        version: contractRef.slice(at + 1),
        requirements: [
          ...claimed.map((id) => ({ id })),
          { id: "task_resolution.no_follow_up_needed" },
          { id: "grounded_communication.cites_sources" },
          { id: "resolved", profile: "outcome", statement: "Resolved." },
        ],
      },
    },
    agentOutput: { state: "absent" },
    cites: [],
  } as unknown as CitedRecord);
  const model = buildOutcomeReportModel({ ...result, records } as ResultRoot, {
    percentages: false,
  });
  // not run: in no conversation, no count
  expect(model.notRun).toEqual(["grounded_communication.cites_sources"]);
  for (const conversation of model.conversations) {
    expect(conversation.criteria).toHaveLength(10);
    expect(
      conversation.criteria.some((c) => c.criterionId === "cites_sources"),
    ).toBe(false);
    expect(
      conversation.criteria.find(
        (c) => c.criterionId === "no_follow_up_needed",
      )!.verdict,
    ).toBe("not_applicable");
  }
  expect(model.notApplicableCount).toBe(conversations.size);
  expect(model.noClaimCount).toBe(0);

  // Without the list nothing is not run, even with the contract cited.
  const unlisted = buildOutcomeReportModel(
    {
      ...result,
      records,
      requirementsCovered: undefined,
    } as unknown as ResultRoot,
    { percentages: false },
  );
  expect(unlisted.notRun).toEqual([]);
});

it("a claim that fails Result-root verification (or is unsupported) never lets its conversation read as resolved", async () => {
  const source = fixture("outcome-report-bundle.json");
  const resultDoc = ((source.disclosures as Obj).result as Obj)
    .agent_input as Obj;
  const claims = resultDoc.claims as Obj[];
  // Target a claim whose conversation is otherwise all-met on its OTHER
  // eight criteria is not guaranteed in real data, so instead: pick any met
  // claim, force it unsupported, and assert its own criterion reads
  // unsupported and its conversation is never "met" with an unsupported
  // criterion in it.
  const target = claims.find(
    (claim) => claim.verdict === "met" && (claim.id as string).includes("::"),
  )!;
  (target.evidence as Obj[])[0]!.digest = "f".repeat(64);
  ((target.presentation as Obj).evidence as Obj[])[0]!.digest = "f".repeat(64);
  const { bundle } = await sealEvidenceBundle(source);
  const result = await buildResultRoot(bundle);
  const model = buildOutcomeReportModel(result, { percentages: false });
  const conversationId = (target.id as string).split("::")[0]!;
  const conversation = model.conversations.find(
    (c) => c.conversationId === conversationId,
  )!;
  const criterion = conversation.criteria.find(
    (c) => `${c.checkId}.${c.criterionId}` === target.requirement_ref,
  )!;
  expect(criterion.verdict).toBe("unsupported");
  expect(conversation.verdict).toBe("not_met");
});

it("held/added are read only from cited human-rating/v1 records, never from the claims' own verdicts -- zero when none are cited", async () => {
  const { bundle } = await sealEvidenceBundle(
    fixture("outcome-report-bundle.json"),
  );
  const result = await buildResultRoot(bundle);
  const model = buildOutcomeReportModel(result, { percentages: false });
  // The mock run only exercised evidencebook-skills' daily judge-and-close
  // skill: no weekly blind expert pass ran, so this bundle cites zero calibration-summary/v1 records. Absent is
  // never pass: held/added read 0, not a fabricated figure.
  expect(model.calibration).toHaveLength(0);
  expect(model.heldCount).toBe(0);
  expect(model.addedCount).toBe(0);
});

type CalibrationRecords = { summary: Obj; ratings: Obj[] };

/**
 * outcome-report-bundle.json plus one `calibration` claim citing the
 * schema-valid calibration-summary/v1 record and human-rating/v1 records in
 * test/testdata/calibration-records.json (after `edit`), each disclosed. The
 * ratings cite three no_invented_policy reports by digest: task-13 (judge
 * met, rater met), task-11 (judge not_met, rater met) and task-17 (judge met,
 * rater not_met), so agreement is 1 of 3, one held and one added.
 * `extraSummary` makes the claim cite a second summary record too;
 * `citeTwice` makes it cite every record twice. `secondClaimSummary` adds a
 * second `calibration` claim, after the first, citing that summary and the
 * same ratings.
 */
async function calibrationModel(
  edit?: (records: CalibrationRecords) => void,
  extraSummary?: Obj,
  citeTwice = false,
  secondClaimSummary?: Obj,
): Promise<ReturnType<typeof buildOutcomeReportModel>> {
  const source = fixture("outcome-report-bundle.json");
  const records = fixture("calibration-records.json") as CalibrationRecords;
  edit?.(records);
  const resultDoc = ((source.disclosures as Obj).result as Obj)
    .agent_input as Obj;
  const claims = resultDoc.claims as Obj[];
  const cited: [string, Obj][] = [
    ["cal-summary-2026-W39", records.summary],
    ...(extraSummary === undefined
      ? []
      : [["cal-summary-extra", extraSummary] as [string, Obj]]),
    ...records.ratings.map((rating, i): [string, Obj] => [
      `cal-rating-2026-W39-${i + 1}`,
      rating,
    ]),
  ];
  const ratingAliases = cited.filter(([alias]) =>
    alias.startsWith("cal-rating-"),
  );
  const secondCited: [string, Obj][] =
    secondClaimSummary === undefined
      ? []
      : [["cal-summary-second", secondClaimSummary], ...ratingAliases];
  for (const [alias, payload] of [
    ...cited,
    ...secondCited.slice(0, secondClaimSummary === undefined ? 0 : 1),
  ]) {
    (source.records as Obj[]).push({ capsule_id: alias });
    (source.disclosures as Obj)[alias] = { agent_input: payload };
  }
  const evidence = [...cited, ...(citeTwice ? cited : [])].map(([alias]) => ({
    digest_alg: "SHA-256",
    digest: alias,
  }));
  const calClaim = {
    id: "cal::2026-W39",
    type: "calibration",
    contract_ref: (claims[0] as Obj).contract_ref,
    requirement_ref: "human-spot-check",
    tier: "recomputed",
    grade: "self-attested",
    sufficiency: "SATISFIED",
    verdict: "not_met",
    evidence,
    proofs: [],
    presentation: { kind: "disclosure", status: "SATISFIED", evidence },
  };
  const secondEvidence = secondCited.map(([alias]) => ({
    digest_alg: "SHA-256",
    digest: alias,
  }));
  const allClaims = [
    ...claims,
    calClaim,
    ...(secondClaimSummary === undefined
      ? []
      : [
          {
            ...calClaim,
            id: "cal::2026-W39-second",
            evidence: secondEvidence,
            presentation: {
              ...calClaim.presentation,
              evidence: secondEvidence,
            },
          },
        ]),
  ];
  (source.disclosures as Obj).result = {
    agent_input: {
      ...resultDoc,
      claims: allClaims,
      aggregate: {
        ...(resultDoc.aggregate as Obj),
        buckets: rebuildBuckets(allClaims),
      },
    },
  };
  const { bundle } = await sealEvidenceBundle(source);
  const result = await buildResultRoot(bundle);
  return buildOutcomeReportModel(result, { percentages: false });
}

const CLAUSE = "grounded_communication.no_invented_policy";

it("reads the cited calibration-summary/v1 record and its human ratings, and the recomputed agreement matches the stated one", async () => {
  const model = await calibrationModel();
  expect(model.calibration).toHaveLength(1);
  const reading = model.calibration[0]!;
  expect(reading.state).toBe("read");
  expect(reading.summary?.recordId).toBe("cal-example-org-2026-W39");
  expect(reading.summary?.judgePin.digest).toBe(
    "90b5b2951e3aaf6f864f3dd6d8e13ccef113569ff0c14000f47bce9249c6a935",
  );
  expect(reading.clauses).toEqual([
    {
      clauseRef: CLAUSE,
      agreement: { k: 1, n: 3 },
      drift: { k: 0, n: 3 },
      recomputedAgreement: { k: 1, n: 3 },
      agreementCheck: "matches",
    },
  ]);
  expect(reading.ratingsNotMatching).toBe(0);
  expect(reading.ratingsOutsideClauses).toBe(0);
  expect(
    reading.ratings.map((entry) => [
      entry.rating.label,
      entry.judged?.verdict,
      entry.judged?.requirementRef,
      entry.agrees,
    ]),
  ).toEqual([
    ["met", "met", CLAUSE, true],
    ["met", "not_met", CLAUSE, false],
    ["not_met", "met", CLAUSE, false],
  ]);
  expect(reading.ratings[0]!.judged?.claimId).toBe(
    `tau2:airline:task-13:trial-0::${CLAUSE}`,
  );
  expect(model.heldCount).toBe(1);
  expect(model.addedCount).toBe(1);
  // No reader computes or stores a rate: every figure is an integer k of n.
  expect(JSON.stringify(model.calibration)).not.toMatch(/\d\.\d|%/u);
});

it.each(["not_evaluable", "out_of_scope", "unsure"])(
  "leaves a rating labelled %s out of k and n, and out of held, so it cannot cause a mismatch",
  async (label) => {
    const model = await calibrationModel((records) => {
      // task-17: judge met. With the label counted, 1 of 3 would contradict
      // the stated 1 of 2.
      records.ratings[2]!.label = label;
      (records.summary.clauses as Obj[])[0]!.agreement = { k: 1, n: 2 };
    });
    const reading = model.calibration[0]!;
    expect(reading.ratings[2]!.judged?.verdict).toBe("met");
    expect(reading.ratings[2]!.agrees).toBeUndefined();
    expect(reading.clauses[0]!.recomputedAgreement).toEqual({ k: 1, n: 2 });
    expect(reading.clauses[0]!.agreementCheck).toBe("matches");
    expect(model.heldCount).toBe(0);
    expect(model.addedCount).toBe(1);
  },
);

it("counts a rating cited by two calibration claims once in held and added", async () => {
  const records = fixture("calibration-records.json") as CalibrationRecords;
  const model = await calibrationModel(undefined, undefined, false, {
    ...records.summary,
    record_id: "cal-example-org-2026-W39-second",
  });
  expect(model.calibration).toHaveLength(2);
  expect(model.calibration.every((r) => r.ratings.length === 3)).toBe(true);
  expect(model.heldCount).toBe(1);
  expect(model.addedCount).toBe(1);
});

it("sorts a reading whose summary does not match after the schema-valid ones", async () => {
  const records = fixture("calibration-records.json") as CalibrationRecords;
  const model = await calibrationModel(undefined, undefined, false, {
    ...records.summary,
    record_id: "cal-example-org-2026-W39-second",
    corrected_rate: { k: 1, n: 3 },
  });
  expect(model.calibration.map((r) => [r.claim.id, r.state])).toEqual([
    ["cal::2026-W39", "read"],
    ["cal::2026-W39-second", "not_matching"],
  ]);
});

it("reads a claim that cites two calibration summaries as ambiguous, and counts nothing from it", async () => {
  const records = fixture("calibration-records.json") as CalibrationRecords;
  const model = await calibrationModel(undefined, {
    ...records.summary,
    record_id: "cal-example-org-2026-W39-other",
  });
  expect(model.calibration).toHaveLength(1);
  const reading = model.calibration[0]!;
  expect(reading.state).toBe("ambiguous");
  expect(reading.summary).toBeUndefined();
  expect(reading.clauses).toEqual([]);
  expect(model.heldCount).toBe(0);
  expect(model.addedCount).toBe(0);
});

it("flags a stated agreement the cited ratings contradict, and keeps the stated count; a clause with no bound rating is not recomputable", async () => {
  const model = await calibrationModel((records) => {
    const clauses = records.summary.clauses as Obj[];
    // Claim perfect agreement no matter what the ratings show, and state a
    // second clause no cited rating is bound to.
    clauses[0]!.agreement = { k: 3, n: 3 };
    clauses.push({
      clause_ref: "task_resolution.done_in_full",
      agreement: { k: 2, n: 2 },
      drift: { k: 0, n: 2 },
    });
  });
  const reading = model.calibration[0]!;
  expect(reading.state).toBe("read");
  expect(reading.clauses).toEqual([
    {
      clauseRef: CLAUSE,
      agreement: { k: 3, n: 3 },
      drift: { k: 0, n: 3 },
      recomputedAgreement: { k: 1, n: 3 },
      agreementCheck: "mismatch",
    },
    {
      clauseRef: "task_resolution.done_in_full",
      agreement: { k: 2, n: 2 },
      drift: { k: 0, n: 2 },
      agreementCheck: "not_recomputable",
    },
  ]);
});

it.each([
  ["3 ratings against a stated 40 of 50", { k: 40, n: 50 }, "not_recomputable"],
  [
    "3 ratings against a stated 1 of 2 (recomputed n above stated n)",
    { k: 1, n: 2 },
    "mismatch",
  ],
  [
    "3 ratings against a stated 0 of 50 (more agreeing than stated k)",
    { k: 0, n: 50 },
    "mismatch",
  ],
] as const)(
  "reads the cited ratings as a sample: %s is %s",
  async (_name, agreement, check) => {
    const reading = (
      await calibrationModel((records) => {
        (records.summary.clauses as Obj[])[0]!.agreement = { ...agreement };
      })
    ).calibration[0]!;
    expect(reading.clauses[0]!.recomputedAgreement).toEqual({ k: 1, n: 3 });
    expect(reading.clauses[0]!.agreementCheck).toBe(check);
  },
);

it("reads a claim that cites only the summary as not recomputable, never a match or a mismatch", async () => {
  const reading = (
    await calibrationModel((records) => {
      records.ratings = [];
    })
  ).calibration[0]!;
  expect(reading.state).toBe("read");
  expect(reading.ratings).toEqual([]);
  expect(reading.clauses).toEqual([
    {
      clauseRef: CLAUSE,
      agreement: { k: 1, n: 3 },
      drift: { k: 0, n: 3 },
      agreementCheck: "not_recomputable",
    },
  ]);
});

it("reads a summary and ratings each cited twice once: not ambiguous, and each rating counted once", async () => {
  const model = await calibrationModel(undefined, undefined, true);
  const reading = model.calibration[0]!;
  expect(reading.state).toBe("read");
  expect(reading.ratings).toHaveLength(3);
  expect(reading.clauses[0]!.recomputedAgreement).toEqual({ k: 1, n: 3 });
  expect(reading.clauses[0]!.agreementCheck).toBe("matches");
  expect(model.heldCount).toBe(1);
  expect(model.addedCount).toBe(1);
});

it("counts a cited rating bound to no clause of the summary, never dropping it silently", async () => {
  const reading = (
    await calibrationModel((records) => {
      // task-0's policy_compliance.confirmed_before_acting report: a judged
      // claim, but not one the summary has a clause for.
      (records.ratings[2]!.case as Obj).digest =
        "7af7c240b071319cc429a62b25e30ece1990c89704f2783a22f59917f8c62b19";
    })
  ).calibration[0]!;
  expect(reading.ratings).toHaveLength(3);
  expect(reading.ratings[2]!.judged?.requirementRef).toBe(
    "policy_compliance.confirmed_before_acting",
  );
  expect(reading.ratingsOutsideClauses).toBe(1);
  expect(reading.clauses[0]!.recomputedAgreement).toEqual({ k: 1, n: 2 });
  expect(reading.clauses[0]!.agreementCheck).toBe("not_recomputable");
});

it.each([
  [
    "a cited rating that does not match human-rating/v1",
    (records: CalibrationRecords) => {
      records.ratings[1]!.blind = false;
    },
    2,
    1,
  ],
  [
    "a cited rating whose case no requirement claim cites",
    (records: CalibrationRecords) => {
      (records.ratings[1]!.case as Obj).digest = "e".repeat(64);
    },
    3,
    0,
  ],
])(
  "reads the agreement as not recomputable with %s, never as a match or a mismatch",
  async (_name, edit, ratings, notMatching) => {
    const reading = (await calibrationModel(edit)).calibration[0]!;
    expect(reading.state).toBe("read");
    expect(reading.ratings).toHaveLength(ratings);
    expect(reading.ratingsNotMatching).toBe(notMatching);
    expect(reading.clauses).toEqual([
      {
        clauseRef: CLAUSE,
        agreement: { k: 1, n: 3 },
        drift: { k: 0, n: 3 },
        agreementCheck: "not_recomputable",
      },
    ]);
  },
);

it.each([
  [
    "a stored rate member",
    (records: CalibrationRecords) => {
      records.summary.corrected_rate = { k: 4, n: 5 };
    },
  ],
  [
    "agreement k greater than n",
    (records: CalibrationRecords) => {
      (records.summary.clauses as Obj[])[0]!.agreement = { k: 4, n: 3 };
    },
  ],
  [
    "drift k greater than n",
    (records: CalibrationRecords) => {
      (records.summary.clauses as Obj[])[0]!.drift = { k: 4, n: 3 };
    },
  ],
  [
    "the retired week and sample members",
    (records: CalibrationRecords) => {
      records.summary.week = "2026-W39";
      records.summary.sample = [];
    },
  ],
])(
  "reads a cited calibration-summary/v1 record with %s as not matching, and counts nothing from it",
  async (_name, edit) => {
    const model = await calibrationModel(edit);
    const reading = model.calibration[0]!;
    expect(reading.state).toBe("not_matching");
    expect(reading.summary).toBeUndefined();
    expect(reading.clauses).toEqual([]);
    expect(model.heldCount).toBe(0);
    expect(model.addedCount).toBe(0);
  },
);

it("attributes a not_evaluable-only miss to the actual not_evaluable criterion, never to an arbitrary met one", async () => {
  const source = fixture("outcome-report-bundle.json");
  const resultDoc = ((source.disclosures as Obj).result as Obj)
    .agent_input as Obj;
  const claims = resultDoc.claims as Obj[];
  // Pick a conversation and force every criterion to met except one that is
  // NOT the first in check/criterion declaration order -- the case the bug
  // mishandled by falling back to criteria[0] (which would be met here).
  const targetRef = "grounded_communication.no_invented_policy";
  const conversationId = (
    claims.find((c) => (c.id as string).endsWith(`::${targetRef}`))!
      .id as string
  ).split("::")[0]!;
  for (const claim of claims) {
    if (!(claim.id as string).startsWith(`${conversationId}::`)) continue;
    if ((claim.id as string).endsWith(`::${targetRef}`)) {
      claim.verdict = "not_evaluable";
      claim.sufficiency = "GAP";
    } else {
      claim.verdict = "met";
      claim.sufficiency = "SATISFIED";
    }
  }
  // Rebuild the buckets from every claim's own (possibly just-mutated)
  // verdict, so conversations untouched above keep their original bucket
  // membership instead of being folded into "met" by mistake.
  (resultDoc.aggregate as Obj).buckets = rebuildBuckets(claims);
  const { bundle } = await sealEvidenceBundle(source);
  const result = await buildResultRoot(bundle);
  const model = buildOutcomeReportModel(result, { percentages: false });
  const conversation = model.conversations.find(
    (c) => c.conversationId === conversationId,
  )!;
  expect(conversation.verdict).toBe("not_evaluable");
  const group = model.missedReasons.find((g) =>
    g.conversations.some((c) => c.conversationId === conversationId),
  )!;
  expect(group).toBeDefined();
  expect(group.key).toBe(targetRef);
});

it("groups missed conversations by criterion when no claim carries a reason_code (the real pipeline's own shape today)", async () => {
  const { bundle } = await sealEvidenceBundle(
    fixture("outcome-report-bundle.json"),
  );
  const result = await buildResultRoot(bundle);
  const model = buildOutcomeReportModel(result, { percentages: false });
  expect(model.missedReasons.length).toBeGreaterThan(0);
  expect(model.missedReasons.every((g) => !g.structured)).toBe(true);
  for (const group of model.missedReasons)
    expect(group.key).toMatch(/^[a-z_]+\.[a-z_]+$/u);
  const total = model.missedReasons.reduce(
    (sum, g) => sum + g.conversations.length,
    0,
  );
  expect(total).toBe(model.missedCount);
});

it("never groups by a raw reason_code: with no sealed label for it, a miss is named by its failing criterion", async () => {
  const source = fixture("outcome-report-bundle.json");
  const resultDoc = ((source.disclosures as Obj).result as Obj)
    .agent_input as Obj;
  const claims = resultDoc.claims as Obj[];
  const coded = claims.find((c) => c.verdict === "not_met")!;
  const codedDigest = (coded.evidence as Obj[])[0]!.digest as string;
  ((source.disclosures as Obj)[codedDigest] as Obj).agent_input = {
    ...(((source.disclosures as Obj)[codedDigest] as Obj).agent_input as Obj),
    reason_code: "broke_fare_rules",
  };

  const { bundle } = await sealEvidenceBundle(source);
  const result = await buildResultRoot(bundle);
  const model = buildOutcomeReportModel(result, { percentages: false });

  expect(model.terms.reasonCodes).toEqual({});
  expect(model.missedReasons.some((g) => g.structured)).toBe(false);
  expect(model.missedReasons.some((g) => g.key === "broke_fare_rules")).toBe(
    false,
  );
  expect(
    model.missedReasons.some((g) => g.label.includes("broke_fare_rules")),
  ).toBe(false);
});

it("reads its terms from the bundle: pack and version from the claims' contract_ref, checks from their requirement_refs, the rest not stated", async () => {
  const { bundle } = await sealEvidenceBundle(
    fixture("outcome-report-bundle.json"),
  );
  const result = await buildResultRoot(bundle);
  const terms = readOutcomeReportTerms(result);
  expect(terms.pack).toEqual({
    id: "tau2-airline-outcomes/v1",
    version: "1",
    outcomeStatement: NOT_STATED,
    locked: NOT_STATED,
    agreement: NOT_STATED,
    resolutionRule: RESOLUTION_RULE,
  });
  expect(
    terms.checks.map((c) => [c.id, c.criteria.map((cr) => cr.id)]),
  ).toEqual(FIXTURE_CHECKS.map((c) => [c.id, c.criteria.map((cr) => cr.id)]));
  expect(terms.checks[0]!.question).toBe("Policy compliance");
  expect(terms.checks[0]!.criteria[0]!.label).toBe("Confirmed before acting");
});

it("reads the outcome statement from a cited Evidence Contract record for the claims' contract, and nothing from an uncited one", async () => {
  const { bundle } = await sealEvidenceBundle(
    fixture("outcome-report-bundle.json"),
  );
  const result = await buildResultRoot(bundle);
  const contract = {
    id: "tau2-airline-outcomes/v1",
    version: "1",
    requirements: [
      {
        id: "resolved",
        profile: "outcome",
        statement: "The request is resolved.",
      },
    ],
  };
  const records = new Map(result.records);
  records.set("contract-rec", {
    capsuleId: "contract-rec",
    agentInput: { state: "disclosed", payload: contract },
    agentOutput: { state: "absent" },
    cites: [],
  } as unknown as CitedRecord);
  const withContract = { ...result, records } as ResultRoot;
  expect(readOutcomeReportTerms(withContract).pack.outcomeStatement).toBe(
    "The request is resolved.",
  );
  records.set("contract-rec", {
    capsuleId: "contract-rec",
    agentInput: { state: "disclosed", payload: { ...contract, version: "2" } },
    agentOutput: { state: "absent" },
    cites: [],
  } as unknown as CitedRecord);
  expect(
    readOutcomeReportTerms({ ...result, records } as ResultRoot).pack
      .outcomeStatement,
  ).toBe(NOT_STATED);
});

it("reads criterion tier from the claims (the compiled contract), never from a hard-coded table -- unknown when nothing cites a criterion", async () => {
  const { bundle } = await sealEvidenceBundle(
    fixture("outcome-report-bundle.json"),
  );
  const result = await buildResultRoot(bundle);
  const model = buildOutcomeReportModel(result, { percentages: false });
  // Every one of rubric v3.2's nine clauses is tier:judged in the real
  // compiled contract this fixture's claims were built from.
  for (const [, tier] of model.criterionTiers) expect(tier).toBe("judged");
  expect(
    model.criterionTiers.get("policy_compliance.confirmed_before_acting"),
  ).toBe("judged");
});

it("reads a criterion as 'mixed' when its claims disagree on tier, never silently picking one", async () => {
  const source = fixture("outcome-report-bundle.json");
  const claims = (
    ((source.disclosures as Obj).result as Obj).agent_input as Obj
  ).claims as Obj[];
  const targetRef = "grounded_communication.prices_from_system";
  let flipped = false;
  for (const claim of claims) {
    if ((claim.requirement_ref as string) === targetRef && !flipped) {
      claim.tier = "recomputed";
      flipped = true;
    }
  }
  expect(flipped).toBe(true);
  const { bundle } = await sealEvidenceBundle(source);
  const result = await buildResultRoot(bundle);
  const model = buildOutcomeReportModel(result, { percentages: false });
  expect(model.criterionTiers.get(targetRef)).toBe("mixed");
});

// ---------------------------------------------------------------------------
// Book-form records (capsulectl disclose on a jsonl profile): a cited
// record's own agent_input is the evidence-book header; the report is the
// carried capsule's agent_input original (CitedRecord.carriedInput). Before
// this, the card read the header as if it were the report and every report
// field -- period, contract, judge pin, rationale -- came out "unknown" /
// "not stated" on every real bundle.
// ---------------------------------------------------------------------------

/**
 * `checked` (default true): the carried capsule checks out, so the record
 * carries `carriedCapsuleId`; false models a report capsule that is missing
 * or fails its digest (resolveCarriedInput still says "withheld").
 */
function asBookForm(
  result: ResultRoot,
  carried: (record: CitedRecord) => CitedRecord["carriedInput"],
  checked = true,
): ResultRoot {
  const records = new Map<string, CitedRecord>();
  for (const [id, original] of result.records) {
    const carriedInput = carried(original);
    // An unchecked carried capsule states no times either (result-root.ts).
    const { stated, ...unstated } = original;
    const record = checked ? original : unstated;
    void stated;
    records.set(id, {
      ...record,
      agentInput: {
        state: "disclosed",
        payload: { record_type: "published_capsule", subject_ref: id },
      },
      ...(carriedInput === undefined ? {} : { carriedInput }),
      ...(checked ? { carriedCapsuleId: id } : {}),
    });
  }
  return { ...result, records };
}

it("reads period, contract and judge pin from a book-form record's carried report, never from the book header", async () => {
  const { bundle } = await sealEvidenceBundle(
    fixture("outcome-report-bundle.json"),
  );
  const result = asBookForm(
    await buildResultRoot(bundle),
    (record) => record.agentInput,
  );
  const model = buildOutcomeReportModel(result, { percentages: false });
  expect(model.days.map((day) => day.date)).toEqual(["2026-09-23"]);
  expect(model.runInfo.judgePinDigest).toBe(
    "d1eb15a561a0eb31fb4bb6be88ce239aa903a77e79985291429065e83c305b96",
  );
  expect(model.runInfo.pinned).toBe(true);
  expect(
    model.conversations[0]!.criteria.find((c) => c.claim !== undefined)
      ?.rationale,
  ).toContain("jev choice");
});

it("a book-form record whose carried report is withheld yields no report fields -- the header is never read as the report", async () => {
  const { bundle } = await sealEvidenceBundle(
    fixture("outcome-report-bundle.json"),
  );
  const result = asBookForm(await buildResultRoot(bundle), () => ({
    state: "withheld",
  }));
  const model = buildOutcomeReportModel(result, { percentages: false });
  // The period falls back to the report capsule's own stated timestamp (a
  // checked capsule field), never to the book header.
  const stated = [...result.records.values()]
    .map((r) => r.stated?.timestamp?.slice(0, 10))
    .filter((d): d is string => d !== undefined);
  expect(model.days.map((day) => day.date)).toEqual(
    [...new Set(stated)].sort().slice(0, 1),
  );
  expect(model.days.map((day) => day.date)).not.toContain("unknown");
  expect(model.runInfo.judgePinDigest).toBeUndefined();
  // withheld, never "not stated": the view says the reports are withheld
  expect(model.runInfo.reportsWithheld).toBeGreaterThan(0);
  expect(model.runInfo.reportsWithheld).toBe(model.runInfo.reportsCited);
  // the contract is still the Result's own: every claim names it
  expect(model.runInfo.contract).toBe("tau2-airline-outcomes/v1@1");
});

it("a book-form report whose carried capsule is missing or fails its checks is invalid, never withheld: counted apart, no judged-day fallback", async () => {
  const { bundle } = await sealEvidenceBundle(
    fixture("outcome-report-bundle.json"),
  );
  // resolveCarriedInput says "withheld" for absent or corrupted capsule
  // bytes; with no checked carried capsule (no carriedCapsuleId) that is a
  // broken report, not a withheld one.
  const result = asBookForm(
    await buildResultRoot(bundle),
    () => ({ state: "withheld" }),
    false,
  );
  const model = buildOutcomeReportModel(result, { percentages: false });
  expect(model.runInfo.reportsWithheld).toBeUndefined();
  expect(model.runInfo.reportsInvalid).toBeGreaterThan(0);
  expect(model.runInfo.reportsInvalid).toBe(model.runInfo.reportsCited);
  expect(
    new Set(
      model.conversations.flatMap((c) =>
        c.criteria.flatMap((cr) =>
          cr.claim === undefined ? [] : [cr.reportState],
        ),
      ),
    ),
  ).toEqual(new Set(["invalid"]));
  expect(model.days.map((day) => day.date)).toEqual(["unknown"]);
  expect(model.conversations.every((c) => c.caseFrom === undefined)).toBe(true);
});

it("draws the contract from the claims' contract_ref (the versioned ref), not the reports' unversioned contract id", async () => {
  const source = fixture("outcome-report-bundle.json");
  for (const claim of (
    ((source.disclosures as Obj).result as Obj).agent_input as Obj
  ).claims as Obj[])
    claim.contract_ref = "airline-support-outcomes@1.4.0";
  const { bundle } = await sealEvidenceBundle(source);
  const model = buildOutcomeReportModel(await buildResultRoot(bundle), {
    percentages: false,
  });
  expect(model.runInfo.contract).toBe("airline-support-outcomes@1.4.0");
});

describe("judge pin components", () => {
  const components = {
    model_id: "jev-1.13.0",
    prompt_digest: "aa".repeat(32),
    axes_digest: "bb".repeat(32),
    sampling_params: { temperature: 0 },
  };
  /** capsule-cli's judgePinDigest preimage: model_version is null when absent. */
  const preimage = { ...components, model_version: null };

  async function withPin(pinDigest: string): Promise<ResultRoot> {
    const source = fixture("outcome-report-bundle.json");
    for (const [key, entry] of Object.entries(source.disclosures as Obj)) {
      if (key === "result") continue;
      const report = (entry as Obj).agent_input as Obj;
      report.judge_pin = components;
      report.judge_pin_digest = pinDigest;
    }
    const { bundle } = await sealEvidenceBundle(source);
    return buildResultRoot(bundle);
  }

  it("recomputes the sealed judge pin digest from the components every report carries", async () => {
    const digest = await jsonDigest(preimage);
    const model = buildOutcomeReportModel(await withPin(digest), {
      percentages: false,
    });
    expect(model.runInfo.judgePin).toMatchObject({
      modelId: "jev-1.13.0",
      promptDigest: "aa".repeat(32),
      axesDigest: "bb".repeat(32),
    });
    const checked = await verifyJudgePin(model.runInfo);
    expect(checked.judgePinRecomputes).toBe(true);
  });

  it("flags components that do not recompute to the sealed digest", async () => {
    const model = buildOutcomeReportModel(await withPin("cd".repeat(32)), {
      percentages: false,
    });
    const checked = await verifyJudgePin(model.runInfo);
    expect(checked.judgePinRecomputes).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// transcript: drawn only when a cited record carries one that commits to the
// same input as the case capsule the judge's reports name
// ---------------------------------------------------------------------------

describe("conversation transcript", () => {
  const CASE = "tau2:airline:task-7:trial-0";
  const SOURCE = "a".repeat(64);
  const DIGEST = "d".repeat(64);
  const transcriptPayload = {
    case: { benchmark: "tau2", domain: "airline", task_id: "7", trial: 0 },
    agent_interaction: {
      messages: [
        { role: "user", content: "cancel my trip" },
        {
          role: "assistant",
          content: "looking it up",
          tool_calls: [
            { name: "get_user_details", arguments: { user_id: "u1" } },
          ],
        },
        { role: "tool", content: '{"user_id":"u1"}' },
      ],
    },
  };
  function synthetic(options: {
    caseDigest?: string;
    transcriptDigest?: string;
    citeCase?: boolean;
    citeTranscript?: boolean;
    caseId?: string;
    /** The conversation id the claims use (default the model-less CASE). */
    conversationId?: string;
    /** `case.agent_model` in the sealed transcript payload. */
    agentModel?: string;
    /** Withhold every report (no transcripts attached): only the report capsules' stated timestamps remain. */
    withholdReports?: boolean;
    /** Replace every report's resolved input (a mismatch, a non-object payload, a report naming no case). */
    reportInput?: unknown;
    /** Replace only the first report's resolved input. */
    firstReportInput?: unknown;
    /** The case capsule's own `action_id` (default `urn:<conversation id>`, the case model's); null states none. */
    caseActionId?: string | null;
  }): ResultRoot {
    const conversationId = options.conversationId ?? CASE;
    const payload =
      options.agentModel === undefined
        ? transcriptPayload
        : {
            ...transcriptPayload,
            case: {
              ...transcriptPayload.case,
              agent_model: options.agentModel,
            },
          };
    const reportInput = {
      state: "disclosed",
      payload: {
        verdict: "met",
        source_capsule_id: SOURCE,
        period: "day:2026-09-23",
        rationale:
          "jev choice: met (probabilities={'met': 0.9, 'not_met': 0.1}, confidence=0.8).",
      },
    };
    const records = new Map<string, unknown>();
    const claims = [];
    for (const check of FIXTURE_CHECKS)
      for (const criterion of check.criteria) {
        const ref = `${check.id}.${criterion.id}`;
        const report = `r-${ref}`;
        records.set(report, {
          capsuleId: report,
          ...(options.firstReportInput !== undefined && records.size === 0
            ? {
                agentInput: options.firstReportInput,
                stated: { timestamp: "2026-09-23T23:59:59Z" },
              }
            : options.withholdReports === true
              ? {
                  agentInput: { state: "withheld" },
                  stated: { timestamp: "2026-09-23T23:59:59Z" },
                }
              : options.reportInput !== undefined
                ? {
                    agentInput: options.reportInput,
                    stated: { timestamp: "2026-09-23T23:59:59Z" },
                  }
                : { agentInput: reportInput }),
          agentOutput: { state: "absent" },
          cites: [],
        });
        const evidence = [{ digest: report, resolved: true }];
        if (options.citeCase !== false)
          evidence.push({ digest: "case-rec", resolved: true });
        if (options.citeTranscript !== false)
          evidence.push({ digest: "tx-rec", resolved: true });
        claims.push({
          id: `${conversationId}::${ref}`,
          type: "requirement",
          recognized: true,
          contractRef: "airline-support-outcomes@1.4.0",
          requirementRef: ref,
          tier: "judged",
          verdict: "met",
          support: "supported",
          failed: false,
          evidence,
        });
      }
    records.set("case-rec", {
      capsuleId: "case-rec",
      stated: { timestamp: "2025-06-05T16:09:32Z" },
      agentInput: { state: "disclosed", payload: {} },
      carriedInput: { state: "withheld" },
      carriedCapsuleId: options.caseId ?? SOURCE,
      carriedInputDigest: options.caseDigest ?? DIGEST,
      ...(options.caseActionId === null
        ? {}
        : { carriedActionId: options.caseActionId ?? `urn:${conversationId}` }),
      agentOutput: { state: "absent" },
      cites: [],
    });
    records.set("tx-rec", {
      capsuleId: "tx-rec",
      agentInput: { state: "disclosed", payload: {} },
      carriedInput: { state: "disclosed", payload },
      carriedCapsuleId: "b".repeat(64),
      carriedInputDigest: options.transcriptDigest ?? DIGEST,
      agentOutput: { state: "absent" },
      cites: [],
    });
    return {
      capsuleId: "result",
      claims,
      records,
      coverage: { excludedNotApplicable: 0 },
    } as unknown as ResultRoot;
  }
  const options = { percentages: false };

  it("is verified, with every turn and tool call in order, when the digests and the case id agree", () => {
    const model = buildOutcomeReportModel(synthetic({}), options);
    const t = model.conversations[0]!.transcript;
    expect(t.state).toBe("verified");
    expect(t.transcriptRecordId).toBe("tx-rec");
    expect(t.caseRecordId).toBe("case-rec");
    expect(t.turns!.map((turn) => turn.role)).toEqual([
      "user",
      "assistant",
      "tool",
    ]);
    expect(t.turns![1]!.toolCalls).toEqual([
      { name: "get_user_details", arguments: '{"user_id":"u1"}' },
    ]);
  });

  it("is a mismatch, and draws no turns, when the transcript commits to a different input", () => {
    const model = buildOutcomeReportModel(
      synthetic({ transcriptDigest: "e".repeat(64) }),
      options,
    );
    const t = model.conversations[0]!.transcript;
    expect(t.state).toBe("mismatch");
    expect(t.turns).toBeUndefined();
  });

  it("is a mismatch when the cited case record is not the one the reports name", () => {
    const model = buildOutcomeReportModel(
      synthetic({ caseId: "c".repeat(64) }),
      options,
    );
    expect(model.conversations[0]!.transcript.state).toBe("mismatch");
  });

  it("matches a case id that names the agent model (case.agent_model), the four-model backfill form", () => {
    const model = buildOutcomeReportModel(
      synthetic({
        conversationId:
          "tau2:airline:claude-3-7-sonnet-20250219:task-7:trial-0",
        agentModel: "claude-3-7-sonnet-20250219",
      }),
      options,
    );
    expect(model.conversations[0]!.transcript.state).toBe("verified");
  });

  it("still matches the older model-less id when the case carries a model", () => {
    const model = buildOutcomeReportModel(
      synthetic({ agentModel: "claude-3-7-sonnet-20250219" }),
      options,
    );
    expect(model.conversations[0]!.transcript.state).toBe("verified");
  });

  it("is a mismatch when the id names a different model than the sealed case", () => {
    const model = buildOutcomeReportModel(
      synthetic({
        conversationId: "tau2:airline:gpt-4.1-2025-04-14:task-7:trial-0",
        agentModel: "claude-3-7-sonnet-20250219",
      }),
      options,
    );
    expect(model.conversations[0]!.transcript.state).toBe("mismatch");
  });

  it("with the reports withheld: the case is the one every claim cites, the judged day is the report capsule's own timestamp, and the pin reads withheld", () => {
    // the case record carries the transcript itself, as the real books do
    const result = synthetic({ withholdReports: true, citeTranscript: false });
    const caseRec = result.records.get("case-rec")!;
    (result.records as Map<string, unknown>).set("case-rec", {
      ...caseRec,
      carriedInput: { state: "disclosed", payload: transcriptPayload },
    });
    const model = buildOutcomeReportModel(result, options);
    const conversation = model.conversations[0]!;
    expect(conversation.sourceCapsuleId).toBe(SOURCE);
    expect(conversation.caseFrom).toBe("claims");
    expect(conversation.judgedDay).toBe("2026-09-23");
    expect(conversation.day).toBe("2025-06-05");
    // never "verified": no report names the case the judge read
    expect(conversation.transcript.state).toBe("cited");
    expect(conversation.transcript.transcriptRecordId).toBe("case-rec");
    expect(conversation.transcript.turns).toHaveLength(3);
    expect(model.runInfo.judgePinDigest).toBeUndefined();
    expect(model.runInfo.reportsWithheld).toBe(9);
    expect(model.runInfo.reportsCited).toBe(9);
  });

  /** The case record carries the transcript itself, as the real books do; no separate transcript record is cited. */
  function caseCarriesTranscript(result: ResultRoot): ResultRoot {
    const caseRec = result.records.get("case-rec")!;
    (result.records as Map<string, unknown>).set("case-rec", {
      ...caseRec,
      carriedInput: { state: "disclosed", payload: transcriptPayload },
    });
    return result;
  }

  it("counts only withheld reports as withheld: a mismatched or non-object report is counted apart, and each criterion says which", () => {
    const mismatched = buildOutcomeReportModel(
      synthetic({ reportInput: { state: "disclosure_mismatch" } }),
      options,
    );
    expect(mismatched.runInfo.reportsWithheld).toBeUndefined();
    expect(mismatched.runInfo.reportsMismatched).toBe(9);
    expect(mismatched.runInfo.reportsCited).toBe(9);
    expect(
      mismatched.conversations[0]!.criteria.map((c) => c.reportState),
    ).toEqual(Array(9).fill("mismatch"));
    const notObject = buildOutcomeReportModel(
      synthetic({ reportInput: { state: "disclosed", payload: "met" } }),
      options,
    );
    expect(notObject.runInfo.reportsWithheld).toBeUndefined();
    expect(notObject.runInfo.reportsUnreadable).toBe(9);
    const mixed = buildOutcomeReportModel(
      synthetic({
        withholdReports: true,
        firstReportInput: { state: "disclosure_mismatch" },
      }),
      options,
    );
    expect(mixed.runInfo.reportsWithheld).toBe(8);
    expect(mixed.runInfo.reportsMismatched).toBe(1);
    expect(mixed.runInfo.reportsCited).toBe(9);
    // a disclosed report is neither, and adds no counts
    const disclosed = buildOutcomeReportModel(synthetic({}), options);
    expect(disclosed.runInfo.reportsCited).toBeUndefined();
    expect(disclosed.conversations[0]!.criteria[0]!.reportState).toBe(
      "disclosed",
    );
  });

  it("takes the case from the claims only when every report is withheld: disclosed reports naming no case leave it unresolved, and the transcript is not verified", () => {
    // an older pipeline: reports disclosed, no source_capsule_id
    const model = buildOutcomeReportModel(
      caseCarriesTranscript(
        synthetic({
          citeTranscript: false,
          reportInput: {
            state: "disclosed",
            payload: { verdict: "met", period: "day:2026-09-23" },
          },
        }),
      ),
      options,
    );
    const conversation = model.conversations[0]!;
    expect(conversation.sourceCapsuleId).toBeUndefined();
    expect(conversation.caseFrom).toBeUndefined();
    expect(conversation.transcript.state).not.toBe("verified");
  });

  it("takes no case from the claims when the reports are mismatched, or only some are withheld", () => {
    for (const result of [
      synthetic({
        citeTranscript: false,
        reportInput: { state: "disclosure_mismatch" },
      }),
      synthetic({
        citeTranscript: false,
        withholdReports: true,
        firstReportInput: { state: "disclosure_mismatch" },
      }),
    ]) {
      const conversation = buildOutcomeReportModel(
        caseCarriesTranscript(result),
        options,
      ).conversations[0]!;
      expect(conversation.sourceCapsuleId).toBeUndefined();
      expect(conversation.transcript.state).not.toBe("verified");
    }
  });

  /** Add a record to a synthetic result and cite it beside every claim's report. */
  function citing(
    result: ResultRoot,
    key: string,
    record: Record<string, unknown>,
    which: (index: number) => boolean = () => true,
  ): ResultRoot {
    (result.records as Map<string, unknown>).set(key, {
      capsuleId: key,
      agentInput: { state: "disclosed", payload: {} },
      agentOutput: { state: "absent" },
      cites: [],
      ...record,
    });
    return {
      ...result,
      claims: result.claims.map((claim, index) =>
        which(index)
          ? {
              ...claim,
              evidence: [...claim.evidence, { digest: key, resolved: true }],
            }
          : claim,
      ),
    } as ResultRoot;
  }

  it("with the reports withheld, the default [report, case, transcript] layout takes the case from the claims; the transcript is 'cited' through a different record, never 'verified'", () => {
    const model = buildOutcomeReportModel(
      synthetic({ withholdReports: true }),
      options,
    );
    const conversation = model.conversations[0]!;
    expect(conversation.sourceCapsuleId).toBe(SOURCE);
    expect(conversation.caseFrom).toBe("claims");
    expect(conversation.transcript.state).toBe("cited");
    expect(conversation.transcript.transcriptRecordId).toBe("tx-rec");
    expect(conversation.transcript.reason).toContain(
      "which conversation the judge read is not shown",
    );
  });

  it("with the reports withheld, conflicting cases with a shared transcript give no case: the shared transcript is never the case", () => {
    // half the claims cite case A, half case B; all cite transcript C
    const result = citing(
      synthetic({ withholdReports: true, citeCase: false }),
      "case-b",
      {
        carriedInput: { state: "withheld" },
        carriedCapsuleId: "e".repeat(64),
        carriedInputDigest: DIGEST,
        carriedActionId: `urn:${CASE}`,
        stated: { timestamp: "2025-06-05T16:09:32Z" },
      },
      (index) => index % 2 === 1,
    );
    const withA = {
      ...result,
      claims: result.claims.map((claim, index) =>
        index % 2 === 0
          ? {
              ...claim,
              evidence: [
                ...claim.evidence,
                { digest: "case-rec", resolved: true },
              ],
            }
          : claim,
      ),
    } as ResultRoot;
    const conversation = buildOutcomeReportModel(withA, options)
      .conversations[0]!;
    expect(conversation.sourceCapsuleId).toBeUndefined();
    expect(conversation.caseFrom).toBeUndefined();
    expect(conversation.transcript.state).toBe("mismatch");
    expect(conversation.dated.basis).toBe("judged");
  });

  it("with the reports withheld, a shared non-case record every claim cites (a policy, rubric or judge-pin capsule) is never the case", () => {
    const result = citing(
      synthetic({
        withholdReports: true,
        citeCase: false,
        citeTranscript: false,
      }),
      "policy-rec",
      {
        carriedInput: { state: "withheld" },
        carriedCapsuleId: "f".repeat(64),
        carriedInputDigest: "9".repeat(64),
        carriedActionId: "urn:evidencebook-skills:policy:airline",
        stated: { timestamp: "2024-01-01T00:00:00Z" },
      },
    );
    const conversation = buildOutcomeReportModel(result, options)
      .conversations[0]!;
    expect(conversation.sourceCapsuleId).toBeUndefined();
    expect(conversation.dated.basis).toBe("judged");
    expect(conversation.day).toBe("2026-09-23");
    // a plain record (no checked carried capsule) is never a case either
    const plain = citing(
      synthetic({
        withholdReports: true,
        citeCase: false,
        citeTranscript: false,
      }),
      "plain-rec",
      { stated: { timestamp: "2024-01-01T00:00:00Z" } },
    );
    expect(
      buildOutcomeReportModel(plain, options).conversations[0]!.sourceCapsuleId,
    ).toBeUndefined();
  });

  it("with the reports withheld, a case record that declares no case, or another conversation's case, is not this conversation's case", () => {
    for (const caseActionId of [null, "urn:tau2:airline:task-8:trial-0"]) {
      const conversation = buildOutcomeReportModel(
        synthetic({ withholdReports: true, caseActionId }),
        options,
      ).conversations[0]!;
      expect(conversation.sourceCapsuleId).toBeUndefined();
      expect(conversation.transcript.state).not.toBe("cited");
      expect(conversation.transcript.state).not.toBe("verified");
    }
  });

  it("with the reports withheld, a case the claims of another conversation also cite is refused for both", () => {
    const one = synthetic({ withholdReports: true });
    const other = "tau2:airline:task-9:trial-0";
    const result = {
      ...one,
      claims: [
        ...one.claims,
        ...one.claims.map((claim) => ({
          ...claim,
          id: claim.id.replace(CASE, other),
        })),
      ],
    } as ResultRoot;
    const model = buildOutcomeReportModel(result, options);
    expect(model.conversations).toHaveLength(2);
    for (const conversation of model.conversations) {
      expect(conversation.sourceCapsuleId).toBeUndefined();
      expect(conversation.transcript.state).not.toBe("cited");
    }
  });

  it("with the reports withheld, a model-named conversation matches the model-less case action id the backfill seals", () => {
    const conversationId =
      "tau2:airline:claude-3-7-sonnet-20250219:task-7:trial-0";
    const conversation = buildOutcomeReportModel(
      synthetic({
        withholdReports: true,
        conversationId,
        agentModel: "claude-3-7-sonnet-20250219",
        caseActionId: `urn:${CASE}`,
      }),
      options,
    ).conversations[0]!;
    expect(conversation.caseFrom).toBe("claims");
    expect(conversation.transcript.state).toBe("cited");
  });

  it("dates the judging from the report capsule only for a withheld report: a mismatched report, and a disclosed one without a period, stay unknown", () => {
    for (const reportInput of [
      { state: "disclosure_mismatch" },
      {
        state: "disclosed",
        payload: { verdict: "met", source_capsule_id: SOURCE },
      },
    ]) {
      const conversation = buildOutcomeReportModel(
        synthetic({ reportInput }),
        options,
      ).conversations[0]!;
      expect(conversation.judgedDay).toBe("unknown");
    }
  });

  it("is absent when no transcript is cited", () => {
    const model = buildOutcomeReportModel(
      synthetic({ citeTranscript: false }),
      options,
    );
    expect(model.conversations[0]!.transcript.state).toBe("absent");
  });
});

// ---------------------------------------------------------------------------
// dating: a conversation is counted under its judged case record's own date
// (source_asserted_at when backfilled, else its timestamp), never converted;
// the judged day stays alongside, and is the fallback
// ---------------------------------------------------------------------------

describe("conversation dating", () => {
  const CASE = "tau2:airline:task-1:trial-0";
  const SOURCE = "a".repeat(64);
  function synthetic(caseRecord: Obj | undefined, citeCase = true): ResultRoot {
    const records = new Map<string, unknown>();
    const claims = [];
    for (const check of FIXTURE_CHECKS)
      for (const criterion of check.criteria) {
        const ref = `${check.id}.${criterion.id}`;
        const report = `r-${ref}`;
        records.set(report, {
          capsuleId: report,
          agentInput: {
            state: "disclosed",
            payload: {
              verdict: "met",
              source_capsule_id: SOURCE,
              period: "day:2026-09-23",
            },
          },
          agentOutput: { state: "absent" },
          cites: [],
        });
        const evidence = [{ digest: report, resolved: true }];
        if (citeCase) evidence.push({ digest: "case-rec", resolved: true });
        claims.push({
          id: `${CASE}::${ref}`,
          type: "requirement",
          recognized: true,
          contractRef: "airline-support-outcomes@1.4.0",
          requirementRef: ref,
          tier: "judged",
          verdict: "met",
          support: "supported",
          failed: false,
          evidence,
        });
      }
    if (caseRecord !== undefined)
      records.set("case-rec", {
        capsuleId: "case-rec",
        agentInput: { state: "disclosed", payload: {} },
        carriedCapsuleId: SOURCE,
        carriedInputDigest: "d".repeat(64),
        agentOutput: { state: "absent" },
        cites: [],
        ...caseRecord,
      });
    return {
      capsuleId: "result",
      claims,
      records,
      coverage: { excludedNotApplicable: 0 },
    } as unknown as ResultRoot;
  }
  const build = (root: ResultRoot) =>
    buildOutcomeReportModel(root, { percentages: false });

  it("backfilled: the source's own source_asserted_at, as given, zone not stated, imported_at kept", () => {
    const model = build(
      synthetic({
        stated: {
          timestamp: "2026-09-22T10:00:00Z",
          provenanceMode: {
            mode: "backfilled",
            source_asserted_at: "2025-06-05T16:06:37.787845",
            imported_at: "2026-09-22T10:00:00Z",
          },
        },
      }),
    );
    const c = model.conversations[0]!;
    expect(c.dated).toEqual({
      basis: "source",
      date: "2025-06-05",
      stated: "2025-06-05T16:06:37.787845",
      zone: "not-stated",
      importedAt: "2026-09-22T10:00:00Z",
    });
    expect(c.judgedDay).toBe("2026-09-23");
    expect(model.days.map((d) => [d.date, d.judgedDays])).toEqual([
      ["2025-06-05", ["2026-09-23"]],
    ]);
    expect(model.dating).toEqual({
      basis: "source",
      counts: { source: 1, record: 0, judged: 0 },
      judgedDays: ["2026-09-23"],
      zoneNotStated: 1,
    });
  });

  it("not backfilled: the case capsule's own timestamp, as given -- never shifted by its zone", () => {
    const c = build(
      synthetic({ stated: { timestamp: "2025-06-05T23:30:00-08:00" } }),
    ).conversations[0]!;
    expect(c.dated).toEqual({
      basis: "record",
      date: "2025-06-05",
      stated: "2025-06-05T23:30:00-08:00",
      zone: "stated",
    });
  });

  it("falls back to the judged day when the case record is not cited, not the one the reports name, unchecked, or states no time", () => {
    const stated = { stated: { timestamp: "2025-06-05T16:06:37Z" } };
    for (const root of [
      synthetic(stated, false),
      synthetic({ ...stated, carriedCapsuleId: "c".repeat(64) }),
      synthetic({}),
      synthetic({ stated: { timestamp: "not a time" } }),
      synthetic({
        stated: { provenanceMode: { mode: "backfilled" } },
      }),
    ]) {
      const model = build(root);
      expect(model.conversations[0]!.dated).toEqual({
        basis: "judged",
        date: "2026-09-23",
      });
      expect(model.dating.basis).toBe("judged");
    }
  });
});

// A check whose criteria all read not_applicable had nothing checked: it is
// not_evaluable, never a vacuous met. A conversation resolves only when at
// least one criterion is met and none fails.
it("never resolves on not_applicable alone", () => {
  const claimsFor = (conversation: string, refs: readonly string[]) =>
    refs.map((ref) => ({
      id: `${conversation}::${ref}`,
      type: "requirement",
      recognized: true,
      contractRef: "pack@1",
      requirementRef: ref,
      tier: "judged",
      verdict: "met",
      support: "supported",
      failed: false,
      evidence: [],
    }));
  const all = FIXTURE_CHECKS.flatMap((check) =>
    check.criteria.map((criterion) => `${check.id}.${criterion.id}`),
  );
  const result = {
    capsuleId: "result",
    claims: [
      ...claimsFor("case-a", all),
      ...claimsFor("case-b", ["policy_compliance.within_fare_rules"]),
    ],
    records: new Map(),
    // case-b's eight missing criteria, each excluded as not applicable
    coverage: { excludedNotApplicable: 8 },
  } as unknown as ResultRoot;
  const model = buildOutcomeReportModel(result, { percentages: false });
  const b = model.conversations.find((c) => c.conversationId === "case-b")!;
  expect(b.verdict).toBe("met");
  expect(b.checkVerdicts.get("policy_compliance")).toBe("met");
  expect(b.checkVerdicts.get("task_resolution")).toBe("not_evaluable");
  expect(model.checkPassCounts.get("task_resolution")).toBe(1);
});

// Result v0 section 3: without requirements_covered every requirement of
// the cited contract is covered, so one no claim cites is still a criterion;
// and a listed requirement this card draws no criterion for still uses up an
// exclusion.
describe("missing claims against the contract and the exclusions", () => {
  const contractRecord = (requirements: readonly string[]) =>
    ({
      capsuleId: "contract-rec",
      agentInput: {
        state: "disclosed",
        payload: {
          id: "pack",
          version: "1",
          requirements: requirements.map((id) => ({ id })),
        },
      },
      agentOutput: { state: "absent" },
      cites: [],
    }) as unknown as CitedRecord;
  const root = (
    excludedNotApplicable: number,
    requirementsCovered?: readonly string[],
  ) =>
    ({
      capsuleId: "result",
      claims: ["check.a"].map((ref) => ({
        id: `case-a::${ref}`,
        type: "requirement",
        recognized: true,
        contractRef: "pack@1",
        requirementRef: ref,
        tier: "judged",
        verdict: "met",
        support: "supported",
        failed: false,
        evidence: [],
      })),
      records: new Map([
        ["contract-rec", contractRecord(["check.a", "check.b", "resolved"])],
      ]),
      coverage: { excludedNotApplicable },
      ...(requirementsCovered === undefined
        ? {}
        : {
            requirementsCovered: requirementsCovered.map((requirementRef) => ({
              contractRef: "pack@1",
              requirementRef,
            })),
          }),
    }) as unknown as ResultRoot;
  const verdictOf = (result: ResultRoot) => {
    const model = buildOutcomeReportModel(result, { percentages: false });
    const conversation = model.conversations[0]!;
    return [
      conversation.criteria.find((c) => c.criterionId === "b")?.verdict,
      conversation.verdict,
    ];
  };

  it("without the list, a contract criterion no claim cites is a gap unless an exclusion accounts for it", () => {
    expect(verdictOf(root(0))).toEqual(["no_claim", "not_evaluable"]);
    expect(verdictOf(root(1))).toEqual(["not_applicable", "met"]);
  });

  it("a listed requirement no claim cites and the card does not draw uses up one exclusion first", () => {
    expect(verdictOf(root(1, ["check.a", "check.b", "resolved"]))).toEqual([
      "no_claim",
      "not_evaluable",
    ]);
    expect(verdictOf(root(2, ["check.a", "check.b", "resolved"]))).toEqual([
      "not_applicable",
      "met",
    ]);
  });
});

it("reads the judge's probabilities only as probabilities: a value outside [0, 1] (an exponent) is not one", () => {
  expect(
    parseJudgeProbabilities(
      "jev choice: met (probabilities={'met': 0.89, 'not_met': 0.11}, confidence=0.86).",
    ),
  ).toEqual({ probabilities: { met: 0.89, not_met: 0.11 }, confidence: 0.86 });
  // one out-of-range value makes the whole set unreadable: no partial set
  expect(
    parseJudgeProbabilities(
      "jev choice: met (probabilities={'met': 1.2e2, 'not_met': 2e-3}, confidence=12).",
    ),
  ).toEqual({});
  // a signed exponent is read as the whole token, never truncated to 1
  expect(
    parseJudgeProbabilities(
      "jev choice: met (probabilities={'met': 1e+2, 'not_met': 0.1}, confidence=0.5).",
    ),
  ).toEqual({ confidence: 0.5 });
  expect(
    parseJudgeProbabilities(
      "jev choice: met (probabilities={'met': 9e-1, 'not_met': 1E-1}, confidence=1e2).",
    ),
  ).toEqual({ probabilities: { met: 0.9, not_met: 0.1 } });
  expect(parseJudgeProbabilities("x (confidence=1e-2).")).toEqual({
    confidence: 0.01,
  });
  expect(parseJudgeProbabilities("x (confidence=1e+2).")).toEqual({});
  // a token that is not a whole number (trailing junk) is not read at all
  expect(
    parseJudgeProbabilities("probabilities={'met': 0.9x, 'not_met': 0.1}"),
  ).toEqual({});
  expect(parseJudgeProbabilities("confidence=0.8abc")).toEqual({});
});

it("(ER 4.2) an out_of_scope claim is its own criterion verdict and count, never not applicable, and rolls up as does-not-apply", async () => {
  const source = fixture("outcome-report-bundle.json");
  const resultDoc = ((source.disclosures as Obj).result as Obj)
    .agent_input as Obj;
  const claims = resultDoc.claims as Obj[];
  const requirementRef = "task_resolution.right_reservation";
  for (const claim of claims)
    if (claim.requirement_ref === requirementRef)
      claim.out_of_scope_allowed = true;
  const target = claims.find(
    (claim) =>
      claim.requirement_ref === requirementRef &&
      claim.verdict === "not_met" &&
      claim.sufficiency === "SATISFIED",
  )!;
  target.verdict = "out_of_scope";
  const buckets = rebuildBuckets(
    claims.filter((claim) => claim.verdict !== "out_of_scope"),
  );
  buckets.out_of_scope = [target.id as string];
  (resultDoc.aggregate as Obj).buckets = buckets;
  const { bundle } = await sealEvidenceBundle(source);
  const result = await buildResultRoot(bundle);
  const model = buildOutcomeReportModel(result, { percentages: false });
  expect(model.outOfScopeCount).toBe(1);
  const conversation = model.conversations.find((c) =>
    c.criteria.some((cr) => cr.claim?.id === target.id),
  )!;
  const criterion = conversation.criteria.find(
    (cr) => cr.claim?.id === target.id,
  )!;
  expect(criterion.verdict).toBe("out_of_scope");
  expect(
    conversation.criteria.filter((cr) => cr.verdict === "not_applicable"),
  ).toHaveLength(0);
});

it("(ER 4.3) a criterion not yet in force that failed verification is still drawn failed, and its conversation never resolves", async () => {
  const { bundle } = await sealEvidenceBundle(
    fixture("outcome-report-bundle.json"),
  );
  const result = await buildResultRoot(bundle);
  const target = result.claims.find((claim) => claim.verdict === "met")!;
  const failedLater = {
    ...result,
    claims: result.claims.map((claim) =>
      claim.id === target.id ? { ...claim, later: true, failed: true } : claim,
    ),
  };
  const model = buildOutcomeReportModel(failedLater, { percentages: false });
  const conversation = model.conversations.find((c) =>
    c.criteria.some((cr) => cr.claim?.id === target.id),
  )!;
  expect(
    conversation.criteria.find((cr) => cr.claim?.id === target.id)!.verdict,
  ).toBe("failed");
  expect(conversation.verdict).not.toBe("met");
});

async function withLater(pick: (claimId: string) => boolean): Promise<{
  base: ReturnType<typeof buildOutcomeReportModel>;
  model: ReturnType<typeof buildOutcomeReportModel>;
  laterIds: string[];
}> {
  const { bundle } = await sealEvidenceBundle(
    fixture("outcome-report-bundle.json"),
  );
  const result = await buildResultRoot(bundle);
  const laterIds = result.claims.filter((c) => pick(c.id)).map((c) => c.id);
  const changed = {
    ...result,
    claims: result.claims.map((claim) =>
      laterIds.includes(claim.id) ? { ...claim, later: true } : claim,
    ),
  };
  return {
    base: buildOutcomeReportModel(result, { percentages: false }),
    model: buildOutcomeReportModel(changed, { percentages: false }),
    laterIds,
  };
}

it("(ER 4.3) a conversation with none later has an empty not-yet-in-force list", async () => {
  const { base } = await withLater(() => false);
  expect(base.notYetInForce).toEqual([]);
  expect(base.conversations.every((c) => c.notYetInForce.length === 0)).toBe(
    true,
  );
});

it("(ER 4.3) a later claim beside in-force claims is kept apart in its conversation, outside every tally", async () => {
  const first = "tau2:airline:task-0:trial-0::";
  const { base, model, laterIds } = await withLater(
    (id) => id.startsWith(first) && id.endsWith("confirmed_before_acting"),
  );
  expect(laterIds).toHaveLength(1);
  expect(model.notYetInForce).toEqual([]);
  expect(model.totalCount).toBe(base.totalCount);
  const conversation = model.conversations.find(
    (c) => c.conversationId === "tau2:airline:task-0:trial-0",
  )!;
  expect(conversation.notYetInForce.map((c) => c.claim?.id)).toEqual(laterIds);
  expect(conversation.criteria.some((c) => c.claim?.id === laterIds[0])).toBe(
    false,
  );
  expect(conversation.criteria.length + 1).toBe(
    base.conversations.find(
      (c) => c.conversationId === conversation.conversationId,
    )!.criteria.length,
  );
});

it("(ER 4.3) a conversation whose every claim is later is in no tally and never could-not-decide", async () => {
  const first = "tau2:airline:task-0:trial-0::";
  const { base, model, laterIds } = await withLater((id) =>
    id.startsWith(first),
  );
  expect(laterIds.length).toBeGreaterThan(0);
  expect(model.notYetInForce.map((c) => c.conversationId)).toEqual([
    "tau2:airline:task-0:trial-0",
  ]);
  const kept = model.notYetInForce[0]!;
  expect(kept.notYetInForce.map((c) => c.claim?.id).sort()).toEqual(
    [...laterIds].sort(),
  );
  expect(kept.criteria).toEqual([]);
  expect(
    model.conversations.some((c) => c.conversationId === kept.conversationId),
  ).toBe(false);
  expect(model.days.flatMap((d) => d.conversations)).not.toContain(kept);
  expect(model.totalCount).toBe(base.totalCount - 1);
  expect(model.noClaimCount).toBeLessThanOrEqual(base.noClaimCount);
});

it("(ER 4.3) an all-later conversation's missing claims use up no exclusion", async () => {
  const { bundle } = await sealEvidenceBundle(
    fixture("outcome-report-bundle.json"),
  );
  const result = await buildResultRoot(bundle);
  const laterId = "tau2:airline:task-0:trial-0";
  const inForceId = "tau2:airline:task-1:trial-0";
  const dropped = new Set<string>();
  for (const id of [laterId, inForceId]) {
    const claim = result.claims.find((c) => c.id.startsWith(`${id}::`))!;
    dropped.add(claim.id);
  }
  const changed = {
    ...result,
    claims: result.claims
      .filter((c) => !dropped.has(c.id))
      .map((c) =>
        c.id.startsWith(`${laterId}::`) ? { ...c, later: true } : c,
      ),
    coverage: { ...result.coverage, excludedNotApplicable: 1 },
  };
  const model = buildOutcomeReportModel(changed, { percentages: false });
  expect(model.notYetInForce.map((c) => c.conversationId)).toEqual([laterId]);
  expect(model.notYetInForce[0]!.criteria).toEqual([]);
  const conversation = model.conversations.find(
    (c) => c.conversationId === inForceId,
  )!;
  expect(
    conversation.criteria.filter((c) => c.verdict === "not_applicable"),
  ).toHaveLength(1);
  expect(model.noClaimCount).toBe(0);
});
