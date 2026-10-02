import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { jsonDigest } from "../src/json.js";
import {
  buildOutcomeReportModel,
  NOT_STATED,
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

it("held/added are read only from calibration-summary/v1 samples, never from the claims' own verdicts -- zero when none are cited", async () => {
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

it("held/added are recomputed from an injected calibration sample, never from the claims' own verdicts", async () => {
  const source = fixture("outcome-report-bundle.json");
  const resultDoc = ((source.disclosures as Obj).result as Obj)
    .agent_input as Obj;
  const claims = resultDoc.claims as Obj[];
  const conversationId = (claims[0]!.id as string).split("::")[0]!;
  (source.records as Obj[]).push({ capsule_id: "cal-2026-W39" });
  const calClaim = {
    id: "cal::2026-W39",
    type: "calibration",
    contract_ref: (claims[0] as Obj).contract_ref,
    requirement_ref: "human-spot-check",
    tier: "recomputed",
    grade: "self-attested",
    sufficiency: "SATISFIED",
    verdict: "not_met",
    evidence: [{ digest_alg: "SHA-256", digest: "cal-2026-W39" }],
    proofs: [],
    presentation: {
      kind: "disclosure",
      status: "SATISFIED",
      evidence: [{ digest_alg: "SHA-256", digest: "cal-2026-W39" }],
    },
  };
  const allClaims = [...claims, calClaim];
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
  (source.disclosures as Obj)["cal-2026-W39"] = {
    agent_input: {
      spec_version: "calibration-summary/v1",
      week: "2026-W39",
      sample: [
        {
          conversation_id: conversationId,
          ai_verdict: "met",
          human_verdict: "not_met",
        },
        {
          conversation_id: "unrelated",
          ai_verdict: "not_met",
          human_verdict: "met",
        },
        {
          conversation_id: "unrelated-2",
          ai_verdict: "met",
          human_verdict: "met",
        },
      ],
    },
  };
  const { bundle } = await sealEvidenceBundle(source);
  const result = await buildResultRoot(bundle);
  const model = buildOutcomeReportModel(result, { percentages: false });
  expect(model.calibration).toHaveLength(1);
  expect(model.heldCount).toBe(1);
  expect(model.addedCount).toBe(1);
});

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

it("recomputes calibration k/n from the enumerable sample, never trusting the record's own stated agreement field", async () => {
  const source = fixture("outcome-report-bundle.json");
  const resultDoc = ((source.disclosures as Obj).result as Obj)
    .agent_input as Obj;
  const claims = resultDoc.claims as Obj[];
  (source.records as Obj[]).push({ capsule_id: "cal-2026-W39" });
  const calClaim = {
    id: "cal::2026-W39",
    type: "calibration",
    contract_ref: (claims[0] as Obj).contract_ref,
    requirement_ref: "human-spot-check",
    tier: "recomputed",
    grade: "self-attested",
    sufficiency: "SATISFIED",
    verdict: "not_met",
    evidence: [{ digest_alg: "SHA-256", digest: "cal-2026-W39" }],
    proofs: [],
    presentation: {
      kind: "disclosure",
      status: "SATISFIED",
      evidence: [{ digest_alg: "SHA-256", digest: "cal-2026-W39" }],
    },
  };
  const allClaims = [...claims, calClaim];
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
  const sample = [
    { conversation_id: "a", ai_verdict: "met", human_verdict: "met" },
    { conversation_id: "b", ai_verdict: "met", human_verdict: "not_met" },
    { conversation_id: "c", ai_verdict: "not_met", human_verdict: "not_met" },
  ];
  const trueK = sample.filter((s) => s.ai_verdict === s.human_verdict).length;
  (source.disclosures as Obj)["cal-2026-W39"] = {
    agent_input: {
      spec_version: "calibration-summary/v1",
      week: "2026-W39",
      // Lie in the stated aggregate: claim perfect agreement no matter what
      // the sample actually shows.
      agreement: { k: sample.length, n: sample.length },
      sample,
    },
  };
  const { bundle } = await sealEvidenceBundle(source);
  const result = await buildResultRoot(bundle);
  const model = buildOutcomeReportModel(result, { percentages: false });
  const week = model.calibration.find((w) => w.n === sample.length)!;
  expect(week).toBeDefined();
  expect(week.k).toBe(trueK);
  expect(week.k).not.toBe(sample.length);
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

function asBookForm(
  result: ResultRoot,
  carried: (record: CitedRecord) => CitedRecord["carriedInput"],
): ResultRoot {
  const records = new Map<string, CitedRecord>();
  for (const [id, record] of result.records) {
    const carriedInput = carried(record);
    records.set(id, {
      ...record,
      agentInput: {
        state: "disclosed",
        payload: { record_type: "published_capsule", subject_ref: id },
      },
      ...(carriedInput === undefined ? {} : { carriedInput }),
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
  expect(model.days.map((day) => day.date)).toEqual(["unknown"]);
  expect(model.runInfo.judgePinDigest).toBeUndefined();
  // the contract is still the Result's own: every claim names it
  expect(model.runInfo.contract).toBe("tau2-airline-outcomes/v1@1");
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
  }): ResultRoot {
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
              rationale:
                "jev choice: met (probabilities={'met': 0.9, 'not_met': 0.1}, confidence=0.8).",
            },
          },
          agentOutput: { state: "absent" },
          cites: [],
        });
        const evidence = [{ digest: report, resolved: true }];
        if (options.citeCase !== false)
          evidence.push({ digest: "case-rec", resolved: true });
        if (options.citeTranscript !== false)
          evidence.push({ digest: "tx-rec", resolved: true });
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
    records.set("case-rec", {
      capsuleId: "case-rec",
      agentInput: { state: "disclosed", payload: {} },
      carriedInput: { state: "withheld" },
      carriedCapsuleId: options.caseId ?? SOURCE,
      carriedInputDigest: options.caseDigest ?? DIGEST,
      agentOutput: { state: "absent" },
      cites: [],
    });
    records.set("tx-rec", {
      capsuleId: "tx-rec",
      agentInput: { state: "disclosed", payload: {} },
      carriedInput: { state: "disclosed", payload: transcriptPayload },
      carriedCapsuleId: "b".repeat(64),
      carriedInputDigest: options.transcriptDigest ?? DIGEST,
      agentOutput: { state: "absent" },
      cites: [],
    });
    return {
      capsuleId: "result",
      claims,
      records,
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
    return { capsuleId: "result", claims, records } as unknown as ResultRoot;
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
  } as unknown as ResultRoot;
  const model = buildOutcomeReportModel(result, { percentages: false });
  const b = model.conversations.find((c) => c.conversationId === "case-b")!;
  expect(b.verdict).toBe("met");
  expect(b.checkVerdicts.get("policy_compliance")).toBe("met");
  expect(b.checkVerdicts.get("task_resolution")).toBe("not_evaluable");
  expect(model.checkPassCounts.get("task_resolution")).toBe(1);
});
