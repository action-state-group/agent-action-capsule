// What the Result page is drawn from, for a Result v0 root: the verification
// the page states, the built-in page the bundle selects, and the Result model
// (buildResultRoot) the page shows, recomputed, with every marker where the
// producer disagreed. capsule-viewer draws the page
// (action-state-group/capsule-viewer).
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { expect, it } from "vitest";
import {
  buildResultRoot,
  type ResultClaim,
  type ResultRoot,
} from "../src/browser.js";
import { builtinPage } from "./helpers/builtin-resolution.js";
import { pageModel, type PageModel } from "./helpers/page-model.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

type Obj = Record<string, unknown>;

function fixture(name: string): Obj {
  return JSON.parse(
    readFileSync(resolve(process.cwd(), "test", "testdata", name), "utf8"),
  ) as Obj;
}

function resultOf(source: Obj): Obj {
  return ((source.disclosures as Obj).result as Obj).agent_input as Obj;
}

const ABSENT_ID =
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

interface Shown extends PageModel {
  /** The built-in page the bundle selects. */
  readonly selected: string;
  /** The Result model, when the bundle verified and selected the Result page. */
  readonly result?: ResultRoot;
}

async function render(bundle: unknown): Promise<Shown> {
  const model = await pageModel(bundle);
  const selected = await builtinPage(model.context);
  return {
    ...model,
    selected,
    ...(selected === "aac.builtin.result/v0"
      ? { result: await buildResultRoot(model.context) }
      : {}),
  };
}

const claimOf = (result: ResultRoot | undefined, id: string): ResultClaim =>
  result!.claims.find((claim) => claim.id === id)!;

const RESULT = "aac.builtin.result/v0";

function tamperCheckpoint(bundle: Obj): Obj {
  const checkpoint = bundle.checkpoint as { mmr_size: number };
  return {
    ...bundle,
    checkpoint: { ...checkpoint, mmr_size: checkpoint.mmr_size + 1 },
  };
}

it("(e) selects the Result page for a verified Result root: coverage, buckets and one claim per row", async () => {
  const { bundle, ids } = await sealEvidenceBundle(
    fixture("result-root-bundle.json"),
  );
  const { banner, selected, result } = await render(bundle);
  expect(banner.state).toBe("incomplete");
  expect(selected).toBe(RESULT);
  expect(result!.capsuleId).toBe(ids["result"]);
  expect(result!.coverage).toEqual({
    evaluatedPopulation: 3,
    excludedNotApplicable: 1,
    unknownCount: 0,
  });
  expect(result!.buckets).toEqual({
    met: ["claim-1"],
    notMet: ["claim-2"],
    notEvaluable: ["claim-3"],
  });
  expect(
    result!.claims.map((claim) => [
      claim.id,
      claim.sufficiency,
      claim.verdict,
      claim.tier,
      claim.grade,
      claim.type,
    ]),
  ).toEqual([
    ["claim-1", "SATISFIED", "met", "recomputed", "witnessed", "requirement"],
    [
      "claim-2",
      "SATISFIED",
      "not_met",
      "judged",
      "self-attested",
      "requirement",
    ],
    [
      "claim-3",
      "GAP",
      "not_evaluable",
      "recomputed",
      "countersigned",
      "requirement",
    ],
  ]);
  for (const claim of result!.claims) {
    expect(claim.support).toBe("supported");
    expect(claim.recognized).toBe(true);
  }
});

it("resolves a claim to the records it cites, and a daily report to the act it cites", async () => {
  const { bundle, ids } = await sealEvidenceBundle(
    fixture("result-root-bundle.json"),
  );
  const { result } = await render(bundle);
  const claim = claimOf(result, "claim-1");
  expect(
    claim.evidence.filter((ref) => ref.resolved).map((ref) => ref.digest),
  ).toEqual([ids["day-1"], ids["day-2"]]);
  expect(result!.records.get(ids["day-2"]!)!.agentInput).toEqual({
    state: "disclosed",
    payload: (
      fixture("result-root-bundle.json").disclosures as Record<string, Obj>
    )["day-2"]!.agent_input,
  });
  expect(claim.proofs.map((proof) => proof.kind)).toEqual(["inclusion_proof"]);
  expect(claim.proofs[0]!.digest).toMatch(/^0123456789abcdef/u);
  // the daily report cites an act, which resolves too
  expect(result!.records.get(ids["day-1"]!)!.cites).toContain(ids["act-1"]);
  const act = result!.records.get(ids["act-1"]!)!;
  expect(JSON.stringify(act.agentInput)).toContain(
    "change my flight to the fourteenth",
  );
  expect(JSON.stringify(act.agentOutput)).toContain(
    "your flight is now on the fourteenth",
  );
  // claim-3: analysis carrier, its summary shown, no proof cited
  const analysis = claimOf(result, "claim-3");
  expect(analysis.presentation).toMatchObject({
    kind: "analysis",
    status: "WITHHELD",
  });
  expect(analysis.presentation.summary).toContain(
    "the counterparty confirmed the record exists",
  );
  expect(analysis.proofs).toEqual([]);
});

it("resolves a disclosure carrier's own evidence list against this bundle", async () => {
  const source = fixture("result-root-bundle.json");
  // the carrier discloses a different list from the claim's evidence: one
  // cited record and one digest this bundle does not carry
  const claim = (resultOf(source).claims as Obj[])[0]!;
  (claim.presentation as Obj).evidence = [
    { digest_alg: "SHA-256", digest: "case-1" },
    { digest_alg: "SHA-256", digest: ABSENT_ID },
  ];
  const { bundle, ids } = await sealEvidenceBundle(source);
  const { result } = await render(bundle);
  const shown = claimOf(result, "claim-1");
  // the verdict still rests on the claim's own evidence, which resolves
  expect(shown.support).toBe("supported");
  expect(shown.presentation.kind).toBe("disclosure");
  expect(shown.presentation.evidence).toEqual([ids["case-1"], ABSENT_ID]);
  expect(result!.records.has(ids["case-1"]!)).toBe(true);
  expect(result!.records.has(ABSENT_ID)).toBe(false);
  expect(JSON.stringify(result!.records.get(ids["case-1"]!))).toContain(
    "the quoted fee did not match",
  );
  // a non-disclosure carrier has no carrier list
  expect(claimOf(result, "claim-3").presentation.evidence).toBeUndefined();
});

it("states a cited record outside the checkpoint as uncheckpointed, with the bundle-level count", async () => {
  const { bundle, ids } = await sealEvidenceBundle(
    fixture("result-root-bundle.json"),
    { uncheckpointed: ["day-2"] },
  );
  expect(
    Object.keys(
      (bundle.completeness_certificate as { memberships: Obj }).memberships,
    ),
  ).not.toContain(ids["day-2"]);
  const { banner, page, selected, result } = await render(bundle);
  expect(banner.state).toBe("failed");
  expect(banner.verdict).toBe("invalid");
  expect(banner.uncheckpointed).toBe(1);
  expect(banner.refusal).toBeUndefined();
  expect(banner.detail).toBe(
    "1 of 5 records are uncheckpointed (bound to no log position), so per-record membership fails. Interval coverage is checkpoint_unverified: relative to a producer-asserted checkpoint that is not signed.",
  );
  // the records are still shown, the Result page with them
  expect(selected).toBe(RESULT);
  expect(result!.claims).toHaveLength(3);
  // each record carries its own standing: the root and day-1 checkpointed,
  // day-2 alone uncheckpointed, and the claim citing both stays supported
  const status = new Map(page.records.map((r) => [r.capsuleId, r.status]));
  expect(status.get(ids["result"]!)).toBe("checkpointed");
  expect(status.get(ids["day-1"]!)).toBe("checkpointed");
  expect(status.get(ids["day-2"]!)).toBe("uncheckpointed");
  expect(
    page.records
      .filter((r) => r.status === "uncheckpointed")
      .map((r) => r.capsuleId),
  ).toEqual([ids["day-2"]]);
  expect(page.uncheckpointedCount).toBe(1);
  expect(page.records).toHaveLength(5);
  const claim = claimOf(result, "claim-1");
  expect(claim.support).toBe("supported");
  expect(claim.verdict).toBe("met");
});

it("(b) a claim whose cited id is missing from the bundle is unsupported, never met, and keeps its row", async () => {
  const source = fixture("result-root-bundle.json");
  ((resultOf(source).claims as Obj[])[0]!.evidence as Obj[])[1]!.digest =
    ABSENT_ID;
  const { bundle } = await sealEvidenceBundle(source);
  const { banner, result } = await render(bundle);
  expect(banner.state).toBe("incomplete");
  expect(result!.claims).toHaveLength(3);
  const claim = claimOf(result, "claim-1");
  expect(claim.support).toBe("unsupported");
  expect(claim.missing).toEqual([ABSENT_ID]);
  expect(claim.evidence.find((ref) => ref.digest === ABSENT_ID)?.resolved).toBe(
    false,
  );
  // the bucket the Result put it in still lists it
  expect(result!.buckets.met).toContain("claim-1");
  // the other claims are untouched
  expect(claimOf(result, "claim-2").verdict).toBe("not_met");
  expect(claimOf(result, "claim-2").support).toBe("supported");
});

it("a claim of an unknown type is unrecognized, with its axes, never dropped", async () => {
  const source = fixture("result-root-bundle.json");
  (resultOf(source).claims as Obj[])[2]!.type = "adjudication";
  const { bundle } = await sealEvidenceBundle(source);
  const { result } = await render(bundle);
  expect(result!.claims).toHaveLength(3);
  const claim = claimOf(result, "claim-3");
  expect(claim.type).toBe("adjudication");
  expect(claim.recognized).toBe(false);
  expect(claim.verdict).toBe("not_evaluable");
  expect(claim.grade).toBe("countersigned");
  expect(claim.support).toBe("supported");
});

it("(c) a tampered claim in the root Result fails verification: no Result page, no payloads", async () => {
  const { bundle, ids } = await sealEvidenceBundle(
    fixture("result-root-bundle.json"),
  );
  const disclosures = bundle.disclosures as Record<string, Obj>;
  const tampered = structuredClone(
    disclosures[ids["result"]!]!.agent_input,
  ) as Obj;
  (tampered.claims as Obj[])[1]!.verdict = "met";
  (tampered.claims as Obj[])[1]!.requirement_ref = "req-2-tampered";
  ((tampered.aggregate as Obj).buckets as Obj) = {
    met: ["claim-1", "claim-2"],
    not_met: [],
    not_evaluable: ["claim-3"],
  };
  const { banner, page, stamps, selected, result } = await render({
    ...bundle,
    disclosures: {
      ...disclosures,
      [ids["result"]!]: { agent_input: tampered },
    },
  });
  expect(banner.state).toBe("failed");
  expect(banner.refusal).toBeDefined();
  expect(selected).toBe("<refusal>");
  expect(result).toBeUndefined();
  expect(JSON.stringify({ banner, page, stamps })).not.toContain(
    "req-2-tampered",
  );
});

it("H2: an unverified Result-root bundle selects no Result page", async () => {
  const { bundle } = await sealEvidenceBundle(
    fixture("result-root-bundle.json"),
  );
  const { banner, selected } = await render(tamperCheckpoint(bundle));
  expect(banner.state).toBe("failed");
  expect(selected).toBe("<refusal>");
});

it("(a) a verified bundle whose root names itself a Result v0 but is malformed is refused, never read as one", async () => {
  const source = fixture("result-root-bundle.json");
  (resultOf(source).claims as Obj[])[2]!.verdict = "met";
  const { bundle } = await sealEvidenceBundle(source);
  const { context } = await pageModel(bundle);
  expect(await builtinPage(context)).toBe(RESULT);
  await expect(buildResultRoot(context)).rejects.toThrow(
    /root is not a Result v0/u,
  );
});

it("still selects the evaluation-summary and report/v1 root families", async () => {
  const week = await render(fixture("week-bundle.json"));
  expect(week.banner.state).toBe("incomplete");
  expect(week.selected).toBe("aac.builtin.evaluation-summary-graph/v0");

  const { bundle } = await sealEvidenceBundle(
    fixture("report-rows-bundle.json"),
  );
  expect((await render(bundle)).selected).toBe("aac.builtin.report-rows/v0");
});

// ---------------------------------------------------------------------------
// The maintainer's adversarial review (2026-09-28): what the page shows is
// the recomputed value, with a marker where the producer disagreed -- never
// the stated number, never silently; a Result that hides a verdict is
// refused, never read; a close state comes from the cited Close's links.
// ---------------------------------------------------------------------------

it("(i) a Result whose 'not met' bucket is empty over a not_met claim is refused", async () => {
  const source = fixture("result-root-bundle.json");
  ((resultOf(source).aggregate as Obj).buckets as Obj).not_met = [];
  const { bundle } = await sealEvidenceBundle(source);
  const { context } = await pageModel(bundle);
  await expect(buildResultRoot(context)).rejects.toThrow(
    /claim-2 \(not_met\) appears in no bucket/u,
  );
});

it("(ii) recomputes coverage with a count mismatch beside it -- the stated number is never the value", async () => {
  const source = fixture("result-root-bundle.json");
  const coverage = (resultOf(source).aggregate as Obj).coverage as Obj;
  coverage.evaluated_population = 4; // three claims
  const { bundle } = await sealEvidenceBundle(source);
  const { result } = await render(bundle);
  expect(result!.coverage.evaluatedPopulation).toBe(3);
  expect(result!.statedCoverage.evaluatedPopulation).toBe(4);
  expect(result!.countMismatches).toEqual([
    { field: "evaluated_population", stated: 4, recomputed: 3 },
  ]);

  // an unresolved claim the producer did not count
  const unresolved = fixture("result-root-bundle.json");
  (resultOf(unresolved).claims as Obj[])[2]!.sufficiency = "UNKNOWN";
  const unknown = (await render((await sealEvidenceBundle(unresolved)).bundle))
    .result!;
  expect(unknown.coverage.unknownCount).toBe(1);
  expect(unknown.countMismatches).toEqual([
    { field: "unknown_count", stated: 0, recomputed: 1 },
  ]);

  // the honest fixture has no mismatch at all
  const clean = await render(
    (await sealEvidenceBundle(fixture("result-root-bundle.json"))).bundle,
  );
  expect(clean.result!.countMismatches).toEqual([]);
});

it("(ii) counts coverage in evaluations: two claims of one requirement are two evaluations, both kept", async () => {
  // claim-2 re-evaluates claim-1's requirement: two evaluations of req-1,
  // one met and one not_met, plus req-3
  const source = fixture("result-root-bundle.json");
  (resultOf(source).claims as Obj[])[1]!.requirement_ref = "req-1";
  const { result } = await render((await sealEvidenceBundle(source)).bundle);
  expect(result!.coverage.evaluatedPopulation).toBe(3);
  expect(result!.countMismatches).toEqual([]);
  expect(result!.buckets.met).toContain("claim-1");
  expect(result!.buckets.notMet).toContain("claim-2");
  expect(claimOf(result, "claim-2").verdict).toBe("not_met");
});

it("(ii) bucket counts are recomputed from the claims' verdicts", async () => {
  const { bundle } = await sealEvidenceBundle(
    fixture("result-root-bundle.json"),
  );
  const { result } = await render(bundle);
  expect(result!.bucketCounts).toEqual({
    met: 1,
    notMet: 1,
    notEvaluable: 1,
    failed: 0,
  });
  const close = (
    await render(
      (await sealEvidenceBundle(fixture("result-root-close-bundle.json")))
        .bundle,
    )
  ).result!;
  expect(close.bucketCounts.notMet).toBe(0);
  expect(close.countMismatches).toEqual([]);
});

it("(iv) a close claim reads the state its cited Close's links read, recomputed, with the acknowledging peer record", async () => {
  const { bundle, ids } = await sealEvidenceBundle(
    fixture("result-root-close-bundle.json"),
  );
  const { result } = await render(bundle);
  const claim = claimOf(result, "close-1");
  expect(claim.type).toBe("close");
  expect(claim.failed).toBe(false);
  expect(claim.close).toMatchObject({
    state: "AGREED",
    derivation: "recomputed",
    stateMismatch: false,
    peerRefMismatch: false,
    keyVerified: true,
    ignored: [],
  });
  expect(claim.close!.keyId).toMatch(/^[0-9a-f]{64}$/u);
  expect(claim.close!.links).toHaveLength(1);
  expect(claim.close!.links[0]).toMatchObject({
    type: "acknowledges",
    recordId: ids["close-b"],
    keyVerified: true,
  });
  expect(claim.close!.links[0]!.keyId).toMatch(/^[0-9a-f]{64}$/u);
  expect(JSON.stringify(claim.close)).toContain("airline-sor");
  // the cited Close and the peer record resolve as citations
  expect(result!.records.has(ids["close-a"]!)).toBe(true);
  expect(result!.records.has(ids["close-b"]!)).toBe(true);
});

it("(iv) a Close relabelled AGREED over a rebuts link reads CONTESTED with a state mismatch -- never the asserted AGREED", async () => {
  const source = fixture("result-root-close-bundle.json");
  const header = ((source.disclosures as Obj)["close-b"] as Obj)
    .agent_input as Obj;
  (header.links as Obj[])[0]!.type = "rebuts";
  const { bundle } = await sealEvidenceBundle(source);
  const { result } = await render(bundle);
  const claim = claimOf(result, "close-1");
  expect(claim.close).toMatchObject({
    state: "CONTESTED",
    asserted: "AGREED",
    derived: "CONTESTED",
    derivation: "recomputed",
    stateMismatch: true,
  });
  expect(claim.close!.links.map((link) => link.type)).toEqual(["rebuts"]);
  // The mismatch FAILS the claim (2026-09-28, second pass), with the stated
  // values kept beside it.
  expect(claim.failed).toBe(true);
  expect(claim.failedOn).toBe("close_state");
  expect(claim.verdict).toBe("met");
  expect(claim.sufficiency).toBe("SATISFIED");
  expect(claim.failure).toBe(
    "close_state mismatch: asserted AGREED, the cited Close's links read CONTESTED",
  );
  // the producer's listing stays; the recomputed met is one, with a count
  // mismatch (stated two); the verifier's failed is one
  expect(result!.buckets.met).toContain("close-1");
  expect(result!.bucketCounts.met).toBe(1);
  expect(result!.bucketCounts.failed).toBe(1);
  expect(result!.countMismatches).toContainEqual({
    field: "buckets.met",
    stated: 2,
    recomputed: 1,
  });
  // the standing claim is untouched
  expect(claimOf(result, "claim-1").verdict).toBe("met");
  expect(claimOf(result, "claim-1").failed).toBe(false);
});

// Maintainer's third pass (2026-09-29): a self-acknowledged Close (the
// acknowledger from the Close's own book) used to render as verified AGREED.
// Now the link is not from the counterparty -- the named peer's book under a
// different key -- so it makes no state: UNILATERAL with a state mismatch,
// the claim fails, and the ignored link is kept with its reason. A
// third-book or same-key acknowledger fails identically.
it("(iv) a self-acknowledged Close never reads as verified AGREED: UNILATERAL, state mismatch, the claim failed, the link ignored", async () => {
  const source = fixture("result-root-close-bundle.json");
  const header = ((source.disclosures as Obj)["close-b"] as Obj)
    .agent_input as Obj;
  header.book_id = "airline"; // the Close's own book
  const { bundle, ids } = await sealEvidenceBundle(source);
  const { result } = await render(bundle);
  const claim = claimOf(result, "close-1");
  expect(claim.failedOn).toBe("close_state");
  expect(claim.close).toMatchObject({
    state: "UNILATERAL",
    asserted: "AGREED",
    stateMismatch: true,
    links: [],
  });
  expect(
    claim.close!.ignored.map((link) => [link.type, link.recordId, link.reason]),
  ).toEqual([
    [
      "acknowledges",
      ids["close-b"],
      "the linking record is from the Close's own book",
    ],
  ]);
  expect(claim.failure).toBe(
    `close_state mismatch: asserted AGREED, the cited Close's links read UNILATERAL (ignored acknowledges from ${ids["close-b"]}: the linking record is from the Close's own book)`,
  );
});

// Maintainer's fourth pass (2026-09-29): a key_id whose Producer Envelope
// does not verify under it is a stated key_id (not verified) and never makes
// a state -- here the peer's record carries its key_id with no signature.
it("(iv) a peer record whose key_id is only stated is ignored as 'stated key_id (not verified)' and never makes AGREED", async () => {
  const { bundle, ids } = await sealEvidenceBundle(
    fixture("result-root-close-bundle.json"),
    { unsigned: ["close-b"] },
  );
  const { result } = await render(bundle);
  const claim = claimOf(result, "close-1");
  expect(claim.failedOn).toBe("close_state");
  expect(claim.close!.state).toBe("UNILATERAL");
  expect(claim.close!.links).toEqual([]);
  expect(
    claim.close!.ignored.map((link) => [link.type, link.recordId, link.reason]),
  ).toEqual([
    [
      "acknowledges",
      ids["close-b"],
      "stated key_id (not verified): the linking record's Producer Envelope does not verify under its key_id",
    ],
  ]);
});

it("(iv) a Close whose own key_id is only stated has its signer unverified", async () => {
  const { bundle } = await sealEvidenceBundle(
    fixture("result-root-close-bundle.json"),
    { unsigned: ["close-a"] },
  );
  const { result } = await render(bundle);
  const close = claimOf(result, "close-1").close!;
  expect(close.keyVerified).toBe(false);
  expect(close.keyId).toMatch(/^[0-9a-f]{64}$/u);
  expect(close.links).toEqual([]);
});

it("(iv) a peer_close_ref that is not the counterparty record fails the claim on that rule", async () => {
  const source = fixture("result-root-close-bundle.json");
  const claim = (((source.disclosures as Obj).result as Obj).agent_input as Obj)
    .claims as Obj[];
  ((claim[1]!.close as Obj).peer_close_ref as Obj).digest = "close-a";
  const { bundle } = await sealEvidenceBundle(source);
  const { result } = await render(bundle);
  const shown = claimOf(result, "close-1");
  expect(shown.failed).toBe(true);
  expect(shown.failedOn).toBe("peer_close_ref");
  expect(shown.close!.peerRefMismatch).toBe(true);
  expect(shown.close!.stateMismatch).toBe(false);
  expect(result!.bucketCounts.failed).toBe(1);
});

it("(iv) a close whose peer never linked to it fails the same way -- UNILATERAL with a state mismatch, never met", async () => {
  const source = fixture("result-root-close-bundle.json");
  const header = ((source.disclosures as Obj)["close-b"] as Obj)
    .agent_input as Obj;
  (header.links as Obj[])[0]!.type = "cites";
  const { bundle } = await sealEvidenceBundle(source);
  const { result } = await render(bundle);
  const claim = claimOf(result, "close-1");
  expect(claim.close!.state).toBe("UNILATERAL");
  expect(claim.close!.stateMismatch).toBe(true);
  expect(claim.failed).toBe(true);
  expect(result!.bucketCounts.met).toBe(1);
  expect(result!.bucketCounts.failed).toBe(1);
  // the honest close bundle fails nothing
  const clean = (
    await render(
      (await sealEvidenceBundle(fixture("result-root-close-bundle.json")))
        .bundle,
    )
  ).result!;
  expect(clean.claims.some((c) => c.failed)).toBe(false);
  expect(clean.bucketCounts.failed).toBe(0);
});

it("(iv) a close whose cited Close is not in this bundle reads the asserted state as producer-asserted, never recomputed", async () => {
  const source = fixture("result-root-close-bundle.json");
  (
    ((resultOf(source).claims as Obj[])[1]!.close as Obj).close_ref as Obj
  ).digest = ABSENT_ID;
  const { bundle } = await sealEvidenceBundle(source);
  const { result } = await render(bundle);
  const claim = claimOf(result, "close-1");
  expect(claim.close).toMatchObject({
    closeRef: ABSENT_ID,
    state: "AGREED",
    asserted: "AGREED",
    derivation: "producer-asserted",
    stateMismatch: false,
  });
  expect(claim.close!.derived).toBeUndefined();
  expect(result!.records.has(ABSENT_ID)).toBe(false);
});

it("the committed sealed Result-root bundle is the seal of the readable fixture", async () => {
  // The presentation-resolution vectors read the sealed file as an input.
  const { bundle } = await sealEvidenceBundle(
    fixture("result-root-bundle.json"),
  );
  expect(bundle).toEqual(fixture("result-root-bundle.sealed.json"));
});

it("(ER 4.2) has the fourth bucket only when the contract switches out_of_scope on, never under met", async () => {
  const source = fixture("result-root-bundle.json");
  const doc = resultOf(source);
  const claims = doc.claims as Obj[];
  claims[0]!.out_of_scope_allowed = true;
  claims[1]!.out_of_scope_allowed = true;
  claims[1]!.verdict = "out_of_scope";
  const buckets = (doc.aggregate as Obj).buckets as Obj;
  buckets.not_met = [];
  buckets.out_of_scope = ["claim-2"];
  const { result } = await render((await sealEvidenceBundle(source)).bundle);
  expect(result!.buckets.outOfScope).toEqual(["claim-2"]);
  expect(result!.bucketCounts.outOfScope).toBe(1);
  expect(result!.buckets.met).not.toContain("claim-2");
  expect(result!.countMismatches).toEqual([]);
  expect(claimOf(result, "claim-2").outOfScopeAllowed).toBe(true);

  // a Result that does not switch it on has no fourth bucket
  const plain = (
    await render(
      (await sealEvidenceBundle(fixture("result-root-bundle.json"))).bundle,
    )
  ).result!;
  expect(plain.buckets.outOfScope).toBeUndefined();
  expect(plain.bucketCounts.outOfScope).toBeUndefined();
});

it("(ER 4.3) keeps claims not yet in force apart from the buckets, as of the Result's date", async () => {
  const source = fixture("result-root-bundle.json");
  const doc = resultOf(source);
  const claims = doc.claims as Obj[];
  claims[0]!.applies_from = "2026-01-01";
  claims[1]!.applies_from = "2027-08-02";
  const aggregate = doc.aggregate as Obj;
  (aggregate.buckets as Obj).not_met = [];
  Object.assign(aggregate.coverage as Obj, {
    evaluated_population: 2,
    not_yet_in_force: 1,
  });
  const { result } = await render((await sealEvidenceBundle(source)).bundle);
  expect(result!.coverage).toEqual({
    evaluatedPopulation: 2,
    excludedNotApplicable: 1,
    unknownCount: 0,
    notYetInForce: 1,
  });
  expect(result!.countMismatches).toEqual([]);
  expect(result!.generatedAt.slice(0, 10)).toBe("2026-09-16");
  const later = claimOf(result, "claim-2");
  expect(later.later).toBe(true);
  expect(later.appliesFrom).toBe("2027-08-02");
  expect(later.verdict).toBe("not_met");
  expect(result!.buckets.notMet).not.toContain("claim-2");
  expect(result!.bucketCounts.notMet).toBe(0);
  expect(claimOf(result, "claim-1").later).toBe(false);
});

it("(ER 4.3) a later claim whose evidence is not in the bundle is unsupported, never its stated verdict", async () => {
  const source = fixture("result-root-bundle.json");
  const doc = resultOf(source);
  const claims = doc.claims as Obj[];
  claims[0]!.applies_from = "2027-08-02";
  (claims[0]!.evidence as Obj[])[0]!.digest = ABSENT_ID;
  const aggregate = doc.aggregate as Obj;
  (aggregate.buckets as Obj).met = [];
  Object.assign(aggregate.coverage as Obj, {
    evaluated_population: 2,
    not_yet_in_force: 1,
  });
  const { result } = await render((await sealEvidenceBundle(source)).bundle);
  const claim = claimOf(result, "claim-1");
  expect(claim.later).toBe(true);
  expect(claim.appliesFrom).toBe("2027-08-02");
  expect(claim.support).toBe("unsupported");
});

it("(ER 4.3) a later Close that failed verification is failed, in the failed count, never its stated verdict", async () => {
  const source = fixture("result-root-close-bundle.json");
  const header = ((source.disclosures as Obj)["close-b"] as Obj)
    .agent_input as Obj;
  (header.links as Obj[])[0]!.type = "rebuts";
  const doc = resultOf(source);
  const close = (doc.claims as Obj[]).find((c) => c.id === "close-1")!;
  close.applies_from = "2099-01-01";
  const aggregate = doc.aggregate as Obj;
  const buckets = aggregate.buckets as Obj;
  for (const key of Object.keys(buckets))
    buckets[key] = (buckets[key] as string[]).filter((id) => id !== "close-1");
  const coverage = aggregate.coverage as Obj;
  coverage.evaluated_population = (coverage.evaluated_population as number) - 1;
  coverage.not_yet_in_force = 1;
  const { result } = await render((await sealEvidenceBundle(source)).bundle);
  expect(result!.bucketCounts.failed).toBe(1);
  const claim = claimOf(result, "close-1");
  expect(claim.later).toBe(true);
  expect(claim.appliesFrom).toBe("2099-01-01");
  expect(claim.failed).toBe(true);
});
