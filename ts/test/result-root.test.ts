import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { verifyBundle } from "../src/bundle.js";
import { EvidenceGraphError } from "../src/evidence-graph.js";
import {
  buildResultRoot,
  CLAIM_REQUIRED,
  DISCLOSED_STATUSES,
  EVIDENCE_STATUSES,
  GRADES,
  isResultRoot,
  PROOF_KINDS,
  RESULT_MEMBERS,
  RESULT_VERSION,
  SUFFICIENCIES,
  TIERS,
  validateEvidenceResult,
  VERDICTS,
} from "../src/result-root.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

type Obj = Record<string, unknown>;

function fixture(name: string): Obj {
  return JSON.parse(
    readFileSync(resolve(process.cwd(), "test", "testdata", name), "utf8"),
  ) as Obj;
}

/** The alias-form Result document inside the readable fixture. */
function resultOf(source: Obj): Obj {
  return ((source.disclosures as Obj).result as Obj).agent_input as Obj;
}

/** The book-form root's disclosed record header, by alias or sealed id. */
function bookHeaderOf(source: Obj, id: string): Obj {
  return ((source.disclosures as Obj)[id] as Obj).agent_input as Obj;
}

const ABSENT_ID =
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

describe("buildResultRoot", () => {
  it("reads coverage, buckets and every claim's axes from the root Result, and resolves cited records", async () => {
    const { bundle, ids } = await sealEvidenceBundle(
      fixture("result-root-bundle.json"),
    );
    expect(await isResultRoot(bundle)).toBe(true);
    const result = await buildResultRoot(bundle);
    expect(result.capsuleId).toBe(ids["result"]);
    expect(result.member).toBe("agent_input");
    expect(result.coverage).toEqual({
      evaluatedPopulation: 3,
      excludedNotApplicable: 1,
      unknownCount: 0,
    });
    expect(result.buckets).toEqual({
      met: ["claim-1"],
      notMet: ["claim-2"],
      notEvaluable: ["claim-3"],
    });
    expect(result.claims.map((claim) => claim.id)).toEqual([
      "claim-1",
      "claim-2",
      "claim-3",
    ]);
    const first = result.claims[0]!;
    expect(first).toMatchObject({
      type: "requirement",
      recognized: true,
      tier: "recomputed",
      grade: "witnessed",
      sufficiency: "SATISFIED",
      verdict: "met",
      support: "supported",
      missing: [],
    });
    expect(first.evidence.map((ref) => ref.digest)).toEqual([
      ids["day-1"],
      ids["day-2"],
    ]);
    expect(first.evidence.every((ref) => ref.resolved)).toBe(true);
    expect(first.proofs).toEqual([
      {
        kind: "inclusion_proof",
        digest:
          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      },
    ]);
    expect(result.claims[2]!.presentation).toMatchObject({
      kind: "analysis",
      status: "WITHHELD",
    });
    // Drill-down records: the two daily reports and the case the claims
    // cite, plus the act the first daily report cites in turn.
    expect([...result.records.keys()].sort()).toEqual(
      [ids["day-1"], ids["day-2"], ids["case-1"], ids["act-1"]].sort(),
    );
    const day = result.records.get(ids["day-1"]!)!;
    expect(day.agentInput.state).toBe("disclosed");
    expect(day.cites).toEqual([ids["act-1"]]);
    expect(day.actionTime).toBe("2026-09-14T23:59:00Z");
    expect(day.logCoordinates).toBeDefined();
    const act = result.records.get(ids["act-1"]!)!;
    expect(act.agentOutput.state).toBe("disclosed");
    expect(act.agentOutput.payload).toEqual({
      reply: "your flight is now on the fourteenth",
    });
  });

  it("(a) rejects a root that is not a Result v0", async () => {
    const week = fixture("week-bundle.json");
    expect(await isResultRoot(week)).toBe(false);
    await expect(buildResultRoot(week)).rejects.toThrow(EvidenceGraphError);
    await expect(buildResultRoot(week)).rejects.toThrow(
      /root is not a Result v0/u,
    );
    const { bundle: rows } = await sealEvidenceBundle(
      fixture("report-rows-bundle.json"),
    );
    expect(await isResultRoot(rows)).toBe(false);
    await expect(buildResultRoot(rows)).rejects.toThrow(EvidenceGraphError);
  });

  it("(a) rejects a root that names itself a Result v0 but is not one, naming the finding", async () => {
    const source = fixture("result-root-bundle.json");
    const result = resultOf(source);
    (result.claims as Obj[])[2]!.verdict = "met"; // under GAP sufficiency
    const { bundle } = await sealEvidenceBundle(source);
    expect(await isResultRoot(bundle)).toBe(true);
    await expect(buildResultRoot(bundle)).rejects.toThrow(
      /claims\[2\]\.verdict: met is not a verdict under sufficiency GAP/u,
    );
  });

  it("(a) rejects a bucket entry that names no claim with that verdict, and a duplicate claim id", async () => {
    const withBadBucket = fixture("result-root-bundle.json");
    ((resultOf(withBadBucket).aggregate as Obj).buckets as Obj).met = [
      "claim-2",
    ];
    await expect(
      buildResultRoot((await sealEvidenceBundle(withBadBucket)).bundle),
    ).rejects.toThrow(
      /buckets\.met: claim-2 is not a claim with that verdict/u,
    );

    const withDuplicate = fixture("result-root-bundle.json");
    (resultOf(withDuplicate).claims as Obj[])[1]!.id = "claim-1";
    await expect(
      buildResultRoot((await sealEvidenceBundle(withDuplicate)).bundle),
    ).rejects.toThrow(/duplicate claim-1/u);
  });

  it("(b) marks a claim whose cited id is not in the bundle as unsupported, never met, never dropped", async () => {
    const source = fixture("result-root-bundle.json");
    const claims = resultOf(source).claims as Obj[];
    ((claims[0]!.evidence as Obj[])[1] as Obj).digest = ABSENT_ID;
    const { bundle, ids } = await sealEvidenceBundle(source);
    const result = await buildResultRoot(bundle);
    expect(result.claims).toHaveLength(3);
    const first = result.claims[0]!;
    expect(first.support).toBe("unsupported");
    expect(first.missing).toEqual([ABSENT_ID]);
    expect(first.evidence).toEqual([
      { digest: ids["day-1"], resolved: true },
      { digest: ABSENT_ID, resolved: false },
    ]);
    // the stated verdict is carried, the support state says it is not to be shown
    expect(first.verdict).toBe("met");
    expect(result.claims[1]!.support).toBe("supported");
    expect(result.records.has(ABSENT_ID)).toBe(false);
  });

  it("(b) marks a claim that cites no evidence at all as unsupported", async () => {
    const source = fixture("result-root-bundle.json");
    (resultOf(source).claims as Obj[])[1]!.evidence = [];
    const result = await buildResultRoot(
      (await sealEvidenceBundle(source)).bundle,
    );
    expect(result.claims[1]).toMatchObject({
      support: "unsupported",
      missing: [],
    });
  });

  it("(c) a tampered claim in the root fails bundle verification and is no longer a disclosed Result", async () => {
    const { bundle, ids } = await sealEvidenceBundle(
      fixture("result-root-bundle.json"),
    );
    const disclosures = bundle.disclosures as Record<string, Obj>;
    const original = disclosures[ids["result"]!]!.agent_input as Obj;
    const tampered = structuredClone(original);
    (tampered.claims as Obj[])[1]!.verdict = "met"; // legal shape, wrong bytes
    ((tampered.aggregate as Obj).buckets as Obj) = {
      met: ["claim-1", "claim-2"],
      not_met: [],
      not_evaluable: ["claim-3"],
    };
    const forged = {
      ...bundle,
      disclosures: {
        ...disclosures,
        [ids["result"]!]: { agent_input: tampered },
      },
    };
    const verification = await verifyBundle(forged);
    const rootDisclosure = verification.disclosures.find(
      (entry) => entry.capsuleId === ids["result"],
    );
    expect(rootDisclosure).toBeDefined();
    expect(rootDisclosure!.status).not.toBe("disclosure_match");
    // the payload no longer hashes to the committed digest, so no Result is disclosed at the root
    expect(await isResultRoot(forged)).toBe(false);
    await expect(buildResultRoot(forged)).rejects.toThrow(EvidenceGraphError);
    // and the untampered bundle still verifies its root disclosure
    const clean = await verifyBundle(bundle);
    expect(
      clean.disclosures.find((entry) => entry.capsuleId === ids["result"])!
        .status,
    ).toBe("disclosure_match");
  });

  it("carries an unknown claim type as unrecognized, with its axes, never dropped", async () => {
    const source = fixture("result-root-bundle.json");
    const claims = resultOf(source).claims as Obj[];
    claims[2]!.type = "reconcile";
    claims[1]!.type = 7;
    const result = await buildResultRoot(
      (await sealEvidenceBundle(source)).bundle,
    );
    expect(result.claims).toHaveLength(3);
    expect(result.claims[0]).toMatchObject({
      type: "requirement",
      recognized: true,
    });
    expect(result.claims[1]).toMatchObject({
      type: "7",
      recognized: false,
      verdict: "not_met",
    });
    expect(result.claims[2]).toMatchObject({
      type: "reconcile",
      recognized: false,
      sufficiency: "GAP",
      tier: "recomputed",
      grade: "countersigned",
    });
  });

  it("accepts a Result carried in the root's agent_output member", async () => {
    const source = fixture("result-root-bundle.json");
    const disclosures = source.disclosures as Record<string, Obj>;
    disclosures.result = { agent_output: disclosures.result!.agent_input };
    const { bundle } = await sealEvidenceBundle(source);
    const result = await buildResultRoot(bundle);
    expect(result.member).toBe("agent_output");
    expect(result.claims).toHaveLength(3);
  });

  describe("book form: the root member is an evidence_result record header", () => {
    // test/testdata/result-root-book-bundle.json is the same Result sealed
    // into an evidence book: disclosures[root].agent_input is the record
    // header evidencebook.Book.Bundle discloses (HeaderMember), record_type
    // evidence_result, links citing the daily reports, statement = the
    // document verbatim. The cited records are the payload fixture's own.
    it("renders as a Result root, headline and coverage equal to the payload form of the same Result", async () => {
      const { bundle, ids } = await sealEvidenceBundle(
        fixture("result-root-book-bundle.json"),
      );
      expect(await isResultRoot(bundle)).toBe(true);
      const book = await buildResultRoot(bundle);
      expect(book.capsuleId).toBe(ids["result"]);
      expect(book.member).toBe("agent_input");
      expect(book.form).toBe("book");

      const sealedPayload = await sealEvidenceBundle(
        fixture("result-root-bundle.json"),
      );
      const payload = await buildResultRoot(sealedPayload.bundle);
      expect(payload.form).toBe("payload");
      expect(book.generatedAt).toBe(payload.generatedAt);
      expect(book.coverage).toEqual(payload.coverage);
      expect(book.buckets).toEqual(payload.buckets);
      // the same records seal to the same ids in both fixtures, so every
      // claim -- axes, support, cited digests, carrier -- is equal too
      expect(book.claims).toEqual(payload.claims);
      expect([...book.records.keys()].sort()).toEqual(
        [...payload.records.keys()].sort(),
      );
      // and the sealed statement is byte-for-byte the sealed payload-form document
      expect(bookHeaderOf(bundle, ids["result"]!).statement).toEqual(
        (sealedPayload.bundle.disclosures as Record<string, Obj>)[
          sealedPayload.ids["result"]!
        ]!.agent_input,
      );
    });

    it("rejects an evidence_result header whose statement is malformed, naming the statement", async () => {
      const source = fixture("result-root-book-bundle.json");
      const statement = bookHeaderOf(source, "result").statement as Obj;
      (statement.claims as Obj[])[2]!.verdict = "met"; // under GAP sufficiency
      const { bundle } = await sealEvidenceBundle(source);
      expect(await isResultRoot(bundle)).toBe(true);
      await expect(buildResultRoot(bundle)).rejects.toThrow(
        /root is not a Result v0: agent_input\.statement\.claims\[2\]\.verdict: met is not a verdict under sufficiency GAP/u,
      );

      const missing = fixture("result-root-book-bundle.json");
      delete bookHeaderOf(missing, "result").statement;
      const sealedMissing = (await sealEvidenceBundle(missing)).bundle;
      expect(await isResultRoot(sealedMissing)).toBe(true);
      await expect(buildResultRoot(sealedMissing)).rejects.toThrow(
        /agent_input\.statement: absent on the evidence_result record header/u,
      );

      const other = fixture("result-root-book-bundle.json");
      bookHeaderOf(other, "result").statement = {
        spec_version: "evaluation-summary/v1",
      };
      await expect(
        buildResultRoot((await sealEvidenceBundle(other)).bundle),
      ).rejects.toThrow(
        /agent_input\.statement\.spec_version: not a member of an Evidence Result v0; agent_input\.statement\.result_version: not evidence-result-v0/u,
      );
    });

    it("rejects a header of another record_type as not a Result root, naming the type", async () => {
      const source = fixture("result-root-book-bundle.json");
      bookHeaderOf(source, "result").record_type = "close";
      const { bundle } = await sealEvidenceBundle(source);
      expect(await isResultRoot(bundle)).toBe(false);
      await expect(buildResultRoot(bundle)).rejects.toThrow(EvidenceGraphError);
      await expect(buildResultRoot(bundle)).rejects.toThrow(
        /root is not a Result v0: agent_input is a book record header of record_type "close", not "evidence_result"/u,
      );
    });

    it("(c) a tampered statement inside the header is no longer a disclosed Result", async () => {
      const { bundle, ids } = await sealEvidenceBundle(
        fixture("result-root-book-bundle.json"),
      );
      const disclosures = bundle.disclosures as Record<string, Obj>;
      const header = structuredClone(
        disclosures[ids["result"]!]!.agent_input as Obj,
      );
      ((header.statement as Obj).claims as Obj[])[1]!.verdict = "met";
      const forged = {
        ...bundle,
        disclosures: {
          ...disclosures,
          [ids["result"]!]: { agent_input: header },
        },
      };
      expect(await isResultRoot(forged)).toBe(false);
      await expect(buildResultRoot(forged)).rejects.toThrow(
        /no disclosed member carries an evidence-result-v0 document or an evidence_result record header/u,
      );
    });
  });

  it("keeps its vocabularies in step with schemas/evidence-result-v0.json", () => {
    const schema = JSON.parse(
      readFileSync(
        new URL("../../schemas/evidence-result-v0.json", import.meta.url),
        "utf8",
      ),
    ) as { $defs: Record<string, Obj> };
    const defs = schema.$defs;
    expect(defs.Tier!.enum).toEqual([...TIERS]);
    expect(defs.Grade!.enum).toEqual([...GRADES]);
    expect(defs.Sufficiency!.enum).toEqual([...SUFFICIENCIES]);
    expect(defs.Verdict!.enum).toEqual([...VERDICTS]);
    expect(defs.EvidenceStatus!.enum).toEqual([...EVIDENCE_STATUSES]);
    expect(defs.DisclosedStatus!.enum).toEqual([...DISCLOSED_STATUSES]);
    expect((defs.ProofRef!.properties as Obj).kind).toEqual({
      enum: [...PROOF_KINDS],
    });
    expect(defs.Claim!.required).toEqual([...CLAIM_REQUIRED]);
    expect(
      ((defs.EvidenceResult!.properties as Obj).result_version as Obj).const,
    ).toBe(RESULT_VERSION);
    // the mirror closes the top level exactly as the schema does, and no
    // further: the members it admits are the schema's own
    expect(defs.EvidenceResult!.additionalProperties).toBe(false);
    expect(Object.keys(defs.EvidenceResult!.properties as Obj)).toEqual([
      ...RESULT_MEMBERS,
    ]);
  });

  it("rejects a key the schema does not define at the top level, and tolerates one below it", () => {
    const source = JSON.parse(
      readFileSync(
        new URL(
          "../../vectors/evidence-result/pos-oo-claims-result.json",
          import.meta.url,
        ),
        "utf8",
      ),
    ) as Obj;
    expect(validateEvidenceResult(source)).toEqual([]);
    expect(validateEvidenceResult({ ...source, score: 0.97 })).toEqual([
      "score: not a member of an Evidence Result v0",
    ]);
    expect(
      validateEvidenceResult({ ...source, view: { spec_version: "view/v0" } }),
    ).toEqual([]);
    // below the top level the mirror is open-world, by design (Q6)
    const aggregate = source.aggregate as Obj;
    expect(
      validateEvidenceResult({
        ...source,
        aggregate: { ...aggregate, score: 0.97 },
        claims: (source.claims as Obj[]).map((claim) => ({
          ...claim,
          note: "tolerated",
        })),
      }),
    ).toEqual([]);
  });

  it("validates the committed positive vector and rejects the committed negatives", () => {
    const dir = new URL("../../vectors/evidence-result/", import.meta.url);
    const read = (name: string): unknown =>
      JSON.parse(readFileSync(new URL(name, dir), "utf8"));
    expect(validateEvidenceResult(read("pos-oo-claims-result.json"))).toEqual(
      [],
    );
    for (const name of [
      "neg-aggregate-without-coverage.json",
      "neg-contract-ref-missing.json",
      "neg-met-with-sufficiency-gap.json",
      "neg-untiered-claim.json",
      "neg-disclosure-carrier-under-withheld.json",
    ])
      expect(validateEvidenceResult(read(name)), name).not.toEqual([]);
  });
});
