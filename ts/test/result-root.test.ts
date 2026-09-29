import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { verifyBundle } from "../src/bundle.js";
import { EvidenceGraphError } from "../src/evidence-graph.js";
import {
  buildResultRoot,
  CLAIM_REQUIRED,
  deriveCloseState,
  recomputeCounts,
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

// ---------------------------------------------------------------------------
// The maintainer's adversarial review (2026-09-28): "headline values,
// especially the close state, are producer assertions nothing recomputes: a
// contested close relabelled 'agreed' validates, and 'not met: none' can
// hide a failure." Four fixes, each pinned here: the exact bucket partition,
// cross-checked counts, one headline document per root, and a close state
// derived from the cited Close's links.
// ---------------------------------------------------------------------------

describe("headline values are recomputed, never taken on the producer's word", () => {
  function bucketsOf(source: Obj): Obj {
    return (resultOf(source).aggregate as Obj).buckets as Obj;
  }

  it("(i) rejects a claim that appears in no bucket -- the producer's 'not met: none' over a not_met claim -- naming the claim and its verdict", async () => {
    const hidden = fixture("result-root-bundle.json");
    bucketsOf(hidden).not_met = []; // claim-2 is not_met; the headline says none
    await expect(
      buildResultRoot((await sealEvidenceBundle(hidden)).bundle),
    ).rejects.toThrow(
      /aggregate\.buckets: claim-2 \(not_met\) appears in no bucket/u,
    );
    await expect(
      buildResultRoot((await sealEvidenceBundle(hidden)).bundle),
    ).rejects.toThrow(/aggregate\.buckets: 2 entries for 3 claims/u);
  });

  it("(i) rejects a claim that appears twice across the buckets, and an entry count that is not the claim count", async () => {
    const twice = fixture("result-root-bundle.json");
    bucketsOf(twice).met = ["claim-1", "claim-1"];
    const sealed = (await sealEvidenceBundle(twice)).bundle;
    await expect(buildResultRoot(sealed)).rejects.toThrow(
      /aggregate\.buckets: claim-1 appears 2 times across the buckets/u,
    );
    await expect(buildResultRoot(sealed)).rejects.toThrow(
      /aggregate\.buckets: 4 entries for 3 claims/u,
    );
    // a claim moved into a second bucket with a matching verdict elsewhere
    // is caught by the verdict rule AND the partition
    const moved = fixture("result-root-bundle.json");
    bucketsOf(moved).not_evaluable = ["claim-3", "claim-2"];
    await expect(
      buildResultRoot((await sealEvidenceBundle(moved)).bundle),
    ).rejects.toThrow(/claim-2 appears 2 times across the buckets/u);
    // the honest partition is what the committed fixture carries
    const clean = await buildResultRoot(
      (await sealEvidenceBundle(fixture("result-root-bundle.json"))).bundle,
    );
    expect(clean.countMismatches).toEqual([]);
    expect(clean.bucketCounts).toEqual({
      met: 1,
      notMet: 1,
      notEvaluable: 1,
      failed: 0,
    });
  });

  it("(ii) recomputes evaluated and unresolved from the claims and carries every stated number the claims disagree with; excluded is carried as stated", async () => {
    const inflated = fixture("result-root-bundle.json");
    const coverage = (resultOf(inflated).aggregate as Obj).coverage as Obj;
    coverage.evaluated_population = 4; // three claims
    const result = await buildResultRoot(
      (await sealEvidenceBundle(inflated)).bundle,
    );
    expect(result.coverage).toEqual({
      evaluatedPopulation: 3,
      excludedNotApplicable: 1,
      unknownCount: 0,
    });
    expect(result.statedCoverage.evaluatedPopulation).toBe(4);
    expect(result.countMismatches).toEqual([
      { field: "evaluated_population", stated: 4, recomputed: 3 },
    ]);

    const unresolved = fixture("result-root-bundle.json");
    (resultOf(unresolved).claims as Obj[])[2]!.sufficiency = "UNKNOWN"; // verdict stays not_evaluable
    const hidden = await buildResultRoot(
      (await sealEvidenceBundle(unresolved)).bundle,
    );
    expect(hidden.coverage.unknownCount).toBe(1);
    expect(hidden.statedCoverage.unknownCount).toBe(0);
    expect(hidden.countMismatches).toEqual([
      { field: "unknown_count", stated: 0, recomputed: 1 },
    ]);
  });

  it("(ii) recomputeCounts: a producer 'not met: none' over a not_met claim yields the recomputed 1 and a mismatch -- the count path never returns the stated value", () => {
    // Through buildResultRoot this document is refused by the partition
    // gate (i); the count path is proven on its own so that no loosening of
    // the gate could ever draw the stated number.
    const source = fixture("result-root-bundle.json");
    bucketsOf(source).not_met = [];
    const counts = recomputeCounts(resultOf(source));
    expect(counts.bucketCounts).toEqual({
      met: 1,
      notMet: 1,
      notEvaluable: 1,
      failed: 0,
    });
    expect(counts.mismatches).toEqual([
      { field: "buckets.not_met", stated: 0, recomputed: 1 },
    ]);
    expect(counts.coverage.evaluatedPopulation).toBe(3);
  });

  it("(iii) rejects a bundle carrying two Result v0 documents, naming both, and a root carrying one in both members", async () => {
    const two = fixture("result-root-bundle.json");
    const disclosures = two.disclosures as Record<string, Obj>;
    disclosures["case-1"] = {
      ...disclosures["case-1"],
      agent_output: structuredClone(resultOf(two)),
    };
    const { bundle, ids } = await sealEvidenceBundle(two);
    expect(await isResultRoot(bundle)).toBe(true);
    await expect(buildResultRoot(bundle)).rejects.toThrow(EvidenceGraphError);
    await expect(buildResultRoot(bundle)).rejects.toThrow(
      new RegExp(
        `bundle carries 2 Result v0 documents: root ${ids["result"]} and ${ids["case-1"]}; a bundle has exactly one headline document`,
        "u",
      ),
    );

    const both = fixture("result-root-bundle.json");
    (both.disclosures as Record<string, Obj>).result = {
      agent_input: resultOf(both),
      agent_output: structuredClone(resultOf(both)),
    };
    await expect(
      buildResultRoot((await sealEvidenceBundle(both)).bundle),
    ).rejects.toThrow(
      /carries a Result v0 in both agent_output and agent_input; a bundle has exactly one headline document/u,
    );

    // a book-form Result beside a payload-form root is a second document too
    const book = fixture("result-root-bundle.json");
    (book.disclosures as Record<string, Obj>)["day-2"] = {
      agent_input: {
        record_type: "evidence_result",
        statement: structuredClone(resultOf(book)),
      },
    };
    await expect(
      buildResultRoot((await sealEvidenceBundle(book)).bundle),
    ).rejects.toThrow(/bundle carries 2 Result v0 documents/u);
  });

  describe("(iv) a close claim's state is read from the cited Close's inbound links in this bundle", () => {
    // test/testdata/result-root-close-bundle.json: claim-1 as before, plus
    // close-1 (type close) citing the airline book's Close `close-a` and the
    // peer's Close `close-b`, whose header carries `acknowledges -> close-a`.
    function closeLink(source: Obj): Obj {
      const header = ((source.disclosures as Obj)["close-b"] as Obj)
        .agent_input as Obj;
      return (header.links as Obj[])[0]!;
    }
    function closeClaim(source: Obj): Obj {
      return (resultOf(source).claims as Obj[])[1]!.close as Obj;
    }

    it("recognizes the close claim and recomputes AGREED from the acknowledges link, matching the assertion", async () => {
      const { bundle, ids } = await sealEvidenceBundle(
        fixture("result-root-close-bundle.json"),
      );
      const result = await buildResultRoot(bundle);
      const claim = result.claims[1]!;
      expect(claim).toMatchObject({
        id: "close-1",
        type: "close",
        recognized: true,
        support: "supported",
        verdict: "met",
        failed: false,
      });
      expect(claim.failure).toBeUndefined();
      expect(result.bucketCounts).toEqual({
        met: 2,
        notMet: 0,
        notEvaluable: 0,
        failed: 0,
      });
      expect(claim.close).toEqual({
        closeRef: ids["close-a"],
        period: {
          start: "2026-09-14T00:00:00Z",
          end: "2026-09-15T00:00:00Z",
        },
        asserted: "AGREED",
        derived: "AGREED",
        state: "AGREED",
        derivation: "recomputed",
        stateMismatch: false,
        peerRefMismatch: false,
        peer: "airline-sor",
        peerCloseRef: ids["close-b"],
        links: [{ type: "acknowledges", recordId: ids["close-b"] }],
      });
      expect(result.records.has(ids["close-a"]!)).toBe(true);
      expect(result.countMismatches).toEqual([]);
      expect(deriveCloseState([])).toBe("UNILATERAL");
      expect(
        deriveCloseState([
          { type: "acknowledges", recordId: "x" },
          { type: "rebuts", recordId: "y" },
        ]),
      ).toBe("CONTESTED");
    });

    it("a Close relabelled AGREED over a rebuts link is CONTESTED with a state mismatch -- never AGREED", async () => {
      const source = fixture("result-root-close-bundle.json");
      closeLink(source).type = "rebuts"; // the peer disputes; the Result still says AGREED
      const { bundle, ids } = await sealEvidenceBundle(source);
      const claim = (await buildResultRoot(bundle)).claims[1]!;
      expect(claim.close).toMatchObject({
        asserted: "AGREED",
        derived: "CONTESTED",
        state: "CONTESTED",
        derivation: "recomputed",
        stateMismatch: true,
        peerRefMismatch: false,
        links: [{ type: "rebuts", recordId: ids["close-b"] }],
      });
      // The mismatch FAILS the claim (#140 section 4.1: a verifier MUST
      // fail the claim on mismatch). The stated verdict is carried on the
      // model as the producer's word and is never counted: the claim is
      // under `failed`, not `met`, and the producer's `buckets.met` of two
      // reads as a count mismatch beside the recomputed one.
      expect(claim.failed).toBe(true);
      expect(claim.failure).toBe(
        "close_state mismatch: asserted AGREED, the cited Close's links read CONTESTED",
      );
      expect(claim.verdict).toBe("met");
      const result = await buildResultRoot(bundle);
      expect(result.bucketCounts).toEqual({
        met: 1,
        notMet: 0,
        notEvaluable: 0,
        failed: 1,
      });
      expect(result.countMismatches).toEqual([
        { field: "buckets.met", stated: 2, recomputed: 1 },
      ]);
      expect(result.coverage.evaluatedPopulation).toBe(2);
      expect(result.buckets.met).toEqual(["claim-1", "close-1"]); // the producer's listing, as written
    });

    it("a failed close claim never contributes to met, wherever the producer listed it -- recomputeCounts with the failed set", () => {
      const source = fixture("result-root-close-bundle.json");
      const counts = recomputeCounts(resultOf(source), new Set(["close-1"]));
      expect(counts.bucketCounts).toEqual({
        met: 1,
        notMet: 0,
        notEvaluable: 0,
        failed: 1,
      });
      expect(counts.mismatches).toEqual([
        { field: "buckets.met", stated: 2, recomputed: 1 },
      ]);
      // still in the evaluated population: the producer did evaluate it
      expect(counts.coverage.evaluatedPopulation).toBe(2);
      // and a failed claim's UNKNOWN sufficiency is withheld with the rest
      const unknown = fixture("result-root-close-bundle.json");
      const close = (resultOf(unknown).claims as Obj[])[1]!;
      close.sufficiency = "UNKNOWN";
      close.verdict = "not_evaluable";
      expect(
        recomputeCounts(resultOf(unknown), new Set(["close-1"])).coverage
          .unknownCount,
      ).toBe(0);
      expect(recomputeCounts(resultOf(unknown)).coverage.unknownCount).toBe(1);
    });

    it("a Close asserted AGREED whose peer never linked to it is UNILATERAL with a state mismatch", async () => {
      const source = fixture("result-root-close-bundle.json");
      closeLink(source).type = "cites"; // not an acknowledgement
      const claim = (
        await buildResultRoot((await sealEvidenceBundle(source)).bundle)
      ).claims[1]!;
      expect(claim.close).toMatchObject({
        asserted: "AGREED",
        derived: "UNILATERAL",
        state: "UNILATERAL",
        stateMismatch: true,
        links: [],
      });
      expect(claim.failed).toBe(true);
    });

    it("a peer_close_ref that is not the record carrying the link is a peer-ref mismatch, with the state still recomputed", async () => {
      const source = fixture("result-root-close-bundle.json");
      (closeClaim(source).peer_close_ref as Obj).digest = "day-1"; // cites the wrong record
      const { bundle, ids } = await sealEvidenceBundle(source);
      const claim = (await buildResultRoot(bundle)).claims[1]!;
      expect(claim.close).toMatchObject({
        state: "AGREED",
        stateMismatch: false,
        peerRefMismatch: true,
        peerCloseRef: ids["day-1"],
      });
      // a peer-ref mismatch is marked, not failed: the state itself agrees
      expect(claim.failed).toBe(false);
    });

    it("a close whose cited Close is not a record in this bundle carries the asserted state as producer-asserted, never bare", async () => {
      const source = fixture("result-root-close-bundle.json");
      (closeClaim(source).close_ref as Obj).digest = ABSENT_ID;
      const claim = (
        await buildResultRoot((await sealEvidenceBundle(source)).bundle)
      ).claims[1]!;
      expect(claim.close).toMatchObject({
        closeRef: ABSENT_ID,
        asserted: "AGREED",
        state: "AGREED",
        derivation: "producer-asserted",
        stateMismatch: false,
        links: [],
      });
      expect(claim.close!.derived).toBeUndefined();
      // nothing to compare against: producer-asserted is not a failure
      expect(claim.failed).toBe(false);
    });

    it("a close claim with a body this module cannot read stays an unrecognized row, never a state", async () => {
      const source = fixture("result-root-close-bundle.json");
      closeClaim(source).close_state = "SETTLED";
      const claim = (
        await buildResultRoot((await sealEvidenceBundle(source)).bundle)
      ).claims[1]!;
      expect(claim).toMatchObject({ type: "close", recognized: false });
      expect(claim.close).toBeUndefined();
    });
  });
});
