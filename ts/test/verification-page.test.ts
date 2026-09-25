import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { verifyBundle } from "../src/bundle.js";
import {
  buildVerificationPageModel,
  unboundRecordIds,
  VERIFY_INDEPENDENTLY_LINE,
} from "../src/verification-page.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

function fixture(name: string): unknown {
  return JSON.parse(
    readFileSync(resolve(process.cwd(), "test", "testdata", name), "utf8"),
  );
}

const bannedWords = [
  "certificate",
  "proves",
  "proof",
  "tamper-proof",
  "tamperproof",
  "first",
];

describe("buildVerificationPageModel", () => {
  it("surfaces the bundle digest, checkpoint root and size", async () => {
    const bundle = fixture("week-bundle.json");
    const verified = await verifyBundle(bundle);
    const model = buildVerificationPageModel(bundle, verified);
    expect(model.bundleDigest).toBe(verified.bundleDigest);
    expect(model.checkpointRoot).toBe(
      (bundle as { checkpoint: { root: string } }).checkpoint.root,
    );
    expect(model.checkpointSize).toBe(
      (bundle as { checkpoint: { mmr_size: number } }).checkpoint.mmr_size,
    );
  });

  it("carries exactly ten checks, each with a five-word result", async () => {
    const bundle = fixture("week-bundle.json");
    const verified = await verifyBundle(bundle);
    const model = buildVerificationPageModel(bundle, verified);
    expect(model.checks).toHaveLength(10);
    for (const check of model.checks) {
      expect(check.result.trim().split(/\s+/u)).toHaveLength(5);
      for (const banned of bannedWords)
        expect(check.result.toLowerCase()).not.toContain(banned);
    }
  });

  it("reports the completeness statement from the bundle's own completeness block", async () => {
    const bundle = fixture("week-bundle.json") as {
      completeness: {
        closure_depth: number;
        records_mode: string;
        payloads_mode: string;
        suppressed_fields: string[];
      };
    };
    const verified = await verifyBundle(bundle);
    const model = buildVerificationPageModel(bundle, verified);
    expect(model.completeness).toEqual({
      closureDepth: bundle.completeness.closure_depth,
      recordsMode: bundle.completeness.records_mode,
      payloadsMode: bundle.completeness.payloads_mode,
      suppressedFields: bundle.completeness.suppressed_fields,
    });
  });

  it("never labels itself a certificate and states the verify-independently line", async () => {
    const bundle = fixture("week-bundle.json");
    const verified = await verifyBundle(bundle);
    const model = buildVerificationPageModel(bundle, verified);
    expect(model.verifyIndependentlyLine).toBe(VERIFY_INDEPENDENTLY_LINE);
    expect(model.verifyIndependentlyLine).toContain(
      "verify.agentactioncapsule.org",
    );
    expect(model.verifyIndependentlyLine.toLowerCase()).not.toContain(
      "certificate",
    );
  });

  it("only shows a receipt grade as one of the two receipt-header words, never a client-ladder word", async () => {
    const bundle = fixture("week-bundle.json") as Record<string, unknown>;
    const withReceipts = {
      ...bundle,
      receipts: [
        {
          witness: "anchor.agentactioncapsule.org",
          grade: "mmr-verified",
          time: "2026-09-15T00:00:00Z",
        },
        {
          witness: "rekor.sigstore.dev",
          grade: "countersigned-observed",
          time: "2026-09-15T01:00:00Z",
        },
        // A client-ladder word is never a grade -- must be dropped, not shown.
        {
          witness: "bad-actor.example",
          grade: "witnessed",
          time: "2026-09-15T02:00:00Z",
        },
      ],
    };
    const verified = await verifyBundle(withReceipts);
    const model = buildVerificationPageModel(withReceipts, verified);
    expect(model.receipts).toEqual([
      {
        witness: "anchor.agentactioncapsule.org",
        grade: "consistency-verified",
        time: "2026-09-15T00:00:00Z",
      },
      {
        witness: "rekor.sigstore.dev",
        grade: "existence-and-time",
        time: "2026-09-15T01:00:00Z",
      },
    ]);
  });

  it("fails the graph-closure check when the bundle is malformed", async () => {
    const verified = await verifyBundle({ not: "a bundle" });
    const model = buildVerificationPageModel({ not: "a bundle" }, verified);
    const closure = model.checks.find(
      (check) => check.name === "Graph closure",
    );
    expect(closure?.status).toBe("fail");
  });
});

describe("checkpoint coverage (records outside any checkpoint)", () => {
  it("names the unbound records from the verifier's own findings and gives every record its own status", async () => {
    const { bundle, ids } = await sealEvidenceBundle(
      fixture("report-rows-uncheckpointed-bundle.json") as Record<
        string,
        unknown
      >,
      { uncheckpointed: ["act-backfilled", "act-late"] },
    );
    const verified = await verifyBundle(bundle);
    // the verifier reports the claim as the draft states it: two supplied
    // records are bound to no position, and nothing else is wrong
    expect(verified.perRecordMembership.status).toBe("fail");
    expect([...verified.perRecordMembership.findings].sort()).toEqual(
      [
        `membership_record_unbound:${ids["act-backfilled"]}`,
        `membership_record_unbound:${ids["act-late"]}`,
      ].sort(),
    );
    expect(verified.intervalCoverage.status).toBe("pass");
    expect(verified.graphClosure.status).toBe("pass");
    expect([...unboundRecordIds(verified)].sort()).toEqual(
      [ids["act-backfilled"], ids["act-late"]].sort(),
    );

    const model = buildVerificationPageModel(bundle, verified);
    expect(model.uncheckpointedCount).toBe(2);
    expect(model.records).toHaveLength(4);
    expect(model.records.map((record) => record.capsuleId)).toEqual(
      (bundle.records as Array<{ capsule_id: string }>).map(
        (record) => record.capsule_id,
      ),
    );
    expect(
      Object.fromEntries(
        model.records.map((record) => [record.capsuleId, record.status]),
      ),
    ).toEqual({
      [ids.root!]: "checkpointed",
      [ids["act-live"]!]: "checkpointed",
      [ids["act-backfilled"]!]: "uncheckpointed",
      [ids["act-late"]!]: "uncheckpointed",
    });
    // a checkpoint with no receipt is witnessed by nobody but its producer
    expect(model.receipts).toEqual([]);
    expect(model.selfWitnessed).toBe(true);
  });

  it("counts zero and marks every record checkpointed on a fully covered bundle", async () => {
    const bundle = fixture("week-bundle.json") as { records: unknown[] };
    const model = buildVerificationPageModel(
      bundle,
      await verifyBundle(bundle),
    );
    expect(model.uncheckpointedCount).toBe(0);
    expect(model.records).toHaveLength(bundle.records.length);
    expect(
      model.records.every((record) => record.status === "checkpointed"),
    ).toBe(true);
  });
});
