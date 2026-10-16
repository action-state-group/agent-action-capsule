import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { verifyBundle } from "../src/bundle.js";
import { verifyRecordSignature } from "../src/producer-envelope-verification.js";

// vectors/bundle/strict/README.md: a verifier never raises on its input. A
// Bundle or record nested beyond what an implementation can read is
// refused, the Bundle with bundle_malformed on every claim (INVALID) and a
// record signature as invalid. The depth differs between languages, so no
// vector reaches it.
const vectors = JSON.parse(
  readFileSync(
    resolve(process.cwd(), "..", "vectors", "bundle", "strict", "vectors.json"),
    "utf8",
  ),
) as { cases: { id: string; bundle: Record<string, unknown> }[] };

/** An array nested `depth` deep, built without recursion. */
function nested(depth: number): unknown {
  let value: unknown = 0;
  for (let i = 0; i < depth; i += 1) value = [value];
  return value;
}

const DEPTH = 1_000_000;

function deepBundle(): Record<string, unknown> {
  const bundle = structuredClone(vectors.cases[0]!.bundle) as {
    records: Record<string, unknown>[];
  };
  bundle.records[0]!.deep = nested(DEPTH);
  return bundle;
}

describe("input nested beyond the stack", () => {
  it("refuses the Bundle in plain mode, never rejects", async () => {
    const result = await verifyBundle(deepBundle());
    for (const claim of [
      result.graphClosure,
      result.intervalCoverage,
      result.perRecordMembership,
    ])
      expect(claim).toEqual({ status: "fail", findings: ["bundle_malformed"] });
  });

  it("refuses the Bundle in strict mode as INVALID, never rejects", async () => {
    const { strict } = await verifyBundle(deepBundle(), { strict: true });
    expect(strict).toEqual({
      verdict: "INVALID",
      kindOk: false,
      claims: [
        { name: "records", status: "fail", findings: ["bundle_malformed"] },
      ],
      witnesses: null,
      records: [],
      checkpointAuthenticated: false,
      signerMatchesCheckpoint: null,
    });
  });

  it("grades a record nested that deep as invalid", async () => {
    const record = {
      ...(vectors.cases[0]!.bundle.records as Record<string, unknown>[])[0],
      deep: nested(DEPTH),
    };
    const { verdict, messages } = await verifyRecordSignature(record);
    expect(verdict).toBe("invalid");
    expect(messages).toHaveLength(1);
  });

  it("reports a capsule_id whose toString is not callable, never throws", async () => {
    const record = {
      capsule_id: { toString: null },
      signature: "00",
    };
    expect(await verifyRecordSignature(record)).toEqual({
      verdict: "invalid",
      messages: [
        "capsule_id=<object>: only one of signature/key_id present -- malformed producer envelope",
      ],
    });
    const both = {
      capsule_id: { toString: null },
      signature: "zz",
      key_id: "00",
    };
    const graded = await verifyRecordSignature(both);
    expect(graded.verdict).toBe("invalid");
    expect(graded.messages[0]).toMatch(/^capsule_id=<object>: /u);
    // The same record in a strict Bundle: a verdict, not a rejection.
    const bundle = structuredClone(vectors.cases[0]!.bundle) as {
      records: Record<string, unknown>[];
    };
    bundle.records[0]!.capsule_id = { toString: null };
    const { strict } = await verifyBundle(bundle, { strict: true });
    expect(strict.verdict).toBe("INVALID");
    expect(strict.records[0]!.capsuleId).toBe("");
  });
});
