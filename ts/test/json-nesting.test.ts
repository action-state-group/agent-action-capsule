import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { verifyBundle } from "../src/bundle.js";
import { decodeStrictJson, jcs, sha256Hex } from "../src/json.js";
import { MAX_NESTING_DEPTH, nestedTooDeep } from "../src/nesting.js";
import { verifyRecordSignature } from "../src/producer-envelope-verification.js";
import { verifySettlements } from "../src/settlement.js";
import { verifyClass1 } from "../src/verify.js";

// vectors/json-nesting/ (#498): objects and arrays nested up to 128 levels
// deep are read and canonicalized; deeper text is refused as malformed and a
// deeper value has no JCS form, as in Go, Python and Rust.

interface NestingCase {
  readonly id: string;
  readonly accept: boolean;
  readonly json: string;
  readonly wraps?: string;
  readonly jcs_sha256?: string;
}

const doc = JSON.parse(
  readFileSync(
    resolve(process.cwd(), "..", "vectors", "json-nesting", "cases.json"),
    "utf8",
  ),
) as { max_nesting_depth: number; cases: NestingCase[] };

/** An array nested `depth` deep around 0, built without recursion. */
function arrays(depth: number): unknown {
  let value: unknown = 0;
  for (let i = 0; i < depth; i += 1) value = [value];
  return value;
}

describe("json-nesting vectors", () => {
  it("state this package's limit", () => {
    expect(doc.max_nesting_depth).toBe(MAX_NESTING_DEPTH);
    expect(MAX_NESTING_DEPTH).toBe(128);
    expect(doc.cases).toHaveLength(9);
  });

  for (const c of doc.cases)
    it(c.id, async () => {
      if (c.accept) {
        const value = decodeStrictJson(c.json);
        expect(nestedTooDeep(value)).toBe(false);
        expect(await sha256Hex(jcs(value))).toBe(c.jcs_sha256);
        return;
      }
      expect(() => decodeStrictJson(c.json)).toThrow(SyntaxError);
      // The platform parser reads deeper text; the value has no JCS form.
      const value: unknown = JSON.parse(c.json);
      expect(nestedTooDeep(value)).toBe(true);
      expect(() => jcs(value)).toThrow(TypeError);
      const twin = doc.cases.find((other) => other.id === c.wraps)!;
      expect(value).toEqual(
        c.json.startsWith("[")
          ? [JSON.parse(twin.json)]
          : { a: JSON.parse(twin.json) },
      );
    });
});

describe("verifiers at the limit", () => {
  it("refuse a Capsule past it with verifier_internal_error only", async () => {
    const atLimit = await verifyClass1({
      deep: arrays(MAX_NESTING_DEPTH - 1),
    } as never);
    expect(atLimit.findings.map((f) => f.code)).not.toContain(
      "verifier_internal_error",
    );
    const past = await verifyClass1({
      deep: arrays(MAX_NESTING_DEPTH),
    } as never);
    expect(past.ok).toBe(false);
    expect(past.findings.map((f) => f.code)).toEqual([
      "verifier_internal_error",
    ]);
  });

  it("refuse a Bundle past it as bundle_malformed", async () => {
    const malformed = { status: "fail", findings: ["bundle_malformed"] };
    const atLimit = await verifyBundle({
      records: [],
      x: arrays(MAX_NESTING_DEPTH - 1),
    });
    expect(atLimit.graphClosure).not.toEqual(malformed);
    const past = await verifyBundle({
      records: [],
      x: arrays(MAX_NESTING_DEPTH),
    });
    expect(past.graphClosure).toEqual(malformed);
    expect(past.intervalCoverage).toEqual(malformed);
    expect(past.perRecordMembership).toEqual(malformed);
  });

  it("count a value that contains itself as too deep", () => {
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    expect(nestedTooDeep(cycle)).toBe(true);
  });
});

describe("record signatures and settlement legs at the limit", () => {
  it("grade a record past it invalid, not unclaimed", async () => {
    const atLimit = await verifyRecordSignature({
      capsule_id: "c",
      x: arrays(MAX_NESTING_DEPTH - 1),
    });
    expect(atLimit.verdict).toBe("unclaimed");
    const past = await verifyRecordSignature({
      capsule_id: "c",
      x: arrays(MAX_NESTING_DEPTH),
    });
    expect(past.verdict).toBe("invalid");
  });

  it("report a settlement leg past it only as capsule_invalid", async () => {
    const report = await verifySettlements([
      { capsule_id: "c1", x: arrays(MAX_NESTING_DEPTH) } as never,
    ]);
    expect(report.failures).toEqual([
      { records: ["c1"], code: "capsule_invalid" },
    ]);
  });

  it("count objects built from class instances as nested", () => {
    class Node {
      child: unknown = null;
    }
    let value: unknown = 0;
    for (let i = 0; i < MAX_NESTING_DEPTH + 1; i++) {
      const node = new Node();
      node.child = value;
      value = node;
    }
    expect(nestedTooDeep(value)).toBe(true);
  });
});
