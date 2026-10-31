import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  computeCapsuleId,
  decodeCapsuleJson,
  verifyClass1,
  type Finding,
} from "../src/verify.js";

// verify does bounded work on hostile numbers (#383, the #381 shape). A wide
// array under a long key used to make the walk build a full path for every
// member and keep a finding per failing number: about 125 GB for a 1 MB
// record. The shared fixture pins the same findings for every implementation.

const NUMBER_CODES = new Set([
  "float_in_digest_field",
  "unsafe_integer_in_digest_field",
]);

const numberFindings = (findings: readonly Finding[]) =>
  findings.filter((f) => NUMBER_CODES.has(f.code));

describe("verify number findings", () => {
  it("match the shared fixture", async () => {
    const text = readFileSync(
      resolve(
        process.cwd(),
        "..",
        "vectors",
        "cross-language",
        "verify-number-findings.json",
      ),
      "utf8",
    );
    const { expected } = JSON.parse(text) as {
      expected: { code: string; path: string }[];
    };
    const found = numberFindings(
      (await verifyClass1(decodeCapsuleJson(text).record!)).findings,
    );
    expect(found.map((f) => f.code)).toEqual(expected.map((e) => e.code));
    found.forEach((f, i) => {
      // Exactly the path: it ends the detail or a ';' follows it.
      const path = expected[i]!.path;
      expect(
        f.detail.endsWith(` at ${path}`) || f.detail.includes(` at ${path};`),
        `${f.detail} lacks ${path}`,
      ).toBe(true);
    });
  });

  // A well-formed record with 250,000 copies of `value` in one array under a
  // 500 KB key: a little over 1 MB of JSON. The same shape as Rust's
  // tests/verify_bounds.rs.
  async function wideRecord(value: string) {
    const record = decodeCapsuleJson(
      JSON.stringify({
        spec_version: "draft-mih-scitt-agent-action-capsule-05",
        format_version: "4",
        canonicalization_id: "jcs",
        action_id: "wide",
        action_type: "fyi",
        operator: "op",
        developer: "dev@v1",
        timestamp: "2026-09-29T00:00:00Z",
      }).replace(
        /\}$/u,
        `,"model_attestation":{"${"k".repeat(500_000)}":[${Array(250_000).fill(value).join(",")}]}}`,
      ),
    );
    let id = "";
    try {
      id = await computeCapsuleId(record);
    } catch {
      // A float or an unsafe integer has no capsule_id.
    }
    record.capsule_id = id;
    return record;
  }

  it.each([
    ["zeros", "0"],
    ["objects", "{}"],
    ["floats", "0.5"],
    ["unsafe", "9007199254740993"],
  ])(
    "stay bounded for a wide array of %s under a long key",
    async (name, value) => {
      const record = await wideRecord(value);
      // The process's peak resident size (KiB), which only grows: how far a
      // call raises it bounds what the call needed at its peak.
      const before = process.resourceUsage().maxRSS;
      const start = Date.now();
      const result = await verifyClass1(record);
      expect(Date.now() - start).toBeLessThan(10_000);
      // The identity check re-canonicalizes the record; before #383 the floats
      // shape needed about 125 GB.
      expect(process.resourceUsage().maxRSS - before).toBeLessThan(256 * 1024);
      const found = numberFindings(result.findings);
      if (name === "zeros" || name === "objects") {
        expect(result.findings.filter((f) => f.severity === "error")).toEqual(
          [],
        );
        expect(result.ok).toBe(true);
        return;
      }
      expect(result.ok).toBe(false);
      expect(found).toHaveLength(64);
      expect(found[0]!.detail).toContain(
        ` at model_attestation.${"k".repeat(256 - "model_attestation.".length)}...`,
      );
      for (const f of found) expect(f.detail.length).toBeLessThan(600);
    },
  );

  it("refuses input nested beyond the stack before the walk, after both caps would be reached", async () => {
    // Nested past the shared limit (vectors/json-nesting/), the record is
    // refused before any walk, so neither cap nor the stack is reached.
    const record = decodeCapsuleJson(
      `{"a":[${Array(64).fill("0.5").join(",")}],"b":[${Array(64).fill("9007199254740993").join(",")}]}`,
    );
    let deep: unknown = 0;
    for (let i = 0; i < 1_000_000; i++) deep = [deep];
    (record as Record<string, unknown>).z = deep;
    const result = await verifyClass1(record);
    expect(result.ok).toBe(false);
    expect(result.findings.map((f) => f.code)).toEqual([
      "verifier_internal_error",
    ]);
  });
});
