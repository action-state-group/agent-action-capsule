import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { hexToBytes } from "../src/producer-envelope-wire.js";
import {
  checkAnchorWitnessed,
  type AnchorWitnessPolicy,
  type AnchorWitnessReport,
} from "../src/witness.js";

// checkAnchorWitnessed against vectors/anchor-witness-v1 (profile v1 §6.2.2),
// the corpus python/tests/test_anchor_witness_v1_vectors.py and Go's
// witness.TestAnchorWitnessVectors run.
const corpus = JSON.parse(
  readFileSync(
    resolve(
      process.cwd(),
      "..",
      "vectors",
      "anchor-witness-v1",
      "vectors.json",
    ),
    "utf8",
  ),
) as {
  policies: Record<string, AnchorWitnessPolicy>;
  cases: {
    name: string;
    anchor: string;
    receipts: string[];
    policy: string | AnchorWitnessPolicy;
    expected: AnchorWitnessReport;
  }[];
};

const policyOf = (policy: string | AnchorWitnessPolicy): AnchorWitnessPolicy =>
  typeof policy === "string" ? corpus.policies[policy]! : policy;

describe("anchor-witness-v1 vectors", () => {
  it.each(corpus.cases.map((c) => [c.name, c] as const))("%s", async (_, c) => {
    const report = await checkAnchorWitnessed(
      c.anchor,
      c.receipts.map(hexToBytes),
      policyOf(c.policy),
    );
    expect(report).toEqual(c.expected);
  });

  it("covers every status", () => {
    expect(new Set(corpus.cases.map((c) => c.expected.status))).toEqual(
      new Set(["PASS", "FAIL", "NOT_CHECKED", "NOT_PRESENT"]),
    );
  });

  it("fails bad inputs without throwing", async () => {
    const policy = corpus.policies.default!;
    const first = corpus.cases[0]!;
    expect(
      (
        await checkAnchorWitnessed(
          "not a digest",
          [new Uint8Array([1])],
          policy,
        )
      ).status,
    ).toBe("FAIL");
    const empty = await checkAnchorWitnessed(
      first.anchor,
      [new Uint8Array()],
      policy,
    );
    expect(empty.status).toBe("FAIL");
    for (const bad of [
      null,
      {},
      { witnesses: "x" },
      { witnesses: [{ name: 1, keys: [] }] },
    ])
      expect(
        (
          await checkAnchorWitnessed(
            first.anchor,
            first.receipts.map(hexToBytes),
            bad,
          )
        ).status,
      ).toBe("NOT_CHECKED");
  });
});
