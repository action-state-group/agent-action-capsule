import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { hexToBytes } from "../src/producer-envelope-wire.js";
import {
  checkCardRegistered,
  type AnchorWitnessPolicy,
  type CardRegisteredReport,
} from "../src/witness.js";

// checkCardRegistered against vectors/card-registration-v0
// (standard-history-v0 §13), the corpus
// python/tests/test_card_registration_v0_vectors.py runs.
const corpus = JSON.parse(
  readFileSync(
    resolve(
      process.cwd(),
      "..",
      "vectors",
      "card-registration-v0",
      "vectors.json",
    ),
    "utf8",
  ),
) as {
  policies: Record<string, AnchorWitnessPolicy>;
  cases: {
    name: string;
    card: string;
    holder: string;
    anchor: string;
    statements: string[];
    policy: string | AnchorWitnessPolicy;
    expected: Omit<CardRegisteredReport, "method">;
  }[];
};

type Case = (typeof corpus.cases)[number];

const policyOf = (policy: string | AnchorWitnessPolicy): AnchorWitnessPolicy =>
  typeof policy === "string" ? corpus.policies[policy]! : policy;

const run = (
  c: Case,
  overrides: Partial<{ holder: string; anchor: string }> = {},
) =>
  checkCardRegistered(
    hexToBytes(c.card),
    overrides.holder ?? c.holder,
    overrides.anchor ?? c.anchor,
    c.statements.map(hexToBytes),
    policyOf(c.policy),
  );

const named = (name: string): Case => {
  const found = corpus.cases.find((c) => c.name === name);
  if (found === undefined) throw new Error(`no case ${name}`);
  return found;
};

describe("card-registration-v0 vectors", () => {
  it.each(corpus.cases.map((c) => [c.name, c] as const))("%s", async (_, c) => {
    const { method, ...report } = await run(c);
    expect(method).toContain("standard-history-v0 §13");
    expect(report).toEqual(c.expected);
  });

  it("has 36 cases and covers every status", () => {
    expect(corpus.cases).toHaveLength(36);
    expect(new Set(corpus.cases.map((c) => c.expected.status))).toEqual(
      new Set(["PASS", "FAIL", "NOT_CHECKED", "NOT_PRESENT"]),
    );
  });

  it("does not depend on statement order", async () => {
    const c = named("pass-beside-fail");
    const report = await checkCardRegistered(
      hexToBytes(c.card),
      c.holder,
      c.anchor,
      c.statements.map(hexToBytes).reverse(),
      policyOf(c.policy),
    );
    expect(report.status).toBe("PASS");
  });

  it("fails another anchor", async () => {
    const c = named("pass-eddsa-time");
    expect((await run(c)).status).toBe("PASS");
    const other = await run(c, { anchor: "11".repeat(32) });
    expect(other.status).toBe("FAIL");
    expect(other.statements).toEqual([
      { status: "FAIL", service: null, registration_time: null },
    ]);
    expect((await run(c, { anchor: c.anchor.toUpperCase() })).status).toBe(
      "FAIL",
    );
  });

  it("fails another holder and bad inputs without throwing", async () => {
    const c = named("pass-eddsa-time");
    expect((await run(c, { holder: "00".repeat(32) })).status).toBe("FAIL");
    const policy = policyOf(c.policy);
    const card = hexToBytes(c.card);
    expect(
      (
        await checkCardRegistered(
          card,
          c.holder,
          c.anchor,
          ["not bytes" as unknown as Uint8Array],
          policy,
        )
      ).status,
    ).toBe("FAIL");
    expect(
      (
        await checkCardRegistered(
          new TextEncoder().encode("not the card"),
          c.holder,
          c.anchor,
          c.statements.map(hexToBytes),
          policy,
        )
      ).status,
    ).toBe("FAIL");
    expect(
      (await checkCardRegistered(card, c.holder, c.anchor, null, policy))
        .status,
    ).toBe("NOT_PRESENT");
  });
});
