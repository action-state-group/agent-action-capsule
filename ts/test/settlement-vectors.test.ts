import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  DELIVERY_DIRECTIONS,
  PAYMENT_REF_TYPES,
  SETTLEMENT_LEGS,
  SETTLEMENT_MEMBERS,
  SETTLEMENT_ROLES,
  SETTLEMENT_STATUSES,
  SETTLEMENT_VERSION,
  WRAPPED_TYPES,
  verifySettlements,
  type SettlementIssue,
} from "../src/settlement.js";

// verifySettlements against vectors/settlement, compared as
// python/tests/test_settlement_library.py does (`iso20022` is not carried by
// the vectors).
const DIR = resolve(process.cwd(), "..", "vectors", "settlement");
const read = (name: string): unknown =>
  JSON.parse(readFileSync(resolve(DIR, name), "utf8"));

type Case = {
  id: string;
  key_policy: Record<string, string | string[]>;
  records: {
    label: string;
    capsule: Record<string, unknown>;
    capsule_id: string;
    envelope_hex?: string;
    envelope_kid?: string;
  }[];
  wrapped_objects: { digest: string; octets_b64u: string }[];
  expect: unknown;
};
const corpus = read("cases.json") as { count: number; cases: Case[] };
const registry = read("registry.json") as Record<string, unknown>;

const b64u = (text: string): Uint8Array =>
  new Uint8Array(Buffer.from(text, "base64url"));

async function run(testCase: Case) {
  const labels = new Map<unknown, string>();
  const capsules = testCase.records.map((record) => {
    labels.set(record.capsule_id, record.label);
    return record.envelope_hex
      ? {
          ...record.capsule,
          signature: record.envelope_hex,
          key_id: record.envelope_kid,
        }
      : record.capsule;
  });
  const report = await verifySettlements(capsules, {
    keyPolicy: testCase.key_policy,
    wrappedObjects: Object.fromEntries(
      testCase.wrapped_objects.map((w) => [w.digest, b64u(w.octets_b64u)]),
    ),
  });
  const relabel = (entries: readonly SettlementIssue[]) =>
    entries.map((entry) => ({
      records: entry.records.map((id) => labels.get(id) ?? id),
      code: entry.code,
    }));
  return {
    conforming: report.conforming,
    failures: relabel(report.failures),
    findings: relabel(report.findings),
    settlements: report.settlements.map((s) => ({
      terms: labels.get(s.terms),
      payment_state: s.paymentState,
      ...(s.agreedStatus === undefined
        ? {}
        : { agreed_status: s.agreedStatus }),
      ...(s.termsAmount === undefined ? {} : { terms_amount: s.termsAmount }),
      ...(s.differs === undefined ? {} : { differs: s.differs }),
      delivery_state: s.deliveryState,
    })),
  };
}

describe("settlement vectors", () => {
  it("runs every case", () => {
    expect(corpus.cases).toHaveLength(corpus.count);
    expect(corpus.count).toBe(24);
  });

  it("tables match the draft registry", () => {
    expect(SETTLEMENT_VERSION).toBe(registry.settlement_version);
    expect(SETTLEMENT_LEGS).toEqual(registry.legs);
    expect(SETTLEMENT_ROLES).toEqual(registry.sealer_roles);
    expect(SETTLEMENT_STATUSES).toEqual(registry.statuses);
    expect(DELIVERY_DIRECTIONS).toEqual(registry.delivery_directions);
    expect(WRAPPED_TYPES).toEqual(registry.wrapped_types);
    expect(
      Object.fromEntries(
        Object.entries(PAYMENT_REF_TYPES).map(([type, entry]) => [
          type,
          { qualifiers: entry.qualifiers, receive_fee: entry.receive_fee },
        ]),
      ),
    ).toEqual(
      Object.fromEntries(
        Object.entries(
          registry.payment_ref_types as Record<
            string,
            { qualifiers: string[]; receive_fee: string }
          >,
        ).map(([type, entry]) => [
          type,
          { qualifiers: entry.qualifiers, receive_fee: entry.receive_fee },
        ]),
      ),
    );
    expect(SETTLEMENT_MEMBERS).toEqual(registry.settlement_members);
  });

  it.each(corpus.cases.map((c) => [c.id, c] as const))(
    "%s",
    async (_id, testCase) => {
      expect(await run(testCase)).toEqual(testCase.expect);
    },
  );
});
