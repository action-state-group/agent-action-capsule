import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  createEd25519Identity,
  signCapsuleId,
} from "../src/producer-envelope.js";
import { hexToBytes } from "../src/producer-envelope-wire.js";
import {
  addDigitStrings,
  base64UrlCanonical,
  rfc3339Utc,
  structureFailures,
  verifySettlements,
} from "../src/settlement.js";
import { computeCapsuleId } from "../src/verify.js";

const corpus = JSON.parse(
  readFileSync(
    resolve(process.cwd(), "..", "vectors", "settlement", "cases.json"),
    "utf8",
  ),
) as {
  keys: Record<string, { seed_hex: string }>;
  cases: {
    id: string;
    key_policy: Record<string, string>;
    records: {
      label: string;
      capsule: Record<string, unknown>;
      envelope_hex?: string;
      envelope_kid?: string;
    }[];
    wrapped_objects: { digest: string; octets_b64u: string }[];
  }[];
};
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");

/** Re-seal a leg after editing its settlement member, under `role`'s key. */
async function reseal(
  capsule: Record<string, unknown>,
  role: string,
  edit: (settlement: Record<string, unknown>) => void,
): Promise<Record<string, unknown>> {
  const settlement = structuredClone(
    capsule.settlement as Record<string, unknown>,
  );
  edit(settlement);
  const body: Record<string, unknown> = { ...capsule, settlement };
  delete body.capsule_id;
  const id = await computeCapsuleId(body as never);
  const identity = createEd25519Identity(
    hexToBytes(corpus.keys[role]!.seed_hex),
  );
  return {
    ...body,
    capsule_id: id,
    signature: hex(signCapsuleId(id, identity)),
    key_id: hex(identity.publicKey),
  };
}

describe("verifySettlements", () => {
  // pos-x402-two-sided-agreed, with the payee's receive_fee removed: the
  // vectors carry an explicit fee on every x402 leg, so no case reaches the
  // reading of an absent x402 fee.
  const x402 = corpus.cases.find((c) => c.id === "pos-x402-two-sided-agreed")!;
  const legs = async (): Promise<Record<string, unknown>[]> =>
    Promise.all(
      x402.records.map(async (record) =>
        record.label === "x402-payee-observed"
          ? reseal(record.capsule, "payee", (s) => delete s.receive_fee)
          : {
              ...record.capsule,
              signature: record.envelope_hex,
              key_id: record.envelope_kid,
            },
      ),
    );
  const offer = x402.wrapped_objects.map((w) =>
    Buffer.from(w.octets_b64u, "base64url"),
  );

  it("reads an absent x402 fee as zero for the exact scheme it holds the offer of", async () => {
    // The wrapped objects passed as a list of octets, keyed by their digest.
    const report = await verifySettlements(await legs(), {
      keyPolicy: x402.key_policy,
      wrappedObjects: offer.map((octets) => new Uint8Array(octets)),
    });
    expect(report.failures).toEqual([]);
    expect(report.findings).toEqual([]);
    expect(report.settlements).toMatchObject([
      { paymentState: "agreed", agreedStatus: "settled" },
    ]);
    expect(report.keyPolicyApplied).toBe(true);
    expect(report.settlements[0]!.iso20022).toEqual({
      payer_observed: "ACSC",
      payee_observed: "ACCC",
    });
  });

  it("leaves it unstated without the offer's octets", async () => {
    const records = await legs();
    const report = await verifySettlements(records);
    expect(report.findings).toEqual([
      { records: [records[2]!.capsule_id], code: "fee_unstated" },
    ]);
    expect(report.settlements).toMatchObject([{ paymentState: "unjoined" }]);
    expect(report.keyPolicyApplied).toBe(false);
  });

  it("compares amounts beyond 2^53 exactly", async () => {
    // 2^53 + 1 cannot be told from 2^53 as a JavaScript number.
    const records = await Promise.all(
      x402.records.map(async (record) => {
        const role = record.capsule.settlement as { sealer_role: string };
        const label = record.label;
        if (label === "x402-terms")
          return {
            ...record.capsule,
            signature: record.envelope_hex,
            key_id: record.envelope_kid,
          };
        return reseal(record.capsule, role.sealer_role, (s) => {
          for (const name of ["amount", "received"])
            if (s[name] !== undefined)
              (s[name] as { value: string }).value =
                label === "x402-payer-observed"
                  ? "9007199254740993"
                  : "9007199254740992";
        });
      }),
    );
    // The legs' terms_ref still names the unchanged terms leg.
    const report = await verifySettlements(records, {
      keyPolicy: x402.key_policy,
    });
    expect(report.settlements).toMatchObject([
      { paymentState: "mismatch", differs: ["amount"] },
    ]);
  });

  it("compares amounts of thousands of digits as digit strings", async () => {
    // payer 10^5000 against received 10^5000 - 1 plus a receive_fee.
    const state = async (fee: string) => {
      const records = await Promise.all(
        x402.records.map(async (record) => {
          const role = record.capsule.settlement as { sealer_role: string };
          if (
            record.label !== "x402-payer-observed" &&
            record.label !== "x402-payee-observed"
          )
            return {
              ...record.capsule,
              signature: record.envelope_hex,
              key_id: record.envelope_kid,
            };
          return reseal(record.capsule, role.sealer_role, (s) => {
            const set = (name: string, value: string) =>
              ((s[name] as { value: string }).value = value);
            if (record.label === "x402-payer-observed")
              set("amount", `1${"0".repeat(5000)}`);
            else {
              set("received", "9".repeat(5000));
              set("receive_fee", fee);
            }
          });
        }),
      );
      const report = await verifySettlements(records, {
        keyPolicy: x402.key_policy,
        wrappedObjects: offer.map((octets) => new Uint8Array(octets)),
      });
      return report.settlements[0]!.paymentState;
    };
    expect(await state("1")).toBe("agreed");
    expect(await state("2")).toBe("mismatch");
  });

  it("adds decimal digit strings", () => {
    expect(addDigitStrings("0", "0")).toBe("0");
    expect(addDigitStrings("999", "1")).toBe("1000");
    expect(addDigitStrings("1", "9".repeat(5000))).toBe(`1${"0".repeat(5000)}`);
    expect(addDigitStrings("123", "877")).toBe("1000");
  });

  it("reports inputs that are not Capsules, never throws", async () => {
    const report = await verifySettlements([null, "x", { capsule_id: 1 }]);
    expect(report.conforming).toBe(false);
    expect(report.failures.map((f) => f.code).slice(0, 2)).toEqual([
      "capsule_invalid",
      "capsule_invalid",
    ]);
    expect(report.failures[0]!.records).toEqual([null]);
  });

  it("names the draft's structural codes", () => {
    expect(structureFailures(null)).toEqual(["settlement_malformed"]);
    expect(
      structureFailures({
        version: "0",
        leg: "payer_observed",
        sealer_role: "payee",
        terms_ref: "0".repeat(64),
        amount: { value: "1.5", assetCode: "USD", assetScale: 2 },
        payment_ref: { type: "acp.order_id", value: "o-1" },
        status: "settled",
        observed_at: "2026-10-15T00:00:00Z",
      }),
    ).toEqual(["leg_role_mismatch", "amount_not_exact"]);
    // A trailing newline is not part of a value, a digest or a timestamp.
    expect(
      structureFailures({
        version: "0",
        leg: "terms",
        sealer_role: "payee",
        amount: { value: "15\n", assetCode: "USD", assetScale: 2 },
      }),
    ).toEqual(["amount_not_exact"]);
  });

  const observed = (overrides: Record<string, unknown>) => ({
    version: "0",
    leg: "payer_observed",
    sealer_role: "payer",
    terms_ref: "0".repeat(64),
    amount: { value: "15", assetCode: "USD", assetScale: 2 },
    payment_ref: { type: "acp.order_id", value: "o-1" },
    status: "settled",
    observed_at: "2026-10-15T00:00:00Z",
    ...overrides,
  });

  it("matches patterns against the whole string, in ASCII digits", () => {
    expect(structureFailures(observed({}))).toEqual([]);
    for (const overrides of [
      { terms_ref: `${"0".repeat(64)}\n` },
      { observed_at: "2026-10-15T00:00:00Z\n" },
      { observed_at: "２０２6-10-15T00:00:00Z" },
      { observed_at: "٢٠٢6-10-15T00:00:00Z" },
    ])
      expect(structureFailures(observed(overrides))).toEqual([
        "settlement_malformed",
      ]);
  });

  it("requires every RFC 3339 UTC time to name a real instant", () => {
    for (const when of [
      "2026-02-30T00:00:00Z",
      "2026-02-29T00:00:00Z", // 2026 is not a leap year
      "1900-02-29T00:00:00Z", // nor is 1900
      "2026-04-31T00:00:00Z",
      "2026-13-01T00:00:00Z",
      "2026-00-10T00:00:00Z",
      "2026-01-00T00:00:00Z",
      "2026-01-01T24:00:00Z",
      "2026-01-01T00:60:00Z",
      "2026-12-31T23:59:60Z", // no leap second
    ])
      expect(structureFailures(observed({ observed_at: when }))).toEqual([
        "settlement_malformed",
      ]);
    for (const when of [
      "2024-02-29T12:00:00.25Z",
      "2000-02-29T00:00:00Z",
      "2026-12-31T23:59:59Z",
      "0000-01-01T00:00:00Z",
    ]) {
      expect(rfc3339Utc(when)).toBe(true);
      expect(structureFailures(observed({ observed_at: when }))).toEqual([]);
    }
    // valid_until, shipped_at and delivered_at follow the same rule.
    expect(
      structureFailures({
        version: "0",
        leg: "terms",
        sealer_role: "payee",
        amount: { value: "1", assetCode: "USD", assetScale: 2 },
        valid_until: "2026-02-30T00:00:00Z",
      }),
    ).toEqual(["settlement_malformed"]);
    for (const name of ["shipped_at", "delivered_at"])
      expect(
        structureFailures(
          delivered({ carrier: "UPS", [name]: "2026-06-31T00:00:00Z" }),
        ),
      ).toEqual(["settlement_malformed"]);
  });

  it("refuses a null payment_ref and non-string members, never throws", () => {
    expect(structureFailures(observed({ payment_ref: null }))).toEqual([
      "settlement_malformed",
    ]);
    expect(
      structureFailures({
        version: "0",
        leg: "delivered",
        sealer_role: "payer",
        terms_ref: "0".repeat(64),
        observed_at: "2026-10-15T00:00:00Z",
        delivery: { direction: ["received"] },
      }),
    ).toEqual(["settlement_malformed"]);
    const wrapped = { type: "x402.offer", digest_alg: "SHA-256" };
    for (const entry of [
      { ...wrapped, type: ["x402.offer"], digest: "0".repeat(64) },
      { ...wrapped, digest: "0".repeat(64), content: 7 },
    ])
      expect(structureFailures(observed({ wrapped: [entry] }))).toEqual([
        "settlement_malformed",
      ]);
  });

  it("reads wrapped content only as canonical unpadded base64url", () => {
    expect(Array.from(base64UrlCanonical("AQI_-w"))).toEqual([1, 2, 63, 251]);
    expect(base64UrlCanonical("")).toEqual(new Uint8Array());
    // Padding, the standard alphabet, a lone final character and non-zero
    // trailing bits each give a second spelling.
    for (const bad of ["AQI=", "AQI/", "AQIDB", "AR", "AQ I", 7])
      expect(() => base64UrlCanonical(bad)).toThrow(TypeError);
  });

  it("reports wrapped content that is not canonical as a digest mismatch", async () => {
    // Carry each wrapped object's octets inline, spelled by `spell`.
    const inline = (spell: (b64u: string) => string) =>
      Promise.all(
        x402.records.map(async (record) => {
          const settlement = record.capsule.settlement as {
            sealer_role: string;
            wrapped?: unknown[];
          };
          if (!settlement.wrapped?.length)
            return {
              ...record.capsule,
              signature: record.envelope_hex,
              key_id: record.envelope_kid,
            };
          return reseal(record.capsule, settlement.sealer_role, (s) => {
            for (const w of s.wrapped as { digest: string; content?: string }[])
              w.content = spell(
                x402.wrapped_objects.find((o) => o.digest === w.digest)!
                  .octets_b64u,
              );
          });
        }),
      );
    const codes = async (spell: (b64u: string) => string) =>
      (await verifySettlements(await inline(spell))).failures.map(
        (f) => f.code,
      );
    expect(await codes((text) => text)).not.toContain(
      "wrapped_digest_mismatch",
    );
    expect(await codes((text) => `${text}==`)).toContain(
      "wrapped_digest_mismatch",
    );
  });

  it("reports content that does not decode as a digest mismatch, even against the empty digest", async () => {
    const payer = x402.records.find((r) => r.label === "x402-payer-observed")!;
    const emptyDigest = createHash("sha256").digest("hex");
    const leg = (content: string) =>
      reseal(payer.capsule, "payer", (s) => {
        s.wrapped = [
          {
            type: "x402.offer",
            digest_alg: "SHA-256",
            digest: emptyDigest,
            content,
          },
        ];
      });
    const codes = async (content: string) =>
      (await verifySettlements([await leg(content)])).failures.map(
        (f) => f.code,
      );
    expect(await codes("")).not.toContain("wrapped_digest_mismatch");
    expect(await codes("!")).toContain("wrapped_digest_mismatch");
  });

  it("reads deeply nested wrapped JSON as no scheme, never throws", async () => {
    const deep = Buffer.from(`${"[".repeat(200_000)}${"]".repeat(200_000)}`);
    const records = await Promise.all(
      x402.records.map(async (record) => {
        const settlement = record.capsule.settlement as {
          sealer_role: string;
        };
        if (record.label !== "x402-payer-observed")
          return {
            ...record.capsule,
            signature: record.envelope_hex,
            key_id: record.envelope_kid,
          };
        return reseal(record.capsule, settlement.sealer_role, (s) => {
          s.wrapped = [
            {
              type: "x402.payment-payload",
              digest_alg: "SHA-256",
              digest: createHash("sha256").update(deep).digest("hex"),
              content: deep.toString("base64url"),
            },
          ];
        });
      }),
    );
    const report = await verifySettlements(records, {
      keyPolicy: x402.key_policy,
    });
    expect(report.failures).toEqual([]);
    expect(report.settlements).toHaveLength(1);
  });

  it("requires a registered payment_ref type's qualifiers to be strings", () => {
    const ref = { type: "x402.transaction", value: "0xabc" };
    expect(
      structureFailures(
        observed({ payment_ref: { ...ref, network: "eip155:8453" } }),
      ),
    ).toEqual([]);
    for (const network of [true, 1, null, ["eip155:8453"], { id: 1 }])
      expect(
        structureFailures(observed({ payment_ref: { ...ref, network } })),
      ).toEqual(["settlement_malformed"]);
  });

  it("authenticates an envelope only from hex digit pairs", async () => {
    const terms = x402.records.find((r) => r.envelope_hex)!;
    const codes = async (signature: string) =>
      (
        await verifySettlements([
          { ...terms.capsule, signature, key_id: terms.envelope_kid },
        ])
      ).failures.map((f) => f.code);
    const envelope = terms.envelope_hex!;
    expect(await codes(envelope)).not.toContain("envelope_invalid");
    expect(await codes(envelope.toUpperCase())).not.toContain(
      "envelope_invalid",
    );
    for (const bad of [
      ` ${envelope}`,
      `${envelope}\n`,
      `${envelope.slice(0, 2)} ${envelope.slice(2)}`,
    ])
      expect(await codes(bad)).toContain("envelope_invalid");
  });

  const delivered = (delivery: Record<string, unknown>) => ({
    version: "0",
    leg: "delivered",
    sealer_role: "payee",
    terms_ref: "0".repeat(64),
    observed_at: "2026-10-15T00:00:00Z",
    delivery: { direction: "sent", ...delivery },
  });

  it("keeps the types of optional delivery members", () => {
    expect(
      structureFailures(
        delivered({
          carrier: "UPS",
          tracking_digest: "ab".repeat(32),
          address_digest: "cd".repeat(32),
          status: "in_transit",
          shipped_at: "2026-10-15T00:00:00Z",
          delivered_at: "2026-10-16T00:00:00.5Z",
        }),
      ),
    ).toEqual([]);
    for (const delivery of [
      { carrier: null },
      { carrier: 7 },
      { carrier: "UPS", tracking_digest: "AB".repeat(32) },
      { carrier: "UPS", tracking_digest: "ab" },
      { carrier: "UPS", address_digest: 1 },
      { carrier: "UPS", status: "lost" },
      { carrier: "UPS", status: ["delivered"] },
      { carrier: "UPS", shipped_at: "yesterday" },
      { carrier: "UPS", shipped_at: "2026-10-15T00:00:00+00:00" },
      { carrier: "UPS", delivered_at: null },
    ])
      expect(structureFailures(delivered(delivery))).toEqual([
        "settlement_malformed",
      ]);
  });

  it("reads terms valid_until as an RFC 3339 UTC time", () => {
    const terms = {
      version: "0",
      leg: "terms",
      sealer_role: "payee",
      amount: { value: "1", assetCode: "USD", assetScale: 2 },
    };
    expect(
      structureFailures({ ...terms, valid_until: "2026-10-16T00:00:00Z" }),
    ).toEqual([]);
    for (const valid_until of [7, null, "2026-10-16", "2026-10-16T00:00:00Z\n"])
      expect(structureFailures({ ...terms, valid_until })).toEqual([
        "settlement_malformed",
      ]);
  });

  it("reports a capsule_id that is not a string as null", async () => {
    const report = await verifySettlements([{ capsule_id: 1 }]);
    expect(report.failures[0]).toEqual({
      records: [null],
      code: "capsule_invalid",
    });
  });

  it("agrees two heads on one side that state one amount at two scales", async () => {
    const payer = x402.records.find((r) => r.label === "x402-payer-observed")!;
    const rescaled = await reseal(payer.capsule, "payer", (s) => {
      const amount = s.amount as { value: string; assetScale: number };
      s.amount = {
        ...amount,
        value: `${amount.value}00`,
        assetScale: amount.assetScale + 2,
      };
    });
    const records = [
      ...x402.records.map((record) => ({
        ...record.capsule,
        signature: record.envelope_hex,
        key_id: record.envelope_kid,
      })),
      rescaled,
    ];
    const report = await verifySettlements(records, {
      keyPolicy: x402.key_policy,
      wrappedObjects: offer.map((octets) => new Uint8Array(octets)),
    });
    // Both payer legs are heads: neither is excluded.
    expect(report.failures).toEqual([]);
    expect(report.settlements).toMatchObject([{ paymentState: "agreed" }]);
    // At another value they differ.
    const other = await reseal(payer.capsule, "payer", (s) => {
      (s.amount as { value: string }).value = "1";
    });
    const differing = await verifySettlements(
      [...records.slice(0, -1), other],
      {
        keyPolicy: x402.key_policy,
        wrappedObjects: offer.map((octets) => new Uint8Array(octets)),
      },
    );
    expect(differing.settlements).toMatchObject([{ paymentState: "mismatch" }]);
  });
});
