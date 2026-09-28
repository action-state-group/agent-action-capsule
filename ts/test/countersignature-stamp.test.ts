import { createHash, sign as edSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  classifyCountersignatures,
  countersignV1SigningInput,
  indexCountersigners,
  pinnedCountersignerSource,
  verifyCountersignV1Signature,
} from "../src/countersignature-stamp.js";
import { bundleDigest } from "../src/bundle.js";
import { createEd25519Identity } from "../src/producer-envelope.js";
import {
  DIRECTORY_SIGNER_KEY_ID,
  countersignerList,
  derivedFixture,
  toHex,
} from "./helpers/derived-fixtures.js";

function testdata(name: string): Buffer {
  return readFileSync(resolve(process.cwd(), "test", "testdata", name));
}

function fixture(name: string): Record<string, unknown> {
  return JSON.parse(testdata(name).toString("utf8")) as Record<string, unknown>;
}

type Entry = {
  type?: string;
  signer: { id: string; key_id: string };
  over: string;
  statement: Record<string, unknown>;
  signature: string;
};

const countersigners = JSON.parse(
  testdata("countersigners.json").toString("utf8"),
) as Array<{ name: string; key_ids: string[] }>;

// capsule-anchor's shared countersign/v1 golden vector, vendored byte for
// byte from capsule-anchor main 4c4365f
// (packages/tests/countersign/vectors/countersign-v1.json). The digest is
// pinned so a local edit, or a drift from the anchor's copy, fails here.
const ANCHOR_VECTOR = "countersign-v1-anchor-golden.json";
const ANCHOR_VECTOR_SHA256 =
  "d057691c3e20f92b815dc47780493f83b594424d8cfb9db13f3782049b3155fb";
const anchor = fixture(ANCHOR_VECTOR) as unknown as {
  bundle: Record<string, unknown>;
  bundle_digest: string;
  directory: { countersigners: Array<{ name: string; key_ids: string[] }> };
  entry: Entry;
  negative: Array<{
    name: string;
    entry: Entry;
    expect: { signature: "valid" | "invalid"; receipt?: "unverified" };
  }>;
  producer_public_key_hex: string;
  signer_seed_hex: string;
  signing_input: string;
};
const anchorCountersigners = anchor.directory.countersigners;

const statementView = {
  checks: [
    { name: "chain consistency", result: "established" },
    { name: "range membership", result: "failed" },
    { name: "key hygiene", result: "not present" },
  ],
  receipt: "absent",
};

async function signedEntry(
  name: "week-bundle-directory-countersigned.json",
): Promise<{ bundle: Record<string, unknown>; entry: Entry; digest: string }> {
  const bundle = await derivedFixture(name);
  const entry = (bundle.countersignatures as Entry[])[0]!;
  return { bundle, entry, digest: await bundleDigest(bundle) };
}

describe("countersign/v1: capsule-anchor's shared golden vector", () => {
  it("is the pinned anchor copy, byte for byte", () => {
    expect(
      createHash("sha256").update(testdata(ANCHOR_VECTOR)).digest("hex"),
    ).toBe(ANCHOR_VECTOR_SHA256);
  });

  it("recomputes the vector's bundle digest, which the entry signs over", async () => {
    expect(await bundleDigest(anchor.bundle)).toBe(anchor.bundle_digest);
    expect(anchor.entry.over).toBe(anchor.bundle_digest);
  });

  it("reproduces the 4-member signing input byte for byte", () => {
    const { over, signer, statement } = anchor.entry;
    expect(
      new TextDecoder().decode(
        countersignV1SigningInput({
          over,
          signer,
          statement,
          type: "countersign/v1",
        }),
      ),
    ).toBe(anchor.signing_input);
  });

  it("verifies the valid entry and resolves it from the vector's countersigner list", async () => {
    const entry = anchor.entry;
    expect(
      await verifyCountersignV1Signature(
        { ...entry, type: "countersign/v1" },
        entry.signer.key_id,
        entry.signature,
      ),
    ).toBe(true);
    expect(
      await classifyCountersignatures(
        [entry],
        await bundleDigest(anchor.bundle),
        [anchor.producer_public_key_hex],
        anchorCountersigners,
      ),
    ).toMatchObject([
      {
        kind: "resolved",
        name: anchorCountersigners[0]!.name,
        // The stamp does not verify receipts: a present one is unverified.
        statement: { receipt: "unverified" },
      },
    ]);
  });

  it("carries every negative the signing fix requires", () => {
    expect(anchor.negative.map((c) => c.name)).toEqual(
      expect.arrayContaining([
        "flipped-result",
        "digest-only-signature",
        "spoofed-signer-id",
        "signature-without-signer",
        "receipt-for-other-statement",
        "receipt-for-other-statement-no-entry-hash",
      ]),
    );
  });

  it.each(anchor.negative.map((c) => [c.name, c] as const))(
    "negative %s fails the way the vector says",
    async (_name, c) => {
      const result = await classifyCountersignatures(
        [c.entry],
        await bundleDigest(anchor.bundle),
        [anchor.producer_public_key_hex],
        anchorCountersigners,
      );
      if (c.expect.signature === "invalid") {
        expect(result).toEqual([{ kind: "invalid" }]);
      } else {
        expect(c.expect.receipt).toBe("unverified");
        expect(result).toMatchObject([
          { kind: "resolved", statement: { receipt: "unverified" } },
        ]);
      }
    },
  );

  it("verifies an absent or empty type as countersign/v1", async () => {
    const digest = await bundleDigest(anchor.bundle);
    const { type: _type, ...untyped } = anchor.entry;
    for (const entry of [untyped, { ...anchor.entry, type: "" }]) {
      expect(
        await classifyCountersignatures(
          [entry],
          digest,
          [],
          anchorCountersigners,
        ),
      ).toMatchObject([{ kind: "resolved" }]);
    }
  });

  it("rejects a signature whose input bound an empty type", async () => {
    const identity = createEd25519Identity(
      Uint8Array.from(Buffer.from(anchor.signer_seed_hex, "hex")),
    );
    expect(toHex(identity.publicKey)).toBe(anchor.entry.signer.key_id);
    const { over, signer, statement } = anchor.entry;
    const signature = toHex(
      edSign(
        null,
        countersignV1SigningInput({ over, signer, statement, type: "" }),
        identity.privateKey,
      ),
    );
    expect(
      await classifyCountersignatures(
        [{ ...anchor.entry, type: "", signature }],
        await bundleDigest(anchor.bundle),
        [],
        anchorCountersigners,
      ),
    ).toEqual([{ kind: "invalid" }]);
  });

  it("renders the anchor's signer as not independent when it is the producer", async () => {
    expect(
      await classifyCountersignatures(
        [anchor.entry],
        await bundleDigest(anchor.bundle),
        [anchor.entry.signer.key_id],
        anchorCountersigners,
      ),
    ).toMatchObject([{ kind: "not-independent" }]);
  });
});

describe("countersigner source", () => {
  it("keeps the committed list in step with the derived fixtures' signer", () => {
    expect(countersigners).toEqual(countersignerList());
  });

  it("never reads countersigners from a witnesses.json document", () => {
    // Countersigners are not rows of the neutral witness directory: even a
    // real key under countersigners[] of a witnesses.json resolves nothing.
    const witnesses = fixture("witnesses-with-placeholder.json") as {
      countersigners: Array<Record<string, unknown>>;
    };
    const filled = {
      ...witnesses,
      countersigners: [
        { ...witnesses.countersigners[0]!, key_ids: [DIRECTORY_SIGNER_KEY_ID] },
      ],
    };
    expect(indexCountersigners(witnesses).size).toBe(0);
    expect(indexCountersigners(filled).size).toBe(0);
  });

  it("resolves a key listed under two names to neither", () => {
    const listing = countersignerList()[0]!;
    const names = indexCountersigners([
      listing,
      { ...listing, name: "Someone Else" },
    ]);
    expect(names.has(DIRECTORY_SIGNER_KEY_ID)).toBe(false);
  });

  it("reads nothing from a source of the wrong shape", () => {
    expect(indexCountersigners(undefined).size).toBe(0);
    expect(
      indexCountersigners([
        { publicKey: DIRECTORY_SIGNER_KEY_ID, name: "Old Flat Array" },
      ]).size,
    ).toBe(0);
  });

  it("loads a list only against its pinned digest", async () => {
    const bytes = new Uint8Array(testdata("countersigners.json"));
    const pinned = createHash("sha256").update(bytes).digest("hex");
    expect(await pinnedCountersignerSource(bytes, pinned)).toEqual(
      countersigners,
    );
    expect(
      await pinnedCountersignerSource(bytes, "00".repeat(32)),
    ).toBeUndefined();
    const witnessBytes = new Uint8Array(
      testdata("witnesses-with-placeholder.json"),
    );
    expect(
      await pinnedCountersignerSource(
        witnessBytes,
        createHash("sha256").update(witnessBytes).digest("hex"),
      ),
    ).toBeUndefined();
  });
});

describe("classifyCountersignatures", () => {
  it("renders the hollow default when countersignatures[] is absent", async () => {
    const bundle = fixture("week-bundle.json");
    expect(bundle.countersignatures).toBeUndefined();
    const digest = await bundleDigest(bundle);
    expect(await classifyCountersignatures([], digest, [], undefined)).toEqual([
      { kind: "hollow" },
    ]);
  });

  it("renders the hollow default when countersignatures[] is an empty array", async () => {
    const bundle = await derivedFixture(
      "week-bundle-empty-countersignatures.json",
    );
    expect(bundle.countersignatures).toEqual([]);
    const digest = await bundleDigest(bundle);
    expect(
      await classifyCountersignatures(
        bundle.countersignatures as unknown[],
        digest,
        [],
        undefined,
      ),
    ).toEqual([{ kind: "hollow" }]);
  });

  it("classifies the producer's own key as not independent, even when a countersigner list names it", async () => {
    const bundle = await derivedFixture(
      "week-bundle-producer-countersigned.json",
    );
    const digest = await bundleDigest(bundle);
    const producerKey = (
      bundle.extensions as { "producer-key/v1": { public_key: string } }
    )["producer-key/v1"].public_key;
    const listed = [{ name: "Producer Inc", key_ids: [producerKey] }];
    const result = await classifyCountersignatures(
      bundle.countersignatures as unknown[],
      digest,
      [producerKey],
      listed,
    );
    expect(result).toEqual([
      {
        kind: "not-independent",
        keyId: producerKey,
        statement: { ...statementView, recomputedAt: "2026-09-10T00:00:00Z" },
      },
    ]);
  });

  it("ignores a self-reported `independent` member", async () => {
    const bundle = await derivedFixture(
      "week-bundle-producer-countersigned.json",
    );
    const digest = await bundleDigest(bundle);
    const producerKey = (
      bundle.extensions as { "producer-key/v1": { public_key: string } }
    )["producer-key/v1"].public_key;
    const entry = {
      ...(bundle.countersignatures as Entry[])[0]!,
      independent: true,
    };
    const result = await classifyCountersignatures(
      [entry],
      digest,
      [producerKey],
      countersigners,
    );
    expect(result[0]).toMatchObject({ kind: "not-independent" });
  });

  it("resolves a listed signer by key_ids[]; the name comes from the list and the checks from the statement", async () => {
    const { entry, digest } = await signedEntry(
      "week-bundle-directory-countersigned.json",
    );
    const result = await classifyCountersignatures(
      [entry],
      digest,
      [],
      countersigners,
    );
    expect(result).toEqual([
      {
        kind: "resolved",
        keyId: DIRECTORY_SIGNER_KEY_ID,
        name: "Example Countersigners Ltd",
        statement: { ...statementView, recomputedAt: "2026-09-12T00:00:00Z" },
      },
    ]);
  });

  it("resolves a rotated key listed alongside the current one", async () => {
    const { entry, digest } = await signedEntry(
      "week-bundle-directory-countersigned.json",
    );
    const rotated = [
      {
        name: "Example Countersigners Ltd",
        key_ids: ["ab".repeat(32), DIRECTORY_SIGNER_KEY_ID],
      },
    ];
    const result = await classifyCountersignatures(
      [entry],
      digest,
      [],
      rotated,
    );
    expect(result[0]).toMatchObject({ kind: "resolved" });
  });

  it("never resolves a countersignature from a witnesses.json document", async () => {
    const { entry, digest } = await signedEntry(
      "week-bundle-directory-countersigned.json",
    );
    const witnessesJson = {
      directory_version: "1",
      witnesses: [{ name: "A Witness", key_ids: [DIRECTORY_SIGNER_KEY_ID] }],
      countersigners: [
        { name: "A Countersigner", key_ids: [DIRECTORY_SIGNER_KEY_ID] },
      ],
    };
    const result = await classifyCountersignatures(
      [entry],
      digest,
      [],
      witnessesJson as never,
    );
    expect(result[0]).toMatchObject({ kind: "unresolved-signer" });
  });

  it("classifies a verified signer that is neither producer nor listed as unresolved-signer", async () => {
    const bundle = await derivedFixture(
      "week-bundle-unresolved-countersigned.json",
    );
    const digest = await bundleDigest(bundle);
    const result = await classifyCountersignatures(
      bundle.countersignatures as unknown[],
      digest,
      [],
      countersigners,
    );
    expect(result).toMatchObject([
      {
        kind: "unresolved-signer",
        statement: { recomputedAt: "2026-09-13T00:00:00Z" },
      },
    ]);
  });

  it("marks a present receipt as unverified and never lets it change the state", async () => {
    const { entry, digest } = await signedEntry(
      "week-bundle-directory-countersigned.json",
    );
    const result = await classifyCountersignatures(
      [{ ...entry, receipt: { receipt_b64: "AAAA", leaf_index: 0 } }],
      digest,
      [],
      countersigners,
    );
    expect(result[0]).toMatchObject({
      kind: "resolved",
      statement: { receipt: "unverified" },
    });
  });

  it("catches a result flipped after signing: the entry is invalid and its checks are not shown", async () => {
    const { entry, digest } = await signedEntry(
      "week-bundle-directory-countersigned.json",
    );
    const checks = (entry.statement.checks as Array<Obj>).map((check) =>
      check.result === "failed" ? { ...check, result: "established" } : check,
    );
    const flipped = { ...entry, statement: { ...entry.statement, checks } };
    expect(
      await classifyCountersignatures([flipped], digest, [], countersigners),
    ).toEqual([{ kind: "invalid" }]);
  });

  it("reports cose-sign1 and unimplemented types as unverified, never as a countersignature", async () => {
    const digest = await bundleDigest(fixture("week-bundle.json"));
    const result = await classifyCountersignatures(
      [
        { type: "cose-sign1", signature: "AAAA" },
        { type: "countersign/v2", anything: true },
      ],
      digest,
      [],
      countersigners,
    );
    expect(result).toEqual([
      { kind: "unverified", type: "cose-sign1" },
      { kind: "unverified", type: "countersign/v2" },
    ]);
  });

  it.each([
    ["a non-string type", (e: Entry) => ({ ...e, type: 7 as never })],
    [
      "a truncated key id",
      (e: Entry) => ({ ...e, signer: { ...e.signer, key_id: "511c34a1" } }),
    ],
    [
      "no signer id",
      (e: Entry) => ({ ...e, signer: { key_id: e.signer.key_id } }),
    ],
    [
      "an unknown result word",
      (e: Entry) => ({
        ...e,
        statement: {
          ...e.statement,
          checks: [{ name: "chain consistency", result: "pass" }],
        },
      }),
    ],
    [
      "empty checks",
      (e: Entry) => ({ ...e, statement: { ...e.statement, checks: [] } }),
    ],
    [
      "a repeated check name",
      (e: Entry) => ({
        ...e,
        statement: {
          ...e.statement,
          checks: [
            { name: "cadence", result: "established" },
            { name: "cadence", result: "failed" },
          ],
        },
      }),
    ],
    [
      "a non-UTC recomputed_at",
      (e: Entry) => ({
        ...e,
        statement: {
          ...e.statement,
          recomputed_at: "2026-09-12T00:00:00+02:00",
        },
      }),
    ],
    [
      "no scope",
      (e: Entry) => ({ ...e, statement: { ...e.statement, scope: undefined } }),
    ],
  ])("classifies an entry with %s as invalid", async (_name, edit) => {
    const { entry, digest } = await signedEntry(
      "week-bundle-directory-countersigned.json",
    );
    expect(
      await classifyCountersignatures(
        [edit(entry)],
        digest,
        [],
        countersigners,
      ),
    ).toEqual([{ kind: "invalid" }]);
  });

  it("fails every countersign/v1 entry when the bundle digest itself is uncomputable", async () => {
    const { entry } = await signedEntry(
      "week-bundle-directory-countersigned.json",
    );
    const result = await classifyCountersignatures(
      [entry],
      undefined,
      [],
      countersigners,
    );
    expect(result).toEqual([{ kind: "invalid" }]);
  });

  it("catches a countersignature over a tampered (wholesale-edited) bundle", async () => {
    const bundle = await derivedFixture(
      "week-bundle-directory-countersigned.json",
    );
    const originalDigest = await bundleDigest(bundle);
    const tampered: Record<string, unknown> = {
      ...bundle,
      root: `${(bundle.root as string).slice(0, -1)}0`,
    };
    const tamperedDigest = await bundleDigest(tampered);
    expect(tamperedDigest).not.toBe(originalDigest);
    const result = await classifyCountersignatures(
      tampered.countersignatures as unknown[],
      tamperedDigest,
      [],
      countersigners,
    );
    expect(result).toEqual([{ kind: "invalid" }]);
  });
});

type Obj = Record<string, unknown>;
