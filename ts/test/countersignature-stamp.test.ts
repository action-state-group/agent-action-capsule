import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  classifyCountersignatures,
  countersignV1SigningInput,
  readCountersignerDirectory,
  verifyCountersignV1Signature,
} from "../src/countersignature-stamp.js";
import { bundleDigest } from "../src/bundle.js";
import {
  DIRECTORY_SIGNER_KEY_ID,
  countersignerDirectory,
  derivedFixture,
} from "./helpers/derived-fixtures.js";

function fixture(name: string): Record<string, unknown> {
  return JSON.parse(
    readFileSync(resolve(process.cwd(), "test", "testdata", name), "utf8"),
  ) as Record<string, unknown>;
}

type Entry = {
  type: string;
  signer: { id: string; key_id: string };
  over: string;
  statement: Record<string, unknown>;
  signature: string;
};

const directory = fixture("countersigner-directory.json");
const golden = fixture("countersign-v1-golden.json") as {
  signing_input_utf8: string;
  valid: Entry;
  invalid: Array<{ name: string; entry: Entry }>;
};

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

describe("countersign/v1 golden vector", () => {
  it("reproduces the independently generated signing input byte for byte", () => {
    const { over, statement, type } = golden.valid;
    expect(
      new TextDecoder().decode(
        countersignV1SigningInput({ over, statement, type }),
      ),
    ).toBe(golden.signing_input_utf8);
  });

  it("verifies the valid entry's signature", async () => {
    const entry = golden.valid;
    expect(
      await verifyCountersignV1Signature(
        entry,
        entry.signer.key_id,
        entry.signature,
      ),
    ).toBe(true);
    expect(
      await classifyCountersignatures([entry], entry.over, [], directory),
    ).toMatchObject([{ kind: "resolved", name: "Example Countersigners Ltd" }]);
  });

  it.each(golden.invalid.map((c) => [c.name, c.entry] as const))(
    "rejects: %s",
    async (_name, entry) => {
      expect(
        await classifyCountersignatures(
          [entry],
          golden.valid.over,
          [],
          directory,
        ),
      ).toEqual([{ kind: "invalid" }]);
    },
  );
});

describe("readCountersignerDirectory", () => {
  it("keeps the committed directory in step with the derived fixtures' signer", () => {
    expect(directory).toEqual(countersignerDirectory());
  });

  it("reads a witnesses.json whose countersigner key is still a placeholder", () => {
    const placeholder = fixture("witnesses-with-placeholder.json");
    const names = readCountersignerDirectory(placeholder);
    // The countersigner row's key is still a placeholder, so it resolves
    // nothing; the witness row's key must never resolve a countersignature.
    expect(names.size).toBe(0);
    const witnessKey = (
      placeholder.witnesses as Array<{ key_ids: string[] }>
    )[0]!.key_ids[0]!;
    expect(names.has(witnessKey)).toBe(false);
  });

  it("resolves that row once its placeholder is filled with a real key", () => {
    const placeholder = fixture("witnesses-with-placeholder.json") as {
      countersigners: Array<Record<string, unknown>>;
    };
    const filled = {
      ...placeholder,
      countersigners: [
        {
          ...placeholder.countersigners[0]!,
          key_ids: [DIRECTORY_SIGNER_KEY_ID],
        },
      ],
    };
    const names = readCountersignerDirectory(filled);
    expect(names.get(DIRECTORY_SIGNER_KEY_ID)).toBe(
      placeholder.countersigners[0]!.name,
    );
  });

  it("resolves a key listed in two rows to neither", () => {
    const row = (countersignerDirectory().countersigners as unknown[])[0];
    const names = readCountersignerDirectory({
      countersigners: [row, { ...(row as object), name: "Someone Else" }],
    });
    expect(names.has(DIRECTORY_SIGNER_KEY_ID)).toBe(false);
  });

  it("reads nothing from a directory of the wrong shape", () => {
    expect(readCountersignerDirectory(undefined).size).toBe(0);
    expect(
      readCountersignerDirectory([
        { publicKey: DIRECTORY_SIGNER_KEY_ID, name: "Old Flat Array" },
      ]).size,
    ).toBe(0);
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

  it("classifies the producer's own key as not independent, even when the directory lists it", async () => {
    const bundle = await derivedFixture(
      "week-bundle-producer-countersigned.json",
    );
    const digest = await bundleDigest(bundle);
    const producerKey = (
      bundle.extensions as { "producer-key/v1": { public_key: string } }
    )["producer-key/v1"].public_key;
    const listed = {
      countersigners: [{ name: "Producer Inc", key_ids: [producerKey] }],
    };
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
      directory,
    );
    expect(result[0]).toMatchObject({ kind: "not-independent" });
  });

  it("resolves a directory signer by key_ids[]; the name comes from the directory and the checks from the statement", async () => {
    const { entry, digest } = await signedEntry(
      "week-bundle-directory-countersigned.json",
    );
    const result = await classifyCountersignatures(
      [entry],
      digest,
      [],
      directory,
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
    const rotated = {
      countersigners: [
        {
          name: "Example Countersigners Ltd",
          key_ids: ["ab".repeat(32), DIRECTORY_SIGNER_KEY_ID],
        },
      ],
    };
    const result = await classifyCountersignatures(
      [entry],
      digest,
      [],
      rotated,
    );
    expect(result[0]).toMatchObject({ kind: "resolved" });
  });

  it("never resolves a countersignature against witnesses[]", async () => {
    const { entry, digest } = await signedEntry(
      "week-bundle-directory-countersigned.json",
    );
    const witnessOnly = {
      witnesses: [{ name: "A Witness", key_ids: [DIRECTORY_SIGNER_KEY_ID] }],
      countersigners: [],
    };
    const result = await classifyCountersignatures(
      [entry],
      digest,
      [],
      witnessOnly,
    );
    expect(result[0]).toMatchObject({ kind: "unresolved-signer" });
  });

  it("classifies a verified signer that is neither producer nor directory as unresolved-signer", async () => {
    const bundle = await derivedFixture(
      "week-bundle-unresolved-countersigned.json",
    );
    const digest = await bundleDigest(bundle);
    const result = await classifyCountersignatures(
      bundle.countersignatures as unknown[],
      digest,
      [],
      directory,
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
      directory,
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
      await classifyCountersignatures([flipped], digest, [], directory),
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
      directory,
    );
    expect(result).toEqual([
      { kind: "unverified", type: "cose-sign1" },
      { kind: "unverified", type: "countersign/v2" },
    ]);
  });

  it.each([
    ["no type", (e: Entry) => ({ ...e, type: undefined })],
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
      await classifyCountersignatures([edit(entry)], digest, [], directory),
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
      directory,
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
      directory,
    );
    expect(result).toEqual([{ kind: "invalid" }]);
  });
});

type Obj = Record<string, unknown>;
