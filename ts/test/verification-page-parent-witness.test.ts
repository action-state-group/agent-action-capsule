import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  buildVerifiedBundleContext,
  decodeFragment,
  verifyBundle,
} from "../src/bundle.js";
import {
  buildVerificationPageModel,
  verificationBanner,
  verificationCheckLists,
} from "../src/verification-page.js";

// The page model lists a checkpoint witnessed through a parent log
// (parent-log-witness/v1) with the extent the strict verifier computed, and
// no longer calls that checkpoint self-witnessed (AAC#347). Bundles from
// vectors/bundle/parent-log-witness.
const vectors = decodeFragment(
  readFileSync(
    resolve(
      process.cwd(),
      "..",
      "vectors",
      "bundle",
      "parent-log-witness",
      "vectors.json",
    ),
  ).toString("base64url"),
) as {
  witness_directory: unknown;
  cases: { id: string; bundle: unknown }[];
};

async function model(id: string, directory = true) {
  const bundle = vectors.cases.find((c) => c.id === id)!.bundle;
  const verified = await verifyBundle(bundle, {
    strict: true,
    ...(directory ? { witnessDirectory: vectors.witness_directory } : {}),
  });
  const strict = verified.strict;
  return {
    page: buildVerificationPageModel(bundle, verified, undefined, { strict }),
    lists: verificationCheckLists(bundle, verified, { strict }),
  };
}

describe("verification page: parent-log witness", () => {
  it("lists a wholly witnessed checkpoint with its extent", async () => {
    const { page, lists } = await model("pos-witnessed-whole");
    expect(page.selfWitnessed).toBe(false);
    expect(page.parentWitness).toEqual({
      entries: 3,
      of: 3,
      whole: true,
      receipts: [
        {
          witness: "https://cll-witness.example",
          keyId: expect.any(String),
          registrationTime: expect.any(Number),
        },
      ],
    });
    expect(lists.page).toContain("parent-log-witness");
  });

  it("states a part extent as entries of the log", async () => {
    const { page } = await model("pos-witnessed-part");
    expect(page.parentWitness).toMatchObject({
      entries: 2,
      of: 3,
      whole: false,
    });
    expect(page.selfWitnessed).toBe(false);
  });

  it("stays self-witnessed when the receipt is not checked", async () => {
    const { page, lists } = await model("pos-witnessed-whole", false);
    expect(page.parentWitness).toBeUndefined();
    expect(page.selfWitnessed).toBe(true);
    expect(lists.notChecked).toContain("parent-log-witness");
  });

  it("lists a broken chain as failed and draws no extent", async () => {
    const { page, lists } = await model("neg-path-edited");
    expect(page.parentWitness).toBeUndefined();
    expect(lists.failed).toContain("parent-log-witness");
  });

  it("draws nothing for a bundle without the block", async () => {
    const { page, lists } = await model("pos-unwitnessed");
    expect(page.parentWitness).toBeUndefined();
    expect(page.selfWitnessed).toBe(true);
    expect([...lists.page, ...lists.failed, ...lists.notChecked]).not.toContain(
      "parent-log-witness",
    );
  });
});

describe("verification banner: parent-log witness", () => {
  const bundleOf = (id: string) =>
    structuredClone(vectors.cases.find((c) => c.id === id)!.bundle) as {
      extensions: Record<string, { parent: { witnesses: unknown[] } }>;
    };

  it("names a broken link as the chain not holding", async () => {
    const banner = verificationBanner(
      await buildVerifiedBundleContext(bundleOf("neg-path-edited")),
      [],
    );
    expect(banner.state).toBe("failed");
    expect(banner.detail).toContain(
      "the chain to the parent log's witnessed checkpoint does not hold (parent_witness_entry_not_included)",
    );
  });

  it("names a bad receipt as the receipt, not the chain", async () => {
    const bundle = bundleOf("pos-witnessed-whole");
    bundle.extensions["parent-log-witness/v1"]!.parent.witnesses = [{}];
    const banner = verificationBanner(
      await buildVerifiedBundleContext(bundle),
      [],
    );
    expect(banner.state).toBe("failed");
    expect(banner.detail).toContain(
      "the witness receipt over the parent log's checkpoint is malformed or does not verify (witness_receipt_malformed)",
    );
    expect(banner.detail).not.toContain("does not hold");
  });
});

describe("verified bundle context: witness directory", () => {
  const bundle = vectors.cases.find(
    (c) => c.id === "pos-witnessed-whole",
  )!.bundle;

  it("checks the parent receipt under the directory it is given", async () => {
    const context = await buildVerifiedBundleContext(bundle, {
      witnessDirectory: vectors.witness_directory,
    });
    expect(context.strict?.parentWitness).toMatchObject({
      status: "pass",
      extent: { entries: 3, of: 3 },
    });
    expect(context.strict?.verdict).toBe("VALID");
  });

  it("trusts no witness without one", async () => {
    const context = await buildVerifiedBundleContext(bundle);
    expect(context.strict?.parentWitness?.status).toBe("withheld");
  });
});
