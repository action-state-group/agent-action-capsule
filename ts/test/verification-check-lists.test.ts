import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { verifyBundle } from "../src/bundle.js";
import {
  CHECKED_ON_THIS_PAGE,
  CHECKPOINT_NOT_CHECKED_NOTE,
  CHECKS_SCOPE_LINE,
  FAILED_ON_THIS_PAGE,
  FULL_VERIFIER_LINE,
  NOT_CHECKED_ON_THIS_PAGE,
  VERIFICATION_CHECK_IDS,
  VERIFICATION_CHECK_WORDS,
  verificationCheckLists,
  verificationCheckWords,
  type VerificationCheckId,
  type VerificationCheckLists,
} from "../src/verification-page.js";
import { derivedFixture } from "./helpers/derived-fixtures.js";
import { pageModel, type PageModel } from "./helpers/page-model.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

type Obj = Record<string, unknown>;

const testdata = (name: string): Obj =>
  JSON.parse(
    readFileSync(resolve(process.cwd(), "test", "testdata", name), "utf8"),
  ) as Obj;
const vector = (...path: string[]): Obj =>
  JSON.parse(
    readFileSync(resolve(process.cwd(), "..", "vectors", ...path), "utf8"),
  ) as Obj;
// A bundle whose checkpoint carries a COSE signature.
const signedCheckpointBundle = (): Obj =>
  vector("minimum-necessary", "bundle-internal-audit", "input.json")
    .bundle as Obj;
const sealed = async (name: string): Promise<Obj> =>
  (await sealEvidenceBundle(testdata(name))).bundle;

// The check lists a page draws, read from the verification model.
interface Shown {
  readonly model: PageModel;
  readonly page: readonly string[];
  readonly failed: readonly string[];
  readonly notChecked: readonly string[];
}

async function show(
  bundle: unknown,
  options: { citedSigners?: boolean } = {},
): Promise<Shown> {
  const model = await pageModel(bundle, options);
  const lists = model.page.checkLists;
  return {
    model,
    page: lists.page,
    failed: lists.failed,
    notChecked: lists.notChecked,
  };
}

// Every line the lists show, with the list each id is in.
function listLines(lists: VerificationCheckLists): [string, string][] {
  return (["page", "failed", "notChecked"] as const).flatMap((list) =>
    lists[list].map((id): [string, string] => [
      `${list}:${id}`,
      verificationCheckWords(id, list, lists),
    ]),
  );
}

// Every line of the core's own text on the verification page: the checks'
// names and results, the coverage reason, the extension lines,
// the check lists and the pointer to a full verifier. Keyed by where it is
// shown.
function panelLines(model: PageModel): [string, string][] {
  const { page } = model;
  return [
    ...page.checks.flatMap((check): [string, string][] => [
      ["check", check.name],
      ["check", check.result],
    ]),
    ...(page.coverage.status === "established"
      ? []
      : [["coverage", page.coverage.reason] as [string, string]]),
    ...page.extensions.map((row): [string, string] => [
      `extension:${row.id}`,
      row.semantics,
    ]),
    ...listLines(page.checkLists),
    ["verify-independently", page.verifyIndependentlyLine],
  ];
}

describe("the verification page's check lists", () => {
  it("a Result page with a cited Close: the cited signers on the page, every record's signature not", async () => {
    // The Result page checks the producer signatures of the Close it cites.
    const { page, failed, notChecked } = await show(
      await sealed("result-root-close-bundle.json"),
      { citedSigners: true },
    );
    expect(page).toEqual([
      "record-digests",
      "record-rules",
      "closure",
      "range",
      "membership",
      "disclosures",
      "cited-signers",
    ]);
    expect(failed).toEqual([]);
    expect(notChecked).toEqual(["producer-signatures"]);
  });

  it("the same records on a page that cites no signer: the signatures stay off the page list", async () => {
    // The rows page draws no Close, so it checks no signer.
    const bundle = await sealed("result-root-close-bundle.json");
    const lists = verificationCheckLists(bundle, await verifyBundle(bundle));
    expect(lists.page).not.toContain("cited-signers");
    expect(lists.notChecked).toEqual(["producer-signatures"]);
  });

  it("a countersigned bundle: the countersignature's signature is checked on the page", async () => {
    const { page, notChecked } = await show(
      await derivedFixture("week-bundle-directory-countersigned.json"),
    );
    expect(page).toContain("countersignatures");
    expect(notChecked).toEqual([]);
  });

  it("a countersignature of an unchecked type, or one carrying a receipt, is listed as not checked", async () => {
    const bundle = await derivedFixture(
      "week-bundle-directory-countersigned.json",
    );
    const [entry] = bundle.countersignatures as Obj[];
    const { page, notChecked } = await show({
      ...bundle,
      countersignatures: [
        { ...entry, receipt: { witness: "witness.example" } },
        { type: "x-other-countersign/v1", signature: "00" },
      ],
    });
    // The receipt is not part of the signing input, so the signature
    // still checks.
    expect(page).toContain("countersignatures");
    expect(notChecked).toEqual([
      "countersignature-types",
      "countersignature-receipts",
    ]);
  });

  it("a witnessed bundle: each witness receipt is listed as not checked", async () => {
    const bundle = {
      ...(await sealed("result-root-bundle.json")),
      receipts: [
        {
          witness: "witness.example",
          grade: "countersigned-observed",
          time: "2026-09-14T00:00:00Z",
        },
      ],
    };
    const { page, notChecked } = await show(bundle);
    expect(page).toContain("range");
    expect(notChecked).toEqual(["witness-receipts"]);
  });

  it("a signed checkpoint this runtime authenticates is checked on the page", async () => {
    const bundle = signedCheckpointBundle();
    const verified = await verifyBundle(bundle);
    // Under node, cll authenticates the COSE checkpoint.
    expect(verified.intervalCoverage).toEqual({ status: "pass", findings: [] });
    const lists = verificationCheckLists(bundle, verified);
    expect(lists.page).toContain("checkpoint-signature");
    expect(lists.notChecked).toEqual([]);
    expect(lists.passedWithoutCheckpoint).toBe(false);
  });

  it("checkpoint_unverified keeps the checkpoint signature off the page list and says the page passed without it", async () => {
    const bundle = signedCheckpointBundle();
    const verified = await verifyBundle(bundle);
    // What a runtime without the checkpoint authenticator records (the
    // browser build: see bundle.ts authenticateCheckpoint).
    const unchecked = {
      status: "pass" as const,
      findings: ["checkpoint_unverified"],
    };
    const lists = verificationCheckLists(bundle, {
      ...verified,
      intervalCoverage: unchecked,
      perRecordMembership: unchecked,
    });
    expect(lists.page).toEqual([
      "record-digests",
      "record-rules",
      "closure",
      "range",
      "membership",
      "disclosures",
    ]);
    expect(lists.notChecked).toEqual(["checkpoint-signature"]);
    expect(lists.passedWithoutCheckpoint).toBe(true);
  });

  it("a bundle that fails another check never says it passed without the checkpoint", async () => {
    const bundle = signedCheckpointBundle();
    const verified = await verifyBundle(bundle);
    const unchecked = {
      status: "pass" as const,
      findings: ["checkpoint_unverified"],
    };
    const lists = verificationCheckLists(bundle, {
      ...verified,
      graphClosure: { status: "fail" as const, findings: ["missing_record"] },
      intervalCoverage: unchecked,
      perRecordMembership: unchecked,
    });
    expect(lists.failed).toEqual(["closure"]);
    expect(lists.notChecked).toEqual(["checkpoint-signature"]);
    expect(lists.passedWithoutCheckpoint).toBe(false);
  });

  it("a declared-incomplete bundle, which the banner fails, never says it passed without the checkpoint", async () => {
    const bundle = signedCheckpointBundle();
    const verified = await verifyBundle(bundle);
    const unchecked = {
      status: "pass" as const,
      findings: ["checkpoint_unverified"],
    };
    // A declared missing record leaves closure withheld: no check on the
    // page fails, but the page's verdict does not pass.
    const lists = verificationCheckLists(bundle, {
      ...verified,
      graphClosure: { status: "withheld" as const, findings: [] },
      intervalCoverage: unchecked,
      perRecordMembership: unchecked,
    });
    expect(lists.failed).toEqual([]);
    expect(lists.notChecked).toEqual(["checkpoint-signature"]);
    expect(lists.passedWithoutCheckpoint).toBe(false);
  });

  it("a checkpoint whose signature does not authenticate moves to the failed list", async () => {
    const bundle = signedCheckpointBundle();
    const verified = await verifyBundle(bundle);
    const invalid = {
      status: "fail" as const,
      findings: ["checkpoint_authentication_invalid"],
    };
    const lists = verificationCheckLists(bundle, {
      ...verified,
      intervalCoverage: invalid,
      perRecordMembership: invalid,
    });
    expect(lists.page).toContain("range");
    expect(lists.page).not.toContain("checkpoint-signature");
    expect(lists.failed).toEqual(["checkpoint-signature"]);
    // The memberships are never reached.
    expect(lists.notChecked).toEqual(["membership"]);
  });

  it("an unsigned checkpoint calls for no checkpoint signature check", async () => {
    const lists = verificationCheckLists(
      await sealed("week-bundle.json"),
      await verifyBundle(await sealed("week-bundle.json")),
    );
    expect([...lists.page, ...lists.failed, ...lists.notChecked]).not.toContain(
      "checkpoint-signature",
    );
  });
});

describe("a tampered bundle", () => {
  it("an edited record moves the record checks out of the page list", async () => {
    const bundle = await sealed("result-root-bundle.json");
    const before = await show(bundle);
    expect(before.page).toContain("record-digests");
    const records = (bundle.records as Obj[]).map((record, index) =>
      index === 0 ? { ...record, operator: "edited-after-sealing" } : record,
    );
    const after = await show({ ...bundle, records });
    expect(after.model.banner.state).toBe("failed");
    expect(after.page).not.toContain("record-digests");
    expect(after.failed).toContain("record-digests");
    expect(after.failed).toContain("closure");
  });

  it("an edited disclosure moves the disclosure check out of the page list", async () => {
    const { page, failed } = await show(
      vector("minimum-necessary", "bundle-mismatch", "input.json").bundle,
    );
    expect(page).not.toContain("disclosures");
    // The strict checkpoint claim fails too: the checkpoint's JSON copy
    // states no log_id (checkpoint_field_missing:log_id).
    expect(failed).toEqual(["checkpoint-signature", "disclosures"]);
  });

  it("an edited countersignature moves the countersignature check out of the page list", async () => {
    const bundle = await derivedFixture(
      "week-bundle-directory-countersigned.json",
    );
    const [entry] = bundle.countersignatures as Obj[];
    const signature = entry!.signature as string;
    const { page, failed, model } = await show({
      ...bundle,
      countersignatures: [
        {
          ...entry,
          signature: `${signature[0] === "0" ? "1" : "0"}${signature.slice(1)}`,
        },
      ],
    });
    expect(page).not.toContain("countersignatures");
    expect(failed).toEqual(["countersignatures"]);
    // A countersignature is not one of the bundle's own checks: the banner
    // scopes its words to those, beside a failed countersignature line.
    expect(model.banner.line).toMatch(/^None of the bundle's checks failed, /u);
    // And the failed line says it does not change the verdict.
    expect(
      verificationCheckWords(
        "countersignatures",
        "failed",
        model.page.checkLists,
      ),
    ).toMatch(/so its result never changes the bundle's verdict\.$/u);
  });

  it("a moved membership entry moves the membership check out of the page list", async () => {
    const cases = vector("bundle", "report-single-record.json").cases as Obj[];
    const negative = cases.find((c) => c.name === "neg-leaf-index-equals-seq")!;
    const { page, failed } = await show(negative.bundle);
    expect(page).not.toContain("membership");
    expect(failed).toEqual(["membership"]);
  });
});

describe("the lists' words", () => {
  const banned =
    /\b(identity|freshness|fresh|proves|proof|certificate|tamper-?proof)\b/iu;

  it("never say identity or freshness, and only a check the page ran says verified", () => {
    for (const id of VERIFICATION_CHECK_IDS) {
      const words = VERIFICATION_CHECK_WORDS[id];
      expect(words).not.toMatch(banned);
      if (id !== "cited-signers") expect(words).not.toMatch(/verified/iu);
    }
    for (const line of [
      CHECKED_ON_THIS_PAGE,
      FAILED_ON_THIS_PAGE,
      NOT_CHECKED_ON_THIS_PAGE,
      FULL_VERIFIER_LINE,
      CHECKS_SCOPE_LINE,
      CHECKPOINT_NOT_CHECKED_NOTE,
    ]) {
      expect(line).not.toMatch(banned);
      expect(line).not.toMatch(/verified/iu);
    }
  });

  it("on every page: no banned word, and verified only in the page list", async () => {
    const bundles: unknown[] = [
      await sealed("result-root-close-bundle.json"),
      await sealed("week-bundle.json"),
      testdata("result-root-close-bundle.json"),
      await derivedFixture("week-bundle-directory-countersigned.json"),
      signedCheckpointBundle(),
      vector("minimum-necessary", "bundle-mismatch", "input.json").bundle,
    ];
    for (const bundle of bundles) {
      const { model } = await show(bundle, { citedSigners: true });
      for (const [where, text] of listLines(model.page.checkLists)) {
        expect(text).not.toMatch(banned);
        if (!where.startsWith("page:")) expect(text).not.toMatch(/verified/iu);
      }
    }
  });

  // The whole panel, every line of the core's own text: it never says
  // "identity" or "freshness", and says "verified" only of a check this page
  // ran, the cited-signers item (the page checked those signatures).
  it("on every line of the panel: no banned word, and verified only for a check the page ran", async () => {
    const countersigned = await derivedFixture(
      "week-bundle-directory-countersigned.json",
    );
    const [entry] = countersigned.countersignatures as Obj[];
    const witnessed = (bundle: Obj): Obj => ({
      ...bundle,
      receipts: [
        {
          witness: "witness-a.example",
          grade: "mmr-verified",
          time: "2026-09-15T00:00:00Z",
        },
        {
          witness: "witness-b.example",
          grade: "countersigned-observed",
          time: "2026-09-15T01:00:00Z",
        },
      ],
    });
    const bundles: unknown[] = [
      await sealed("result-root-close-bundle.json"),
      witnessed(await sealed("result-root-bundle.json")),
      await sealed("outcome-report-bundle.json"),
      await sealed("compliance-bundle.json"),
      testdata("result-root-close-bundle.json"),
      {
        ...countersigned,
        countersignatures: [
          { ...entry, receipt: { witness: "witness-a.example" } },
          { type: "x-other-countersign/v1", signature: "00" },
        ],
      },
      signedCheckpointBundle(),
      vector("minimum-necessary", "bundle-mismatch", "input.json").bundle,
      ...(vector("bundle", "composed", "vectors.json").cases as Obj[]).map(
        (c) => c.container,
      ),
    ];
    let rows = 0;
    for (const bundle of bundles) {
      const { model } = await show(bundle, { citedSigners: true });
      for (const [where, text] of panelLines(model)) {
        rows += 1;
        expect(text).not.toMatch(/\b(?:identity|freshness|fresh)\b/iu);
        if (/\bverified\b/iu.test(text))
          expect(where, text).toBe("page:cited-signers");
      }
    }
    expect(rows).toBeGreaterThan(100);
  });

  it("a check id the lists know always has words", () => {
    const ids: readonly VerificationCheckId[] = VERIFICATION_CHECK_IDS;
    expect(Object.keys(VERIFICATION_CHECK_WORDS).sort()).toEqual(
      [...ids].sort(),
    );
  });
});
