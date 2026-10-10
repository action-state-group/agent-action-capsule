// @vitest-environment jsdom

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { renderEvidenceGraph } from "../src/browser.js";
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
  type VerificationCheckId,
} from "../src/verification-page.js";
import { derivedFixture } from "./helpers/derived-fixtures.js";
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

interface Shown {
  readonly root: HTMLElement;
  readonly page: string[];
  readonly failed: string[];
  readonly notChecked: string[];
}

async function show(
  bundle: unknown,
  options: { verifierHint?: string } = {},
): Promise<Shown> {
  const root = document.createElement("main");
  await renderEvidenceGraph(bundle, root, undefined, options);
  const ids = (which: string): string[] =>
    Array.from(
      root.querySelectorAll<HTMLElement>(
        `[data-page="verification"] ul[data-checks="${which}"] > li`,
      ),
      (item) => item.dataset.check!,
    );
  return {
    root,
    page: ids("page"),
    failed: ids("failed"),
    notChecked: ids("not-checked"),
  };
}

// Every word the panel's lists and their lines can show.
function listText(root: HTMLElement): string[] {
  return Array.from(
    root.querySelectorAll<HTMLElement>(
      '[data-page="verification"] [data-checks]',
    ),
    (node) => node.textContent ?? "",
  );
}

describe("the verification page's check lists", () => {
  it("a Result page with a cited Close: the cited signers on the page, every record's signature not", async () => {
    const { root, page, failed, notChecked } = await show(
      await sealed("result-root-close-bundle.json"),
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
    const headings = Array.from(
      root.querySelectorAll('[data-page="verification"] h4'),
      (h) => h.textContent,
    );
    expect(headings).toContain(CHECKED_ON_THIS_PAGE);
    expect(headings).toContain(NOT_CHECKED_ON_THIS_PAGE);
    expect(headings).not.toContain(FAILED_ON_THIS_PAGE);
    expect(
      root.querySelector('[data-checks="full-verifier"]')?.textContent,
    ).toBe(FULL_VERIFIER_LINE);
    expect(root.querySelector('[data-checks="scope"]')?.textContent).toBe(
      CHECKS_SCOPE_LINE,
    );
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
    expect(
      after.root.querySelector("[data-verify]")?.getAttribute("data-verify"),
    ).toBe("failed");
    expect(after.page).not.toContain("record-digests");
    expect(after.failed).toContain("record-digests");
    expect(after.failed).toContain("closure");
  });

  it("an edited disclosure moves the disclosure check out of the page list", async () => {
    const { page, failed } = await show(
      vector("minimum-necessary", "bundle-mismatch", "input.json").bundle,
    );
    expect(page).not.toContain("disclosures");
    expect(failed).toEqual(["disclosures"]);
  });

  it("an edited countersignature moves the countersignature check out of the page list", async () => {
    const bundle = await derivedFixture(
      "week-bundle-directory-countersigned.json",
    );
    const [entry] = bundle.countersignatures as Obj[];
    const signature = entry!.signature as string;
    const { page, failed } = await show({
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

  it("on every rendered page: no banned word, and verified only in the page list", async () => {
    const bundles: unknown[] = [
      await sealed("result-root-close-bundle.json"),
      await sealed("week-bundle.json"),
      testdata("result-root-close-bundle.json"),
      await derivedFixture("week-bundle-directory-countersigned.json"),
      signedCheckpointBundle(),
      vector("minimum-necessary", "bundle-mismatch", "input.json").bundle,
    ];
    for (const bundle of bundles) {
      const { root } = await show(bundle);
      for (const text of listText(root)) expect(text).not.toMatch(banned);
      for (const item of root.querySelectorAll<HTMLElement>(
        '[data-page="verification"] [data-checks]:not([data-checks="page"])',
      ))
        expect(item.textContent).not.toMatch(/verified/iu);
    }
  });

  // The whole panel, every row: the core's own text never says "identity"
  // or "freshness", and says "verified" only of a check this page ran. The
  // only such lines are the cited-signers item (the page checked those
  // signatures) and the extension integrity cell, whose words the contract
  // fixes (section 3.2): "Integrity verified" when the bundle digest covering
  // the block was computed here, "Integrity not verified" when it could not
  // be. The fixtures carry no such word in their own data (witness names,
  // countersigner check names), so every hit would be the core's text.
  it("on every row of the rendered panel: no banned word, and verified only for a check the page ran", async () => {
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
    const allowed = (node: Element, text: string): boolean =>
      node.closest(
        'ul[data-checks="page"] > li[data-check="cited-signers"]',
      ) !== null ||
      (node.closest("table[data-extensions] td") !== null &&
        /^Integrity (?:not )?verified;/u.test(text));
    let rows = 0;
    for (const bundle of bundles) {
      const { root } = await show(bundle);
      const panel = root.querySelector('[data-page="verification"]')!;
      for (const node of panel.querySelectorAll("*")) {
        // Each element's own text, not its children's.
        const text = Array.from(node.childNodes)
          .filter((child) => child.nodeType === 3)
          .map((child) => child.textContent ?? "")
          .join("");
        if (text.trim() === "") continue;
        rows += 1;
        expect(text).not.toMatch(/\b(?:identity|freshness|fresh)\b/iu);
        if (/\bverified\b/iu.test(text))
          expect(allowed(node, text), text).toBe(true);
      }
      expect(panel.textContent).not.toContain("consistency-verified");
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

describe("the host's verifier hint", () => {
  it("is shown as text after the neutral pointer, under the not-checked list", async () => {
    const hint = "example-verifier check <b>FILE</b>";
    const { root } = await show(await sealed("result-root-close-bundle.json"), {
      verifierHint: hint,
    });
    const pointer = root.querySelector('[data-checks="full-verifier"]')!;
    const shown = root.querySelector<HTMLElement>("[data-verifier-hint]")!;
    expect(shown.tagName).toBe("PRE");
    expect(shown.textContent).toBe(hint);
    expect(shown.querySelector("b")).toBeNull();
    expect(pointer.nextElementSibling).toBe(shown);
  });

  it("changes no list", async () => {
    const bundle = await sealed("result-root-close-bundle.json");
    const plain = await show(bundle);
    const hinted = await show(bundle, { verifierHint: "example-verifier" });
    expect([hinted.page, hinted.failed, hinted.notChecked]).toEqual([
      plain.page,
      plain.failed,
      plain.notChecked,
    ]);
  });

  it("is not shown, nor the pointer, when every called-for check ran", async () => {
    const { root } = await show(await sealed("week-bundle.json"), {
      verifierHint: "example-verifier",
    });
    expect(root.querySelector('[data-checks="not-checked"]')).toBeNull();
    expect(root.querySelector('[data-checks="full-verifier"]')).toBeNull();
    expect(root.querySelector("[data-verifier-hint]")).toBeNull();
  });
});
