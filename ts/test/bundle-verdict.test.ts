import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import {
  buildVerifiedBundleContext,
  verifyBundle,
  withCountersigners,
} from "../src/bundle.js";
import { VERIFICATION_BANNER_LINES as LINES } from "../src/browser.js";
import { browserPageModel } from "./helpers/browser-page-model.js";
import { pageModel, type PageModel } from "./helpers/page-model.js";
import { bundleVerified } from "../src/verification-page.js";
import { sealEvidenceBundle, TEST_KEYS } from "./helpers/sealed-bundle.js";

// The page states the strict verifier's verdict (#196): valid, incomplete or
// invalid, the outcomes a full verifier reports for the same bundle, and it
// says "passed" only for valid. Read from the verification model a viewer
// draws (verificationBanner and the page's check lists); capsule-viewer
// draws it.

type Obj = Record<string, unknown>;
type Build = (bundle: unknown) => Promise<PageModel>;

// A two-record bundle: a deal root citing one act, each disclosing a payload.
const SOURCE = (keyId?: string): Obj => ({
  root: "deal",
  records: [
    { capsule_id: "act", ...(keyId ? { key_id: keyId } : {}) },
    {
      capsule_id: "deal",
      ...(keyId ? { key_id: keyId } : {}),
      chain: { parent_capsule_id: "act", relation: "derived_from" },
    },
  ],
  disclosures: {
    act: { agent_output: { step: "act", amount: 1 } },
    deal: { agent_input: { spec_version: "x-example-deal/v0", step: "open" } },
  },
});

/** Signed checkpoint and every record producer-signed. */
const fullySigned = async (): Promise<Obj> =>
  (await sealEvidenceBundle(SOURCE(TEST_KEYS.a), { signCheckpoint: true }))
    .bundle;
/** The issue's case: a signed checkpoint, records with no producer signature. */
const signedCheckpointUnsignedRecords = async (): Promise<Obj> =>
  (await sealEvidenceBundle(SOURCE(), { signCheckpoint: true })).bundle;

function tamperPayload(bundle: Obj): Obj {
  const disclosures = structuredClone(bundle.disclosures) as Record<
    string,
    Record<string, Obj>
  >;
  const entry = Object.values(disclosures).find(
    (value) => value.agent_output !== undefined,
  )!;
  entry.agent_output!.amount = 2;
  return { ...bundle, disclosures };
}

// The banner the page model gives: its state (data-verify on a drawn page),
// verdict, checkpoint and line.
const banner = (model: PageModel) => model.banner;
// The details line under the banner, or "" when it draws none.
const detail = (model: PageModel): string => model.banner.detail;
// Everything the banner and its details line say.
const said = (model: PageModel): string =>
  `${model.banner.line} ${detail(model)}`;
const checks = (model: PageModel, list: string): readonly string[] =>
  list === "page"
    ? model.page.checkLists.page
    : list === "failed"
      ? model.page.checkLists.failed
      : model.page.checkLists.notChecked;
// The refusal line that withholds the records, or null.
const refusal = (model: PageModel): string | null =>
  model.banner.refusal ?? null;

// The library build's page model.
const libraryModel: Build = (bundle) => pageModel(bundle);

const verdict = async (bundle: unknown): Promise<string> =>
  (await verifyBundle(bundle, { strict: true })).strict.verdict;

// The shipped browser build (see helpers/browser-page-model.ts).
let browserModel: Build;
beforeAll(async () => {
  const model = await browserPageModel();
  browserModel = (bundle) => model(bundle);
}, 60_000);

describe("the banner never claims more than was checked", () => {
  it("library build, fully signed bundle: valid, the only case that says passed", async () => {
    const bundle = await fullySigned();
    expect(await verdict(bundle)).toBe("VALID");
    const model = await libraryModel(bundle);
    const top = banner(model);
    expect(top.verdict).toBe("valid");
    expect(top.checkpoint).toBe("verified");
    expect(top.state).toBe("verified");
    expect(top.line).toBe(LINES.verified);
    expect(detail(model)).toBe("");
    // Both signatures were checked here, so the page lists them as checked.
    expect(checks(model, "page")).toEqual(
      expect.arrayContaining(["checkpoint-signature", "producer-signatures"]),
    );
    expect(checks(model, "not-checked")).toEqual([]);
  });

  it("browser build, signed checkpoint it cannot authenticate, unsigned records: incomplete, labelled checkpoint_unverified (issue #196)", async () => {
    const model = await browserModel(await signedCheckpointUnsignedRecords());
    const top = banner(model);
    expect(top.verdict).toBe("incomplete");
    expect(top.checkpoint).toBe("unverified");
    expect(top.state).toBe("incomplete");
    expect(top.line).toBe(LINES.incomplete);
    expect(detail(model)).toBe(
      "This page did not check " +
        "any record's producer signature, because no record is signed (producer_signature_unclaimed); " +
        "the checkpoint signature, which this page cannot check (checkpoint_verifier_unavailable). " +
        "Interval coverage and per-record membership are checkpoint_unverified: " +
        "relative to a producer-asserted checkpoint this page could not authenticate.",
    );
    // The verification page says the same.
    expect(checks(model, "not-checked")).toContain("checkpoint-signature");
  });

  it("browser build, a bundle the library calls valid: at most incomplete", async () => {
    const bundle = await fullySigned();
    const top = banner(await browserModel(bundle));
    expect(top.verdict).toBe("incomplete");
    expect(top.checkpoint).toBe("unverified");
    expect(top.line).not.toBe(LINES.verified);
  });

  it("an unsigned checkpoint: incomplete, relative to a checkpoint that is not signed", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE(TEST_KEYS.a));
    const model = await libraryModel(bundle);
    const top = banner(model);
    expect(top.verdict).toBe("incomplete");
    expect(top.checkpoint).toBe("absent");
    // An unsigned checkpoint is not a check the bundle calls for, so the
    // page draws no not-checked list and the banner does not point at one.
    expect(top.line).toBe(LINES.incompleteNoList);
    expect(detail(model)).toBe(
      "This page did not check " +
        "the checkpoint signature, because the checkpoint is not signed (checkpoint_signature_absent). " +
        "Interval coverage and per-record membership are checkpoint_unverified: " +
        "relative to a producer-asserted checkpoint that is not signed.",
    );
  });

  it("some records unsigned: names how many", async () => {
    const { bundle } = await sealEvidenceBundle(
      {
        ...SOURCE(TEST_KEYS.a),
        records: [
          { capsule_id: "act" },
          {
            capsule_id: "deal",
            key_id: TEST_KEYS.a,
            chain: { parent_capsule_id: "act", relation: "derived_from" },
          },
        ],
      },
      { signCheckpoint: true },
    );
    const model = await libraryModel(bundle);
    const top = banner(model);
    expect(top.verdict).toBe("incomplete");
    expect(top.checkpoint).toBe("verified");
    expect(detail(model)).toBe(
      "This page did not check " +
        "the producer signature of 1 of 2 records, because that record is not signed (producer_signature_unclaimed).",
    );
  });

  it("a tampered payload: invalid in both builds, refused, no passed wording", async () => {
    const bundle = tamperPayload(await fullySigned());
    expect(await verdict(bundle)).toBe("INVALID");
    for (const build of [libraryModel, browserModel]) {
      const model = await build(bundle);
      const top = banner(model);
      expect(top.verdict).toBe("invalid");
      expect(top.state).toBe("failed");
      expect(top.line).toBe(LINES.refused);
      expect(detail(model)).toBe("");
      expect(refusal(model)).not.toBe(null);
    }
  });

  it("a producer signature under the wrong key: invalid, though the rows render", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE(TEST_KEYS.a), {
      signCheckpoint: true,
      signWith: { act: "b" },
    });
    expect(await verdict(bundle)).toBe("INVALID");
    const model = await libraryModel(bundle);
    const top = banner(model);
    expect(top.verdict).toBe("invalid");
    expect(top.state).toBe("failed");
    expect(top.line).toBe(LINES.failed);
    expect(detail(model)).toBe(
      "What failed: 1 of 2 records' producer signatures do not verify (producer_signature_invalid).",
    );
    expect(checks(model, "failed")).toEqual(["producer-signatures"]);
  });

  it("a key_id with no signature: invalid", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE(TEST_KEYS.a), {
      signCheckpoint: true,
      unsigned: ["act"],
    });
    expect(await verdict(bundle)).toBe("INVALID");
    const model = await libraryModel(bundle);
    expect(banner(model).verdict).toBe("invalid");
    expect(banner(model).state).toBe("failed");
    expect(detail(model)).toContain("producer_signature_invalid");
  });

  it("a checkpoint whose JSON copy disagrees with what it signed: invalid", async () => {
    const bundle = await fullySigned();
    const checkpoint = bundle.checkpoint as Obj;
    const edited = {
      ...bundle,
      checkpoint: { ...checkpoint, timestamp: "2026-09-15T00:00:00Z" },
    };
    expect(await verdict(edited)).toBe("INVALID");
    const model = await libraryModel(edited);
    const top = banner(model);
    expect(top.verdict).toBe("invalid");
    expect(top.checkpoint).toBe("invalid");
    expect(detail(model)).toBe(
      "What failed: the checkpoint's fields do not match its signature (checkpoint_field_mismatch).",
    );
    expect(checks(model, "failed")).toContain("checkpoint-signature");
    const garbled = { ...bundle, checkpoint: { ...checkpoint, cose: "AAAA" } };
    expect(banner(await libraryModel(garbled)).verdict).toBe("invalid");
  });

  it("sets data-verdict on every page, and says passed only when it is valid", async () => {
    const { bundle: unsignedCheckpoint } = await sealEvidenceBundle(SOURCE());
    const cases: unknown[] = [
      await fullySigned(),
      await signedCheckpointUnsignedRecords(),
      unsignedCheckpoint,
      tamperPayload(await fullySigned()),
      {},
      { bundle_version: "2", bundle_kind: "evidence-bundle/v2" },
    ];
    for (const value of cases)
      for (const build of [libraryModel, browserModel]) {
        const model = await build(value);
        const top = banner(model);
        expect(["valid", "incomplete", "invalid"]).toContain(top.verdict);
        // `verified` only for a valid verdict, never for less.
        expect(top.state === "verified").toBe(top.verdict === "valid");
        expect(top.checkpoint).toMatch(
          /^(?:verified|unverified|invalid|absent)$/u,
        );
        if (top.verdict !== "valid")
          expect(said(model)).not.toContain(LINES.verified);
      }
  });
});

describe("the strict result beside the page's own checks", () => {
  const strictCase = (id: string): Obj => {
    const vectors = JSON.parse(
      readFileSync(
        resolve(
          process.cwd(),
          "..",
          "vectors",
          "bundle",
          "strict",
          "vectors.json",
        ),
        "utf8",
      ),
    ) as { cases: { id: string; bundle: Obj }[] };
    return structuredClone(vectors.cases.find((c) => c.id === id)!.bundle);
  };

  it("a receipt it did not check is listed as not checked; a malformed one fails", async () => {
    const bundle = strictCase("pos-witness-cll-no-directory");
    let model = await libraryModel(bundle);
    expect(banner(model).verdict).toBe("valid");
    expect(checks(model, "not-checked")).toContain("witness-receipts");
    const checkpoint = bundle.checkpoint as Obj;
    checkpoint.witnesses = [...(checkpoint.witnesses as unknown[]), 7];
    model = await libraryModel(bundle);
    const top = banner(model);
    expect(top.verdict).toBe("invalid");
    expect(detail(model)).toBe(
      "What failed: 1 of 2 witness receipts are malformed (witness_receipt_malformed).",
    );
    expect(checks(model, "failed")).toContain("witness-receipts");
    expect(checks(model, "page")).not.toContain("witness-receipts");
  });

  it("records bound to no log position: membership is listed as failed, never checked", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE(TEST_KEYS.a), {
      signCheckpoint: true,
      uncheckpointed: ["act"],
    });
    const model = await libraryModel(bundle);
    const top = banner(model);
    expect(top.state).toBe("failed");
    expect(top.verdict).toBe("invalid");
    expect(refusal(model)).toBeNull();
    expect(detail(model)).toBe(
      "1 of 2 records are uncheckpointed (bound to no log position), so per-record membership fails.",
    );
    expect(checks(model, "failed")).toContain("membership");
    expect(checks(model, "page")).not.toContain("membership");
  });

  // The gate exempts a record bound to no log position only when every
  // membership finding is such a record: one beside it whose proof does not
  // verify, or whose entry names another log, still refuses the records.
  for (const [name, spoil] of [
    [
      "an inclusion proof that does not verify",
      (entry: Obj) => {
        const proof = entry.inclusion_proof as Obj;
        entry.inclusion_proof = {
          ...proof,
          witness: (proof.witness as string[]).map(() => "00".repeat(32)),
        };
      },
    ],
    [
      "an entry that names another log",
      (entry: Obj) => {
        (entry.log_coordinates as Obj).log_id = "some-other-log";
      },
    ],
  ] as const)
    it(`a record bound to no log position beside ${name}: refused`, async () => {
      // Several records stay in the log, so each proof has a witness path.
      const { bundle } = await sealEvidenceBundle(
        JSON.parse(
          readFileSync(
            resolve(
              import.meta.dirname,
              "testdata",
              "report-rows-uncheckpointed-bundle.json",
            ),
            "utf8",
          ),
        ) as Obj,
        { uncheckpointed: ["act-backfilled"] },
      );
      const memberships = (bundle.completeness_certificate as Obj)
        .memberships as Record<string, Obj>;
      const entries = Object.values(memberships);
      expect(
        ((entries[1]!.inclusion_proof as Obj).witness as unknown[]).length,
      ).toBeGreaterThan(0);
      spoil(entries[1]!);
      const context = await buildVerifiedBundleContext(bundle);
      expect(bundleVerified(context.verification)).toBe(false);
      const model = await libraryModel(bundle);
      expect(banner(model).state).toBe("failed");
      expect(refusal(model)).not.toBeNull();
    });

  it("a checkpoint missing a field it signs: says so", async () => {
    const model = await libraryModel(
      strictCase("neg-checkpoint-field-missing"),
    );
    expect(banner(model).verdict).toBe("invalid");
    expect(detail(model)).toBe(
      "What failed: the checkpoint is missing fields its signature covers (checkpoint_field_missing).",
    );
  });

  it("a cose of null: the checkpoint is invalid, as the lists say", async () => {
    const model = await libraryModel(strictCase("neg-checkpoint-cose-null"));
    expect(banner(model).verdict).toBe("invalid");
    expect(banner(model).checkpoint).toBe("invalid");
    expect(checks(model, "failed")).toContain("checkpoint-signature");
  });

  // #361: a producer-selected bundle (completeness.selection) has no
  // interval to check; the page reads each record's proof as the strict
  // checks do, so the strict verdict, INCOMPLETE, is what it shows.
  it("a producer selection renders as incomplete, with each record's proof checked and no interval", async () => {
    const model = await libraryModel(
      strictCase("incomplete-producer-selected"),
    );
    const top = banner(model);
    expect(top.state).toBe("incomplete");
    expect(top.verdict).toBe("incomplete");
    expect(refusal(model)).toBeNull();
    expect(detail(model)).toContain("selection_not_checkable");
    expect(checks(model, "page")).toContain("membership");
    for (const list of ["page", "failed", "not-checked"])
      expect(checks(model, list)).not.toContain("range");
  });

  it("a producer selection the strict checks call INVALID is still refused, records and all", async () => {
    // A record with a stated key and no signature: INVALID by its
    // signature, while every proof still verifies.
    const unsigned = strictCase("incomplete-producer-selected");
    const record = (unsigned.records as Obj[]).find(
      (r) => typeof r.signature === "string",
    );
    expect(record).toBeDefined();
    delete record!.signature;
    expect(await verdict(unsigned)).toBe("INVALID");
    for (const bundle of [
      strictCase("neg-producer-selected-proof-invalid"),
      strictCase("neg-producer-selected-coordinates-log-and-seq"),
      strictCase("neg-producer-selected-unbound"),
      unsigned,
    ]) {
      const model = await libraryModel(bundle);
      expect(banner(model).verdict).toBe("invalid");
      expect(refusal(model)).not.toBeNull();
    }
  });

  it("the browser build, which cannot read a selection's proofs, refuses it rather than claim more", async () => {
    const model = await browserModel(
      strictCase("incomplete-producer-selected"),
    );
    expect(banner(model).state).toBe("failed");
    expect(refusal(model)).not.toBeNull();
  });

  it("keeps the strict result when the countersigners change", async () => {
    const context = await buildVerifiedBundleContext(await fullySigned());
    expect(context.strict?.verdict).toBe("VALID");
    expect(withCountersigners(context, []).strict).toBe(context.strict);
  });
});

// The page's verdict is the strict verifier's, so it agrees with every
// implementation on the shared strict vectors. Only the cases a page can
// reproduce: it has no witness directory and allows unsigned records. The
// browser build cannot authenticate a checkpoint, so there it may claim
// less than a full verifier. It says more only for a bundle whose one
// failure is in a checkpoint it could not check, and then says so: it is
// incomplete, with `data-checkpoint="unverified"`.
const ORDER: Readonly<Record<string, number>> = {
  invalid: 0,
  incomplete: 1,
  valid: 2,
};
describe("the page's verdict on vectors/bundle/strict", () => {
  const vectors = JSON.parse(
    readFileSync(
      resolve(
        process.cwd(),
        "..",
        "vectors",
        "bundle",
        "strict",
        "vectors.json",
      ),
      "utf8",
    ),
  ) as {
    cases: {
      id: string;
      options: { require_signature: boolean; witness_directory: boolean };
      bundle: unknown;
      expect: { verdict: string };
    }[];
  };
  // A page has no witness directory (every receipt reads as withheld, so a
  // directory case would not agree) and never requires a signature.
  const cases = vectors.cases.filter(
    (c) => !c.options.require_signature && !c.options.witness_directory,
  );

  it("has cases a page can reproduce", () => {
    expect(cases.length).toBeGreaterThan(0);
  });

  it.each(cases.map((c) => [c.id, c] as const))("%s", async (id, c) => {
    const expected = c.expect.verdict.toLowerCase();
    const pageRoot = await libraryModel(c.bundle);
    const top = banner(pageRoot);
    expect(top.verdict).toBe(expected);
    const browserRoot = await browserModel(c.bundle);
    const browser = banner(browserRoot);
    expect(["invalid", "incomplete"]).toContain(browser.verdict);
    if (ORDER[browser.verdict!]! > ORDER[expected]!) {
      // Allowed only when every failure is the checkpoint's, which the
      // browser build cannot check.
      const { strict } = await verifyBundle(c.bundle, { strict: true });
      expect(strict.witnesses?.status).not.toBe("fail");
      for (const claim of strict.claims.filter((x) => x.status === "fail"))
        expect(
          claim.name === "checkpoint" ||
            claim.findings.every(
              (f) => f === "checkpoint_authentication_invalid",
            ),
        ).toBe(true);
      expect(browser.verdict).toBe("incomplete");
      expect(browser.checkpoint).toBe("unverified");
      expect(detail(browserRoot)).toContain("checkpoint_verifier_unavailable");
    }
    for (const page of [pageRoot, browserRoot])
      if (banner(page).verdict !== "valid")
        expect(said(page)).not.toContain(LINES.verified);
  });
});
