import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { build } from "esbuild";
import { beforeAll, describe, expect, it } from "vitest";
import {
  buildVerifiedBundleContext,
  verifyBundle,
  withCountersigners,
} from "../src/bundle.js";
import { renderEvidenceGraph } from "../src/browser.js";
import { sealEvidenceBundle, TEST_KEYS } from "./helpers/sealed-bundle.js";

// The page states the strict verifier's verdict (#196): valid, incomplete or
// invalid, the outcomes a full verifier reports for the same bundle, and it
// says "passed" only for valid.
//
// A DOM constructed directly with jsdom rather than a whole-file environment
// override: esbuild (which builds the browser bundle below) refuses to run
// under the jsdom environment's TextEncoder.
// jsdom ships no type declarations, so it is loaded untyped.
const { JSDOM } = createRequire(import.meta.url)("jsdom") as {
  JSDOM: new () => { window: Window & typeof globalThis };
};
const dom = new JSDOM();
globalThis.document = dom.window.document;
globalThis.HTMLElement = dom.window.HTMLElement;

type Obj = Record<string, unknown>;
type Render = (bundle: unknown, root: HTMLElement) => Promise<void>;

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

const banner = (root: HTMLElement): HTMLElement =>
  root.querySelector<HTMLElement>("[data-verdict]")!;
const checks = (root: HTMLElement, list: string): string[] =>
  [
    ...root.querySelectorAll<HTMLElement>(
      `[data-page="verification"] [data-checks="${list}"] [data-check]`,
    ),
  ].map((item) => item.dataset.check!);

async function renderWith(render: Render, bundle: unknown) {
  const root = document.createElement("main");
  await render(bundle, root);
  return root;
}

const verdict = async (bundle: unknown): Promise<string> =>
  (await verifyBundle(bundle, { strict: true })).strict.verdict;

// The shipped browser build: src/browser.ts bundled for the browser as
// capsule-viewer's emitter does (in memory here), so cll resolves to its
// browser substrate, which has no checkpoint authenticator.
let browserRender: Render;
beforeAll(async () => {
  const output = await build({
    entryPoints: [new URL("../src/browser.ts", import.meta.url).pathname],
    bundle: true,
    format: "iife",
    globalName: "EvidenceGraph",
    write: false,
    logLevel: "silent",
  });
  const module = new Function(
    `${output.outputFiles[0]!.text}; return EvidenceGraph;`,
  )() as { renderEvidenceGraph: Render };
  browserRender = module.renderEvidenceGraph;
}, 60_000);

describe("the banner never claims more than was checked", () => {
  it("library build, fully signed bundle: valid, the only case that says passed", async () => {
    const bundle = await fullySigned();
    expect(await verdict(bundle)).toBe("VALID");
    const root = await renderWith(renderEvidenceGraph, bundle);
    const top = banner(root);
    expect(top.dataset.verdict).toBe("valid");
    expect(top.dataset.checkpoint).toBe("verified");
    expect(top.dataset.verify).toBe("verified");
    expect(top.textContent).toBe("Bundle verification passed");
    // Both signatures were checked here, so the page lists them as checked.
    expect(checks(root, "page")).toEqual(
      expect.arrayContaining(["checkpoint-signature", "producer-signatures"]),
    );
    expect(checks(root, "not-checked")).toEqual([]);
  });

  it("browser build, signed checkpoint it cannot authenticate, unsigned records: incomplete, labelled checkpoint_unverified (issue #196)", async () => {
    const root = await renderWith(
      browserRender,
      await signedCheckpointUnsignedRecords(),
    );
    const top = banner(root);
    expect(top.dataset.verdict).toBe("incomplete");
    expect(top.dataset.checkpoint).toBe("unverified");
    expect(top.dataset.verify).toBe("verified");
    expect(top.textContent).not.toContain("passed");
    expect(top.textContent).toBe(
      "Bundle verification incomplete: no check failed, but this page did not check " +
        "any record's producer signature, because no record is signed (producer_signature_unclaimed); " +
        "the checkpoint signature, which this page cannot check (checkpoint_verifier_unavailable). " +
        "Interval coverage and per-record membership are checkpoint_unverified: " +
        "relative to a producer-asserted checkpoint this page could not authenticate.",
    );
    // The verification page says the same.
    expect(checks(root, "not-checked")).toContain("checkpoint-signature");
  });

  it("browser build, a bundle the library calls valid: at most incomplete", async () => {
    const bundle = await fullySigned();
    const top = banner(await renderWith(browserRender, bundle));
    expect(top.dataset.verdict).toBe("incomplete");
    expect(top.dataset.checkpoint).toBe("unverified");
    expect(top.textContent).not.toContain("passed");
  });

  it("an unsigned checkpoint: incomplete, relative to a checkpoint that is not signed", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE(TEST_KEYS.a));
    const top = banner(await renderWith(renderEvidenceGraph, bundle));
    expect(top.dataset.verdict).toBe("incomplete");
    expect(top.dataset.checkpoint).toBe("absent");
    expect(top.textContent).toBe(
      "Bundle verification incomplete: no check failed, but this page did not check " +
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
    const top = banner(await renderWith(renderEvidenceGraph, bundle));
    expect(top.dataset.verdict).toBe("incomplete");
    expect(top.dataset.checkpoint).toBe("verified");
    expect(top.textContent).toBe(
      "Bundle verification incomplete: no check failed, but this page did not check " +
        "the producer signature of 1 of 2 records, because that record is not signed (producer_signature_unclaimed).",
    );
  });

  it("a tampered payload: invalid in both builds, refused, no passed wording", async () => {
    const bundle = tamperPayload(await fullySigned());
    expect(await verdict(bundle)).toBe("INVALID");
    for (const render of [renderEvidenceGraph, browserRender]) {
      const root = await renderWith(render, bundle);
      const top = banner(root);
      expect(top.dataset.verdict).toBe("invalid");
      expect(top.dataset.verify).toBe("failed");
      expect(top.textContent).toBe("Bundle verification failed");
      expect(root.querySelector('[data-refusal="unverified-bundle"]')).not.toBe(
        null,
      );
    }
  });

  it("a producer signature under the wrong key: invalid, though the rows render", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE(TEST_KEYS.a), {
      signCheckpoint: true,
      signWith: { act: "b" },
    });
    expect(await verdict(bundle)).toBe("INVALID");
    const root = await renderWith(renderEvidenceGraph, bundle);
    const top = banner(root);
    expect(top.dataset.verdict).toBe("invalid");
    expect(top.dataset.verify).toBe("verified");
    expect(top.textContent).toBe(
      "Bundle verification failed: 1 of 2 records' producer signatures do not verify (producer_signature_invalid).",
    );
    expect(checks(root, "failed")).toEqual(["producer-signatures"]);
  });

  it("a key_id with no signature: invalid", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE(TEST_KEYS.a), {
      signCheckpoint: true,
      unsigned: ["act"],
    });
    expect(await verdict(bundle)).toBe("INVALID");
    const top = banner(await renderWith(renderEvidenceGraph, bundle));
    expect(top.dataset.verdict).toBe("invalid");
    expect(top.textContent).toContain("producer_signature_invalid");
  });

  it("a checkpoint whose JSON copy disagrees with what it signed: invalid", async () => {
    const bundle = await fullySigned();
    const checkpoint = bundle.checkpoint as Obj;
    const edited = {
      ...bundle,
      checkpoint: { ...checkpoint, timestamp: "2026-09-15T00:00:00Z" },
    };
    expect(await verdict(edited)).toBe("INVALID");
    const root = await renderWith(renderEvidenceGraph, edited);
    const top = banner(root);
    expect(top.dataset.verdict).toBe("invalid");
    expect(top.dataset.checkpoint).toBe("invalid");
    expect(top.textContent).toBe(
      "Bundle verification failed: the signed checkpoint (checkpoint_field_mismatch).",
    );
    expect(checks(root, "failed")).toContain("checkpoint-signature");
    const garbled = { ...bundle, checkpoint: { ...checkpoint, cose: "AAAA" } };
    expect(
      banner(await renderWith(renderEvidenceGraph, garbled)).dataset.verdict,
    ).toBe("invalid");
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
      for (const render of [renderEvidenceGraph, browserRender]) {
        const top = banner(await renderWith(render, value));
        expect(["valid", "incomplete", "invalid"]).toContain(
          top.dataset.verdict,
        );
        expect(top.dataset.checkpoint).toMatch(
          /^(?:verified|unverified|invalid|absent)$/u,
        );
        if (top.dataset.verdict !== "valid")
          expect(top.textContent).not.toContain("passed");
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
    let root = await renderWith(renderEvidenceGraph, bundle);
    expect(banner(root).dataset.verdict).toBe("valid");
    expect(checks(root, "not-checked")).toContain("witness-receipts");
    const checkpoint = bundle.checkpoint as Obj;
    checkpoint.witnesses = [...(checkpoint.witnesses as unknown[]), 7];
    root = await renderWith(renderEvidenceGraph, bundle);
    const top = banner(root);
    expect(top.dataset.verdict).toBe("invalid");
    expect(top.textContent).toBe(
      "Bundle verification failed: the witness receipts (witness_receipt_malformed).",
    );
    expect(checks(root, "failed")).toContain("witness-receipts");
    expect(checks(root, "page")).not.toContain("witness-receipts");
  });

  it("records bound to no log position: membership is listed as failed, never checked", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE(TEST_KEYS.a), {
      signCheckpoint: true,
      uncheckpointed: ["act"],
    });
    const root = await renderWith(renderEvidenceGraph, bundle);
    const top = banner(root);
    expect(top.dataset.verify).toBe("verified");
    expect(top.dataset.verdict).toBe("invalid");
    expect(top.textContent).toBe(
      "Bundle verification failed: 1 of 2 records are uncheckpointed (bound to no log position), so per-record membership fails.",
    );
    expect(checks(root, "failed")).toContain("membership");
    expect(checks(root, "page")).not.toContain("membership");
  });

  it("a cose of null: the checkpoint is invalid, as the lists say", async () => {
    const top = banner(
      await renderWith(
        renderEvidenceGraph,
        strictCase("neg-checkpoint-cose-null"),
      ),
    );
    expect(top.dataset.verdict).toBe("invalid");
    expect(top.dataset.checkpoint).toBe("invalid");
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
// The page's own checks refuse a producer-selected bundle (its interval is
// not checkable), so the page says invalid where the strict verdict is
// incomplete: less, never more.
const REFUSED_BY_THE_PAGE = new Set(["incomplete-producer-selected"]);
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
    const top = banner(await renderWith(renderEvidenceGraph, c.bundle));
    expect(top.dataset.verdict).toBe(
      REFUSED_BY_THE_PAGE.has(id) ? "invalid" : expected,
    );
    const browser = banner(await renderWith(browserRender, c.bundle));
    expect(["invalid", "incomplete"]).toContain(browser.dataset.verdict);
    if (ORDER[browser.dataset.verdict!]! > ORDER[expected]!) {
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
      expect(browser.dataset.verdict).toBe("incomplete");
      expect(browser.dataset.checkpoint).toBe("unverified");
      expect(browser.textContent).toContain("checkpoint_verifier_unavailable");
    }
    for (const page of [top, browser])
      if (page.dataset.verdict !== "valid")
        expect(page.textContent).not.toContain("passed");
  });
});
