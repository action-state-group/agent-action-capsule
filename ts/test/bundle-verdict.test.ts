import { build } from "esbuild";
import { JSDOM } from "jsdom";
import { beforeAll, describe, expect, it } from "vitest";
import {
  bundleVerdict,
  bundleVerdictDetail,
  verifyBundle,
} from "../src/bundle.js";
import { renderEvidenceGraph } from "../src/browser.js";
import { sealEvidenceBundle, TEST_KEYS } from "./helpers/sealed-bundle.js";

// A DOM constructed directly with jsdom rather than a whole-file environment
// override: esbuild (which builds the browser bundle below) refuses to run
// under the jsdom environment's TextEncoder.
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

async function renderWith(render: Render, bundle: unknown) {
  const root = document.createElement("main");
  await render(bundle, root);
  return root;
}

// The shipped browser build: src/browser.ts bundled for the browser exactly
// as `npm run emitter:iife` does (in memory here), so cll resolves to its
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

describe("bundleVerdict (capsulectl verify --bundle rules)", () => {
  it("is valid only when every claim passes: signed checkpoint, signed records", async () => {
    const result = await verifyBundle(await fullySigned());
    expect(result.checkpointSignature).toEqual({
      status: "pass",
      findings: [],
    });
    expect(result.producerSignatures).toEqual({ status: "pass", findings: [] });
    expect(Object.values(result.recordSignatures)).toEqual([
      "authored",
      "authored",
    ]);
    expect(result.intervalCoverage).toEqual({ status: "pass", findings: [] });
    expect(bundleVerdict(result)).toBe("valid");
  });

  it("is incomplete for unsigned records, naming producer_signature_unclaimed", async () => {
    const result = await verifyBundle(await signedCheckpointUnsignedRecords());
    expect(result.producerSignatures.status).toBe("withheld");
    expect(result.producerSignatures.findings).toHaveLength(2);
    expect(
      result.producerSignatures.findings.every((finding) =>
        finding.startsWith("producer_signature_unclaimed:"),
      ),
    ).toBe(true);
    const detail = bundleVerdictDetail(result);
    expect(detail.verdict).toBe("incomplete");
    expect(detail.notShown.map((entry) => entry.claim)).toEqual([
      "producer_signatures",
    ]);
  });

  it("is incomplete for an unsigned checkpoint: checkpoint_signature_absent, coverage checkpoint_unverified", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE(TEST_KEYS.a));
    const detail = bundleVerdictDetail(await verifyBundle(bundle));
    expect(detail.verdict).toBe("incomplete");
    expect(detail.checkpointUnverified).toBe(true);
    expect(detail.notShown).toContainEqual({
      claim: "checkpoint",
      status: "withheld",
      findings: ["checkpoint_signature_absent"],
    });
    expect(detail.notShown).toContainEqual({
      claim: "interval_coverage",
      status: "pass",
      findings: ["checkpoint_unverified"],
    });
  });

  it("is invalid for a tampered payload (disclosure mismatch)", async () => {
    const detail = bundleVerdictDetail(
      await verifyBundle(tamperPayload(await fullySigned())),
    );
    expect(detail.verdict).toBe("invalid");
    expect(detail.failed).toEqual(["disclosures"]);
  });

  it("is invalid when a producer signature does not verify under its key_id", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE(TEST_KEYS.a), {
      signCheckpoint: true,
      signWith: { act: "b" },
    });
    const result = await verifyBundle(bundle);
    expect(result.producerSignatures.status).toBe("fail");
    expect(Object.values(result.recordSignatures).sort()).toEqual([
      "authored",
      "invalid",
    ]);
    expect(bundleVerdict(result)).toBe("invalid");
  });

  it("is invalid when a record states a key_id but carries no signature", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE(TEST_KEYS.a), {
      signCheckpoint: true,
      unsigned: ["act"],
    });
    const result = await verifyBundle(bundle);
    expect(result.producerSignatures.findings).toHaveLength(1);
    expect(result.producerSignatures.findings[0]).toMatch(
      /^producer_signature_invalid:/u,
    );
    expect(bundleVerdict(result)).toBe("invalid");
  });

  it("is invalid when the checkpoint's JSON copy disagrees with what it signed", async () => {
    const bundle = await fullySigned();
    const checkpoint = bundle.checkpoint as Obj;
    const edited = {
      ...bundle,
      checkpoint: { ...checkpoint, timestamp: "2026-09-15T00:00:00Z" },
    };
    const result = await verifyBundle(edited);
    expect(result.checkpointSignature).toEqual({
      status: "fail",
      findings: ["checkpoint_field_mismatch:timestamp"],
    });
    expect(bundleVerdict(result)).toBe("invalid");
    const garbled = {
      ...bundle,
      checkpoint: { ...checkpoint, cose: "AAAA" },
    };
    expect((await verifyBundle(garbled)).checkpointSignature.status).toBe(
      "fail",
    );
  });

  it("is invalid for a bundle with no records or a malformed bundle", async () => {
    expect(bundleVerdict(await verifyBundle({}))).toBe("invalid");
    expect(bundleVerdict(await verifyBundle("not a bundle"))).toBe("invalid");
  });
});

describe("the banner never claims more than was checked", () => {
  it("library build, fully signed bundle: VALID, the only case that says passed", async () => {
    const root = await renderWith(renderEvidenceGraph, await fullySigned());
    const top = banner(root);
    expect(top.dataset.verdict).toBe("valid");
    expect(top.dataset.checkpoint).toBe("verified");
    expect(top.dataset.verify).toBe("verified");
    expect(top.textContent).toMatch(/^Bundle verification passed: VALID\./u);
    expect(top.textContent).not.toContain("checkpoint_unverified");
    expect(
      root.querySelector('[data-page="verification"] [data-page-verdict]')
        ?.textContent,
    ).toBe("verdict: VALID");
  });

  it("browser build, signed checkpoint it cannot authenticate, unsigned records: INCOMPLETE, labelled checkpoint_unverified (issue #196)", async () => {
    const root = await renderWith(
      browserRender,
      await signedCheckpointUnsignedRecords(),
    );
    const top = banner(root);
    expect(top.dataset.verdict).toBe("incomplete");
    expect(top.dataset.checkpoint).toBe("unverified");
    expect(top.textContent).not.toContain("passed");
    expect(top.textContent).toMatch(/^Bundle verification INCOMPLETE:/u);
    expect(top.textContent).toContain(
      "the checkpoint signature, which this page could not authenticate (checkpoint_unverified)",
    );
    expect(top.textContent).toContain("producer_signature_unclaimed");
    expect(top.textContent).toContain(
      "relative to a producer-asserted checkpoint this page could not authenticate",
    );
    // the finding is on the verification page too
    const page = root.querySelector<HTMLElement>('[data-page="verification"]')!;
    expect(
      page.querySelector('[data-checkpoint="unverified"]')?.textContent,
    ).toContain("checkpoint_unverified");
    expect(
      page.querySelector('[data-claim="interval_coverage"]')?.textContent,
    ).toBe("interval_coverage: pass (checkpoint_unverified)");
    expect(page.querySelector('[data-claim="checkpoint"]')?.textContent).toBe(
      "checkpoint: withheld (checkpoint_unverified)",
    );
  });

  it("browser build, a bundle the library calls VALID: at most INCOMPLETE", async () => {
    const bundle = await fullySigned();
    expect(bundleVerdict(await verifyBundle(bundle))).toBe("valid");
    const top = banner(await renderWith(browserRender, bundle));
    expect(top.dataset.verdict).toBe("incomplete");
    expect(top.dataset.checkpoint).toBe("unverified");
    expect(top.textContent).not.toContain("passed");
  });

  it("a tampered payload: INVALID in both builds, refused, no passed wording", async () => {
    const bundle = tamperPayload(await fullySigned());
    for (const render of [renderEvidenceGraph, browserRender]) {
      const root = await renderWith(render, bundle);
      const top = banner(root);
      expect(top.dataset.verdict).toBe("invalid");
      expect(top.dataset.verify).toBe("failed");
      expect(top.textContent).toMatch(
        /^Bundle verification failed: INVALID \(disclosures\)/u,
      );
      expect(top.textContent).not.toContain("passed");
      expect(root.querySelector('[data-refusal="unverified-bundle"]')).not.toBe(
        null,
      );
    }
  });

  it("sets data-verdict on every page, verified or not", async () => {
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
