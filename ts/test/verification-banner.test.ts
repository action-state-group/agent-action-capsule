import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";
import { buildVerifiedBundleContext } from "../src/bundle.js";
import { renderEvidenceGraph } from "../src/browser.js";
import {
  UNVERIFIED_BUNDLE_REFUSAL,
  VERIFICATION_BANNER_LINES as LINES,
  verificationBanner,
  type VerificationBanner,
} from "../src/verification-page.js";
import { sealEvidenceBundle, TEST_KEYS } from "./helpers/sealed-bundle.js";

// verificationBanner is the banner's state, line, verdict and details line
// computed from the verification result alone, so a viewer draws AAC's
// verdict without computing one (contract section 6.2). These cases are the
// model's own; each also checks that the page this package draws says exactly
// what the model says.
const { JSDOM } = createRequire(import.meta.url)("jsdom") as {
  JSDOM: new () => { window: Window & typeof globalThis };
};
const dom = new JSDOM();
globalThis.document = dom.window.document;
globalThis.HTMLElement = dom.window.HTMLElement;

type Obj = Record<string, unknown>;

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

async function model(bundle: unknown): Promise<VerificationBanner> {
  return verificationBanner(await buildVerifiedBundleContext(bundle));
}

// The drawn banner, its details line and refusal, as the model's members.
async function drawn(bundle: unknown): Promise<VerificationBanner> {
  const root = document.createElement("main");
  await renderEvidenceGraph(bundle, root);
  const top = root.querySelector<HTMLElement>("[data-verdict]")!;
  const refusal = root.querySelector<HTMLElement>(
    '[data-refusal="unverified-bundle"]',
  );
  return {
    state: top.dataset.verify as VerificationBanner["state"],
    line: top.textContent!,
    verdict: top.dataset.verdict as VerificationBanner["verdict"],
    checkpoint: top.dataset.checkpoint as VerificationBanner["checkpoint"],
    detail:
      root.querySelector<HTMLElement>("[data-banner-detail]")?.textContent ??
      "",
    uncheckpointed: Number(top.dataset.uncheckpointed),
    ...(refusal === null ? {} : { refusal: refusal.textContent! }),
  };
}

describe("verificationBanner", () => {
  it("a fully signed bundle: verified, no details line", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE(TEST_KEYS.a), {
      signCheckpoint: true,
    });
    const banner = await model(bundle);
    expect(banner).toEqual({
      state: "verified",
      line: LINES.verified,
      verdict: "valid",
      checkpoint: "verified",
      detail: "",
      uncheckpointed: 0,
    });
    expect(await drawn(bundle)).toEqual(banner);
  });

  it("an unsigned checkpoint: incomplete, and no not-checked list to point at", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE(TEST_KEYS.a));
    const banner = await model(bundle);
    expect(banner.state).toBe("incomplete");
    expect(banner.line).toBe(LINES.incompleteNoList);
    expect(banner.checkpoint).toBe("absent");
    expect(banner.detail).toBe(
      "This page did not check " +
        "the checkpoint signature, because the checkpoint is not signed (checkpoint_signature_absent). " +
        "Interval coverage and per-record membership are checkpoint_unverified: " +
        "relative to a producer-asserted checkpoint that is not signed.",
    );
    expect(banner.refusal).toBeUndefined();
    expect(await drawn(bundle)).toEqual(banner);
  });

  it("a producer signature under the wrong key: failed, the records still shown", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE(TEST_KEYS.a), {
      signCheckpoint: true,
      signWith: { act: "b" },
    });
    const banner = await model(bundle);
    expect(banner.state).toBe("failed");
    expect(banner.line).toBe(LINES.failed);
    expect(banner.verdict).toBe("invalid");
    expect(banner.detail).toBe(
      "What failed: 1 of 2 records' producer signatures do not verify (producer_signature_invalid).",
    );
    expect(banner.refusal).toBeUndefined();
    expect(await drawn(bundle)).toEqual(banner);
  });

  it("a tampered payload: refused, with the refusal line and no details", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE(TEST_KEYS.a), {
      signCheckpoint: true,
    });
    const tampered = tamperPayload(bundle);
    const banner = await model(tampered);
    expect(banner).toEqual({
      state: "failed",
      line: LINES.refused,
      verdict: "invalid",
      checkpoint: "verified",
      detail: "",
      uncheckpointed: 0,
      refusal: UNVERIFIED_BUNDLE_REFUSAL,
    });
    expect(await drawn(tampered)).toEqual(banner);
  });
});
