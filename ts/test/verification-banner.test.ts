import { describe, expect, it } from "vitest";
import { buildVerifiedBundleContext } from "../src/bundle.js";
import {
  UNVERIFIED_BUNDLE_REFUSAL,
  VERIFICATION_BANNER_LINES as LINES,
  verificationBanner,
  type VerificationBanner,
} from "../src/verification-page.js";
import { pageModel } from "./helpers/page-model.js";
import { sealEvidenceBundle, TEST_KEYS } from "./helpers/sealed-bundle.js";

// verificationBanner is the banner's state, line, verdict and details line
// computed from the verification result alone, so a viewer draws AAC's
// verdict without computing one (contract section 6.2). These cases are the
// model's own; each also checks that the banner read with the
// countersignature classification a page draws says exactly the same.

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
  return verificationBanner(await buildVerifiedBundleContext(bundle), []);
}

// The banner a page draws: with the countersignature stamps it classifies.
async function drawn(bundle: unknown): Promise<VerificationBanner> {
  return (await pageModel(bundle)).banner;
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

  it("a countersignature it cannot check: the incomplete line points at the not-checked list", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE(TEST_KEYS.a));
    const countersigned = {
      ...bundle,
      countersignatures: [{ type: "countersign/v2", anything: true }],
    };
    const context = await buildVerifiedBundleContext(countersigned);
    const without = verificationBanner(context, []);
    const banner = verificationBanner(context, [
      { kind: "unverified", type: "countersign/v2", reason: "type" },
    ]);
    // Only the line changes: the stamp adds a not-checked list for the
    // banner to point at, and never changes the state or the verdict.
    expect(without.line).toBe(LINES.incompleteNoList);
    expect(banner).toEqual({ ...without, line: LINES.incomplete });
    expect(await drawn(countersigned)).toEqual(banner);
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

  it("a record bound to no log position: failed, counted, the records still shown", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE(TEST_KEYS.a), {
      signCheckpoint: true,
      uncheckpointed: ["act"],
    });
    const banner = await model(bundle);
    expect(banner).toEqual({
      state: "failed",
      line: LINES.failed,
      verdict: "invalid",
      checkpoint: "verified",
      detail:
        "1 of 2 records are uncheckpointed (bound to no log position), so per-record membership fails.",
      uncheckpointed: 1,
    });
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
