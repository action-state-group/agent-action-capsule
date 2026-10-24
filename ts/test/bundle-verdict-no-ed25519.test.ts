// A runtime whose WebCrypto has no Ed25519 while the page's own checks still
// authenticate the checkpoint: no strict verdict, so the banner reads the
// plain claims. Ed25519 is reported missing here; everything else is real.
import { describe, expect, it, vi } from "vitest";

vi.mock("../src/json.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/json.js")>()),
  probeEd25519: async () => false,
}));

const { pageModel } = await import("./helpers/page-model.js");
const { buildVerifiedBundleContext } = await import("../src/bundle.js");
const { sealEvidenceBundle } = await import("./helpers/sealed-bundle.js");

describe("no Ed25519, a checkpoint the page's own checks authenticated", () => {
  it("is verified, not named as unchecked, and carries no checkpoint_unverified sentence", async () => {
    const { bundle } = await sealEvidenceBundle(
      {
        root: "deal",
        records: [
          { capsule_id: "act" },
          {
            capsule_id: "deal",
            chain: { parent_capsule_id: "act", relation: "derived_from" },
          },
        ],
      },
      { signCheckpoint: true },
    );
    expect((await buildVerifiedBundleContext(bundle)).strict).toBeUndefined();
    const { banner, page } = await pageModel(bundle);
    expect(banner.verdict).toBe("incomplete");
    expect(banner.checkpoint).toBe("verified");
    expect(banner.state).toBe("incomplete");
    expect(banner.detail).toBe("No record is signed.");
    expect(JSON.stringify({ banner, page })).not.toContain(
      "checkpoint_unverified",
    );
    expect(page.checkLists.page).toContain("checkpoint-signature");
  });
});
