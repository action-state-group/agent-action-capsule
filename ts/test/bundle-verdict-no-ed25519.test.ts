// A runtime whose WebCrypto has no Ed25519 while the page's own checks still
// authenticate the checkpoint: no strict verdict, so the banner reads the
// plain claims. Ed25519 is reported missing here; everything else is real.
import { createRequire } from "node:module";
import { describe, expect, it, vi } from "vitest";

// A DOM from jsdom directly, as in bundle-verdict.test.ts: the signed
// checkpoint is checked with Node's own crypto, not the jsdom realm's.
const { JSDOM } = createRequire(import.meta.url)("jsdom") as {
  JSDOM: new () => { window: Window & typeof globalThis };
};
const dom = new JSDOM();
globalThis.document = dom.window.document;
globalThis.HTMLElement = dom.window.HTMLElement;

vi.mock("../src/json.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/json.js")>()),
  probeEd25519: async () => false,
}));

const { renderEvidenceGraph } = await import("../src/evidence-graph-view.js");
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
    const root = document.createElement("main");
    await renderEvidenceGraph(bundle, root);
    const banner = root.querySelector<HTMLElement>("[data-verify]")!;
    expect(banner.dataset.verdict).toBe("incomplete");
    expect(banner.dataset.checkpoint).toBe("verified");
    expect(banner.dataset.verify).toBe("incomplete");
    expect(root.querySelector("[data-banner-detail]")?.textContent).toBe(
      "No record is signed.",
    );
    expect(root.textContent).not.toContain("checkpoint_unverified");
    const page = Array.from(
      root.querySelectorAll<HTMLElement>('ul[data-checks="page"] > li'),
      (item) => item.dataset.check!,
    );
    expect(page).toContain("checkpoint-signature");
  });
});
