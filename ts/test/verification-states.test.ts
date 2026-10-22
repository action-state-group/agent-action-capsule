// The verification banner's states (spec/presentation-contract-v0.md section
// 6.2; issues #309 and #346): a page shows exactly one of checking,
// verified, incomplete, failed and unable to verify, each with the core's
// fixed line from vectors/viewer-core-text/. `checking` is drawn before the
// digests are computed and replaced by the final state; `unable` is never
// drawn as failed, and `verified` never appears before the checks finish.
//
//   AAC_WRITE_VECTORS=1 npx vitest run test/verification-states.test.ts
//
// rewrites the corpus (and its SHA256SUMS) instead of comparing it.
import { createHash } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve as resolvePath } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderEvidenceGraph } from "../src/evidence-graph-view.js";
import { setSha256FallbackForTesting } from "../src/json.js";
import {
  BANNER_STATES,
  generateCoreTextVectors,
  type WireBannerState,
} from "./helpers/viewer-core-text-vectors.js";
import { sealEvidenceBundle, TEST_KEYS } from "./helpers/sealed-bundle.js";

// A DOM constructed directly with jsdom rather than a whole-file environment
// override, as test/bundle-verdict.test.ts does: under the jsdom
// environment the signed checkpoint's bytes come from another realm and the
// page cannot check them. jsdom ships no type declarations.
const { JSDOM } = createRequire(import.meta.url)("jsdom") as {
  JSDOM: new () => { window: Window & typeof globalThis };
};
const dom = new JSDOM();
globalThis.document = dom.window.document;
globalThis.HTMLElement = dom.window.HTMLElement;
const { MutationObserver } = dom.window;

type Obj = Record<string, unknown>;
const VECTORS = resolvePath(process.cwd(), "..", "vectors");
const DIR = resolvePath(VECTORS, "viewer-core-text");
const sha256 = (bytes: Buffer | string): string =>
  createHash("sha256").update(bytes).digest("hex");

function checksums(): string {
  const lines = readdirSync(DIR)
    .filter((name) => name !== "SHA256SUMS")
    .sort()
    .map((name) => `${sha256(readFileSync(resolvePath(DIR, name)))}  ${name}`);
  return `${lines.join("\n")}\n`;
}

describe("vectors/viewer-core-text", () => {
  it("the committed corpus is exactly what the generator writes", () => {
    const files = generateCoreTextVectors();
    if (process.env.AAC_WRITE_VECTORS === "1") {
      mkdirSync(DIR, { recursive: true });
      for (const [name, text] of Object.entries(files))
        writeFileSync(resolvePath(DIR, name), text);
      writeFileSync(resolvePath(DIR, "SHA256SUMS"), checksums());
    }
    for (const [name, text] of Object.entries(files))
      expect(readFileSync(resolvePath(DIR, name), "utf8"), name).toBe(text);
    expect(readFileSync(resolvePath(DIR, "SHA256SUMS"), "utf8")).toBe(
      checksums(),
    );
  });

  it("the top-level index lists the corpus", () => {
    const top = readFileSync(resolvePath(VECTORS, "SHA256SUMS"), "utf8");
    for (const name of readdirSync(DIR).filter((n) => n !== "SHA256SUMS"))
      expect(top).toContain(
        `${sha256(readFileSync(resolvePath(DIR, name)))}  viewer-core-text/${name}`,
      );
    const index = JSON.parse(
      readFileSync(resolvePath(VECTORS, "manifest.json"), "utf8"),
    ) as { corpora: Record<string, string> };
    expect(index.corpora.viewer_core_text).toBe(
      "viewer-core-text/manifest.json",
    );
  });

  it("no banner line names an internal token or says passed", () => {
    for (const state of BANNER_STATES) {
      expect(state.line).not.toMatch(/_|passed/u);
      expect(state.line).not.toMatch(/\bverified\b/iu);
    }
  });
});

// The banner states from the committed corpus, read back from disk alone
// (after the corpus test above has written it, under AAC_WRITE_VECTORS).
const corpus = (): { banner: WireBannerState[]; refusal: string } =>
  JSON.parse(readFileSync(resolvePath(DIR, "core-text.json"), "utf8")) as {
    banner: WireBannerState[];
    refusal: string;
  };
const state = (id: string): WireBannerState =>
  corpus().banner.find((entry) => entry.id === id)!;

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

function tamperPayload(bundle: Obj): Obj {
  const disclosures = structuredClone(bundle.disclosures) as Record<
    string,
    Record<string, Obj>
  >;
  Object.values(disclosures).find(
    (value) => value.agent_output !== undefined,
  )!.agent_output!.amount = 2;
  return { ...bundle, disclosures };
}

async function render(bundle: unknown): Promise<HTMLElement> {
  const root = document.createElement("main");
  await renderEvidenceGraph(bundle, root);
  return root;
}

// The banner, its data attributes and the elements before the first row.
function expectState(root: HTMLElement, expected: WireBannerState): void {
  const banners = root.querySelectorAll<HTMLElement>("[data-verify]");
  expect(banners).toHaveLength(1);
  const banner = banners[0]!;
  expect(banner.textContent).toBe(expected.line);
  expect(banner.dataset.verify).toBe(expected.data_verify);
  expect(banner.dataset.verdict ?? null).toBe(expected.data_verdict);
  const refusal = root.querySelector('[data-refusal="unverified-bundle"]');
  expect(refusal !== null).toBe(
    expected.data_verify === "failed" && !expected.records_shown,
  );
  if (refusal !== null) expect(refusal.textContent).toBe(corpus().refusal);
}

afterEach(() => {
  vi.unstubAllGlobals();
  setSha256FallbackForTesting(true);
});

describe("one golden page per state", () => {
  it("verified: every signature checked here", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE(TEST_KEYS.a), {
      signCheckpoint: true,
    });
    expectState(await render(bundle), state("verified"));
  });

  it("incomplete, with a not-checked list: a signed checkpoint, unsigned records, in the browser build's terms", async () => {
    // A checkpoint signed by a key the page cannot authenticate is not
    // possible to fake here, so the incomplete page with a not-checked list
    // is the one whose records carry signatures this page could not check.
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
    const root = await render(bundle);
    expectState(root, state("incomplete"));
    expect(
      root.querySelector(
        '[data-page="verification"] [data-checks="not-checked"]',
      ),
    ).not.toBeNull();
  });

  it("incomplete, with no not-checked list: nothing is signed", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE());
    const root = await render(bundle);
    expectState(root, state("incomplete-no-list"));
    expect(
      root.querySelector(
        '[data-page="verification"] [data-checks="not-checked"]',
      ),
    ).toBeNull();
    expect(root.querySelector("[data-banner-detail]")?.textContent).toContain(
      "checkpoint_signature_absent",
    );
  });

  it("failed, records still shown: a record bound to no log position", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE(TEST_KEYS.a), {
      signCheckpoint: true,
      uncheckpointed: ["act"],
    });
    const root = await render(bundle);
    expectState(root, state("failed"));
    expect(root.querySelector("[data-banner-detail]")?.textContent).toBe(
      "1 of 2 records are uncheckpointed (bound to no log position), so per-record membership fails.",
    );
  });

  it("refused: a tampered payload", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE(TEST_KEYS.a), {
      signCheckpoint: true,
    });
    const root = await render(tamperPayload(bundle));
    expectState(root, state("refused"));
    expect(root.querySelector("[data-banner-detail]")).toBeNull();
  });

  it("unable to verify: no SHA-256 at all, never drawn as failed", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE());
    vi.stubGlobal("crypto", undefined);
    setSha256FallbackForTesting(false);
    const root = await render(bundle);
    expectState(root, state("unable"));
    expect(root.querySelector('[data-verify="failed"]')).toBeNull();
  });
});

describe("checking", () => {
  // A slow hash: every SHA-256 waits on `release`, so the page is held in
  // the checking state until the test lets the digests through.
  function holdDigests(): () => void {
    const real = globalThis.crypto.subtle;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const subtle = new Proxy(real, {
      get(target, name) {
        if (name === "digest")
          return async (...args: Parameters<SubtleCrypto["digest"]>) => {
            await gate;
            return target.digest(...args);
          };
        const value = Reflect.get(target, name) as unknown;
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    vi.stubGlobal("crypto", {
      subtle,
      getRandomValues: globalThis.crypto.getRandomValues.bind(
        globalThis.crypto,
      ),
    });
    return release;
  }

  it("is drawn alone before the checks finish, then replaced by the final state", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE(TEST_KEYS.a), {
      signCheckpoint: true,
    });
    const release = holdDigests();
    const root = document.createElement("main");
    root.append("previous page");
    const done = renderEvidenceGraph(bundle, root);
    // Let every microtask before the first digest run.
    await new Promise((resolve) => setTimeout(resolve, 20));
    expectState(root, state("checking"));
    expect(root.childNodes).toHaveLength(1);
    expect(root.querySelector('[data-verify="verified"]')).toBeNull();
    release();
    await done;
    expectState(root, state("verified"));
    expect(root.querySelector('[data-verify="checking"]')).toBeNull();
  });

  it("is drawn for a bundle that turns out to fail, which then shows failed, never verified on the way", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE(TEST_KEYS.a), {
      signCheckpoint: true,
    });
    const release = holdDigests();
    const root = document.createElement("main");
    const seen: string[] = [];
    const observer = new MutationObserver(() => {
      const verify =
        root.querySelector<HTMLElement>("[data-verify]")?.dataset.verify;
      if (verify !== undefined && seen.at(-1) !== verify) seen.push(verify);
    });
    observer.observe(root, {
      childList: true,
      subtree: true,
      attributes: true,
    });
    const done = renderEvidenceGraph(tamperPayload(bundle), root);
    await new Promise((resolve) => setTimeout(resolve, 20));
    release();
    await done;
    await new Promise((resolve) => setTimeout(resolve, 0));
    observer.disconnect();
    expect(seen).toEqual(["checking", "failed"]);
  });
});
