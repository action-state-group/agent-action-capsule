// The verification banner's states (spec/verification-display-v0.md section
// 6.2; issues #309 and #346): a page shows exactly one of checking,
// verified, incomplete, failed and unable to verify, each with the core's
// fixed line from vectors/viewer-core-text/. Here each final state is read
// from the verification model (verificationBanner) a viewer draws;
// capsule-viewer renders every state against the same corpus, including
// `checking` before the digests are computed.
//
//   AAC_WRITE_VECTORS=1 npx vitest run test/verification-states.test.ts
//
// rewrites the corpus (and its SHA256SUMS) instead of comparing it.
import { createHash } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { digestCapability, setSha256FallbackForTesting } from "../src/json.js";
import { UNABLE_TO_VERIFY_LINES } from "../src/verification-page.js";
import {
  BANNER_STATES,
  generateCoreTextVectors,
  type WireBannerState,
} from "./helpers/viewer-core-text-vectors.js";
import { pageModel, type PageModel } from "./helpers/page-model.js";
import { sealEvidenceBundle, TEST_KEYS } from "./helpers/sealed-bundle.js";

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

  // Skipped while writing: generate_all_vectors.py rewrites the top-level
  // list after every generator has run.
  it.skipIf(process.env.AAC_WRITE_VECTORS === "1")(
    "the top-level index lists the corpus",
    () => {
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
    },
  );

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

const render = (bundle: unknown): Promise<PageModel> => pageModel(bundle);

// The banner's state, verdict, line and refusal, against the corpus.
function expectState(root: PageModel, expected: WireBannerState): void {
  const { banner } = root;
  expect(banner.line).toBe(expected.line);
  expect(banner.state).toBe(expected.data_verify);
  expect(banner.verdict).toBe(expected.data_verdict);
  expect(banner.refusal !== undefined).toBe(
    expected.data_verify === "failed" && !expected.records_shown,
  );
  if (banner.refusal !== undefined)
    expect(banner.refusal).toBe(corpus().refusal);
}

afterEach(() => {
  vi.unstubAllGlobals();
  setSha256FallbackForTesting(true);
});

describe("one golden banner per state", () => {
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
    expect(root.page.checkLists.notChecked).not.toEqual([]);
  });

  it("incomplete, with no not-checked list: nothing is signed", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE());
    const root = await render(bundle);
    expectState(root, state("incomplete-no-list"));
    expect(root.page.checkLists.notChecked).toEqual([]);
    expect(root.banner.detail).toContain("checkpoint_signature_absent");
  });

  it("failed, records still shown: a record bound to no log position", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE(TEST_KEYS.a), {
      signCheckpoint: true,
      uncheckpointed: ["act"],
    });
    const root = await render(bundle);
    expectState(root, state("failed"));
    expect(root.banner.detail).toBe(
      "1 of 2 records are uncheckpointed (bound to no log position), so per-record membership fails.",
    );
  });

  it("refused: a tampered payload", async () => {
    const { bundle } = await sealEvidenceBundle(SOURCE(TEST_KEYS.a), {
      signCheckpoint: true,
    });
    const root = await render(tamperPayload(bundle));
    expectState(root, state("refused"));
    expect(root.banner.detail).toBe("");
  });

  it("unable to verify: no SHA-256 at all, a state of its own with the core's line", async () => {
    vi.stubGlobal("crypto", undefined);
    setSha256FallbackForTesting(false);
    // A viewer draws `unable` (never failed) when it has no digest at all.
    expect(digestCapability()).toBe("none");
    const unable = state("unable");
    expect(unable.line).toBe(UNABLE_TO_VERIFY_LINES.banner);
    expect(unable.data_verify).toBe("unable");
    expect(unable.data_verdict).toBeNull();
    expect(unable.records_shown).toBe(false);
  });
});
