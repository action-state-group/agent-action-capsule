// A page outside a secure context (a file, an app's attachment viewer) has
// no SubtleCrypto. These tests remove `crypto` the way such a page lacks it
// and check that integrity still verifies with the plain SHA-256, that an
// Ed25519 signature reads "not checked in this viewer" rather than failed,
// and that a runtime with no SHA-256 at all refuses to verify rather than
// report a failure, so a viewer shows "unable to verify in this viewer",
// never the failure banner. The banner and lists are read from the
// verification model; capsule-viewer draws them.
//
// Under vitest the Node condition of @action-state-group/cll is loaded,
// whose MMR hash is node:crypto; the browser condition's MMR fallback is
// covered in cll-ts (test/mmr-conformance.test.ts) and end to end by
// capsule-viewer's built page.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  buildVerifiedBundleContext,
  bundleDigest,
  verifyBundle,
} from "../src/bundle.js";
import { classifyCountersignatures } from "../src/countersignature-stamp.js";
import {
  Sha256UnavailableError,
  digestCapability,
  ed25519Available,
  probeEd25519,
  setSha256FallbackForTesting,
  sha256Hex,
} from "../src/json.js";
import { buildResultRoot } from "../src/result-root.js";
import { UNABLE_TO_VERIFY_LINES } from "../src/verification-page.js";
import { pageModel } from "./helpers/page-model.js";
import { sealEvidenceBundle, TEST_KEYS } from "./helpers/sealed-bundle.js";

function fixture(name: string): Record<string, unknown> {
  return JSON.parse(
    readFileSync(resolve(process.cwd(), "test", "testdata", name), "utf8"),
  ) as Record<string, unknown>;
}

const anchor = fixture("countersign-v1-anchor-golden.json") as unknown as {
  bundle: Record<string, unknown>;
  bundle_digest: string;
  directory: { countersigners: Array<{ name: string; key_ids: string[] }> };
  entry: unknown;
};

const withoutWebCrypto = (): void => {
  vi.stubGlobal("crypto", undefined);
  expect(globalThis.crypto).toBeUndefined();
};

afterEach(() => {
  vi.unstubAllGlobals();
  setSha256FallbackForTesting(true);
});

describe("without SubtleCrypto", () => {
  it("hashes with the plain SHA-256, equal to node:crypto", async () => {
    withoutWebCrypto();
    expect(digestCapability()).toBe("fallback");
    expect(ed25519Available()).toBe(false);
    for (const text of ["", "abc", "x".repeat(1000)]) {
      const bytes = new TextEncoder().encode(text);
      expect(await sha256Hex(bytes)).toBe(
        createHash("sha256").update(bytes).digest("hex"),
      );
    }
  });

  it("verifies a bundle to the same result as with WebCrypto", async () => {
    const bundle = fixture("week-bundle.json");
    expect(digestCapability()).toBe("webcrypto");
    const expected = await verifyBundle(bundle);
    expect(expected.bundleDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(expected.graphClosure.status).toBe("pass");
    expect(expected.intervalCoverage.status).toBe("pass");
    expect(expected.perRecordMembership.status).toBe("pass");
    withoutWebCrypto();
    expect(await verifyBundle(bundle)).toEqual(expected);
  });

  it("leaves a countersign/v1 signature not checked, never invalid", async () => {
    const entries = [anchor.entry];
    const source = anchor.directory.countersigners;
    const digest = await bundleDigest(anchor.bundle);
    const [checked] = await classifyCountersignatures(
      entries,
      digest,
      [],
      source,
    );
    expect(checked?.kind).toBe("resolved");
    withoutWebCrypto();
    expect(
      await classifyCountersignatures(entries, digest, [], source),
    ).toEqual([
      { kind: "unverified", type: "countersign/v1", reason: "no-ed25519" },
    ]);
  });

  it("leaves it not checked when SubtleCrypto has no Ed25519", async () => {
    const real = globalThis.crypto.subtle;
    const digest = await bundleDigest(anchor.bundle);
    const subtleRejecting = (name: string) => ({
      digest: real.digest.bind(real),
      importKey: () =>
        Promise.reject(new DOMException("Ed25519 unsupported", name)),
      verify: real.verify.bind(real),
    });
    vi.stubGlobal("crypto", { subtle: subtleRejecting("NotSupportedError") });
    expect(
      await classifyCountersignatures([anchor.entry], digest, [], []),
    ).toEqual([
      { kind: "unverified", type: "countersign/v1", reason: "no-ed25519" },
    ]);
    // Any other rejection is a signature that did not verify.
    vi.stubGlobal("crypto", { subtle: subtleRejecting("DataError") });
    expect(
      await classifyCountersignatures([anchor.entry], digest, [], []),
    ).toEqual([{ kind: "invalid" }]);
  });

  it("reads a close claim's state as asserted, not contradicted, when no signer can be checked", async () => {
    const { bundle } = await sealEvidenceBundle(
      fixture("result-root-close-bundle.json"),
    );
    const checked = (await buildResultRoot(bundle)).claims[1]!;
    expect(checked.close).toMatchObject({
      keyVerified: true,
      derivation: "recomputed",
      state: "AGREED",
    });
    withoutWebCrypto();
    const claim = (await buildResultRoot(bundle)).claims[1]!;
    expect(claim).toMatchObject({ verdict: "met", failed: false });
    expect(claim.close).toMatchObject({
      keyVerified: false,
      keyNotChecked: true,
      asserted: "AGREED",
      state: "AGREED",
      derivation: "producer-asserted",
      stateMismatch: false,
    });
    expect(claim.close?.derived).toBeUndefined();
    expect(claim.close?.ignored.map((i) => i.reason)).toEqual([
      "the cited Close's key_id is a stated key_id (not verified): this viewer cannot check its Producer Envelope, so no signer can be shown to differ from its own",
    ]);
  });

  it("probes Ed25519 support rather than assume it from SubtleCrypto", async () => {
    const real = globalThis.crypto.subtle;
    vi.stubGlobal("crypto", {
      subtle: {
        digest: real.digest.bind(real),
        importKey: () =>
          Promise.reject(new DOMException("unsupported", "NotSupportedError")),
      },
    });
    expect(ed25519Available()).toBe(true); // not yet probed
    await buildVerifiedBundleContext(fixture("week-bundle.json"));
    expect(ed25519Available()).toBe(false);
    expect(await probeEd25519()).toBe(false);
    vi.unstubAllGlobals();
    expect(ed25519Available()).toBe(true);
    expect(await probeEd25519()).toBe(true);
  });

  it("renders a bundle that passed the page's checks as incomplete, never failed", async () => {
    withoutWebCrypto();
    const { banner } = await pageModel(fixture("week-bundle.json"));
    expect(banner.state).toBe("incomplete");
    // No Ed25519, so no strict verdict; this bundle carries no signature.
    expect(banner.verdict).toBe("incomplete");
    expect(banner.detail).toBe(
      "Neither the checkpoint nor any record is signed. Interval coverage and per-record membership are checkpoint_unverified: relative to a producer-asserted checkpoint that is not signed.",
    );
    expect(banner.refusal).toBeUndefined();
  });

  it("still says invalid for a record bound to no log position", async () => {
    const { bundle } = await sealEvidenceBundle(
      fixture("report-mixed-tz-bundle.json"),
      { uncheckpointed: ["act-naive"] },
    );
    withoutWebCrypto();
    const { banner, page } = await pageModel(bundle);
    expect(banner.state).toBe("failed");
    expect(banner.verdict).toBe("invalid");
    expect(banner.detail).toBe(
      "1 of 5 records are uncheckpointed (bound to no log position), so per-record membership fails. Interval coverage is checkpoint_unverified: relative to a producer-asserted checkpoint that is not signed.",
    );
    // The lists agree: membership failed, never checked.
    expect(page.checkLists.failed).toContain("membership");
    expect(page.checkLists.page).not.toContain("membership");
  });

  it("names the signatures it could not check", async () => {
    const { bundle } = await sealEvidenceBundle({
      root: "deal",
      records: [
        { capsule_id: "act", key_id: TEST_KEYS.a },
        {
          capsule_id: "deal",
          key_id: TEST_KEYS.a,
          chain: { parent_capsule_id: "act", relation: "derived_from" },
        },
      ],
    });
    withoutWebCrypto();
    const { banner } = await pageModel(bundle);
    expect(banner.verdict).toBe("incomplete");
    expect(banner.checkpoint).toBe("absent");
    expect(banner.state).toBe("incomplete");
    expect(banner.detail).toMatch(
      /^This page cannot check signatures, so the records' producer signatures could not be checked\./u,
    );
  });
});

describe("with no SHA-256 at all", () => {
  it("throws rather than return a failed verification", async () => {
    withoutWebCrypto();
    setSha256FallbackForTesting(false);
    expect(digestCapability()).toBe("none");
    await expect(sha256Hex(new Uint8Array())).rejects.toBeInstanceOf(
      Sha256UnavailableError,
    );
    await expect(
      verifyBundle(fixture("week-bundle.json")),
    ).rejects.toBeInstanceOf(Sha256UnavailableError);
  });

  it("builds no context, so a viewer can only say 'unable to verify in this viewer', never failed", async () => {
    withoutWebCrypto();
    setSha256FallbackForTesting(false);
    await expect(
      buildVerifiedBundleContext(fixture("week-bundle.json")),
    ).rejects.toBeInstanceOf(Sha256UnavailableError);
    // The words a viewer then shows never say the bundle failed.
    for (const line of Object.values(UNABLE_TO_VERIFY_LINES))
      expect(line).not.toMatch(/verification failed|did not verify/i);
  });
});
