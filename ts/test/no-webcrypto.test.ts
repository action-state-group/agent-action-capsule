// @vitest-environment jsdom

// A page outside a secure context (a file, an app's attachment viewer) has
// no SubtleCrypto. These tests remove `crypto` the way such a page lacks it
// and check that integrity still verifies with the plain SHA-256, that an
// Ed25519 signature reads "not checked in this viewer" rather than failed,
// and that a runtime with no SHA-256 at all renders "unable to verify in
// this viewer", never the failure banner.
//
// Under vitest the Node condition of @action-state-group/cll is loaded,
// whose MMR hash is node:crypto; the browser condition's MMR fallback is
// covered in cll-ts (test/mmr-conformance.test.ts) and end to end by the
// built IIFE in test/no-webcrypto-iife.test.ts.

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
  UNABLE_TO_VERIFY_LINES,
  renderEvidenceGraph,
} from "../src/evidence-graph-view.js";
import {
  Sha256UnavailableError,
  digestCapability,
  ed25519Available,
  probeEd25519,
  setSha256FallbackForTesting,
  sha256Hex,
} from "../src/json.js";
import { buildResultRoot } from "../src/result-root.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

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

  it("renders a verified bundle as verified, and its verdict as incomplete, never failed", async () => {
    withoutWebCrypto();
    const root = document.createElement("main");
    await renderEvidenceGraph(fixture("week-bundle.json"), root);
    const banner = root.querySelector<HTMLElement>("[data-verify]")!;
    expect(banner.dataset.verify).toBe("verified");
    // No Ed25519, so no strict verdict: no signature was checked.
    expect(banner.dataset.verdict).toBe("incomplete");
    expect(banner.textContent).toBe(
      "Bundle verification incomplete: no check failed, but this viewer cannot check signatures, so the checkpoint signature and the records' producer signatures were not checked.",
    );
    expect(root.querySelector('[data-refusal="unverified-bundle"]')).toBeNull();
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

  it("renders 'unable to verify in this viewer' with the command, not the failure banner", async () => {
    withoutWebCrypto();
    setSha256FallbackForTesting(false);
    const root = document.createElement("main");
    const command = "capsulectl verify --bundle report.html";
    await renderEvidenceGraph(fixture("week-bundle.json"), root, undefined, {
      verifyCommand: command,
    });
    expect(root.querySelector('[data-verify="unable"]')?.textContent).toBe(
      UNABLE_TO_VERIFY_LINES.banner,
    );
    expect(
      root.querySelector('[data-refusal="unable-to-verify"]'),
    ).not.toBeNull();
    expect(root.querySelector("[data-verify-command]")?.textContent).toBe(
      command,
    );
    expect(root.querySelector('[data-verify="failed"]')).toBeNull();
    expect(root.querySelector('[data-refusal="unverified-bundle"]')).toBeNull();
    expect(root.textContent).not.toMatch(/verification failed|did not verify/i);
    expect(root.querySelector("[data-report-date]")).toBeNull();
  });

  it("says where to check the file when no command is given", async () => {
    withoutWebCrypto();
    setSha256FallbackForTesting(false);
    const root = document.createElement("main");
    await renderEvidenceGraph(fixture("week-bundle.json"), root);
    expect(root.querySelector('[data-verify="unable"]')).not.toBeNull();
    expect(root.querySelector("[data-verify-command]")).toBeNull();
    expect(root.textContent).toContain(UNABLE_TO_VERIFY_LINES.noCommand);
    expect(root.querySelector('[data-verify="failed"]')).toBeNull();
    expect(root.querySelector('[data-refusal="unverified-bundle"]')).toBeNull();
  });
});
