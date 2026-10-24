import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import vm from "node:vm";
import { build } from "esbuild";
import { beforeAll, describe, expect, it } from "vitest";

// The browser entry (src/browser.ts, bundled here as a page bundles it), run
// the way a page outside a secure context runs it: a fresh context with no
// `crypto` global, so no SubtleCrypto for the record digests (json.ts) or the
// MMR proofs (@action-state-group/cll's browser condition, which esbuild
// bundles here).

const tsRoot = resolve(import.meta.dirname, "..");

type Check = { name: string; status: string };
type Runtime = {
  // The bundle, parsed in the runtime's own realm as a page parses it: the
  // verifier accepts plain objects of its own realm only.
  bundle: unknown;
  digestCapability(): string;
  setSha256FallbackForTesting(enabled: boolean): void;
  buildVerifiedBundleContext(bundle: unknown): Promise<{
    verification: unknown;
  }>;
  buildVerificationPageModel(
    bundle: unknown,
    verification: unknown,
  ): { checks: Check[]; bundleDigest?: string };
};

let source: string;

function runtime(withCrypto: boolean): Runtime {
  const sandbox: Record<string, unknown> = {
    TextEncoder,
    TextDecoder,
    atob,
    btoa,
    URL,
  };
  if (withCrypto) sandbox.crypto = globalThis.crypto;
  const context = vm.createContext(sandbox);
  expect(vm.runInContext("typeof crypto", context)).toBe(
    withCrypto ? "object" : "undefined",
  );
  vm.runInContext(source, context);
  sandbox.bundleText = bundleText;
  return {
    ...(vm.runInContext("EvidenceGraph", context) as Omit<Runtime, "bundle">),
    bundle: vm.runInContext("JSON.parse(bundleText)", context),
  };
}

const bundleText = readFileSync(
  resolve(tsRoot, "test", "testdata", "week-bundle.json"),
  "utf8",
);

async function checks(eg: Runtime): Promise<Check[]> {
  const context = await eg.buildVerifiedBundleContext(eg.bundle);
  return eg
    .buildVerificationPageModel(eg.bundle, context.verification)
    .checks.map(({ name, status }) => ({ name, status }));
}

describe("the browser entry without a crypto global", () => {
  beforeAll(async () => {
    const result = await build({
      entryPoints: [resolve(tsRoot, "src", "browser.ts")],
      bundle: true,
      format: "iife",
      globalName: "EvidenceGraph",
      platform: "browser",
      write: false,
    });
    source = result.outputFiles[0]!.text;
  }, 60_000);

  it("passes the same ten checks as with WebCrypto", async () => {
    const expected = await checks(runtime(true));
    expect(expected).toHaveLength(10);
    expect(expected.every((c) => c.status === "pass")).toBe(true);
    const eg = runtime(false);
    expect(eg.digestCapability()).toBe("fallback");
    expect(await checks(eg)).toEqual(expected);
  });

  it("refuses to verify, rather than fail, with the fallback off", async () => {
    const eg = runtime(false);
    eg.setSha256FallbackForTesting(false);
    expect(eg.digestCapability()).toBe("none");
    await expect(
      eg.buildVerifiedBundleContext(eg.bundle),
    ).rejects.toMatchObject({
      name: "Sha256UnavailableError",
    });
  });
});
