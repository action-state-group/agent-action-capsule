import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import vm from "node:vm";
import { build } from "esbuild";
import { beforeAll, describe, expect, it } from "vitest";

// The checkpoint signature as a page checks it: the browser entry
// (src/browser.ts) bundled as a page bundles it, so @action-state-group/cll
// resolves to its browser condition, run with and without a `crypto` global.
// CLL's browser entry carries its own SHA-256 and strict Ed25519 (#435), so a
// page reaches the checkpoint verdict Node does. Without WebCrypto there is no
// strict result (records need Ed25519), and the banner reads the page's own
// checks of the checkpoint instead.
//
// vectors/cross-language/cll-ed25519-vectors.json is a verbatim copy of
// checkpointed-local-log's checkpoint-conformance-vectors/ed25519-vectors.json
// at c45422a: COSE checkpoints whose only defect, if any, is a small-order
// signing key.

const tsRoot = resolve(import.meta.dirname, "..");

type Obj = Record<string, unknown>;
type Claim = { name: string; status: string; findings: string[] };
type Strict = {
  verdict: string;
  claims: Claim[];
  checkpointAuthenticated: boolean;
};
type Case = {
  id: string;
  options: { require_signature: boolean; witness_directory: boolean };
  bundle: Obj;
  expect: {
    verdict: string;
    claims: Claim[];
    checkpoint_authenticated: boolean;
  };
};
type CoseCase = { name: string; cose_hex: string; valid: boolean };
type Runtime = {
  /** The banner's checkpoint word and the strict result, if any. */
  read(
    bundle: unknown,
  ): Promise<{ checkpoint: string; verified: boolean; strict?: Strict }>;
  strict(bundle: unknown, options: Obj): Promise<Strict>;
  /** The function bundle.ts loads from CLL, as the page bundle resolved it. */
  checkpointMetadata(cose: Uint8Array): Promise<unknown>;
};

const strictVectors = JSON.parse(
  readFileSync(
    resolve(tsRoot, "..", "vectors", "bundle", "strict", "vectors.json"),
    "utf8",
  ),
) as { witness_directory: unknown; cases: Case[] };
const coseCases = (
  JSON.parse(
    readFileSync(
      resolve(
        tsRoot,
        "..",
        "vectors",
        "cross-language",
        "cll-ed25519-vectors.json",
      ),
      "utf8",
    ),
  ) as { cose_cases: CoseCase[] }
).cose_cases;

const checkpointCases = strictVectors.cases.filter((c) =>
  c.expect.claims.some((claim) => claim.name === "checkpoint"),
);
const signedWholeLog = checkpointCases.find(
  (c) => c.id === "pos-signed-whole-log",
)!.bundle;
const checkpoint = signedWholeLog.checkpoint as Obj;

/** `signedWholeLog` with its checkpoint's COSE bytes replaced. */
const withCose = (cose: Uint8Array): Obj => ({
  ...signedWholeLog,
  checkpoint: { ...checkpoint, cose: Buffer.from(cose).toString("base64url") },
});
const tampered = (): Obj => {
  const cose = Buffer.from(checkpoint.cose as string, "base64url");
  cose[cose.length - 1]! ^= 1;
  return withCose(cose);
};

let source: string;

function runtime(withCrypto: boolean): Runtime {
  const sandbox: Obj = { TextEncoder, TextDecoder, atob, btoa, URL };
  if (withCrypto) sandbox.crypto = globalThis.crypto;
  const context = vm.createContext(sandbox);
  expect(vm.runInContext("typeof crypto", context)).toBe(
    withCrypto ? "object" : "undefined",
  );
  vm.runInContext(source, context);
  // Bundles are parsed in the runtime's own realm, as a page parses them.
  const run = vm.runInContext(
    `({
      async read(text) {
        const context = await Page.buildVerifiedBundleContext(JSON.parse(text));
        return {
          checkpoint: Page.verificationBanner(context, []).checkpoint,
          verified: Page.bundleVerified(context.verification),
          strict: context.strict,
        };
      },
      async strict(text, options) {
        return (await Page.verifyBundle(JSON.parse(text), options)).strict;
      },
      checkpointMetadata: (hex) =>
        Page.cllCheckpointMetadata(
          new Uint8Array(hex.match(/../g).map((byte) => parseInt(byte, 16))),
        ),
    })`,
    context,
  ) as {
    read(text: string): ReturnType<Runtime["read"]>;
    strict(text: string, options: Obj): Promise<Strict>;
    checkpointMetadata(hex: string): Promise<unknown>;
  };
  return {
    read: (bundle) => run.read(JSON.stringify(bundle)),
    strict: (bundle, options) => run.strict(JSON.stringify(bundle), options),
    checkpointMetadata: (cose) =>
      run.checkpointMetadata(Buffer.from(cose).toString("hex")),
  };
}

const checkpointClaim = (strict: Strict | undefined) =>
  strict?.claims.find((claim) => claim.name === "checkpoint");

beforeAll(async () => {
  const result = await build({
    stdin: {
      contents: `export * from "./src/browser.ts";
        export { checkpointMetadata as cllCheckpointMetadata } from "@action-state-group/cll";`,
      resolveDir: tsRoot,
      loader: "ts",
    },
    bundle: true,
    format: "iife",
    globalName: "Page",
    platform: "browser",
    metafile: true,
    write: false,
  });
  // The page gets CLL's browser entry, never its Node one.
  const cll = Object.keys(result.metafile.inputs).filter((path) =>
    path.includes("@action-state-group/cll/"),
  );
  expect(cll).toContain("node_modules/@action-state-group/cll/dist/browser.js");
  expect(cll).not.toContain(
    "node_modules/@action-state-group/cll/dist/index.js",
  );
  source = result.outputFiles[0]!.text;
}, 60_000);

describe.each([
  ["with WebCrypto", true],
  ["without a crypto global", false],
])("a page's checkpoint check %s", (_label, withCrypto) => {
  it("reads a valid checkpoint verified", async () => {
    const { checkpoint, strict } =
      await runtime(withCrypto).read(signedWholeLog);
    expect(checkpoint).toBe("verified");
    expect(strict === undefined).toBe(!withCrypto);
    if (withCrypto)
      expect(checkpointClaim(strict)).toEqual({
        name: "checkpoint",
        status: "pass",
        findings: [],
      });
  });

  it("reads a tampered checkpoint invalid", async () => {
    const { checkpoint, strict } = await runtime(withCrypto).read(tampered());
    expect(checkpoint).toBe("invalid");
    if (withCrypto)
      expect(checkpointClaim(strict)).toEqual({
        name: "checkpoint",
        status: "fail",
        findings: ["checkpoint_signature_invalid"],
      });
  });

  // A COSE checkpoint from another log reads invalid on this Bundle whatever
  // its key; what tells a small-order forgery from an honest checkpoint is
  // the signature check itself, which refuses only the forgery.
  it.each(coseCases.map((c) => [c.name, c] as const))(
    "reads CLL COSE case %s invalid, refusing its signature only if forged",
    async (_name, coseCase) => {
      const page = runtime(withCrypto);
      const cose = Buffer.from(coseCase.cose_hex, "hex");
      expect((await page.read(withCose(cose))).checkpoint).toBe("invalid");
      expect((await page.checkpointMetadata(cose)) !== undefined).toBe(
        coseCase.valid,
      );
      if (withCrypto) {
        const claim = checkpointClaim(
          await page.strict(withCose(cose), { strict: true }),
        )!;
        expect(claim.status).toBe("fail");
        expect(claim.findings.includes("checkpoint_signature_invalid")).toBe(
          !coseCase.valid,
        );
      }
    },
  );

  it("has small-order forgeries and honest COSE cases to read", () => {
    const forged = coseCases.filter((c) => !c.valid);
    expect(forged.length).toBeGreaterThan(0);
    expect(forged.every((c) => c.name.startsWith("small-order kid"))).toBe(
      true,
    );
    expect(coseCases.some((c) => c.valid)).toBe(true);
  });
});

// A producer-selected Bundle (records 1 and 3 of a log) as a page reads it.
// With WebCrypto Ed25519 the strict checks run, authenticate the checkpoint
// and prove each record, so the page's gate (bundleVerified) passes and the
// strict verdict is INCOMPLETE. Without it there is no strict result: the
// plain checks read the selection as an interval, so the page refuses it
// rather than show records a full verifier may call INVALID.
describe("a page's producer-selected Bundle", () => {
  const selected = strictVectors.cases.find(
    (c) => c.id === "incomplete-producer-selected",
  )!.bundle;

  it("renders as incomplete with WebCrypto", async () => {
    const { checkpoint, verified, strict } = await runtime(true).read(selected);
    expect(verified).toBe(true);
    expect(checkpoint).toBe("verified");
    expect(strict?.verdict).toBe("INCOMPLETE");
  });

  it("is refused without a crypto global", async () => {
    const { verified, strict } = await runtime(false).read(selected);
    expect(strict).toBeUndefined();
    expect(verified).toBe(false);
  });
});

describe("the browser's strict checkpoint claim", () => {
  it.each(checkpointCases.map((c) => [c.id, c] as const))(
    "%s matches the strict vector",
    async (_id, testCase) => {
      const strict = await runtime(true).strict(testCase.bundle, {
        strict: true,
        requireSignature: testCase.options.require_signature,
        ...(testCase.options.witness_directory
          ? { witnessDirectory: strictVectors.witness_directory }
          : {}),
      });
      expect(checkpointClaim(strict)).toEqual(
        testCase.expect.claims.find((claim) => claim.name === "checkpoint"),
      );
      expect(strict.checkpointAuthenticated).toBe(
        testCase.expect.checkpoint_authenticated,
      );
      expect(strict.verdict).toBe(testCase.expect.verdict);
    },
  );
});
