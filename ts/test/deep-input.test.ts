import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { buildVerifiedBundleContext, verifyBundle } from "../src/bundle.js";
import { renderEvidenceGraph } from "../src/evidence-graph-view.js";
import { UNVERIFIED_BUNDLE_REFUSAL } from "../src/verification-page.js";
import { verifyRecordSignature } from "../src/producer-envelope-verification.js";

// vectors/bundle/strict/README.md: a verifier never raises on its input. A
// Bundle or record nested beyond what an implementation can read is
// refused, the Bundle with bundle_malformed on every claim (INVALID) and a
// record signature as invalid. The depth differs between languages, so no
// vector reaches it.
const vectors = JSON.parse(
  readFileSync(
    resolve(process.cwd(), "..", "vectors", "bundle", "strict", "vectors.json"),
    "utf8",
  ),
) as { cases: { id: string; bundle: Record<string, unknown> }[] };

/** An array nested `depth` deep, built without recursion. */
function nested(depth: number): unknown {
  let value: unknown = 0;
  for (let i = 0; i < depth; i += 1) value = [value];
  return value;
}

const DEPTH = 1_000_000;

function deepBundle(): Record<string, unknown> {
  const bundle = structuredClone(vectors.cases[0]!.bundle) as {
    records: Record<string, unknown>[];
  };
  bundle.records[0]!.deep = nested(DEPTH);
  return bundle;
}

describe("input nested beyond the stack", () => {
  it("refuses the Bundle in plain mode, never rejects", async () => {
    const result = await verifyBundle(deepBundle());
    for (const claim of [
      result.graphClosure,
      result.intervalCoverage,
      result.perRecordMembership,
    ])
      expect(claim).toEqual({ status: "fail", findings: ["bundle_malformed"] });
  });

  it("refuses the Bundle in strict mode as INVALID, never rejects", async () => {
    const { strict } = await verifyBundle(deepBundle(), { strict: true });
    expect(strict).toEqual({
      verdict: "INVALID",
      kindOk: false,
      claims: [
        { name: "records", status: "fail", findings: ["bundle_malformed"] },
      ],
      witnesses: null,
      records: [],
      checkpointAuthenticated: false,
      signerMatchesCheckpoint: null,
    });
  });

  it("grades a record nested that deep as invalid", async () => {
    const record = {
      ...(vectors.cases[0]!.bundle.records as Record<string, unknown>[])[0],
      deep: nested(DEPTH),
    };
    const { verdict, messages } = await verifyRecordSignature(record);
    expect(verdict).toBe("invalid");
    expect(messages).toHaveLength(1);
  });

  it("reports a capsule_id whose toString is not callable, never throws", async () => {
    const record = {
      capsule_id: { toString: null },
      signature: "00",
    };
    expect(await verifyRecordSignature(record)).toEqual({
      verdict: "invalid",
      messages: [
        "capsule_id=<object>: only one of signature/key_id present -- malformed producer envelope",
      ],
    });
    const both = {
      capsule_id: { toString: null },
      signature: "zz",
      key_id: "00",
    };
    const graded = await verifyRecordSignature(both);
    expect(graded.verdict).toBe("invalid");
    expect(graded.messages[0]).toMatch(/^capsule_id=<object>: /u);
    // The same record in a strict Bundle: a verdict, not a rejection.
    const bundle = structuredClone(vectors.cases[0]!.bundle) as {
      records: Record<string, unknown>[];
    };
    bundle.records[0]!.capsule_id = { toString: null };
    const { strict } = await verifyBundle(bundle, { strict: true });
    expect(strict.verdict).toBe("INVALID");
    expect(strict.records[0]!.capsuleId).toBe("");
  });
});

// #360: the viewer's context copies and freezes its input before verifying
// it. Both walks are iterative, so the copy succeeds and the verifier's own
// refusal is what the page shows.
describe("a context over input nested beyond the stack", () => {
  it("is built over the refused result, never rejects", async () => {
    const context = await buildVerifiedBundleContext(deepBundle());
    expect(context.verification.graphClosure).toEqual({
      status: "fail",
      findings: ["bundle_malformed"],
    });
    expect(context.strict?.verdict).toBe("INVALID");
    // The copy goes all the way down, and every level is frozen.
    let level = (context.bundle as { records: Record<string, unknown>[] })
      .records[0]!.deep;
    let depth = 0;
    while (Array.isArray(level)) {
      if (depth % 100_000 === 0) expect(Object.isFrozen(level)).toBe(true);
      level = level[0];
      depth += 1;
    }
    expect(depth).toBe(DEPTH);
  });

  it("renders the refusal, never rejects", async () => {
    // jsdom ships no type declarations, so it is loaded untyped.
    const { JSDOM } = createRequire(import.meta.url)("jsdom") as {
      JSDOM: new () => { window: Window & typeof globalThis };
    };
    const dom = new JSDOM();
    globalThis.document = dom.window.document;
    globalThis.HTMLElement = dom.window.HTMLElement;
    const root = document.createElement("main");
    await renderEvidenceGraph(deepBundle(), root);
    expect(
      root.querySelector<HTMLElement>("[data-verify]")?.dataset.verify,
    ).toBe("failed");
    expect(
      root.querySelector('[data-refusal="unverified-bundle"]')?.textContent,
    ).toBe(UNVERIFIED_BUNDLE_REFUSAL);
  });
});

describe("the context's copy keeps its semantics", () => {
  it("keeps a __proto__ member, shared references and non-plain objects, reads each key once and invokes no accessor", async () => {
    const shared = { n: 1 };
    const bundle = JSON.parse(
      '{"records": [], "extensions": {"__proto__": {"x": 1}}}',
    ) as Record<string, unknown>;
    bundle.a = shared;
    bundle.b = [shared, shared];
    const date = new Date(0);
    bundle.when = date;
    let reads = 0;
    Object.defineProperty(bundle, "counted", {
      enumerable: true,
      get: () => {
        reads += 1;
        return { v: 1 };
      },
    });
    const { bundle: owned } = await buildVerifiedBundleContext(bundle);
    const copy = owned as Record<string, unknown>;
    expect(Object.hasOwn(copy.extensions as object, "__proto__")).toBe(true);
    expect(Object.getPrototypeOf(copy.extensions)).toBe(Object.prototype);
    expect(copy.a).not.toBe(shared);
    expect((copy.b as unknown[])[0]).toBe(copy.a);
    expect((copy.b as unknown[])[1]).toBe(copy.a);
    expect(copy.when).toBe(date);
    expect(Object.isFrozen(date)).toBe(false);
    expect(reads).toBe(1);
    expect(Object.isFrozen(copy.counted)).toBe(true);
    expect(Object.isFrozen(copy.extensions)).toBe(true);
  });

  it("copies a cycle as a cycle", async () => {
    const bundle: Record<string, unknown> = { records: [] };
    bundle.self = bundle;
    const { bundle: owned } = await buildVerifiedBundleContext(bundle);
    const copy = owned as Record<string, unknown>;
    expect(copy.self).toBe(copy);
    expect(copy).not.toBe(bundle);
  });
});
