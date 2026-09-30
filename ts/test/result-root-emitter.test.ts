import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { JSDOM } from "jsdom";
import { describe, expect, it } from "vitest";
import { emitEvidenceGraphHtml } from "../src/emitter.js";
import { renderEvidenceGraph } from "../src/browser.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

// The emitted report.html is opened in a browser; jsdom stands in for it
// here, constructed directly so emitEvidenceGraphHtml's node:fs shell read
// keeps its file: import.meta.url (see report-tamper.test.ts).
const dom = new JSDOM();
globalThis.document = dom.window.document;
globalThis.HTMLElement = dom.window.HTMLElement;

type Obj = Record<string, unknown>;
const BUNDLE_MARKER = /window\.__BUNDLE__ = ([\s\S]*?);<\/script>/u;
const IIFE = "/*IIFE_MARKER*/";

const testdata = (name: string): string =>
  resolve(process.cwd(), "test", "testdata", name);

function fixture(name: string): Obj {
  return JSON.parse(readFileSync(testdata(name), "utf8")) as Obj;
}

function extractBundle(html: string): Obj {
  const match = BUNDLE_MARKER.exec(html);
  if (match?.[1] === undefined) throw new Error("embedded bundle not found");
  return JSON.parse(match[1]) as Obj;
}

async function renderHtml(html: string): Promise<HTMLElement> {
  const root = document.createElement("main");
  await renderEvidenceGraph(extractBundle(html), root);
  return root;
}

/**
 * (d) Go/TS parity for a Result-root bundle. The Go emitter is a byte-equal
 * shell wrapper with no knowledge of root families, so the same committed
 * sealed bundle must produce the same HTML from both; go/emitter's
 * TestEmitResultRootHTMLMatchesTypeScript reads the same two files.
 *
 * To regenerate both after an intentional fixture change: seal
 * result-root-bundle.json with sealEvidenceBundle, write it pretty-printed to
 * result-root-bundle.sealed.json, and write emitEvidenceGraphHtml(sealed,
 * "/*IIFE_MARKER*\/") to go/emitter/testdata/expected-result-root.html.
 */
describe("Result-root bundle through the emitter", () => {
  it("the committed sealed bundle is the seal of the readable fixture", async () => {
    const { bundle } = await sealEvidenceBundle(
      fixture("result-root-bundle.json"),
    );
    expect(bundle).toEqual(fixture("result-root-bundle.sealed.json"));
  });

  it("emits byte-for-byte the HTML the Go twin is pinned to", () => {
    const html = emitEvidenceGraphHtml(
      fixture("result-root-bundle.sealed.json"),
      IIFE,
    );
    const expected = readFileSync(
      resolve(
        process.cwd(),
        "..",
        "go",
        "emitter",
        "testdata",
        "expected-result-root.html",
      ),
      "utf8",
    );
    expect(html).toBe(expected);
  });

  it("the emitted report verifies and renders the Result page", async () => {
    const html = emitEvidenceGraphHtml(
      fixture("result-root-bundle.sealed.json"),
      IIFE,
    );
    const root = await renderHtml(html);
    expect(root.querySelector('[data-verify="verified"]')).not.toBeNull();
    expect(root.querySelector('[data-page="result"]')).not.toBeNull();
    expect(root.querySelectorAll("[data-claim-row]")).toHaveLength(3);
  });

  it("a book-built root (evidence_result record header) emits a report that verifies and renders the same Result page", async () => {
    const { bundle } = await sealEvidenceBundle(
      fixture("result-root-book-bundle.json"),
    );
    const html = emitEvidenceGraphHtml(bundle, IIFE);
    expect(html).toContain('"record_type":"evidence_result"');
    const root = await renderHtml(html);
    expect(root.querySelector('[data-verify="verified"]')).not.toBeNull();
    expect(root.querySelector('[data-page="result"]')).not.toBeNull();
    expect(root.querySelectorAll("[data-claim-row]")).toHaveLength(3);
  });

  it("(c) editing a claim inside the shipped report.html fails verification and draws no Result", async () => {
    const html = emitEvidenceGraphHtml(
      fixture("result-root-bundle.sealed.json"),
      IIFE,
    );
    const edited = html.replace('"verdict":"not_met"', '"verdict":"met"');
    expect(edited).not.toBe(html);
    const root = await renderHtml(edited);
    expect(root.querySelector('[data-verify="failed"]')).not.toBeNull();
    expect(root.querySelector('[data-page="result"]')).toBeNull();
    expect(root.querySelectorAll("[data-claim-row]")).toHaveLength(0);
  });
});

describe("Result-root bundle with a close claim through the emitter", () => {
  it("emits a report whose close state is recomputed from the embedded bundle's links", async () => {
    const { bundle, ids } = await sealEvidenceBundle(
      fixture("result-root-close-bundle.json"),
    );
    const html = emitEvidenceGraphHtml(bundle, IIFE);
    const root = await renderHtml(html);
    expect(root.querySelector('[data-verify="verified"]')).not.toBeNull();
    expect(root.querySelectorAll("[data-claim-row]")).toHaveLength(2);
    const state = root.querySelector<HTMLElement>(
      '[data-claim-row="close-1"] [data-close-state]',
    )!;
    expect(state.dataset.closeState).toBe("AGREED");
    expect(state.dataset.closeDerivation).toBe("recomputed");
    // editing the peer's link inside the shipped report (the embedded bundle
    // is JCS-sorted, so `target` precedes `type`) breaks its disclosure
    // digest: the bundle no longer verifies, so no state is drawn at all
    const edited = html.replace(
      `"target":"${ids["close-a"]}","type":"acknowledges"`,
      `"target":"${ids["close-a"]}","type":"rebuts"`,
    );
    expect(edited).not.toBe(html);
    const forged = await renderHtml(edited);
    expect(forged.querySelector('[data-verify="failed"]')).not.toBeNull();
    expect(forged.querySelector("[data-close-state]")).toBeNull();
  });
});
