import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { emitEvidenceGraphHtml } from "../src/emitter.js";

const bundle = JSON.parse(
  readFileSync(
    resolve(import.meta.dirname, "testdata", "week-bundle.json"),
    "utf8",
  ),
) as unknown;
const iife = "/*IIFE_MARKER*/";

describe("emitEvidenceGraphHtml", () => {
  it("embeds the bundle, browser runtime, and boot call", () => {
    const html = emitEvidenceGraphHtml(bundle, iife);

    expect(html).toContain('id="app"');
    expect(html).toContain("renderEvidenceGraph(window.__BUNDLE__");
    expect(html).toContain(iife);
  });

  it("round-trips the inlined bundle", () => {
    const html = emitEvidenceGraphHtml(bundle, iife);
    const match = /window\.__BUNDLE__ = ([\s\S]*?);<\/script>/.exec(html);

    expect(match?.[1]).toBeDefined();
    expect(JSON.parse(match![1]!)).toEqual(bundle);
  });

  it("removes all embed placeholders", () => {
    const html = emitEvidenceGraphHtml(bundle, iife);

    expect(html).not.toContain("__BUNDLE_JSON__");
    expect(html).not.toContain("__BROWSER_IIFE__");
  });

  it("returns self-contained HTML with an inline bundle", () => {
    const html = emitEvidenceGraphHtml(bundle, iife);

    expect(html.toLowerCase()).toMatch(/^<!doctype html/);
    expect(html).toContain("window.__BUNDLE__ = {");
    expect(html).not.toMatch(/window\.__BUNDLE__ = https?:/);
  });
});
