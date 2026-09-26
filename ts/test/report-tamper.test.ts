import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { JSDOM } from "jsdom";
import { describe, expect, it } from "vitest";
import { emitEvidenceGraphHtml } from "../src/emitter.js";
import { renderEvidenceGraph } from "../src/browser.js";
import { derivedFixture } from "./helpers/derived-fixtures.js";

// A real report.html is opened in a browser, not the Node test process, so
// the render/verify step below needs a DOM -- constructed directly with
// jsdom rather than a whole-file environment override, which would also
// replace import.meta.url's scheme for emitEvidenceGraphHtml's own node:fs
// read of the shell template.
const dom = new JSDOM();
globalThis.document = dom.window.document;
globalThis.HTMLElement = dom.window.HTMLElement;

const BUNDLE_MARKER = /window\.__BUNDLE__ = ([\s\S]*?);<\/script>/u;

function bundle(): Record<string, unknown> {
  return JSON.parse(
    readFileSync(
      resolve(process.cwd(), "test", "testdata", "week-bundle.json"),
      "utf8",
    ),
  ) as Record<string, unknown>;
}

function directory(): Array<{
  publicKey: string;
  name: string;
  logoDataUrl: string;
  checksRecomputed: number;
}> {
  return JSON.parse(
    readFileSync(
      resolve(
        process.cwd(),
        "test",
        "testdata",
        "countersigner-directory.json",
      ),
      "utf8",
    ),
  );
}

/** Build a real emitted report.html, exactly the artifact a viewer opens. */
function emitReport(value: unknown): string {
  return emitEvidenceGraphHtml(value, "/*IIFE_MARKER*/");
}

/** Extract the embedded bundle back out of an emitted (possibly tampered) HTML string. */
function extractBundle(html: string): unknown {
  const match = BUNDLE_MARKER.exec(html);
  if (match?.[1] === undefined)
    throw new Error("embedded bundle not found in report.html");
  return JSON.parse(match[1]);
}

/** Edit the embedded bundle JSON in-place inside the emitted HTML text itself,
 * exactly as a tamperer editing the shipped report.html file would. */
function tamperHtml(
  html: string,
  mutate: (value: Record<string, unknown>) => unknown,
): string {
  const match = BUNDLE_MARKER.exec(html);
  if (match?.[1] === undefined)
    throw new Error("embedded bundle not found in report.html");
  const mutated = mutate(JSON.parse(match[1]) as Record<string, unknown>);
  const replacement = JSON.stringify(mutated);
  return `${html.slice(0, match.index)}window.__BUNDLE__ = ${replacement};</script>${html.slice(match.index + match[0].length)}`;
}

async function verifiedBanner(html: string): Promise<string | undefined> {
  const value = extractBundle(html);
  const root = document.createElement("main");
  await renderEvidenceGraph(value, root);
  return root.querySelector<HTMLElement>("[data-verify]")?.dataset.verify;
}

describe("report.html tamper test (rows are data, never prose)", () => {
  it("passes verification on the untampered report", async () => {
    const html = emitReport(bundle());
    expect(await verifiedBanner(html)).toBe("verified");
  });

  it("catches editing a number: the recomputed row disagrees", async () => {
    const html = emitReport(bundle());
    const tampered = tamperHtml(html, (value) => {
      const checkpoint = value.checkpoint as { root: string; mmr_size: number };
      return {
        ...value,
        checkpoint: { ...checkpoint, mmr_size: checkpoint.mmr_size + 1 },
      };
    });
    expect(await verifiedBanner(tampered)).toBe("failed");
  });

  it("catches editing a signed record: the capsule_id no longer matches", async () => {
    const html = emitReport(bundle());
    const tampered = tamperHtml(html, (value) => {
      const records = (value.records as Array<Record<string, unknown>>).map(
        (record, index) =>
          index === 0 ? { ...record, action_type: "decide" } : record,
      );
      return { ...value, records };
    });
    const result = extractBundle(tampered) as {
      records: Array<{ capsule_id: string }>;
    };
    const root = document.createElement("main");
    await renderEvidenceGraph(result, root);
    // The tampered record's own Class-1 check must fail identity, independent
    // of whether the graph still renders (a mutated first record may or may
    // not still satisfy buildEvidenceGraph's shape).
    const { verifyBundle } = await import("../src/bundle.js");
    const verified = await verifyBundle(result);
    const tamperedId = result.records[0]!.capsule_id;
    expect(verified.capsuleResults[tamperedId]?.ok).toBe(false);
  });

  it("catches dropping a record: range/membership fails", async () => {
    const html = emitReport(bundle());
    const tampered = tamperHtml(html, (value) => {
      const records = (value.records as unknown[]).slice(1);
      return { ...value, records };
    });
    expect(await verifiedBanner(tampered)).toBe("failed");
  });

  it("catches editing the bundle wholesale: the countersignature fails", async () => {
    const base = bundle();
    const countersignaturesFixture = (await derivedFixture(
      "week-bundle-directory-countersigned.json",
    )) as { countersignatures: unknown[] };
    const signed = {
      ...base,
      countersignatures: countersignaturesFixture.countersignatures,
    };
    const html = emitReport(signed);

    const { verifyBundle } = await import("../src/bundle.js");
    const { classifyCountersignatures } = await import(
      "../src/countersignature-stamp.js"
    );
    const untamperedDigest = (await verifyBundle(extractBundle(html) as never))
      .bundleDigest;
    const untamperedStamp = await classifyCountersignatures(
      signed.countersignatures,
      untamperedDigest,
      undefined,
      directory(),
    );
    expect(untamperedStamp[0]).toMatchObject({ kind: "directory" });

    const tampered = tamperHtml(html, (value) => ({
      ...value,
      root: `${(value.root as string).slice(0, -1)}0`,
    }));
    const tamperedValue = extractBundle(tampered) as {
      countersignatures: unknown[];
    };
    const tamperedDigest = (await verifyBundle(tamperedValue as never))
      .bundleDigest;
    const tamperedStamp = await classifyCountersignatures(
      tamperedValue.countersignatures,
      tamperedDigest,
      undefined,
      directory(),
    );
    expect(tamperedStamp[0]).toEqual({ kind: "invalid" });
  });

  it("keeps the existing XSS breakout regression on a tampered payload", () => {
    const payload = "</script><script>window.pwned=1</script>";
    const html = emitEvidenceGraphHtml({ payload }, "/*IIFE_MARKER*/");
    expect(html).not.toContain(payload);
    expect(html).toContain("\\u003c/script\\u003e");
  });
});
