// @vitest-environment jsdom

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  buildVerifiedBundleContext,
  disclosureOf,
  isVerifiedBundleContext,
  type VerifiedBundleContext,
} from "../src/bundle.js";
import { renderEvidenceGraph } from "../src/browser.js";
import {
  buildEvidenceGraph,
  EvidenceGraphError,
} from "../src/evidence-graph.js";
import { buildReportRows } from "../src/report-rows.js";
import { buildResultRoot, isResultRoot } from "../src/result-root.js";
import { derivedFixture } from "./helpers/derived-fixtures.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

type Obj = Record<string, unknown>;

function fixture(name: string): Obj {
  return JSON.parse(
    readFileSync(resolve(process.cwd(), "test", "testdata", name), "utf8"),
  ) as Obj;
}

const SENTINEL = "TAMPERED-PAYLOAD-SENTINEL";

/**
 * A disclosure value that does not hash to its committed digest and counts
 * every read of its members. The verifier reads it once (to digest it and
 * classify the mismatch); after the context is built, no builder may.
 */
function trap(): { value: Obj; reads: () => number; reset: () => void } {
  let reads = 0;
  const value: Obj = {};
  Object.defineProperty(value, "tampered", {
    enumerable: true,
    get: () => {
      reads += 1;
      return SENTINEL;
    },
  });
  return {
    value,
    reads: () => reads,
    reset: () => {
      reads = 0;
    },
  };
}

function tamper(
  bundle: Obj,
  id: string,
  field: string,
): ReturnType<typeof trap> {
  const t = trap();
  const disclosures = bundle.disclosures as Record<string, Obj>;
  disclosures[id] = { ...disclosures[id], [field]: t.value };
  return t;
}

async function contextWithMismatch(
  bundle: Obj,
  id: string,
  field: "agent_input" | "agent_output",
): Promise<{ context: VerifiedBundleContext; t: ReturnType<typeof trap> }> {
  const t = tamper(bundle, id, field);
  const context = await buildVerifiedBundleContext(bundle);
  // The verifier itself classified the member as a mismatch...
  expect(context.verification.disclosures).toContainEqual({
    capsuleId: id,
    member: field,
    status: "disclosure_mismatch",
  });
  // ...and the context carries that classification, with no payload.
  expect(disclosureOf(context, id, field)).toEqual({
    state: "disclosure_mismatch",
  });
  expect(t.reads()).toBeGreaterThan(0);
  t.reset();
  return { context, t };
}

async function renderedText(context: VerifiedBundleContext): Promise<string> {
  const root = document.createElement("main");
  await renderEvidenceGraph(context, root);
  return root.innerHTML;
}

describe("VerifiedBundleContext: no builder reads a mismatched payload", () => {
  it("report/v1 rows: a cited record's mismatched input is withheld from its citation", async () => {
    const { bundle, ids } = await sealEvidenceBundle(
      fixture("report-rows-bundle.json"),
    );
    const { context, t } = await contextWithMismatch(
      bundle,
      ids["act-established"]!,
      "agent_input",
    );
    const rows = await buildReportRows(context);
    expect(t.reads()).toBe(0);
    const citation = rows!.rows
      .flatMap((row) => row.citations)
      .find((c) => c.capsuleId === ids["act-established"]);
    expect(citation?.disclosure).toBe("disclosure_mismatch");
    expect(citation).not.toHaveProperty("disclosedPayload");
    const html = await renderedText(context);
    expect(t.reads()).toBe(0);
    expect(html).not.toContain(SENTINEL);
  });

  it("report/v1 rows: a mismatched root payload yields no row model", async () => {
    const { bundle, ids } = await sealEvidenceBundle(
      fixture("report-rows-bundle.json"),
    );
    const { context, t } = await contextWithMismatch(
      bundle,
      ids["root"]!,
      "agent_input",
    );
    await expect(buildReportRows(context)).resolves.toBeUndefined();
    expect(t.reads()).toBe(0);
  });

  it("Result root: a cited record's mismatched member is carried as a mismatch, never a payload", async () => {
    const { bundle, ids } = await sealEvidenceBundle(
      fixture("result-root-bundle.json"),
    );
    const { context, t } = await contextWithMismatch(
      bundle,
      ids["act-1"]!,
      "agent_output",
    );
    await expect(isResultRoot(context)).resolves.toBe(true);
    const result = await buildResultRoot(context);
    expect(t.reads()).toBe(0);
    const act = result.records.get(ids["act-1"]!)!;
    expect(act.agentOutput).toEqual({ state: "disclosure_mismatch" });
    expect(act.agentInput.state).toBe("disclosed");
    const html = await renderedText(context);
    expect(t.reads()).toBe(0);
    expect(html).not.toContain(SENTINEL);
  });

  it("Result root: a mismatched root document is refused", async () => {
    const { bundle, ids } = await sealEvidenceBundle(
      fixture("result-root-bundle.json"),
    );
    const { context, t } = await contextWithMismatch(
      bundle,
      ids["result"]!,
      "agent_input",
    );
    await expect(isResultRoot(context)).resolves.toBe(false);
    await expect(buildResultRoot(context)).rejects.toThrow(EvidenceGraphError);
    expect(t.reads()).toBe(0);
  });

  it("evaluation graph: an act's mismatched output is withheld from the act", async () => {
    const bundle = structuredClone(fixture("week-bundle.json"));
    const clean = await buildEvidenceGraph(bundle);
    const act = clean.reports
      .flatMap((report) => report.cases.flatMap((c) => c.acts))
      .find((candidate) => candidate.agentOutputDisclosure === "disclosed")!;
    expect(act).toBeDefined();
    const { context, t } = await contextWithMismatch(
      bundle,
      act.capsuleId,
      "agent_output",
    );
    const graph = await buildEvidenceGraph(context);
    expect(t.reads()).toBe(0);
    const tampered = graph.reports
      .flatMap((report) => report.cases.flatMap((c) => c.acts))
      .find((candidate) => candidate.capsuleId === act.capsuleId)!;
    expect(tampered.agentOutputDisclosure).toBe("disclosure_mismatch");
    expect(tampered).not.toHaveProperty("agentOutput");
    const html = await renderedText(context);
    expect(t.reads()).toBe(0);
    expect(html).not.toContain(SENTINEL);
  });

  it("evaluation graph: a mismatched root aggregate is refused", async () => {
    const bundle = structuredClone(fixture("week-bundle.json"));
    const { context, t } = await contextWithMismatch(
      bundle,
      bundle.root as string,
      "agent_input",
    );
    await expect(buildEvidenceGraph(context)).rejects.toThrow(
      EvidenceGraphError,
    );
    expect(t.reads()).toBe(0);
  });

  // Found while building the context: the builders' own re-resolution
  // checked a payload against the digest its record committed to, but not
  // whether the verifier accepted the record. A record edited after sealing
  // (its capsule_id no longer recomputes) whose disclosure still matched its
  // own committed digest was read as a payload. Strict now: a record the
  // verifier rejected is not in the context at all.
  it("a record whose identity failed verification is not read at all", async () => {
    const { bundle, ids } = await sealEvidenceBundle(
      fixture("report-rows-bundle.json"),
    );
    const records = bundle.records as Obj[];
    const index = records.findIndex(
      (record) => record.capsule_id === ids["act-established"],
    );
    records[index] = { ...records[index], operator: "edited-after-sealing" };
    const context = await buildVerifiedBundleContext(bundle);
    expect(context.recordIndex.has(ids["act-established"]!)).toBe(false);
    const rows = await buildReportRows(context);
    expect(
      rows!.rows
        .flatMap((row) => row.citations)
        .some((c) => c.capsuleId === ids["act-established"]),
    ).toBe(false);
  });
});

describe("VerifiedBundleContext: construction", () => {
  it("is built once and reused by the legacy (bundle) builders' context overloads", async () => {
    const { bundle } = await sealEvidenceBundle(
      fixture("result-root-bundle.json"),
    );
    const context = await buildVerifiedBundleContext(bundle);
    expect(isVerifiedBundleContext(context)).toBe(true);
    expect(await buildResultRoot(context)).toEqual(
      await buildResultRoot(bundle),
    );
    expect(context.records).toHaveLength((bundle.records as Obj[]).length);
    expect(context.extensions).toBe(context.verification.extensions);
    expect(context.countersignatures).toBe(
      context.verification.countersignatures,
    );
  });

  it("a hand-built object of the same shape is not a context", async () => {
    const { bundle } = await sealEvidenceBundle(
      fixture("result-root-bundle.json"),
    );
    const context = await buildVerifiedBundleContext(bundle);
    const forged = { ...context };
    expect(isVerifiedBundleContext(forged)).toBe(false);
    // Treated as a raw bundle: it has no records, so it is refused.
    await expect(buildResultRoot(forged)).rejects.toThrow(EvidenceGraphError);
  });
});

describe("VerifiedBundleContext: countersigners", () => {
  it("countersigners carried by the context reach the verification page", async () => {
    const bundle = await derivedFixture(
      "week-bundle-directory-countersigned.json",
    );
    const countersigners = fixture("countersigners.json") as never;
    const context = await buildVerifiedBundleContext(bundle, {
      countersigners,
    });
    const root = document.createElement("main");
    // The shell's call shape: no third argument.
    await renderEvidenceGraph(context, root);
    const stamp = root.querySelector('[data-stamp-kind="resolved"]');
    expect(stamp?.querySelector("span")?.textContent).toBe(
      "Countersigned by Example Countersigners Ltd · recomputed 2026-09-12T00:00:00Z",
    );
  });

  it("a bare bundle with no list still renders the signer as unlisted", async () => {
    const bundle = await derivedFixture(
      "week-bundle-directory-countersigned.json",
    );
    const root = document.createElement("main");
    await renderEvidenceGraph(bundle, root);
    expect(
      root.querySelector('[data-stamp-kind="unresolved-signer"]'),
    ).not.toBeNull();
  });

  it("an explicit third argument overrides the context's list", async () => {
    const bundle = await derivedFixture(
      "week-bundle-directory-countersigned.json",
    );
    const context = await buildVerifiedBundleContext(bundle, {
      countersigners: fixture("countersigners.json") as never,
    });
    const root = document.createElement("main");
    await renderEvidenceGraph(context, root, []);
    expect(
      root.querySelector('[data-stamp-kind="unresolved-signer"]'),
    ).not.toBeNull();
  });
});
