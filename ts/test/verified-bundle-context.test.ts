// @vitest-environment jsdom

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  buildVerifiedBundleContext,
  disclosureOf,
  isVerifiedBundleContext,
  type VerifiedBundleContext,
  withCountersigners,
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

describe("VerifiedBundleContext: effectively immutable", () => {
  async function countersignedContext(): Promise<{
    bundle: Obj;
    context: VerifiedBundleContext;
  }> {
    const bundle = await derivedFixture(
      "week-bundle-directory-countersigned.json",
    );
    bundle.extensions = { "example-extension/v1": { enabled: true } };
    const context = await buildVerifiedBundleContext(bundle, {
      countersigners: fixture("countersigners.json") as never,
    });
    return { bundle, context };
  }

  /** Everything a reader can observe, as plain data. */
  function snapshot(context: VerifiedBundleContext): unknown {
    return JSON.parse(
      JSON.stringify({
        bundle: context.bundle,
        root: context.root,
        verification: context.verification,
        resolvedDisclosures: [...context.resolvedDisclosures],
        records: context.records,
        recordIndex: [...context.recordIndex],
        countersignatures: context.countersignatures,
        countersigners: context.countersigners,
        extensions: context.extensions,
        completeness: context.completeness,
      }),
    );
  }

  // Each entry is a module trying to change one part of the context for
  // every reader after it. Every one must throw.
  type Mutable = Record<string, unknown> & unknown[];
  const attempts: ReadonlyArray<
    readonly [string, (context: VerifiedBundleContext) => void]
  > = [
    [
      "the context itself",
      (c) => {
        (c as unknown as Obj).root = "forged";
      },
    ],
    [
      "the verification result",
      (c) => {
        (c.verification as unknown as Obj).graphClosure = {
          status: "pass",
          findings: [],
        };
      },
    ],
    [
      "a claim inside the verification result",
      (c) => {
        (c.verification.perRecordMembership as unknown as Obj).status = "pass";
      },
    ],
    [
      "a capsule result inside the verification result",
      (c) => {
        const first = Object.values(c.verification.capsuleResults)[0]!;
        (first as unknown as Obj).ok = false;
      },
    ],
    [
      "the verifier's disclosure results",
      (c) => {
        (c.verification.disclosures as unknown as Mutable).push({
          capsuleId: "forged",
          member: "agent_input",
          status: "disclosure_match",
        });
      },
    ],
    [
      "resolvedDisclosures (set)",
      (c) => {
        (c.resolvedDisclosures as unknown as Map<string, unknown>).set(
          "forged",
          {},
        );
      },
    ],
    [
      "resolvedDisclosures (delete)",
      (c) => {
        const [id] = [...c.resolvedDisclosures.keys()];
        (c.resolvedDisclosures as unknown as Map<string, unknown>).delete(id!);
      },
    ],
    [
      "a resolved disclosure entry",
      (c) => {
        const [entry] = [...c.resolvedDisclosures.values()];
        (entry as unknown as Obj).agent_input = {
          state: "disclosed",
          payload: "forged",
        };
      },
    ],
    [
      "a disclosed payload",
      (c) => {
        const disclosed = [...c.resolvedDisclosures.values()]
          .flatMap((entry) => [entry.agent_input, entry.agent_output])
          .find(
            (member) =>
              member.state === "disclosed" &&
              typeof member.payload === "object" &&
              member.payload !== null,
          )!;
        const payload = disclosed.payload as Obj;
        payload[Object.keys(payload)[0] ?? "member"] = "forged";
      },
    ],
    [
      "the record list",
      (c) => {
        (c.records as unknown as Mutable).reverse();
      },
    ],
    [
      "the record index (set)",
      (c) => {
        (c.recordIndex as unknown as Map<string, unknown>).set("forged", {});
      },
    ],
    [
      "the record index (clear)",
      (c) => {
        (c.recordIndex as unknown as Map<string, unknown>).clear();
      },
    ],
    [
      "an indexed record",
      (c) => {
        const [record] = [...c.recordIndex.values()];
        (record as unknown as Obj).operator = "forged";
      },
    ],
    [
      "the extensions",
      (c) => {
        (c.extensions as unknown as Mutable).length = 0;
      },
    ],
    [
      "an extension result",
      (c) => {
        (c.extensions[0] as unknown as Obj).status = "verified";
      },
    ],
    [
      "the countersignatures",
      (c) => {
        (c.countersignatures as unknown as Mutable).pop();
      },
    ],
    [
      "a countersignature's value",
      (c) => {
        (c.countersignatures[0]!.value as Obj).kind = "forged";
      },
    ],
    [
      "the countersigner list",
      (c) => {
        (c.countersigners as unknown as Mutable).length = 0;
      },
    ],
    [
      "the completeness claims",
      (c) => {
        (c.completeness as unknown as Obj).graphClosure = {
          status: "pass",
          findings: [],
        };
      },
    ],
    [
      "the completeness memberships",
      (c) => {
        (c.completeness.memberships as Obj).forged = {};
      },
    ],
    [
      "the bundle copy",
      (c) => {
        ((c.bundle as Obj).records as Mutable).length = 0;
      },
    ],
  ];

  it("the fixture exercises every part", async () => {
    const { context } = await countersignedContext();
    expect(context.extensions.length).toBeGreaterThan(0);
    expect(context.countersignatures.length).toBeGreaterThan(0);
    expect(context.countersigners?.length).toBeGreaterThan(0);
    expect(context.records.length).toBeGreaterThan(0);
    expect(
      [...context.resolvedDisclosures.values()]
        .flatMap((entry) => [entry.agent_input, entry.agent_output])
        .some(
          (member) =>
            member.state === "disclosed" &&
            typeof member.payload === "object" &&
            member.payload !== null,
        ),
    ).toBe(true);
    expect(typeof context.countersignatures[0]!.value).toBe("object");
  });

  it.each(attempts)(
    "a module mutating %s throws and the next module sees the original",
    async (_part, mutate) => {
      const { context } = await countersignedContext();
      const before = snapshot(context);
      const graphBefore = await buildEvidenceGraph(context);
      const htmlBefore = await renderedText(context);
      expect(() => mutate(context)).toThrow(TypeError);
      expect(snapshot(context)).toEqual(before);
      expect(await buildEvidenceGraph(context)).toEqual(graphBefore);
      expect(await renderedText(context)).toBe(htmlBefore);
    },
  );

  it("is built over a copy: the caller's bundle and list stay writable and later edits do not reach it", async () => {
    const { bundle, context } = await countersignedContext();
    const before = snapshot(context);
    expect(Object.isFrozen(bundle)).toBe(false);
    expect(context.bundle).not.toBe(bundle);
    (bundle.records as Obj[]).length = 0;
    bundle.root = "edited";
    expect(snapshot(context)).toEqual(before);
  });

  it("a context with a new countersigner list is frozen the same way", async () => {
    const { context } = await countersignedContext();
    const swapped = withCountersigners(context, [
      ...(context.countersigners ?? []),
    ]);
    expect(Object.isFrozen(swapped)).toBe(true);
    expect(Object.isFrozen(swapped.countersigners)).toBe(true);
    expect(swapped.recordIndex).toBe(context.recordIndex);
  });
});
