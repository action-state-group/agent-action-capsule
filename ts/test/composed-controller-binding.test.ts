// The composed/v1 controller_binding join (draft-mih-zhang-agent-disclosure-bundle-02,
// "Controller Binding Records" and "Joins"): the 14 cases of
// vectors/bundle/composed-controller-binding/, read as go/bundle's
// TestComposedControllerBindingVectors reads them. The delivered binding
// records and revocation statements are options beside the Bundle.
import { createHash, createPrivateKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  composedDigest,
  composedDigestPreimage,
  jcs,
  verifyBundle,
  type ComposedResult,
} from "../src/index.js";

type Obj = Record<string, unknown>;
interface Case {
  id: string;
  container: Obj;
  controller_bindings: Obj[];
  binding_revocations: Obj[];
  expect: Obj & {
    canonical_preimage: string;
    composed_digest: string;
    status: string;
    members: Record<string, Obj>;
    composition_closure: Obj;
    joins: Obj[];
    corroboration: Obj[];
  };
}
const FILE = JSON.parse(
  readFileSync(
    resolve(
      process.cwd(),
      "..",
      "vectors",
      "bundle",
      "composed-controller-binding",
      "vectors.json",
    ),
    "utf8",
  ),
) as {
  count: number;
  keys: Record<string, { seed_hex: string; public_key_hex: string }>;
  cases: Case[];
};

async function composed(
  c: Case,
  delivered: boolean,
): Promise<Exclude<ComposedResult, { malformed: true }>> {
  const result = await verifyBundle(
    c.container,
    delivered
      ? {
          controllerBindings: c.controller_bindings,
          bindingRevocations: c.binding_revocations,
        }
      : {},
  );
  const entry = result.extensions.find((e) => e.kind === "composed/v1")!;
  if (entry.composed!.malformed) throw new Error("malformed block");
  return entry.composed!;
}

/** The result in the vectors' `expect` vocabulary (go/bundle expectShape). */
function expectShape(
  result: Exclude<ComposedResult, { malformed: true }>,
): Obj {
  const members: Obj = {};
  for (const m of result.members) {
    const member: Obj = {
      outcome: m.outcome,
      body: m.body,
      digest: m.digest,
      claims:
        m.bundle === undefined
          ? null
          : {
              graph_closure: m.bundle.graphClosure.status,
              interval_coverage: m.bundle.intervalCoverage.status,
              per_record_membership: m.bundle.perRecordMembership.status,
            },
    };
    if (m.bundle?.history !== undefined)
      member.history = {
        state: m.bundle.history.state,
        since: m.bundle.history.since,
      };
    members[m.id] = member;
  }
  const closure: Obj = {
    status: result.compositionClosure.status,
    missing: [...result.compositionClosure.missing],
  };
  if (result.compositionClosure.status === "withheld")
    closure.finding = result.compositionClosure.findings[0];
  return {
    composed_digest: result.composedDigest.recomputed,
    status: result.status,
    members,
    composition_closure: closure,
    joins: result.joins.map((j) => ({
      members: [...j.members],
      declared: j.declared,
      derived: j.derived ?? null,
      result: j.result,
    })),
    corroboration: result.corroboration.map((c) => {
      const value: Obj = { members: [...c.members], result: c.result };
      if (c.result === "redundant") {
        value.reason = c.reason;
        value.report = c.report;
      }
      if (c.result === "corroborating") value.qualifier = c.qualifier;
      return value;
    }),
  };
}

describe("composed controller_binding vectors", () => {
  it("has 14 cases", () => {
    expect(FILE.count).toBe(14);
    expect(FILE.cases).toHaveLength(14);
  });
  for (const c of FILE.cases)
    it(c.id, async () => {
      const block = (c.container.extensions as Obj)["composed/v1"];
      expect(new TextDecoder().decode(composedDigestPreimage(block))).toBe(
        c.expect.canonical_preimage,
      );
      expect(await composedDigest(block)).toBe(c.expect.composed_digest);
      const result = await composed(c, true);
      expect(result.status).toBe(c.expect.status);
      const { canonical_preimage: _preimage, ...want } = c.expect;
      expect(expectShape(result)).toEqual(want);
    });

  // Without the delivered records, every controller_binding join is
  // not_derivable: the basis never derives from the block alone.
  it("is not derivable without the delivered record", async () => {
    for (const c of FILE.cases) {
      const result = await composed(c, false);
      expect(result.joins[0]!.result, c.id).toBe("not_derivable");
      expect(result.corroboration[0]!.result, c.id).toBe("not_applicable");
    }
  });
});
