// Member keys under controller_binding and same_key
// (draft-mih-zhang-agent-disclosure-bundle-03, "Joins"; #663): every case of
// vectors/bundle/composed-key-source/, compared with its whole `expect`, as
// python/tests/test_composed_library.py test_key_source_vectors reads them.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  composedDigestPreimage,
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
    canonical_preimage?: string;
    composed_digest?: string;
    composed_digest_equals_case?: string;
    status: string;
    malformed?: boolean;
  };
}
const FILE = JSON.parse(
  readFileSync(
    resolve(
      process.cwd(),
      "..",
      "vectors",
      "bundle",
      "composed-key-source",
      "vectors.json",
    ),
    "utf8",
  ),
) as { count: number; cases: Case[] };

async function composed(c: Case): Promise<ComposedResult> {
  const result = await verifyBundle(c.container, {
    controllerBindings: c.controller_bindings,
    bindingRevocations: c.binding_revocations,
  });
  const entry = result.extensions.find((e) => e.kind === "composed/v1")!;
  return entry.composed!;
}

/** The result in the vectors' `expect` vocabulary. */
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
    if (m.history !== undefined)
      member.history_member = {
        derivation: m.history.derivation,
        envelope_signature: m.history.envelopeSignature,
        artifact_digest: m.history.artifactDigest,
        request_digest: m.history.requestDigest,
        artifact_anchor: m.history.artifactAnchor,
        anchor_checkpoint: m.history.anchorCheckpoint,
        key: m.history.key ?? null,
        time: m.history.time ?? null,
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
    joins: result.joins.map((j) => {
      const value: Obj = {
        members: [...j.members],
        declared: j.declared,
        derived: j.derived ?? null,
        result: j.result,
      };
      if (j.keySources !== undefined)
        value.key_sources = j.keySources.map((k) => ({
          member: k.member,
          source: k.source,
        }));
      if (j.keys !== undefined && j.keys.length > 0)
        value.keys = j.keys.map((k) => ({ member: k.member, key: k.key }));
      if (j.historyTimes !== undefined)
        value.history_times = {
          history: j.historyTimes.history,
          history_time: j.historyTimes.historyTime,
          record: j.historyTimes.record,
          record_time: j.historyTimes.recordTime,
          relation: j.historyTimes.relation,
        };
      return value;
    }),
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

describe("composed key source vectors", () => {
  it("has every case", () => {
    expect(FILE.cases).toHaveLength(FILE.count);
    expect(FILE.count).toBeGreaterThan(0);
  });
  for (const c of FILE.cases)
    it(c.id, async () => {
      const result = await composed(c);
      if (c.expect.malformed === true) {
        expect(result.status).toBe("fail");
        expect(result.malformed).toBe(true);
        expect("joins" in result).toBe(false);
        return;
      }
      const block = (c.container.extensions as Obj)["composed/v1"];
      expect(new TextDecoder().decode(composedDigestPreimage(block))).toBe(
        c.expect.canonical_preimage,
      );
      if (result.malformed) throw new Error("malformed block");
      expect(result.status, result.findings.join(", ")).toBe(c.expect.status);
      const {
        canonical_preimage: _preimage,
        composed_digest_equals_case: _equals,
        ...want
      } = c.expect;
      expect(expectShape(result)).toEqual(want);
    });
});
