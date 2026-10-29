// composed/v1: the verify core's port of go/bundle/composed.go. The
// composition section's selection and drawing are capsule-viewer's.
//
// Parity: testdata/composed-parity/ holds, per case, the output of
// `capsulectl verify --bundle` (capsule-cli, which verifies composed/v1 with
// this repository's Go reference) for the same bundle. Cases `vector-*` are
// the published vectors (vectors/bundle/composed); the others are built from
// them by testdata/composed-parity/generate.py, which also says how the
// capsulectl outputs were produced.
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  composedDigest,
  composedDigestPreimage,
  verifyBundle,
  verifyComposed,
  type ComposedResult,
} from "../src/browser.js";

type Obj = Record<string, unknown>;

const read = (...path: string[]): unknown =>
  JSON.parse(readFileSync(resolve(process.cwd(), ...path), "utf8"));
const VECTORS = read("..", "vectors", "bundle", "composed", "vectors.json") as {
  cases: { id: string; container: Obj; expect: Obj }[];
};
const PARITY_DIR = resolve(
  process.cwd(),
  "test",
  "testdata",
  "composed-parity",
);

/** Every parity case: its bundle and capsulectl's output for it. */
function parityCases(): { name: string; bundle: Obj; cli: Obj }[] {
  return readdirSync(PARITY_DIR)
    .filter((f) => f.endsWith(".capsulectl.json"))
    .sort()
    .map((f) => {
      const name = f.slice(0, -".capsulectl.json".length);
      const bundle = name.startsWith("vector-")
        ? VECTORS.cases.find((c) => `vector-${c.id}` === name)!.container
        : (read(
            "test",
            "testdata",
            "composed-parity",
            `${name}.bundle.json`,
          ) as Obj);
      return {
        name,
        bundle,
        cli: read("test", "testdata", "composed-parity", f) as Obj,
      };
    });
}

const cliComposed = (cli: Obj): Obj => {
  const output = cli.output as { extensions: Obj[] };
  return output.extensions.find((e) => e.kind === "composed/v1")!
    .composed as Obj;
};

/** The TS result, in capsulectl's JSON shape (internal/cli/composed.go). */
function asCli(result: ComposedResult): Obj {
  if (result.malformed)
    return { status: result.status, findings: result.findings };
  return {
    status: result.status,
    findings: result.findings,
    composed_digest: result.composedDigest,
    members: result.members.map((m) => ({
      id: m.id,
      observer: m.observer,
      outcome: m.outcome,
      body: m.body,
      digest: m.digest,
      findings: m.findings,
      ...(m.bundle === undefined
        ? {}
        : {
            bundle: {
              graph_closure: m.bundle.graphClosure,
              interval_coverage: m.bundle.intervalCoverage,
              per_record_membership: m.bundle.perRecordMembership,
            },
          }),
      ...(m.refusalSignature === undefined
        ? {}
        : { refusal_signature: m.refusalSignature }),
    })),
    composition_closure: result.compositionClosure,
    joins: result.joins.map((j) => ({
      members: j.members,
      basis: j.basis,
      declared: j.declared,
      derived: j.derived ?? null,
      result: j.result,
      ...(j.differences.length === 0 ? {} : { differences: j.differences }),
    })),
    corroboration: result.corroboration,
  };
}

/** capsulectl's composed output, reduced to the fields asCli reports. */
function fromCli(composed: Obj): Obj {
  const digest = composed.composed_digest as Obj;
  return {
    status: composed.status,
    findings: composed.findings,
    composed_digest: digest,
    members: (composed.members as Obj[]).map((m) => {
      const bundle = m.bundle as Obj | undefined;
      const claim = (c: unknown) => c as Obj;
      return {
        id: m.id,
        observer: m.observer,
        outcome: m.outcome,
        body: m.body,
        digest: m.digest,
        findings: m.findings,
        ...(bundle === undefined
          ? {}
          : {
              bundle: {
                graph_closure: claim(bundle.graph_closure),
                interval_coverage: claim(bundle.interval_coverage),
                per_record_membership: claim(bundle.per_record_membership),
              },
            }),
        ...(m.refusal_signature === undefined
          ? {}
          : { refusal_signature: (m.refusal_signature as Obj).status }),
      };
    }),
    composition_closure: composed.composition_closure,
    joins: composed.joins,
    corroboration: composed.corroboration,
  };
}

async function tsComposed(bundle: Obj): Promise<ComposedResult> {
  const entry = (await verifyBundle(bundle)).extensions.find(
    (e) => e.kind === "composed/v1",
  );
  return entry!.composed!;
}

describe("composed/v1 verification (port of go/bundle/composed.go)", () => {
  it.each(VECTORS.cases.map((c) => [c.id, c] as const))(
    "%s: the published vector's expected results",
    async (_id, c) => {
      const block = (c.container.extensions as Obj)["composed/v1"];
      const expectation = c.expect as {
        composed_digest: string;
        canonical_preimage: string;
        members: Record<string, Obj>;
        composition_closure: Obj;
        joins: Obj[];
        corroboration: Obj[];
      };
      expect(new TextDecoder().decode(composedDigestPreimage(block))).toBe(
        expectation.canonical_preimage,
      );
      expect(await composedDigest(block)).toBe(expectation.composed_digest);
      const result = await tsComposed(c.container);
      if (result.malformed) throw new Error("malformed");
      expect(result.status).toBe((c.expect as { status: string }).status);
      for (const m of result.members) {
        const want = expectation.members[m.id]!;
        expect([m.outcome, m.body, m.digest]).toEqual([
          want.outcome,
          want.body,
          want.digest,
        ]);
        const response = want.response as Record<string, string> | undefined;
        expect(
          m.responseSignature === undefined
            ? undefined
            : {
                request_digest: m.findings.includes(
                  "response_request_digest_mismatch",
                )
                  ? "mismatch"
                  : "matches",
                artifact_digest: m.findings.includes(
                  "response_artifact_digest_mismatch",
                )
                  ? "mismatch"
                  : "matches",
                signature: m.responseSignature,
              },
        ).toEqual(response);
        const claims = want.claims as Record<string, string> | null;
        expect(
          m.bundle === undefined
            ? null
            : {
                graph_closure: m.bundle.graphClosure.status,
                interval_coverage: m.bundle.intervalCoverage.status,
                per_record_membership: m.bundle.perRecordMembership.status,
              },
        ).toEqual(claims);
      }
      expect(result.compositionClosure.status).toBe(
        expectation.composition_closure.status,
      );
      expect(result.compositionClosure.missing).toEqual(
        expectation.composition_closure.missing,
      );
      expect(
        result.joins.map((j) => ({
          members: j.members,
          declared: j.declared,
          derived: j.derived ?? null,
          result: j.result,
        })),
      ).toEqual(expectation.joins);
      expect(result.corroboration).toEqual(
        expectation.corroboration.map((c) =>
          c.result === "redundant" ? { ...c, reasons: [c.reason] } : c,
        ),
      );
    },
  );

  it.each(VECTORS.cases.map((c) => [c.id, c] as const))(
    "%s: the strict verdicts, and VALID only for a case that states it",
    async (_id, c) => {
      const verdict = async (bundle: unknown): Promise<string> =>
        (await verifyBundle(bundle, { strict: true })).strict.verdict;
      const block = (c.container.extensions as Obj)["composed/v1"] as {
        members: Obj[];
      };
      const members: Record<string, string> = {};
      for (const m of block.members)
        if (m.bundle !== undefined)
          members[m.id as string] = await verdict(m.bundle);
      const strict = { container: await verdict(c.container), members };
      const full =
        strict.container === "VALID" &&
        c.expect.status === "pass" &&
        Object.values(members).every((v) => v === "VALID");
      if (c.expect.strict === undefined) {
        expect(full).toBe(false);
        return;
      }
      expect(strict).toEqual(c.expect.strict);
      expect(full ? "VALID" : "INCOMPLETE").toBe(c.expect.verdict);
    },
  );

  it.each(parityCases().map((c) => [c.name, c] as const))(
    "%s: every composed result equals capsulectl verify --bundle",
    async (_name, c) => {
      expect(asCli(await tsComposed(c.bundle))).toEqual(
        fromCli(cliComposed(c.cli)),
      );
    },
  );

  it("the parity cases cover every join state, both results of a derivation and every agreement result", () => {
    const joins = parityCases().flatMap(
      (c) => cliComposed(c.cli).joins as Obj[],
    );
    expect(new Set(joins.map((j) => j.derived))).toEqual(
      new Set(["agree", "mismatch", "unjoined", "one_sided", null]),
    );
    expect(new Set(joins.map((j) => j.result))).toEqual(
      new Set(["derived_matches", "join_state_mismatch", "not_derivable"]),
    );
    const agreement = parityCases().flatMap(
      (c) => cliComposed(c.cli).corroboration as Obj[],
    );
    expect(new Set(agreement.map((a) => a.result))).toEqual(
      new Set(["corroborating", "redundant", "not_applicable"]),
    );
  });

  it("a malformed block reports nothing but the malformation, and is not interpreted", async () => {
    const bundle = {
      ...VECTORS.cases[0]!.container,
      extensions: { "composed/v1": { composed_digest: "00" } },
    };
    const verified = await verifyBundle(bundle);
    expect(verified.extensions).toEqual([
      {
        kind: "composed/v1",
        status: "uninterpreted",
        integrityCovered: true,
        composed: {
          status: "fail",
          malformed: true,
          findings: ["composed_block_malformed:composed_digest"],
        },
      },
    ]);
    expect(
      await verifyComposed({ composed_digest: "00" }, () => {
        throw new Error("no member is verified");
      }),
    ).toEqual(verified.extensions[0]!.composed);
  });
});
