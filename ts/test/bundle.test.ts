import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { MmrTree, inclusionProof, rangeProof } from "@action-state-group/cll";
import { describe, expect, it } from "vitest";
import {
  bundleDigest,
  computeCapsuleId,
  decodeFragment,
  encodeFragment,
  jsonDigest,
  verifyBundle,
} from "../src/index.js";

type Bundle = Record<string, unknown>;
type Vector = {
  name: string;
  expected: {
    graph_closure: string;
    interval_coverage: string;
    interval_findings?: string[];
    per_record_membership: string;
    membership_findings?: string[];
    disclosures?: string[];
  };
};
const vectors = JSON.parse(
  readFileSync(
    resolve(import.meta.dirname, "testdata", "bundle-vectors.json"),
    "utf8",
  ),
) as { count: number; cases: Vector[] };

const proof = (value: Awaited<ReturnType<typeof inclusionProof>>) => ({
  ...value,
  witness: [...value.witness],
  peaks_left: [...value.peaks_left],
  peaks_right: [...value.peaks_right],
});
async function capsule(
  number: number,
  output?: unknown,
  input?: unknown,
  chain?: Bundle,
): Promise<Bundle> {
  const value: Bundle = {
    spec_version: "draft-mih-scitt-agent-action-capsule-04",
    format_version: "4",
    canonicalization_id: "jcs",
    action_id: `bundle-${number}`,
    action_type: "decide",
    operator: "ACME-CO",
    developer: "agent@v1",
    timestamp: `2026-09-14T00:00:0${number}Z`,
    assurance: {
      effect_mode: "not_applicable",
      attestation_mode: "self_attested",
      ledger_mode: "standalone",
    },
    disposition: {
      verdict_class: "blocked",
      decision: "reject",
      approver: "policy",
      human_disposed: false,
    },
  };
  if (output !== undefined)
    value.model_attestation = {
      compute_attestation: { agent_output_digest: await jsonDigest(output) },
    };
  if (input !== undefined) {
    const attestation = (value.model_attestation ?? {
      compute_attestation: {},
    }) as Bundle;
    (attestation.compute_attestation as Bundle).agent_input_digest =
      await jsonDigest(input);
    value.model_attestation = attestation;
  }
  if (chain) value.chain = chain;
  value.capsule_id = await computeCapsuleId(value as never);
  return value;
}
async function testBundle(
  records: Bundle[],
  root: Bundle,
  output?: unknown,
  missing: string[] = [],
): Promise<Bundle> {
  const tree = new MmrTree();
  for (const record of records)
    await tree.appendHexIdentity(record.capsule_id as string);
  const size = tree.size,
    proofs = await Promise.all(
      records.map((_, index) => inclusionProof(tree, BigInt(index), size)),
    );
  const rangeP = await rangeProof(tree, 0n, BigInt(records.length - 1), size);
  const members: Record<string, unknown> = {};
  for (const [index, record] of records.entries())
    members[record.capsule_id as string] = {
      log_coordinates: {
        log_id: "bundle-log",
        seq: index + 1,
        leaf_index: index,
      },
      inclusion_proof: proof(proofs[index]!),
    };
  return {
    bundle_version: "2",
    bundle_kind: "evidence-bundle/v2",
    root: root.capsule_id,
    records,
    completeness: {
      closure_depth: 2,
      records_mode: missing.length ? "declared_incomplete" : "complete",
      payloads_mode: "selected",
      suppressed_fields: ["agent_input"],
      missing,
    },
    disclosures:
      output === undefined
        ? {}
        : { [records[0]!.capsule_id as string]: { agent_output: output } },
    completeness_certificate: {
      log_id: "bundle-log",
      range_root: Array.from(await tree.root(), (byte) =>
        byte.toString(16).padStart(2, "0"),
      ).join(""),
      first_seq: 1,
      last_seq: records.length,
      body_digests: records.map((record) => record.capsule_id),
      range_proof: {
        from_seq: 1,
        to_seq: records.length,
        size: Number(size),
        from_index: rangeP.from_index,
        to_index: rangeP.to_index,
        witness: rangeP.witness,
      },
      memberships: members,
    },
    checkpoint: {
      root: Array.from(await tree.root(), (byte) =>
        byte.toString(16).padStart(2, "0"),
      ).join(""),
      mmr_size: Number(size),
    },
    extensions: { "example/unimplemented": { note: "digest-covered only" } },
  };
}
async function fixture(name: string): Promise<Bundle> {
  const output = { response: { account: "A-17", amount: "42.00" } },
    input = { request: { account: "A-17", amount: "42.00" } };
  const first = await capsule(1, output),
    middle = await capsule(2, undefined, input),
    root = await capsule(3);
  let bundle = await testBundle([first, middle, root], root, output);
  if (name === "neg-deleted-interior-record") {
    bundle.records = [first, root];
    delete ((bundle.completeness_certificate as Bundle).memberships as Bundle)[
      middle.capsule_id as string
    ];
  }
  if (name === "neg-replaced-interior-record") {
    const replacement = await capsule(9, undefined, input),
      memberships = (bundle.completeness_certificate as Bundle)
        .memberships as Bundle,
      original = memberships[middle.capsule_id as string];
    delete memberships[middle.capsule_id as string];
    memberships[replacement.capsule_id as string] = original;
    bundle.records = [first, replacement, root];
  }
  if (
    name === "neg-dangling-citation" ||
    name === "pos-declared-missing-citation"
  ) {
    const absent = "f".repeat(64),
      citedRoot = await capsule(4, undefined, undefined, {
        parent_capsule_id: absent,
        relation: "derived_from",
      });
    bundle = await testBundle(
      [first, middle, citedRoot],
      citedRoot,
      undefined,
      name.startsWith("pos-") ? [absent] : [],
    );
  }
  if (name === "neg-disclosure-mismatch-nested-match")
    (bundle.disclosures as Bundle)[middle.capsule_id as string] = {
      agent_input: { request: { account: "A-17", amount: "99.00" } },
    };
  if (name === "neg-supplied-record-unbound")
    bundle.records = [...(bundle.records as Bundle[]), await capsule(9)];
  if (name === "neg-membership-proof-coordinate-mismatch") {
    const member = (
      (bundle.completeness_certificate as Bundle).memberships as Bundle
    )[middle.capsule_id as string] as Bundle;
    (member.inclusion_proof as Bundle).leaf_index = 0;
  }
  if (name === "pos-default-completeness-values") {
    delete (bundle.completeness as Bundle).closure_depth;
    delete (bundle.completeness as Bundle).missing;
  }
  if (name === "neg-portable-proof-version-kind") {
    const member = (
      (bundle.completeness_certificate as Bundle).memberships as Bundle
    )[middle.capsule_id as string] as Bundle;
    (member.inclusion_proof as Bundle).v = 2;
    (member.inclusion_proof as Bundle).kind = "not-inclusion";
  }
  if (name === "neg-boolean-proof-integer") {
    const member = (
      (bundle.completeness_certificate as Bundle).memberships as Bundle
    )[middle.capsule_id as string] as Bundle;
    (member.inclusion_proof as Bundle).v = true;
  }
  return bundle;
}
describe("shared Evidence Bundle vectors", () => {
  it("pins the shared manifest source and SHA-256", () => {
    expect(vectors.count).toBe(12);
    expect(
      readFileSync(
        resolve(
          import.meta.dirname,
          "..",
          "..",
          "vectors",
          "bundle",
          "vectors.json",
        ),
        "utf8",
      ),
    ).toBe(
      readFileSync(
        resolve(import.meta.dirname, "testdata", "bundle-vectors.json"),
        "utf8",
      ),
    );
  });
  for (const vector of vectors.cases)
    it(vector.name, async () => {
      const bundle = await fixture(vector.name);
      expect(decodeFragment(encodeFragment(bundle))).toEqual(bundle);
      const actual = await verifyBundle(bundle);
      expect(actual.graphClosure.status).toBe(vector.expected.graph_closure);
      expect(actual.intervalCoverage.status).toBe(
        vector.expected.interval_coverage,
      );
      expect(actual.perRecordMembership.status).toBe(
        vector.expected.per_record_membership,
      );
      if (vector.expected.interval_findings)
        expect(actual.intervalCoverage.findings).toEqual(
          vector.expected.interval_findings,
        );
      if (vector.expected.membership_findings)
        expect(actual.perRecordMembership.findings).toEqual(
          vector.expected.membership_findings,
        );
      if (vector.expected.disclosures)
        expect(actual.disclosures.map((item) => item.status).sort()).toEqual(
          [...vector.expected.disclosures].sort(),
        );
    });
  it("matches the cross-language countersignature digest", async () => {
    expect(
      await bundleDigest({
        b: 1,
        a: "value",
        countersignatures: [
          { type: "cose-sign1", signature: "ignored-by-digest" },
        ],
      }),
    ).toBe("04a0f2c6e056b32f5659fdec506f9f6d6a0b250227004b0fd7ed43d0b77035a5");
  });
  it("keeps decoding transport-only and labels reserved reporting", async () => {
    expect(decodeFragment(encodeFragment(null))).toBeNull();
    const result = await verifyBundle({
      countersignatures: ["reserved"],
      verification: { producer: "claimed" },
    });
    expect(result.countersignatures).toEqual([
      { value: "reserved", status: "unverified" },
    ]);
    expect(result.verification).toEqual({
      value: { producer: "claimed" },
      status: "producer_self_report",
    });
  });

  it("rejects an altered interior body digest (range binding)", async () => {
    const bundle = await fixture("pos-valid-bundle");
    const cert = bundle.completeness_certificate as Record<string, unknown>;
    (cert.body_digests as string[])[1] = "aa".repeat(32);
    const result = await verifyBundle(bundle);
    expect(result.intervalCoverage.status).toBe("fail");
    expect(result.intervalCoverage.findings).toContain("range_proof_invalid");
  });

  it("rejects a sub-tip range (F1 tip bind)", async () => {
    const caps = [
      await capsule(1),
      await capsule(2),
      await capsule(3),
      await capsule(4),
    ];
    const tree = new MmrTree();
    for (const c of caps) await tree.appendHexIdentity(c.capsule_id as string);
    const size = tree.size;
    const rootHex = Array.from(await tree.root(), (b) =>
      b.toString(16).padStart(2, "0"),
    ).join("");
    const rangeP = await rangeProof(tree, 0n, 2n, size);
    const records = caps.slice(0, 3);
    const members: Record<string, unknown> = {};
    for (const [i, c] of records.entries())
      members[c.capsule_id as string] = {
        log_coordinates: { log_id: "bundle-log", seq: i + 1, leaf_index: i },
        inclusion_proof: proof(await inclusionProof(tree, BigInt(i), size)),
      };
    const bundle: Bundle = {
      bundle_version: "2",
      bundle_kind: "evidence-bundle/v2",
      root: records.at(-1)!.capsule_id,
      records,
      completeness: { records_mode: "complete", missing: [] },
      completeness_certificate: {
        log_id: "bundle-log",
        range_root: rootHex,
        first_seq: 1,
        last_seq: 3,
        body_digests: records.map((r) => r.capsule_id),
        range_proof: {
          from_seq: 1,
          to_seq: 3,
          size: Number(size),
          from_index: rangeP.from_index,
          to_index: rangeP.to_index,
          witness: rangeP.witness,
        },
        memberships: members,
      },
      checkpoint: { root: rootHex, mmr_size: Number(size) },
    };
    const result = await verifyBundle(bundle);
    expect(result.intervalCoverage.status).toBe("fail");
    expect(result.intervalCoverage.findings).toContain("range_proof_invalid");
  });
});
