import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { bundleDigest } from "../src/bundle.js";
import {
  classifyCountersignatures,
  declaredProducerKeys,
  type CountersignatureStamp,
  type CountersignerSource,
} from "../src/countersignature-stamp.js";
import {
  computeCapsuleId,
  verifyClass1,
  type ParsedJson,
} from "../src/index.js";

// The outcome-claim-limit vectors (vectors/outcome-claim-limits, generated
// by python/scripts/generate_outcome_claim_limits_vectors.py).
const DIR = resolve(process.cwd(), "..", "vectors", "outcome-claim-limits");

type Verdict = {
  accept: boolean;
  reason?: string;
  observed_by?: string;
  countersigner?: string;
};
type StampName = "not independent" | "unresolved signer" | "resolved";
type Capsule = Record<string, ParsedJson>;
type Class1 = {
  ok: boolean;
  derived: Record<string, string>;
  finding_codes: string[];
};
type CapsuleCase = {
  id: string;
  kind: "negative" | "positive";
  capsule: Capsule;
  expect: Verdict & { class1: Class1; grade: string };
  mutants: Array<{ set: Record<string, string>; expect: Verdict }>;
};
type BundleCase = {
  id: string;
  kind: "negative" | "positive";
  bundle: Record<string, unknown>;
  bundle_digest: string;
  countersigners: CountersignerSource;
  expect: Verdict & { stamp: StampName };
  mutants: Array<{
    bundle?: Record<string, unknown>;
    bundle_digest?: string;
    countersigners?: CountersignerSource;
    extra_producer_keys?: string[];
    expect: Verdict & { stamp: StampName };
  }>;
};

const raw = readFileSync(resolve(DIR, "vectors.json"));
const corpus = JSON.parse(raw.toString("utf8")) as {
  cases: Array<CapsuleCase | BundleCase>;
};
const capsuleCases = corpus.cases.filter(
  (c): c is CapsuleCase => "capsule" in c,
);
const bundleCases = corpus.cases.filter((c): c is BundleCase => "bundle" in c);

const STAMP_NAME: Partial<Record<CountersignatureStamp["kind"], StampName>> = {
  "not-independent": "not independent",
  "unresolved-signer": "unresolved signer",
  resolved: "resolved",
};

async function class1(capsule: Capsule): Promise<Class1> {
  const result = await verifyClass1(capsule);
  return {
    ok: result.ok,
    derived: { ...result.assurance },
    finding_codes: result.findings.map((f) => f.code),
  };
}

// The physical_proof rule: the Class-1 result, then the payload grade. Any
// grade other than gate_executed, an unregistered one included, is no
// stronger than runtime_claimed (REGISTRY §5).
async function physicalProof(capsule: Capsule): Promise<Verdict> {
  const c1 = await class1(capsule);
  const effect = capsule.effect as Record<string, unknown> | undefined;
  if (
    !c1.ok ||
    c1.derived.effect_mode !== "confirmed" ||
    effect?.effect_attestation !== "gate_executed"
  )
    return { accept: false, reason: "physical_completion_absent" };
  return { accept: true, observed_by: "gate" };
}

// The independent_outcome_proof rule over the stamp the library computes.
async function independentProof(
  bundle: Record<string, unknown>,
  countersigners: CountersignerSource,
  extraProducerKeys: readonly string[] = [],
): Promise<Verdict & { stamp: StampName | CountersignatureStamp["kind"] }> {
  const stamps = await classifyCountersignatures(
    bundle.countersignatures as unknown[],
    await bundleDigest(bundle),
    [...declaredProducerKeys(bundle), ...extraProducerKeys],
    countersigners,
  );
  expect(stamps).toHaveLength(1);
  const s = stamps[0]!;
  const stamp = STAMP_NAME[s.kind] ?? s.kind;
  if (s.kind === "resolved")
    return { stamp, accept: true, countersigner: s.name };
  if (s.kind === "not-independent")
    return { stamp, accept: false, reason: "outcome_signer_not_independent" };
  if (s.kind === "unresolved-signer")
    return { stamp, accept: false, reason: "outcome_signer_unresolved" };
  return { stamp, accept: false, reason: s.kind };
}

function withChanges(
  capsule: Capsule,
  changes: Record<string, string>,
): Capsule {
  const out = structuredClone(capsule) as Record<string, unknown>;
  for (const [path, value] of Object.entries(changes)) {
    const parts = path.split(".");
    let node = out;
    for (const name of parts.slice(0, -1))
      node = node[name] as Record<string, unknown>;
    node[parts[parts.length - 1]!] = value;
  }
  return out as Capsule;
}

describe("outcome-claim-limit vectors", () => {
  it("vectors.json is the file SHA256SUMS pins", () => {
    const sums = readFileSync(resolve(DIR, "SHA256SUMS"), "utf8");
    const digest = createHash("sha256").update(raw).digest("hex");
    expect(sums).toContain(`${digest}  vectors.json`);
    expect(capsuleCases).toHaveLength(2);
    expect(bundleCases).toHaveLength(2);
  });

  for (const c of capsuleCases) {
    it(`${c.id}: ${c.expect.accept ? "accepted" : c.expect.reason}`, async () => {
      expect(await computeCapsuleId(c.capsule)).toBe(c.capsule.capsule_id);
      expect(await class1(c.capsule)).toEqual(c.expect.class1);
      const { class1: _c1, grade: _g, ...verdict } = c.expect;
      expect(await physicalProof(c.capsule)).toEqual(verdict);
    });
    for (const m of c.mutants) {
      it(`${c.id}: mutant ${JSON.stringify(m.set)} flips`, async () => {
        const mutated = withChanges(c.capsule, m.set);
        mutated.capsule_id = await computeCapsuleId(mutated);
        expect((await class1(mutated)).ok).toBe(true);
        const got = await physicalProof(mutated);
        expect(got.accept).toBe(m.expect.accept);
        expect(got.reason).toBe(m.expect.reason);
        expect(got.accept).not.toBe(c.expect.accept);
      });
    }
  }

  it("the Class-1 result is the same for both Capsule twins", async () => {
    const [neg, pos] = capsuleCases;
    expect(neg!.capsule.capsule_id).not.toBe(pos!.capsule.capsule_id);
    expect(await class1(neg!.capsule)).toEqual(await class1(pos!.capsule));
    expect((await class1(neg!.capsule)).derived).not.toHaveProperty(
      "effect_attestation",
    );
  });

  for (const c of bundleCases) {
    it(`${c.id}: ${c.expect.stamp}`, async () => {
      expect(await bundleDigest(c.bundle)).toBe(c.bundle_digest);
      expect(await independentProof(c.bundle, c.countersigners)).toEqual(
        c.expect,
      );
    });
    for (const [i, m] of c.mutants.entries()) {
      it(`${c.id}: mutant ${i} flips to ${m.expect.stamp}`, async () => {
        const bundle = m.bundle ?? c.bundle;
        if (m.bundle_digest !== undefined)
          expect(await bundleDigest(bundle)).toBe(m.bundle_digest);
        const got = await independentProof(
          bundle,
          m.countersigners ?? c.countersigners,
          m.extra_producer_keys ?? [],
        );
        expect(got).toEqual(m.expect);
        expect(got.accept).not.toBe(c.expect.accept);
      });
    }
  }
});
